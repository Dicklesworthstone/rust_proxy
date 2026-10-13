use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::LazyLock;
use std::time::Duration;

const MAX_FEED_BYTES: usize = 16 * 1024 * 1024;
static FEED_CLIENT: LazyLock<Result<reqwest::Client>> = LazyLock::new(|| {
    reqwest::Client::builder()
        .user_agent("OpenAI File Downloader, XaiImageApiFetch/1.0")
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .context("Failed building provider-feed HTTP client")
});

async fn fetch_body(url: &str) -> Result<Vec<u8>> {
    let client = FEED_CLIENT
        .as_ref()
        .map_err(|err| anyhow::anyhow!("{err}"))?;
    let mut response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed fetching {url}"))?
        .error_for_status()?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_FEED_BYTES as u64)
    {
        anyhow::bail!("Provider feed exceeds {MAX_FEED_BYTES} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX_FEED_BYTES - body.len() {
            anyhow::bail!("Provider feed exceeds {MAX_FEED_BYTES} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validated_ranges(prefixes: impl IntoIterator<Item = String>) -> Result<HashSet<String>> {
    let mut out = HashSet::new();
    for prefix in prefixes {
        let (ip, bits) = prefix
            .split_once('/')
            .context("Provider range must be an IPv4 CIDR")?;
        let ip: Ipv4Addr = ip
            .parse()
            .with_context(|| format!("Invalid IPv4 range: {prefix}"))?;
        if bits.is_empty() || !bits.bytes().all(|b| b.is_ascii_digit()) {
            anyhow::bail!("Invalid IPv4 prefix length: {prefix}");
        }
        let bits: u32 = bits.parse().context("Invalid IPv4 prefix length")?;
        if bits > 32 {
            anyhow::bail!("Invalid IPv4 prefix length: {prefix}");
        }
        let mask = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        };
        out.insert(format!("{}/{}", Ipv4Addr::from(u32::from(ip) & mask), bits));
    }
    if out.is_empty() {
        anyhow::bail!("Provider feed contained no usable IPv4 ranges");
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct AwsRanges {
    prefixes: Vec<AwsPrefix>,
}

#[derive(Debug, Deserialize)]
struct AwsPrefix {
    ip_prefix: String,
}

#[derive(Debug, Deserialize)]
struct GoogleRanges {
    prefixes: Vec<GooglePrefix>,
}

#[derive(Debug, Deserialize)]
struct GooglePrefix {
    #[serde(rename = "ipv4Prefix")]
    ipv4_prefix: Option<String>,
}

pub async fn fetch_google_ipv4() -> Result<HashSet<String>> {
    let url = "https://www.gstatic.com/ipranges/goog.json";
    let ranges: GoogleRanges = serde_json::from_slice(&fetch_body(url).await?)
        .with_context(|| format!("Failed parsing Google ip ranges {url}"))?;
    validated_ranges(ranges.prefixes.into_iter().filter_map(|p| p.ipv4_prefix))
}

pub async fn fetch_aws_ipv4() -> Result<HashSet<String>> {
    let url = "https://ip-ranges.amazonaws.com/ip-ranges.json";
    let ranges: AwsRanges = serde_json::from_slice(&fetch_body(url).await?)
        .with_context(|| format!("Failed parsing AWS ip ranges {url}"))?;
    validated_ranges(ranges.prefixes.into_iter().map(|p| p.ip_prefix))
}

pub async fn fetch_cloudflare_ipv4() -> Result<HashSet<String>> {
    let url = "https://www.cloudflare.com/ips-v4";
    let body = String::from_utf8(fetch_body(url).await?)
        .with_context(|| format!("Failed reading {url}"))?;
    validated_ranges(
        body.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn ranges_are_validated_as_a_whole_and_canonicalized() {
        let ranges = validated_ranges([
            "203.0.113.7/24".into(),
            "203.0.113.0/24".into(),
            "198.51.100.1/32".into(),
        ])
        .unwrap();
        assert_eq!(ranges.len(), 2);
        assert!(ranges.contains("203.0.113.0/24"));
        for bad in [
            "2001:db8::/32",
            "203.0.113.0/33",
            "203.0.113.0",
            "garbage/24",
            "1.2.3.4/-1",
        ] {
            assert!(
                validated_ranges(["198.51.100.0/24".into(), bad.into()]).is_err(),
                "accepted {bad}"
            );
        }
        assert!(validated_ranges(Vec::new()).is_err());
    }

    #[tokio::test]
    async fn feed_http_rejects_non_success_truncation_and_size_before_publication() {
        for (response, accepted) in [
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata".to_string(),
                true,
            ),
            (
                "HTTP/1.1 503 Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata"
                    .to_string(),
                false,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\ndata"
                    .to_string(),
                false,
            ),
            (
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    MAX_FEED_BYTES + 1
                ),
                false,
            ),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let size = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..size]);
                assert!(request.contains("OpenAI File Downloader, XaiImageApiFetch/1.0"));
                stream.write_all(response.as_bytes()).await.unwrap();
            });
            let result = fetch_body(&format!("http://{addr}/ranges")).await;
            assert_eq!(result.is_ok(), accepted, "{result:?}");
            if let Ok(body) = result {
                assert_eq!(body, b"data");
            }
            server.await.unwrap();
        }
    }
}

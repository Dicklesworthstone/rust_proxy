use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;

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
    let ranges = reqwest::get(url)
        .await
        .with_context(|| format!("Failed fetching {url}"))?
        .json::<GoogleRanges>()
        .await
        .with_context(|| format!("Failed parsing Google ip ranges {url}"))?;

    let mut out = HashSet::new();
    for prefix in ranges.prefixes {
        if let Some(ipv4) = prefix.ipv4_prefix {
            out.insert(ipv4);
        }
    }
    Ok(out)
}

pub async fn fetch_aws_ipv4() -> Result<HashSet<String>> {
    let url = "https://ip-ranges.amazonaws.com/ip-ranges.json";
    let ranges = reqwest::get(url)
        .await
        .with_context(|| format!("Failed fetching {url}"))?
        .json::<AwsRanges>()
        .await
        .with_context(|| format!("Failed parsing AWS ip ranges {url}"))?;

    let mut out = HashSet::new();
    for prefix in ranges.prefixes {
        out.insert(prefix.ip_prefix);
    }
    Ok(out)
}

pub async fn fetch_cloudflare_ipv4() -> Result<HashSet<String>> {
    let url = "https://www.cloudflare.com/ips-v4";
    let body = reqwest::get(url)
        .await
        .with_context(|| format!("Failed fetching {url}"))?
        .text()
        .await
        .with_context(|| format!("Failed reading {url}"))?;
    let mut out = HashSet::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            out.insert(trimmed.to_string());
        }
    }
    Ok(out)
}

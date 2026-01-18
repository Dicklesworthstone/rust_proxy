use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
}

pub fn parse_proxy_url(raw: &str) -> Result<ProxyEndpoint> {
    let normalized = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{}", raw)
    };
    let url = Url::parse(&normalized).with_context(|| format!("Invalid proxy URL: {raw}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Proxy URL missing host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("Proxy URL missing port"))?;
    Ok(ProxyEndpoint {
        host: host.to_string(),
        port,
    })
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let value = bytes as f64;
    if value < KB {
        format!("{} B", bytes)
    } else if value < MB {
        format!("{:.1} KB", value / KB)
    } else if value < GB {
        format!("{:.1} MB", value / MB)
    } else {
        format!("{:.2} GB", value / GB)
    }
}

pub fn format_duration_since(when: Option<DateTime<Utc>>) -> String {
    let Some(ts) = when else {
        return "-".to_string();
    };
    let now = Utc::now();
    let delta = now.signed_duration_since(ts);
    if delta.num_seconds() < 0 {
        return "0s".to_string();
    }
    format_duration(delta.to_std().unwrap_or(Duration::from_secs(0)))
}

pub fn format_duration(duration: Duration) -> String {
    let mut secs = duration.as_secs();
    let days = secs / 86400;
    secs %= 86400;
    let hours = secs / 3600;
    secs %= 3600;
    let minutes = secs / 60;
    let seconds = secs % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 || !parts.is_empty() {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 || !parts.is_empty() {
        parts.push(format!("{}m", minutes));
    }
    parts.push(format!("{}s", seconds));

    parts.join(" ")
}

pub fn format_timeout(ms: u64) -> Result<Duration> {
    if ms == 0 {
        bail!("Timeout must be greater than 0")
    }
    Ok(Duration::from_millis(ms))
}

pub fn format_since_label(when: Option<DateTime<Utc>>) -> String {
    if let Some(ts) = when {
        let now = Utc::now();
        let delta = now.signed_duration_since(ts);
        let pretty = format_duration(delta.to_std().unwrap_or(Duration::from_secs(0)));
        format!("{pretty} ago")
    } else {
        "-".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proxy_url_with_scheme() {
        let result = parse_proxy_url("http://proxy.example.com:8080").unwrap();
        assert_eq!(result.host, "proxy.example.com");
        assert_eq!(result.port, 8080);
    }

    #[test]
    fn test_parse_proxy_url_without_scheme() {
        let result = parse_proxy_url("proxy.example.com:3128").unwrap();
        assert_eq!(result.host, "proxy.example.com");
        assert_eq!(result.port, 3128);
    }

    #[test]
    fn test_parse_proxy_url_default_http_port() {
        let result = parse_proxy_url("http://proxy.example.com").unwrap();
        assert_eq!(result.host, "proxy.example.com");
        assert_eq!(result.port, 80);
    }

    #[test]
    fn test_parse_proxy_url_https_default_port() {
        let result = parse_proxy_url("https://proxy.example.com").unwrap();
        assert_eq!(result.host, "proxy.example.com");
        assert_eq!(result.port, 443);
    }

    #[test]
    fn test_parse_proxy_url_invalid() {
        let result = parse_proxy_url("not a valid url ::::");
        assert!(result.is_err());
    }

    #[test]
    fn test_format_bytes_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn test_format_bytes_kb() {
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(10240), "10.0 KB");
    }

    #[test]
    fn test_format_bytes_mb() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 5), "5.0 MB");
    }

    #[test]
    fn test_format_bytes_gb() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_bytes(1024 * 1024 * 1024 * 2), "2.00 GB");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(Duration::from_secs(60)), "1m 0s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3599)), "59m 59s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h 0m 0s");
        assert_eq!(format_duration(Duration::from_secs(7200)), "2h 0m 0s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
    }

    #[test]
    fn test_format_duration_days() {
        assert_eq!(format_duration(Duration::from_secs(86400)), "1d 0h 0m 0s");
        assert_eq!(format_duration(Duration::from_secs(90061)), "1d 1h 1m 1s");
    }

    #[test]
    fn test_format_timeout_valid() {
        let result = format_timeout(1000).unwrap();
        assert_eq!(result, Duration::from_millis(1000));
    }

    #[test]
    fn test_format_timeout_zero() {
        let result = format_timeout(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_duration_since_none() {
        assert_eq!(format_duration_since(None), "-");
    }

    #[test]
    fn test_format_since_label_none() {
        assert_eq!(format_since_label(None), "-");
    }
}

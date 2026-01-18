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

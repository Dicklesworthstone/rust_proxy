use crate::config::{AppConfig, ProxyConfig};
use crate::state::StateStore;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{timeout, Instant, MissedTickBehavior};

/// Result of a health check
pub struct HealthCheckResult {
    pub success: bool,
    pub latency_ms: f64,
    pub failure_reason: Option<String>,
}

/// Perform a health check on a single proxy by testing TCP connectivity
/// and HTTP CONNECT capability
pub async fn check_proxy_health(proxy: &ProxyConfig, timeout_ms: u64) -> HealthCheckResult {
    let timeout_dur = Duration::from_millis(timeout_ms);
    let start = Instant::now();

    // Parse proxy URL to get host and port
    let proxy_addr = match parse_proxy_address(&proxy.url) {
        Ok(addr) => addr,
        Err(e) => {
            return HealthCheckResult {
                success: false,
                latency_ms: start.elapsed().as_millis() as f64,
                failure_reason: Some(format!("Invalid proxy URL: {}", e)),
            };
        }
    };

    let result = timeout(timeout_dur, check_proxy_connect(&proxy_addr)).await;
    let latency_ms = start.elapsed().as_millis() as f64;

    match result {
        Ok(Ok(())) => HealthCheckResult {
            success: true,
            latency_ms,
            failure_reason: None,
        },
        Ok(Err(e)) => HealthCheckResult {
            success: false,
            latency_ms,
            failure_reason: Some(e.to_string()),
        },
        Err(_) => HealthCheckResult {
            success: false,
            latency_ms,
            failure_reason: Some("Connection timeout".to_string()),
        },
    }
}

/// Parse proxy URL to extract host:port
fn parse_proxy_address(url: &str) -> Result<String> {
    // Handle URLs like "http://host:port" or just "host:port"
    let url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("http://{}", url)
    };

    let parsed = url::Url::parse(&url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Missing host"))?;
    let port = parsed.port().unwrap_or(80);
    Ok(format!("{}:{}", host, port))
}

/// Test that the proxy accepts CONNECT requests
async fn check_proxy_connect(proxy_addr: &str) -> Result<()> {
    // Connect to proxy
    let mut stream = TcpStream::connect(proxy_addr).await?;

    // Use www.google.com as a stable target for CONNECT test
    let connect_request = "CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n";
    stream.write_all(connect_request.as_bytes()).await?;

    // Read response
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);

    // Check for success response (200 or similar)
    let first_line = response.lines().next().unwrap_or("");

    if first_line.contains("200") {
        Ok(())
    } else if first_line.contains("407") {
        // 407 Proxy Authentication Required - proxy is reachable but needs auth
        // This is still considered "reachable" for health purposes
        Ok(())
    } else if first_line.starts_with("HTTP/") {
        anyhow::bail!("Proxy returned: {}", first_line)
    } else {
        anyhow::bail!("Invalid response from proxy")
    }
}

/// Health check loop that runs as a background task in the daemon
pub async fn health_check_loop(
    config: AppConfig,
    state: Arc<StateStore>,
    mut shutdown: watch::Receiver<bool>,
) {
    let interval = Duration::from_secs(config.settings.health_check_interval_secs);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    tracing::info!(
        interval_secs = config.settings.health_check_interval_secs,
        proxies = config.proxies.len(),
        "Health check loop started"
    );

    // Perform initial health check on startup
    run_health_checks(&config, &state).await;

    loop {
        tokio::select! {
            biased;

            _ = shutdown.changed() => {
                tracing::info!("Health check loop shutting down");
                break;
            }
            _ = ticker.tick() => {
                run_health_checks(&config, &state).await;
            }
        }
    }
}

/// Run health checks on all configured proxies
async fn run_health_checks(config: &AppConfig, state: &StateStore) {
    let timeout_ms = config.settings.health_check_timeout_ms;
    let threshold = config.settings.consecutive_failures_threshold;

    for proxy in &config.proxies {
        let result = check_proxy_health(proxy, timeout_ms).await;

        tracing::debug!(
            proxy_id = %proxy.id,
            success = result.success,
            latency_ms = result.latency_ms,
            failure_reason = ?result.failure_reason,
            "Health check completed"
        );

        state
            .record_health_check(
                &proxy.id,
                result.success,
                if result.success {
                    Some(result.latency_ms)
                } else {
                    None
                },
                result.failure_reason,
                threshold,
            )
            .await;

        if !result.success {
            tracing::warn!(
                proxy_id = %proxy.id,
                "Proxy health check failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proxy_address_with_scheme() {
        let addr = parse_proxy_address("http://proxy.example.com:8080").unwrap();
        assert_eq!(addr, "proxy.example.com:8080");
    }

    #[test]
    fn test_parse_proxy_address_without_scheme() {
        let addr = parse_proxy_address("proxy.example.com:8080").unwrap();
        assert_eq!(addr, "proxy.example.com:8080");
    }

    #[test]
    fn test_parse_proxy_address_default_port() {
        let addr = parse_proxy_address("http://proxy.example.com").unwrap();
        assert_eq!(addr, "proxy.example.com:80");
    }

    #[test]
    fn test_parse_proxy_address_https() {
        let addr = parse_proxy_address("https://proxy.example.com").unwrap();
        assert_eq!(addr, "proxy.example.com:80"); // Still 80 since we use unwrap_or(80)
    }
}

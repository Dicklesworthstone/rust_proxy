use crate::config::{AppConfig, ProxyConfig};
use crate::state::{HealthStatus, RuntimeState, StateStore};
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

/// Event indicating a failover occurred
#[derive(Debug, Clone)]
pub struct FailoverEvent {
    pub from_proxy: String,
    pub to_proxy: String,
    pub reason: String,
}

/// Check if failover should occur and return the event if so
pub async fn check_and_perform_failover(
    config: &AppConfig,
    state: &StateStore,
    runtime: &RuntimeState,
) -> Option<FailoverEvent> {
    // Only proceed if auto_failover is enabled
    if !config.settings.auto_failover {
        return None;
    }

    // Get the currently effective proxy
    let effective = runtime.get_effective_proxy().await?;

    // Check if the effective proxy is unhealthy
    let health = state.get_health_status(&effective).await;
    if health != HealthStatus::Unhealthy {
        return None; // Current proxy is still okay
    }

    // Find the best healthy alternative
    let alternative = find_best_healthy_proxy(config, state, &effective).await?;

    // Create the failover event
    Some(FailoverEvent {
        from_proxy: effective,
        to_proxy: alternative,
        reason: "health check failure".to_string(),
    })
}

/// Find the highest-priority healthy proxy (excluding the current one)
pub async fn find_best_healthy_proxy(
    config: &AppConfig,
    state: &StateStore,
    exclude: &str,
) -> Option<String> {
    // Get all proxies sorted by priority (lower = higher priority)
    let mut candidates: Vec<_> = config.proxies.iter().filter(|p| p.id != exclude).collect();

    // Sort by priority (None treated as lowest priority, i.e., 100)
    candidates.sort_by_key(|p| p.priority.unwrap_or(100));

    // Find the first healthy proxy
    for proxy in candidates {
        let health = state.get_health_status(&proxy.id).await;
        if health == HealthStatus::Healthy {
            return Some(proxy.id.clone());
        }
    }

    None // No healthy alternatives
}

/// Check if failback should occur (original proxy recovered)
pub async fn check_and_perform_failback(
    config: &AppConfig,
    state: &StateStore,
    runtime: &RuntimeState,
) -> bool {
    // Only proceed if auto_failback is enabled and we're in a failover state
    if !config.settings.auto_failback {
        return false;
    }

    if !runtime.is_failed_over().await {
        return false;
    }

    // Get the original proxy
    let original = match runtime.get_original_proxy().await {
        Some(p) => p,
        None => return false,
    };

    // Check if the original proxy is healthy again
    let health = state.get_health_status(&original).await;

    if health == HealthStatus::Healthy {
        // Original is healthy - record recovery detection
        runtime.record_recovery_detected().await;

        // Check if failback delay has passed
        if runtime
            .failback_delay_passed(config.settings.failback_delay_secs)
            .await
        {
            return true;
        }
    } else {
        // Original is still unhealthy - clear recovery detection
        runtime.clear_recovery_detected().await;
    }

    false
}

/// Health check loop that runs as a background task in the daemon
pub async fn health_check_loop(
    config: AppConfig,
    state: Arc<StateStore>,
    runtime: RuntimeState,
    mut shutdown: watch::Receiver<bool>,
) {
    let interval = Duration::from_secs(config.settings.health_check_interval_secs);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    tracing::info!(
        interval_secs = config.settings.health_check_interval_secs,
        proxies = config.proxies.len(),
        auto_failover = config.settings.auto_failover,
        auto_failback = config.settings.auto_failback,
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

                // Check for failover if enabled
                if config.settings.auto_failover {
                    if let Some(event) = check_and_perform_failover(&config, &state, &runtime).await {
                        tracing::warn!(
                            from = %event.from_proxy,
                            to = %event.to_proxy,
                            reason = %event.reason,
                            "Failover triggered"
                        );
                        runtime.failover_to(&event.to_proxy).await;
                    }
                }

                // Check for failback if enabled and we're in failover state
                if config.settings.auto_failback
                    && check_and_perform_failback(&config, &state, &runtime).await
                {
                    let original = runtime.get_original_proxy().await;
                    tracing::info!(
                        to = ?original,
                        "Failback triggered - returning to original proxy"
                    );
                    runtime.failback().await;
                }
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

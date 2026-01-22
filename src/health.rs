use crate::config::{AppConfig, HealthCheckTarget, ProxyConfig};
use crate::metrics;
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
/// and HTTP CONNECT or GET capability based on the configured target
pub async fn check_proxy_health(
    proxy: &ProxyConfig,
    timeout_ms: u64,
    target: &HealthCheckTarget,
) -> HealthCheckResult {
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

    let result = timeout(
        timeout_dur,
        check_proxy_with_target(&proxy_addr, proxy, target),
    )
    .await;
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

/// Test that the proxy is reachable using the configured health check target
async fn check_proxy_with_target(
    proxy_addr: &str,
    proxy: &ProxyConfig,
    target: &HealthCheckTarget,
) -> Result<()> {
    match target {
        HealthCheckTarget::Connect { host, port } => {
            check_proxy_connect(proxy_addr, host, *port).await
        }
        HealthCheckTarget::Get { url } => check_proxy_get(proxy_addr, proxy, url).await,
    }
}

/// Test that the proxy accepts CONNECT requests to the specified target
async fn check_proxy_connect(proxy_addr: &str, host: &str, port: u16) -> Result<()> {
    // Connect to proxy
    let mut stream = TcpStream::connect(proxy_addr).await?;

    // Build CONNECT request with configured target
    let target = format!("{}:{}", host, port);
    let connect_request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", target, target);
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

/// Test that the proxy can perform an HTTP GET request to the specified URL
async fn check_proxy_get(proxy_addr: &str, proxy: &ProxyConfig, url: &str) -> Result<()> {
    // Parse the target URL
    let parsed_url = url::Url::parse(url)?;
    let host = parsed_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Missing host in URL"))?;
    let port = parsed_url.port_or_known_default().unwrap_or(80);
    let path = if parsed_url.path().is_empty() {
        "/"
    } else {
        parsed_url.path()
    };
    let query = parsed_url
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    // Connect to proxy
    let mut stream = TcpStream::connect(proxy_addr).await?;

    // For HTTPS URLs, we need to use CONNECT first to establish tunnel
    if parsed_url.scheme() == "https" {
        let target = format!("{}:{}", host, port);
        let connect_request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", target, target);
        stream.write_all(connect_request.as_bytes()).await?;

        // Read CONNECT response
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);
        let first_line = response.lines().next().unwrap_or("");

        if !first_line.contains("200") && !first_line.contains("407") {
            anyhow::bail!("CONNECT failed: {}", first_line);
        }

        // For HTTPS health checks via CONNECT, successful tunnel is enough
        // We don't do TLS handshake for simplicity - the CONNECT success is sufficient
        return Ok(());
    }

    // For HTTP URLs, send GET request through proxy
    let get_request = format!(
        "GET {}{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        path, query, host
    );

    // Add proxy auth if configured
    let (username, password) = proxy.auth.resolve();
    let request = if let (Some(user), Some(pass)) = (username, password) {
        let credentials = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", user, pass),
        );
        format!(
            "{}Proxy-Authorization: Basic {}\r\n\r\n",
            get_request, credentials
        )
    } else {
        format!("{}\r\n", get_request)
    };

    stream.write_all(request.as_bytes()).await?;

    // Read response
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);

    // Check for success response
    let first_line = response.lines().next().unwrap_or("");

    if first_line.contains("200")
        || first_line.contains("204")
        || first_line.contains("301")
        || first_line.contains("302")
    {
        Ok(())
    } else if first_line.contains("407") {
        // 407 Proxy Authentication Required - proxy is reachable but needs auth
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

                // Update degradation state (debounced) based on current health
                let healthy = state.get_healthy_proxies().await;
                runtime
                    .update_degradation_state(&healthy, config.settings.degradation_delay_secs)
                    .await;

                // Check for failover if enabled
                if config.settings.auto_failover {
                    if let Some(event) = check_and_perform_failover(&config, &state, &runtime).await {
                        tracing::warn!(
                            from = %event.from_proxy,
                            to = %event.to_proxy,
                            reason = %event.reason,
                            "Failover triggered"
                        );
                        // Record failover metric
                        metrics::record_failover(&event.from_proxy, &event.to_proxy);
                        runtime.failover_to(&event.to_proxy).await;
                        metrics::set_effective_proxy(
                            config.proxies.iter().map(|p| p.id.as_str()),
                            Some(&event.to_proxy),
                        );
                    }
                }

                // Check for failback if enabled and we're in failover state
                if config.settings.auto_failback
                    && check_and_perform_failback(&config, &state, &runtime).await
                {
                    let original = runtime.get_original_proxy().await;
                    let effective = runtime.get_effective_proxy().await;
                    tracing::info!(
                        to = ?original,
                        "Failback triggered - returning to original proxy"
                    );
                    // Record failback metric (counts as a failover from current to original)
                    if let (Some(from), Some(to)) = (effective, original.clone()) {
                        metrics::record_failover(&from, &to);
                    }
                    runtime.failback().await;
                    metrics::set_effective_proxy(
                        config.proxies.iter().map(|p| p.id.as_str()),
                        original.as_deref(),
                    );
                }
            }
        }
    }
}

/// Run health checks on all configured proxies
async fn run_health_checks(config: &AppConfig, state: &StateStore) {
    let timeout_ms = config.settings.health_check_timeout_ms;
    let threshold = config.settings.consecutive_failures_threshold;
    let target = &config.settings.health_check_target;

    for proxy in &config.proxies {
        let result = check_proxy_health(proxy, timeout_ms, target).await;

        tracing::debug!(
            proxy_id = %proxy.id,
            success = result.success,
            latency_ms = result.latency_ms,
            failure_reason = ?result.failure_reason,
            "Health check completed"
        );

        // Record metrics for this health check
        let latency_secs = result.latency_ms / 1000.0;
        metrics::record_health_check(&proxy.id, result.success, latency_secs);

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

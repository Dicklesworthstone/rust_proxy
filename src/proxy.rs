use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use std::net::{SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::{AppConfig, DegradationPolicy, ProxyConfig};
use crate::load_balancer::LoadBalancer;
use crate::metrics;
use crate::state::StateStore;

/// Timeout for each proxy attempt when using try_all degradation policy
const TRY_ALL_TIMEOUT_PER_PROXY_SECS: u64 = 10;

/// Guard that tracks connection metrics with RAII pattern.
///
/// When dropped, automatically decrements active connections and records duration.
struct ConnectionGuard {
    proxy_id: String,
    start: Instant,
}

impl ConnectionGuard {
    fn new(proxy_id: String) -> Self {
        metrics::connection_started(&proxy_id);
        Self {
            proxy_id,
            start: Instant::now(),
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let duration_secs = self.start.elapsed().as_secs_f64();
        metrics::connection_ended(&self.proxy_id, duration_secs);
    }
}

/// Check if an accept() error is transient and should be retried.
///
/// Transient errors are temporary conditions that may resolve on their own.
/// We should log them, back off briefly, and continue accepting connections.
fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    // Check by ErrorKind first (portable)
    if matches!(
        e.kind(),
        ErrorKind::ConnectionReset     // Client reset during accept
            | ErrorKind::ConnectionAborted // Client aborted during accept
            | ErrorKind::Interrupted       // Signal interrupted syscall
            | ErrorKind::WouldBlock // Would block (shouldn't happen, but safe)
    ) {
        return true;
    }

    // Check by raw OS error code (Linux-specific)
    // These don't have stable ErrorKind mappings
    matches!(
        e.raw_os_error(),
        Some(23)    // ENFILE: system file table full
            | Some(24)  // EMFILE: process file descriptor limit
            | Some(103) // ECONNABORTED: connection aborted
            | Some(105) // ENOBUFS: no buffer space
            | Some(12) // ENOMEM: out of memory (temporary)
    )
}

/// Manages exponential backoff for accept loop errors
struct AcceptBackoff {
    current_ms: u64,
    min_ms: u64,
    max_ms: u64,
    consecutive_errors: u32,
}

impl AcceptBackoff {
    fn new() -> Self {
        Self {
            current_ms: 10,
            min_ms: 10,
            max_ms: 5000,
            consecutive_errors: 0,
        }
    }

    fn record_error(&mut self) -> Duration {
        self.consecutive_errors += 1;
        let backoff = Duration::from_millis(self.current_ms);
        self.current_ms = (self.current_ms * 2).min(self.max_ms);
        backoff
    }

    fn record_success(&mut self) {
        self.current_ms = self.min_ms;
        self.consecutive_errors = 0;
    }
}

/// Configuration for connection retry with exponential backoff
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
        }
    }
}

const SO_ORIGINAL_DST: libc::c_int = 80;

#[derive(Debug, Clone)]
pub struct UpstreamProxy {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl UpstreamProxy {
    pub fn from_config(proxy: &ProxyConfig) -> Result<Self> {
        let (user, pass) = proxy.auth.resolve();
        let parsed = crate::util::parse_proxy_url(&proxy.url)?;
        Ok(Self {
            id: proxy.id.clone(),
            host: parsed.host,
            port: parsed.port,
            username: user,
            password: pass,
        })
    }
}

/// Run the proxy with a single fixed upstream proxy.
///
/// This function is kept for backward compatibility and simple use cases
/// where load balancing is not needed.
#[allow(dead_code)]
pub async fn run_proxy(
    listen_port: u16,
    upstream: UpstreamProxy,
    state: Arc<StateStore>,
    retry_config: RetryConfig,
) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind to {addr}"))?;
    tracing::info!("transparent proxy listening on {addr}");

    let mut backoff = AcceptBackoff::new();

    loop {
        let (client, _) = match listener.accept().await {
            Ok(conn) => {
                backoff.record_success();
                conn
            }
            Err(e) if is_transient_accept_error(&e) => {
                let delay = backoff.record_error();
                tracing::warn!(
                    error = %e,
                    error_code = ?e.raw_os_error(),
                    consecutive_errors = backoff.consecutive_errors,
                    backoff_ms = delay.as_millis(),
                    "Accept error (transient, will retry)"
                );
                tokio::time::sleep(delay).await;
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "Accept error (fatal, exiting)");
                return Err(e.into());
            }
        };

        let upstream_clone = upstream.clone();
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(err) =
                handle_connection(client, upstream_clone, state_clone, retry_config).await
            {
                tracing::warn!("connection error: {err}");
            }
        });
    }
}

/// Run the proxy with load balancing - selects a proxy for each connection.
///
/// This function uses the configured load balancing strategy to select
/// a proxy for each incoming connection, enabling distribution across
/// multiple healthy proxies.
pub async fn run_proxy_with_load_balancing(
    listen_port: u16,
    config: Arc<AppConfig>,
    state: Arc<StateStore>,
    load_balancer: Arc<LoadBalancer>,
    retry_config: RetryConfig,
) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind to {addr}"))?;
    tracing::info!(
        "transparent proxy listening on {addr} (strategy: {:?})",
        config.settings.load_balance_strategy
    );

    let mut backoff = AcceptBackoff::new();

    loop {
        let (client, client_addr) = match listener.accept().await {
            Ok(conn) => {
                backoff.record_success();
                conn
            }
            Err(e) if is_transient_accept_error(&e) => {
                let delay = backoff.record_error();
                tracing::warn!(
                    error = %e,
                    error_code = ?e.raw_os_error(),
                    consecutive_errors = backoff.consecutive_errors,
                    backoff_ms = delay.as_millis(),
                    "Accept error (transient, will retry)"
                );
                tokio::time::sleep(delay).await;
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "Accept error (fatal, exiting)");
                return Err(e.into());
            }
        };

        let config_clone = config.clone();
        let state_clone = state.clone();
        let lb_clone = load_balancer.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection_with_load_balancing(
                client,
                client_addr,
                config_clone,
                state_clone,
                lb_clone,
                retry_config,
            )
            .await
            {
                tracing::warn!("connection error: {err}");
            }
        });
    }
}

/// Handle a single connection with load-balanced proxy selection.
async fn handle_connection_with_load_balancing(
    mut client: TcpStream,
    client_addr: SocketAddr,
    config: Arc<AppConfig>,
    state: Arc<StateStore>,
    load_balancer: Arc<LoadBalancer>,
    retry_config: RetryConfig,
) -> Result<()> {
    // Get original destination first (needed for all code paths including try_all)
    let original = get_original_dst(&client)?;
    let target = match original {
        SocketAddr::V4(v4) => v4,
        _ => {
            return Err(anyhow!("IPv6 destinations are not supported"));
        }
    };
    let target_host = target.ip().to_string();
    let target_port = target.port();

    // Select proxy using load balancer
    let proxy_id = load_balancer
        .select_proxy(
            config.settings.load_balance_strategy,
            &config.proxies,
            &state,
        )
        .await;

    // If no healthy proxy, apply degradation policy
    let (proxy_id, upstream, mut upstream_socket) = match proxy_id {
        Some(id) => {
            // Find the proxy config
            let proxy_cfg = config
                .proxies
                .iter()
                .find(|p| p.id == id)
                .ok_or_else(|| anyhow!("Selected proxy '{}' not found in config", id))?;

            // Create upstream proxy from config
            let upstream = UpstreamProxy::from_config(proxy_cfg)?;

            tracing::debug!(
                proxy = %id,
                strategy = ?config.settings.load_balance_strategy,
                client = %client_addr,
                "Selected proxy for connection"
            );

            // Connect to upstream
            let upstream_socket =
                match connect_with_retry(&upstream.host, upstream.port, &retry_config).await {
                    Ok(socket) => socket,
                    Err(e) => {
                        metrics::record_request_error(&id);
                        return Err(e);
                    }
                };

            // Build auth header and send CONNECT
            let auth_header =
                if let (Some(user), Some(pass)) = (&upstream.username, &upstream.password) {
                    let token = Base64.encode(format!("{}:{}", user, pass));
                    format!("Proxy-Authorization: Basic {}\r\n", token)
                } else {
                    String::new()
                };

            let connect_req = format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n{}\r\n",
                target_host, target_port, target_host, target_port, auth_header
            );

            let mut socket = upstream_socket;
            if let Err(e) = socket.write_all(connect_req.as_bytes()).await {
                metrics::record_request_error(&id);
                return Err(e.into());
            }
            if let Err(e) = socket.flush().await {
                metrics::record_request_error(&id);
                return Err(e.into());
            }

            // Read and validate CONNECT response
            let mut header_buf = Vec::with_capacity(4096);
            let mut tmp = [0u8; 512];
            let header_end = loop {
                let n = match socket.read(&mut tmp).await {
                    Ok(0) => {
                        metrics::record_request_error(&id);
                        return Err(anyhow!("Upstream proxy closed connection during CONNECT"));
                    }
                    Ok(n) => n,
                    Err(e) => {
                        metrics::record_request_error(&id);
                        return Err(e.into());
                    }
                };
                header_buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
                if header_buf.len() > 16 * 1024 {
                    metrics::record_request_error(&id);
                    return Err(anyhow!("Proxy CONNECT response too large"));
                }
            };

            let header_bytes = &header_buf[..header_end];
            let trailer = &header_buf[header_end..];
            let header_text = String::from_utf8_lossy(header_bytes);
            let status_line = header_text.lines().next().unwrap_or_default();
            let status_code = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|token| token.parse::<u16>().ok())
                .ok_or_else(|| {
                    metrics::record_request_error(&id);
                    anyhow!("Proxy CONNECT invalid status line: {status_line}")
                })?;
            if !(200..300).contains(&status_code) {
                metrics::record_request_error(&id);
                return Err(anyhow!("Proxy CONNECT failed: {status_line}"));
            }

            // Send any trailer data to client
            if !trailer.is_empty() {
                if let Err(e) = client.write_all(trailer).await {
                    metrics::record_request_error(&id);
                    return Err(e.into());
                }
                if let Err(e) = client.flush().await {
                    metrics::record_request_error(&id);
                    return Err(e.into());
                }
            }

            (id, upstream, socket)
        }
        None => {
            // No healthy proxy - apply degradation policy
            match config.settings.degradation_policy {
                DegradationPolicy::FailClosed => {
                    tracing::warn!(
                        client = %client_addr,
                        "Rejecting connection: no healthy proxy available (fail_closed)"
                    );
                    if let Err(err) = send_degradation_error(&mut client).await {
                        tracing::debug!(error = %err, "Failed to send degradation response");
                    }
                    return Err(anyhow!("No healthy proxy available (fail_closed)"));
                }
                DegradationPolicy::TryAll => {
                    // Try each proxy sequentially until one works
                    match try_all_proxies(&config, &target_host, target_port, &retry_config).await {
                        Ok((socket, id, upstream)) => {
                            tracing::info!(
                                proxy = %id,
                                client = %client_addr,
                                "try_all degradation policy succeeded"
                            );
                            (id, upstream, socket)
                        }
                        Err(e) => {
                            tracing::error!(
                                client = %client_addr,
                                error = %e,
                                "try_all policy exhausted all proxies"
                            );
                            if let Err(err) = send_degradation_error(&mut client).await {
                                tracing::debug!(error = %err, "Failed to send degradation response");
                            }
                            return Err(e);
                        }
                    }
                }
                DegradationPolicy::UseLast => {
                    // Try the most recently healthy proxy, fall back to try_all if it fails
                    match use_last_proxy(&config, &state, &target_host, target_port, &retry_config)
                        .await
                    {
                        Ok((socket, id, upstream)) => {
                            tracing::info!(
                                proxy = %id,
                                client = %client_addr,
                                "use_last degradation policy succeeded"
                            );
                            (id, upstream, socket)
                        }
                        Err(e) => {
                            tracing::error!(
                                client = %client_addr,
                                error = %e,
                                "use_last policy exhausted all proxies"
                            );
                            if let Err(err) = send_degradation_error(&mut client).await {
                                tracing::debug!(error = %err, "Failed to send degradation response");
                            }
                            return Err(e);
                        }
                    }
                }
                policy => {
                    tracing::warn!(
                        client = %client_addr,
                        policy = ?policy,
                        "No healthy proxy available (policy not yet implemented)"
                    );
                    return Err(anyhow!("No healthy proxy available"));
                }
            }
        }
    };

    // Create connection guard to track metrics (RAII pattern)
    // This will automatically decrement active connections and record duration on drop
    let _guard = ConnectionGuard::new(proxy_id.clone());

    // Bidirectional copy - tunnel is already established
    let (bytes_to_up, bytes_to_client) =
        match tokio::io::copy_bidirectional(&mut client, &mut upstream_socket).await {
            Ok(bytes) => bytes,
            Err(e) => {
                metrics::record_request_error(&proxy_id);
                return Err(e.into());
            }
        };

    // Record successful request and bytes transferred
    metrics::record_request_success(&proxy_id);
    metrics::record_bytes(&proxy_id, bytes_to_up, bytes_to_client);

    state
        .record_traffic(&upstream.id, bytes_to_up, bytes_to_client)
        .await;

    Ok(())
}

async fn send_degradation_error(stream: &mut TcpStream) -> Result<()> {
    let response = concat!(
        "HTTP/1.1 503 Service Unavailable\r\n",
        "Content-Type: text/plain\r\n",
        "Connection: close\r\n",
        "\r\n",
        "No healthy proxy available"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Attempt to connect through each proxy in priority order (try_all degradation policy).
///
/// Returns (upstream_socket, proxy_id) on first successful connection, or an error
/// if all proxies fail.
async fn try_all_proxies(
    config: &AppConfig,
    target_host: &str,
    target_port: u16,
    retry_config: &RetryConfig,
) -> Result<(TcpStream, String, UpstreamProxy)> {
    tracing::warn!("All proxies unhealthy, trying each sequentially (try_all policy)");

    // Sort proxies by priority (lower = higher priority)
    let mut proxies: Vec<_> = config.proxies.iter().collect();
    proxies.sort_by_key(|p| p.priority.unwrap_or(100));

    let mut last_error: Option<anyhow::Error> = None;

    for (idx, proxy_cfg) in proxies.iter().enumerate() {
        tracing::debug!(
            proxy = %proxy_cfg.id,
            attempt = idx + 1,
            total = proxies.len(),
            "Attempting connection (try_all policy)"
        );

        // Convert to UpstreamProxy
        let upstream = match UpstreamProxy::from_config(proxy_cfg) {
            Ok(u) => u,
            Err(e) => {
                tracing::debug!(
                    proxy = %proxy_cfg.id,
                    error = %e,
                    "Failed to parse proxy config, skipping"
                );
                last_error = Some(e);
                continue;
            }
        };

        // Try to connect with timeout
        let connect_result = tokio::time::timeout(
            Duration::from_secs(TRY_ALL_TIMEOUT_PER_PROXY_SECS),
            try_proxy_connect(&upstream, target_host, target_port, retry_config),
        )
        .await;

        match connect_result {
            Ok(Ok(stream)) => {
                tracing::info!(
                    proxy = %proxy_cfg.id,
                    "Connection succeeded despite unhealthy status (try_all policy)"
                );
                return Ok((stream, proxy_cfg.id.clone(), upstream));
            }
            Ok(Err(e)) => {
                tracing::debug!(
                    proxy = %proxy_cfg.id,
                    error = %e,
                    "Connection attempt failed"
                );
                last_error = Some(e);
            }
            Err(_) => {
                tracing::debug!(
                    proxy = %proxy_cfg.id,
                    timeout_secs = TRY_ALL_TIMEOUT_PER_PROXY_SECS,
                    "Connection attempt timed out"
                );
                last_error = Some(anyhow!(
                    "Connection timeout after {}s",
                    TRY_ALL_TIMEOUT_PER_PROXY_SECS
                ));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("No proxies configured")))
}

/// Attempt to connect through the most recently healthy proxy (use_last degradation policy).
///
/// Returns (upstream_socket, proxy_id, upstream) on success, or falls back to try_all
/// if the last healthy proxy fails.
async fn use_last_proxy(
    config: &AppConfig,
    state: &StateStore,
    target_host: &str,
    target_port: u16,
    retry_config: &RetryConfig,
) -> Result<(TcpStream, String, UpstreamProxy)> {
    // Get the most recently healthy proxy
    let last_healthy_id = state.get_last_healthy_proxy().await;

    let last_healthy_id = match last_healthy_id {
        Some(id) => id,
        None => {
            tracing::warn!(
                "No proxy has ever been healthy, falling back to try_all (use_last policy)"
            );
            return try_all_proxies(config, target_host, target_port, retry_config).await;
        }
    };

    tracing::info!(
        proxy = %last_healthy_id,
        "Attempting last healthy proxy (use_last policy)"
    );

    // Find the proxy config
    let proxy_cfg = match config.proxies.iter().find(|p| p.id == last_healthy_id) {
        Some(cfg) => cfg,
        None => {
            tracing::warn!(
                proxy = %last_healthy_id,
                "Last healthy proxy no longer in config, falling back to try_all (use_last policy)"
            );
            return try_all_proxies(config, target_host, target_port, retry_config).await;
        }
    };

    // Convert to UpstreamProxy
    let upstream = match UpstreamProxy::from_config(proxy_cfg) {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(
                proxy = %last_healthy_id,
                error = %e,
                "Failed to parse last healthy proxy config, falling back to try_all (use_last policy)"
            );
            return try_all_proxies(config, target_host, target_port, retry_config).await;
        }
    };

    // Try to connect with timeout
    let connect_result = tokio::time::timeout(
        Duration::from_secs(TRY_ALL_TIMEOUT_PER_PROXY_SECS),
        try_proxy_connect(&upstream, target_host, target_port, retry_config),
    )
    .await;

    match connect_result {
        Ok(Ok(stream)) => {
            tracing::info!(
                proxy = %last_healthy_id,
                "Connection to last healthy proxy succeeded (use_last policy)"
            );
            Ok((stream, last_healthy_id, upstream))
        }
        Ok(Err(e)) => {
            tracing::warn!(
                proxy = %last_healthy_id,
                error = %e,
                "Last healthy proxy failed, falling back to try_all (use_last policy)"
            );
            try_all_proxies(config, target_host, target_port, retry_config).await
        }
        Err(_) => {
            tracing::warn!(
                proxy = %last_healthy_id,
                timeout_secs = TRY_ALL_TIMEOUT_PER_PROXY_SECS,
                "Last healthy proxy timed out, falling back to try_all (use_last policy)"
            );
            try_all_proxies(config, target_host, target_port, retry_config).await
        }
    }
}

/// Try to establish a CONNECT tunnel through a single proxy.
///
/// Returns the connected upstream socket ready for bidirectional copy.
async fn try_proxy_connect(
    upstream: &UpstreamProxy,
    target_host: &str,
    target_port: u16,
    retry_config: &RetryConfig,
) -> Result<TcpStream> {
    // Connect to upstream proxy
    let mut upstream_socket =
        connect_with_retry(&upstream.host, upstream.port, retry_config).await?;

    // Build auth header
    let auth_header = if let (Some(user), Some(pass)) = (&upstream.username, &upstream.password) {
        let token = Base64.encode(format!("{}:{}", user, pass));
        format!("Proxy-Authorization: Basic {}\r\n", token)
    } else {
        String::new()
    };

    // Send CONNECT request
    let connect_req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n{}\r\n",
        target_host, target_port, target_host, target_port, auth_header
    );

    upstream_socket.write_all(connect_req.as_bytes()).await?;
    upstream_socket.flush().await?;

    // Read and validate response
    let mut header_buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 512];
    let header_end = loop {
        let n = upstream_socket.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("Upstream proxy closed connection during CONNECT"));
        }
        header_buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if header_buf.len() > 16 * 1024 {
            return Err(anyhow!("Proxy CONNECT response too large"));
        }
    };

    let header_bytes = &header_buf[..header_end];
    let header_text = String::from_utf8_lossy(header_bytes);
    let status_line = header_text.lines().next().unwrap_or_default();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|token| token.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("Proxy CONNECT invalid status line: {status_line}"))?;

    if !(200..300).contains(&status_code) {
        return Err(anyhow!("Proxy CONNECT failed: {status_line}"));
    }

    Ok(upstream_socket)
}

/// Handle a single connection with a fixed upstream proxy.
#[allow(dead_code)]
async fn handle_connection(
    mut client: TcpStream,
    upstream: UpstreamProxy,
    state: Arc<StateStore>,
    retry_config: RetryConfig,
) -> Result<()> {
    let original = get_original_dst(&client)?;
    let target = match original {
        SocketAddr::V4(v4) => v4,
        _ => return Err(anyhow!("IPv6 destinations are not supported")),
    };
    let target_host = target.ip().to_string();
    let target_port = target.port();

    let mut upstream_socket =
        connect_with_retry(&upstream.host, upstream.port, &retry_config).await?;

    let auth_header = if let (Some(user), Some(pass)) = (&upstream.username, &upstream.password) {
        let token = Base64.encode(format!("{}:{}", user, pass));
        format!("Proxy-Authorization: Basic {}\r\n", token)
    } else {
        String::new()
    };

    let connect_req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n{}\r\n",
        target_host, target_port, target_host, target_port, auth_header
    );

    upstream_socket.write_all(connect_req.as_bytes()).await?;
    upstream_socket.flush().await?;

    let mut header_buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 512];
    let header_end = loop {
        let n = upstream_socket.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("Upstream proxy closed connection during CONNECT"));
        }
        header_buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if header_buf.len() > 16 * 1024 {
            return Err(anyhow!("Proxy CONNECT response too large"));
        }
    };

    let header_bytes = &header_buf[..header_end];
    let trailer = &header_buf[header_end..];
    let header_text = String::from_utf8_lossy(header_bytes);
    let status_line = header_text.lines().next().unwrap_or_default();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|token| token.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("Proxy CONNECT invalid status line: {status_line}"))?;
    if !(200..300).contains(&status_code) {
        return Err(anyhow!("Proxy CONNECT failed: {status_line}"));
    }

    if !trailer.is_empty() {
        client.write_all(trailer).await?;
        client.flush().await?;
    }

    let (bytes_to_up, bytes_to_client) =
        tokio::io::copy_bidirectional(&mut client, &mut upstream_socket).await?;
    state
        .record_traffic(&upstream.id, bytes_to_up, bytes_to_client)
        .await;

    Ok(())
}

/// Connect to upstream with exponential backoff retry
async fn connect_with_retry(host: &str, port: u16, config: &RetryConfig) -> Result<TcpStream> {
    let mut last_error = None;
    let mut backoff_ms = config.initial_backoff_ms;

    for attempt in 0..=config.max_retries {
        match TcpStream::connect((host, port)).await {
            Ok(stream) => {
                if attempt > 0 {
                    tracing::info!(
                        "Connected to upstream {}:{} after {} retries",
                        host,
                        port,
                        attempt
                    );
                }
                return Ok(stream);
            }
            Err(e) => {
                last_error = Some(e);
                if attempt < config.max_retries {
                    tracing::warn!(
                        "Failed to connect to upstream {}:{} (attempt {}/{}), retrying in {}ms: {}",
                        host,
                        port,
                        attempt + 1,
                        config.max_retries + 1,
                        backoff_ms,
                        last_error.as_ref().unwrap()
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    // Exponential backoff: double the delay, capped at max_backoff_ms
                    backoff_ms = (backoff_ms * 2).min(config.max_backoff_ms);
                }
            }
        }
    }

    Err(anyhow!(
        "Failed to connect to upstream {}:{} after {} attempts: {}",
        host,
        port,
        config.max_retries + 1,
        last_error.unwrap()
    ))
}

fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        ) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }

        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn test_transient_error_by_error_kind() {
        // Transient errors should return true
        assert!(is_transient_accept_error(&Error::new(
            ErrorKind::ConnectionReset,
            "test"
        )));
        assert!(is_transient_accept_error(&Error::new(
            ErrorKind::ConnectionAborted,
            "test"
        )));
        assert!(is_transient_accept_error(&Error::new(
            ErrorKind::Interrupted,
            "test"
        )));
        assert!(is_transient_accept_error(&Error::new(
            ErrorKind::WouldBlock,
            "test"
        )));
    }

    #[test]
    fn test_transient_error_by_os_code() {
        // Linux-specific transient errors (by OS code)
        assert!(is_transient_accept_error(&Error::from_raw_os_error(24))); // EMFILE
        assert!(is_transient_accept_error(&Error::from_raw_os_error(23))); // ENFILE
        assert!(is_transient_accept_error(&Error::from_raw_os_error(103))); // ECONNABORTED
        assert!(is_transient_accept_error(&Error::from_raw_os_error(105))); // ENOBUFS
        assert!(is_transient_accept_error(&Error::from_raw_os_error(12))); // ENOMEM
    }

    #[test]
    fn test_fatal_errors_not_transient() {
        // Fatal errors should return false
        assert!(!is_transient_accept_error(&Error::new(
            ErrorKind::AddrInUse,
            "test"
        )));
        assert!(!is_transient_accept_error(&Error::new(
            ErrorKind::PermissionDenied,
            "test"
        )));
        assert!(!is_transient_accept_error(&Error::new(
            ErrorKind::NotFound,
            "test"
        )));
        assert!(!is_transient_accept_error(&Error::from_raw_os_error(98))); // EADDRINUSE
        assert!(!is_transient_accept_error(&Error::from_raw_os_error(13))); // EACCES
    }

    #[test]
    fn test_backoff_exponential_growth() {
        let mut backoff = AcceptBackoff::new();

        // First error returns 10ms
        assert_eq!(backoff.record_error().as_millis(), 10);
        assert_eq!(backoff.consecutive_errors, 1);

        // Doubles each time
        assert_eq!(backoff.record_error().as_millis(), 20);
        assert_eq!(backoff.record_error().as_millis(), 40);
        assert_eq!(backoff.record_error().as_millis(), 80);
        assert_eq!(backoff.record_error().as_millis(), 160);
    }

    #[test]
    fn test_backoff_max_cap() {
        let mut backoff = AcceptBackoff::new();

        // Run many iterations to ensure we hit the cap
        for _ in 0..20 {
            backoff.record_error();
        }

        // Should be capped at 5000ms
        assert!(backoff.current_ms <= 5000);

        // Next error should still be capped
        let delay = backoff.record_error();
        assert_eq!(delay.as_millis(), 5000);
    }

    #[test]
    fn test_backoff_reset_on_success() {
        let mut backoff = AcceptBackoff::new();

        // Accumulate some errors
        backoff.record_error();
        backoff.record_error();
        backoff.record_error();
        assert!(backoff.current_ms > 10);
        assert_eq!(backoff.consecutive_errors, 3);

        // Success should reset
        backoff.record_success();
        assert_eq!(backoff.current_ms, 10);
        assert_eq!(backoff.consecutive_errors, 0);
    }

    #[test]
    fn test_backoff_exact_sequence() {
        let mut backoff = AcceptBackoff::new();

        let expected_sequence = [10, 20, 40, 80, 160, 320, 640, 1280, 2560, 5000, 5000];

        for (i, expected_ms) in expected_sequence.iter().enumerate() {
            let delay = backoff.record_error();
            assert_eq!(
                delay.as_millis(),
                *expected_ms as u128,
                "Mismatch at iteration {i}"
            );
        }
    }
}

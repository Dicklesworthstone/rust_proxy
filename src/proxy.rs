use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::{AppConfig, DegradationPolicy, ProxyConfig};
use crate::iptables::DIRECT_BYPASS_MARK;
use crate::load_balancer::LoadBalancer;
use crate::metrics;
use crate::state::{RuntimeState, StateStore};

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
    config_rx: tokio::sync::watch::Receiver<std::sync::Arc<AppConfig>>,
    state: Arc<StateStore>,
    runtime: Arc<RuntimeState>,
    load_balancer: Arc<LoadBalancer>,
    retry_config: RetryConfig,
) -> Result<()> {
    let config = config_rx.borrow().clone();
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
        // Hot-reload: snapshot the latest config for this connection.
        let config_clone = config_rx.borrow().clone();
        let state_clone = state.clone();
        let runtime_clone = runtime.clone();
        let lb_clone = load_balancer.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection_with_load_balancing(
                client,
                client_addr,
                config_clone,
                state_clone,
                runtime_clone,
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
    runtime: Arc<RuntimeState>,
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
    let target_host = original_dst_connect_host(*target.ip());
    let target_port = target.port();

    // Select proxy using load balancer
    let proxy_id = load_balancer
        .select_proxy(
            config.settings.load_balance_strategy,
            &config.proxies,
            &state,
            // Steer Single-strategy routing from the live failover state.
            runtime.get_effective_proxy().await.as_deref(),
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
            match handle_degradation(
                &config,
                &state,
                &runtime,
                &target_host,
                target_port,
                &retry_config,
                &mut client,
            )
            .await
            {
                Ok(Some((socket, id, upstream))) => {
                    tracing::info!(
                        proxy = %id,
                        client = %client_addr,
                        policy = ?config.settings.degradation_policy,
                        "Degradation policy succeeded"
                    );
                    (id, upstream, socket)
                }
                Ok(None) => {
                    // Degradation delay not yet elapsed - use fail_closed behavior
                    tracing::warn!(
                        client = %client_addr,
                        delay_secs = config.settings.degradation_delay_secs,
                        "Rejecting connection: no healthy proxy (within degradation delay)"
                    );
                    if let Err(err) = send_degradation_error(&mut client).await {
                        tracing::debug!(error = %err, "Failed to send degradation response");
                    }
                    return Err(anyhow!(
                        "No healthy proxy available (within degradation delay)"
                    ));
                }
                Err(e) => {
                    tracing::error!(
                        client = %client_addr,
                        error = %e,
                        policy = ?config.settings.degradation_policy,
                        "Degradation policy failed"
                    );
                    if let Err(err) = send_degradation_error(&mut client).await {
                        tracing::debug!(error = %err, "Failed to send degradation response");
                    }
                    return Err(e);
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

/// Apply the configured degradation policy when no healthy proxy is available.
///
/// This unified function handles all degradation policies:
/// - FailClosed: Immediately reject the connection
/// - TryAll: Try each proxy in priority order until one works
/// - UseLast: Try the most recently healthy proxy, fall back to try_all
/// - Direct: Connect directly to the target (if allowed)
///
/// Returns Ok(None) if degradation delay hasn't elapsed yet (within grace period),
/// signaling the caller should use fail_closed behavior.
/// Returns Ok(Some(...)) with the connection details if degradation succeeded.
/// Returns Err if degradation policy could not establish a connection.
async fn handle_degradation(
    config: &AppConfig,
    state: &StateStore,
    runtime: &RuntimeState,
    target_host: &str,
    target_port: u16,
    retry_config: &RetryConfig,
    client: &mut TcpStream,
) -> Result<Option<(TcpStream, String, UpstreamProxy)>> {
    // Check if degradation mode is active (delay period has elapsed)
    if !runtime.is_degraded().await {
        tracing::debug!(
            policy = ?config.settings.degradation_policy,
            delay_secs = config.settings.degradation_delay_secs,
            "Degradation delay not yet elapsed, using fail_closed behavior"
        );
        return Ok(None); // Not yet degraded, caller should use fail_closed
    }

    tracing::debug!(
        policy = ?config.settings.degradation_policy,
        "Applying degradation policy"
    );

    match config.settings.degradation_policy {
        DegradationPolicy::FailClosed => {
            // fail_closed always rejects - return error
            Err(anyhow!("No healthy proxy available (fail_closed policy)"))
        }

        DegradationPolicy::TryAll => {
            let (stream, proxy_id, upstream) =
                try_all_proxies(config, target_host, target_port, retry_config, client).await?;
            Ok(Some((stream, proxy_id, upstream)))
        }

        DegradationPolicy::UseLast => {
            let (stream, proxy_id, upstream) = use_last_proxy(
                config,
                state,
                target_host,
                target_port,
                retry_config,
                client,
            )
            .await?;
            Ok(Some((stream, proxy_id, upstream)))
        }

        DegradationPolicy::Direct => {
            let (stream, proxy_id, upstream) =
                direct_connect(config, runtime, target_host, target_port).await?;
            Ok(Some((stream, proxy_id, upstream)))
        }
    }
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
    client: &mut TcpStream,
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
            Ok(Ok((stream, trailer))) => {
                // Relay any early data the proxy pipelined after the 2xx CONNECT
                // response before handing the stream to the tunnel copy phase.
                if let Err(e) = forward_trailer_to_client(client, &trailer).await {
                    tracing::debug!(
                        proxy = %proxy_cfg.id,
                        error = %e,
                        "Failed to forward post-CONNECT early data"
                    );
                    last_error = Some(e);
                    continue;
                }
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
    client: &mut TcpStream,
) -> Result<(TcpStream, String, UpstreamProxy)> {
    // Get the most recently healthy proxy
    let last_healthy_id = state.get_last_healthy_proxy().await;

    let last_healthy_id = match last_healthy_id {
        Some(id) => id,
        None => {
            tracing::warn!(
                "No proxy has ever been healthy, falling back to try_all (use_last policy)"
            );
            return try_all_proxies(config, target_host, target_port, retry_config, client).await;
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
            return try_all_proxies(config, target_host, target_port, retry_config, client).await;
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
            return try_all_proxies(config, target_host, target_port, retry_config, client).await;
        }
    };

    // Try to connect with timeout
    let connect_result = tokio::time::timeout(
        Duration::from_secs(TRY_ALL_TIMEOUT_PER_PROXY_SECS),
        try_proxy_connect(&upstream, target_host, target_port, retry_config),
    )
    .await;

    match connect_result {
        Ok(Ok((stream, trailer))) => {
            // Relay any early data the proxy pipelined after the 2xx CONNECT
            // response before handing the stream to the tunnel copy phase.
            if let Err(e) = forward_trailer_to_client(client, &trailer).await {
                tracing::warn!(
                    proxy = %last_healthy_id,
                    error = %e,
                    "Failed to forward post-CONNECT early data, falling back to try_all (use_last policy)"
                );
                return try_all_proxies(config, target_host, target_port, retry_config, client)
                    .await;
            }
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
            try_all_proxies(config, target_host, target_port, retry_config, client).await
        }
        Err(_) => {
            tracing::warn!(
                proxy = %last_healthy_id,
                timeout_secs = TRY_ALL_TIMEOUT_PER_PROXY_SECS,
                "Last healthy proxy timed out, falling back to try_all (use_last policy)"
            );
            try_all_proxies(config, target_host, target_port, retry_config, client).await
        }
    }
}

/// Establish a direct connection to the target, bypassing all proxies.
///
/// This is used by the Direct degradation policy when all proxies are unhealthy
/// and allow_direct_fallback is enabled in the configuration.
///
/// **Security Warning**: Direct connections bypass all proxy security controls,
/// may expose the client's IP address to targets, and skip any proxy-based
/// audit logging. This should only be used when availability is more important
/// than proxy enforcement.
async fn direct_connect(
    config: &AppConfig,
    runtime: &RuntimeState,
    target_host: &str,
    target_port: u16,
) -> Result<(TcpStream, String, UpstreamProxy)> {
    // Verify direct fallback is explicitly enabled in configuration
    if !config.settings.allow_direct_fallback {
        return Err(anyhow!(
            "Direct fallback requested but allow_direct_fallback is false. \
             Set allow_direct_fallback = true in config to enable direct connections."
        ));
    }

    let (firewall_active, bypass_mark) = runtime.firewall_context().await;
    if firewall_active && bypass_mark.is_none() {
        return Err(anyhow!(
            "Direct degradation policy unavailable: the daemon's own connections \
             have no firewall self-exemption, so a direct connect to a targeted \
             IP would be re-redirected into this proxy in an unbounded loop. \
             Run the daemon with CAP_NET_ADMIN available (SO_MARK exemption)."
        ));
    }

    tracing::warn!(
        target = %target_host,
        port = target_port,
        "DIRECT CONNECTION: All proxies unhealthy, connecting directly. \
         This bypasses proxy security controls!"
    );

    // Connect directly to the target
    let target_addr: SocketAddr = format!("{target_host}:{target_port}")
        .parse()
        .with_context(|| format!("Invalid direct target {target_host}:{target_port}"))?;
    let socket = tokio::time::timeout(Duration::from_secs(TRY_ALL_TIMEOUT_PER_PROXY_SECS), async {
        let res: Result<TcpStream> = match bypass_mark {
            Some(mark) => connect_with_mark(target_addr, mark).await,
            None => TcpStream::connect(target_addr)
                .await
                .context(format!("Direct connection to {target_addr} failed")),
        };
        res
    })
    .await
    .map_err(|_| anyhow!("Direct connection to {target_addr} timed out"))??;

    // Create a synthetic UpstreamProxy to track as "direct"
    let direct_upstream = UpstreamProxy {
        id: "direct".to_string(),
        host: target_host.to_string(),
        port: target_port,
        username: None,
        password: None,
    };

    Ok((socket, "direct".to_string(), direct_upstream))
}

/// Open a TCP connection whose packets carry `mark` (SO_MARK), exempting them
/// from our own nat OUTPUT REDIRECT via the `-m mark` RETURN rule installed by
/// [`crate::iptables::apply_rules`].
///
/// The mark MUST be set before `connect(2)`: it is copied onto the socket's
/// sk_buff at SYN time, which is exactly what keeps this flow out of the
/// redirect that would otherwise loop it back into our listener.
async fn connect_with_mark(addr: SocketAddr, mark: u32) -> Result<TcpStream> {
    // Blocking connect offloaded to the blocking pool so the caller keeps its
    // timeout semantics; the mark must be applied before connect(2) so the
    // SYN itself carries it and escapes our own REDIRECT rule.
    tokio::task::spawn_blocking(move || -> Result<TcpStream> {
        use socket2::{Domain, Protocol, Socket, Type};

        let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
            .context("Failed creating direct-connect socket")?;
        sock.set_mark(mark)
            .context("Failed setting SO_MARK on direct-connect socket")?;
        sock.connect(&addr.into())
            .context("Direct connect(2) failed")?;
        sock.set_nonblocking(true)
            .context("Failed setting non-blocking mode on direct-connect socket")?;
        let std_stream = std::net::TcpStream::from(sock);
        TcpStream::from_std(std_stream)
            .context("Failed registering direct-connect socket with tokio")
    })
    .await
    .context("Direct-connect blocking task panicked")?
}

/// Probe whether this process may set SO_MARK (requires CAP_NET_ADMIN).
/// Called once at daemon startup to choose the self-exemption mechanism
/// before any firewall rules are built.
pub fn can_set_so_mark() -> bool {
    use socket2::{Domain, Protocol, Socket, Type};
    match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
        Ok(sock) => sock.set_mark(DIRECT_BYPASS_MARK).is_ok(),
        Err(_) => false,
    }
}

/// Try to establish a CONNECT tunnel through a single proxy.
///
/// Returns the connected upstream socket ready for bidirectional copy, along with
/// any early bytes the proxy pipelined after the 2xx CONNECT response header
/// (`header_buf[header_end..]`). Callers MUST forward those bytes to the client
/// before entering the tunnel copy phase; dropping them corrupts the stream
/// whenever the upstream sends data immediately after establishing the tunnel.
async fn try_proxy_connect(
    upstream: &UpstreamProxy,
    target_host: &str,
    target_port: u16,
    retry_config: &RetryConfig,
) -> Result<(TcpStream, Vec<u8>)> {
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

    // Preserve any early bytes the proxy pipelined after the response header so
    // the caller can relay them to the client (mirrors the primary path).
    let trailer = header_buf[header_end..].to_vec();

    Ok((upstream_socket, trailer))
}

/// Forward post-CONNECT-header bytes to the client, mirroring the primary path's
/// trailer relay. A failure here means the client stream is broken; callers must
/// treat the connection attempt as failed rather than entering the tunnel phase.
async fn forward_trailer_to_client(client: &mut TcpStream, trailer: &[u8]) -> Result<()> {
    debug_assert!(!trailer.is_empty());
    client.write_all(trailer).await?;
    client.flush().await?;
    Ok(())
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
    let target_host = original_dst_connect_host(*target.ip());
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

/// Runtime-gated test mode flag, resolved once per process so the production
/// hot path never touches the environment.
static TEST_MODE_ENABLED: LazyLock<bool> =
    LazyLock::new(|| std::env::var("RUST_PROXY_TEST_MODE").as_deref() == Ok("1"));

/// Hostname captured from `RUST_PROXY_TEST_ORIGINAL_DST` when the seam value is
/// a DNS name rather than a literal IP. A `SocketAddr` cannot carry a hostname,
/// so the connection plumbing gets a placeholder IP while the upstream CONNECT
/// request line uses this name. Only ever set under RUST_PROXY_TEST_MODE.
static TEST_ORIGINAL_DST_HOST: OnceLock<String> = OnceLock::new();

/// Parse the `RUST_PROXY_TEST_ORIGINAL_DST` seam value ("host:port") into a
/// placeholder IPv4 socket address. Returns `None` unless the operator opted
/// into RUST_PROXY_TEST_MODE, leaving production behavior untouched.
fn test_original_dst_fallback() -> Option<SocketAddr> {
    if !*TEST_MODE_ENABLED {
        return None;
    }
    let raw = std::env::var("RUST_PROXY_TEST_ORIGINAL_DST").ok()?;
    let (host, port) = raw.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    tracing::debug!(
        host,
        port,
        "SO_ORIGINAL_DST replaced by RUST_PROXY_TEST_ORIGINAL_DST seam value"
    );
    match host.parse::<Ipv4Addr>() {
        Ok(ip) => Some(SocketAddr::V4(SocketAddrV4::new(ip, port))),
        Err(_) => {
            let _ = TEST_ORIGINAL_DST_HOST.set(host.to_string());
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
        }
    }
}

/// Host placed in the upstream CONNECT request line for the given original
/// destination IP: the injected seam hostname when the test-mode fallback
/// captured one, otherwise the IP string exactly as before the seam existed.
fn original_dst_connect_host(target_ip: Ipv4Addr) -> String {
    match TEST_ORIGINAL_DST_HOST.get() {
        Some(host) => host.clone(),
        None => target_ip.to_string(),
    }
}

fn get_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    // Runtime-gated test seam: when the operator opts into RUST_PROXY_TEST_MODE
    // with RUST_PROXY_TEST_ORIGINAL_DST set, the injected destination replaces
    // the SO_ORIGINAL_DST lookup. It is probed first because some kernels
    // return a spurious success (the socket's own address) instead of failing
    // on connections that never traversed iptables REDIRECT. With the envs
    // unset this is a no-op and production behavior is byte-identical.
    if let Some(addr) = test_original_dst_fallback() {
        return Ok(addr);
    }

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

    /// Open a loopback client TcpStream for tests that need a sink argument but
    /// never assert on what is written to it. Hermetic: 127.0.0.1 only.
    async fn throwaway_client_stream() -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        TcpStream::connect(addr).await.expect("connect loopback")
    }

    /// A connected (client, peer) loopback socket pair for asserting bytes.
    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client = TcpStream::connect(addr).await.expect("connect loopback");
        let (peer, _) = listener.accept().await.expect("accept loopback");
        (client, peer)
    }

    /// Spawn a scripted fake CONNECT proxy on loopback. Each step is
    /// (delay_ms_before_write, bytes). The proxy first drains the client's
    /// CONNECT request headers, then plays the script. When `hold_open` is true
    /// the connection is held open afterwards (tunnel usable); when false it is
    /// closed so any subsequent connect attempt fails fast. Returns the bound address.
    async fn spawn_scripted_proxy(
        script: &[(u64, &[u8])],
        hold_open: bool,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake proxy");
        let addr = listener.local_addr().expect("fake proxy addr");
        let script: Vec<(u64, Vec<u8>)> = script
            .iter()
            .map(|(delay, data)| (*delay, data.to_vec()))
            .collect();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Drain the CONNECT request up to end of headers.
                let mut buf = [0u8; 4096];
                let mut seen = 0usize;
                while seen < 4096 {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            seen += n;
                            if buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                for (delay, data) in &script {
                    if *delay > 0 {
                        tokio::time::sleep(Duration::from_millis(*delay)).await;
                    }
                    if sock.write_all(data).await.is_err() {
                        return;
                    }
                    let _ = sock.flush().await;
                }
                if hold_open {
                    // Hold the tunnel open so the stream stays usable.
                    let mut hold = [0u8; 64];
                    while let Ok(0) | Err(_) = sock.read(&mut hold).await {}
                }
                // Dropping `sock` closes the connection.
            }
        });
        addr
    }

    fn single_proxy_config(proxy_addr: std::net::SocketAddr) -> AppConfig {
        use crate::config::{ProxyAuth, ProxyConfig, Settings};
        AppConfig {
            settings: Settings {
                degradation_policy: DegradationPolicy::UseLast,
                degradation_delay_secs: 0,
                ..Settings::default()
            },
            proxies: vec![ProxyConfig {
                id: "fake-proxy".to_string(),
                url: format!("http://{}", proxy_addr),
                auth: ProxyAuth::default(),
                priority: Some(1),
                health_check_url: None,
                weight: 100,
            }],
            ..AppConfig::default()
        }
    }

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

    // Degradation policy unit tests

    #[tokio::test]
    async fn test_handle_degradation_returns_none_when_not_degraded() {
        use crate::config::{AppConfig, DegradationPolicy, Settings};

        // Create a config with try_all policy
        let mut config = AppConfig {
            settings: Settings {
                degradation_policy: DegradationPolicy::TryAll,
                ..Settings::default()
            },
            ..AppConfig::default()
        };
        config.settings.degradation_delay_secs = 10; // Long delay

        // Create StateStore using test constructor
        let state = crate::state::StateStore::new_for_testing();

        // Create RuntimeState that is NOT degraded
        let runtime = RuntimeState::new(Some("proxy-a".to_string()));
        // Don't call update_degradation_state, so is_degraded() returns false

        let retry_config = RetryConfig::default();

        let mut client = throwaway_client_stream().await;
        let result = handle_degradation(
            &config,
            &state,
            &runtime,
            "example.com",
            443,
            &retry_config,
            &mut client,
        )
        .await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // None means "within delay period"
    }

    #[tokio::test]
    async fn test_handle_degradation_fail_closed_returns_error() {
        use crate::config::{AppConfig, DegradationPolicy, Settings};

        // Create a config with fail_closed policy
        let mut config = AppConfig {
            settings: Settings {
                degradation_policy: DegradationPolicy::FailClosed,
                ..Settings::default()
            },
            ..AppConfig::default()
        };
        config.settings.degradation_delay_secs = 0; // Immediate

        // Create StateStore using test constructor
        let state = crate::state::StateStore::new_for_testing();

        // Create RuntimeState that IS degraded
        let runtime = RuntimeState::new(Some("proxy-a".to_string()));
        // Trigger degradation with empty healthy list and 0 delay
        let empty: Vec<String> = vec![];
        runtime.update_degradation_state(&empty, 0).await;
        assert!(runtime.is_degraded().await); // Verify it's degraded

        let retry_config = RetryConfig::default();

        let mut client = throwaway_client_stream().await;
        let result = handle_degradation(
            &config,
            &state,
            &runtime,
            "example.com",
            443,
            &retry_config,
            &mut client,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fail_closed"));
    }

    #[tokio::test]
    async fn test_handle_degradation_direct_requires_opt_in() {
        use crate::config::{AppConfig, DegradationPolicy, Settings};

        // Create a config with direct policy but NOT allowing direct fallback
        let config = AppConfig {
            settings: Settings {
                degradation_policy: DegradationPolicy::Direct,
                allow_direct_fallback: false, // Not allowed
                degradation_delay_secs: 0,
                ..Settings::default()
            },
            ..AppConfig::default()
        };

        // Create StateStore using test constructor
        let state = crate::state::StateStore::new_for_testing();

        // Create RuntimeState that IS degraded
        let runtime = RuntimeState::new(Some("proxy-a".to_string()));
        let empty: Vec<String> = vec![];
        runtime.update_degradation_state(&empty, 0).await;

        let retry_config = RetryConfig::default();

        let mut client = throwaway_client_stream().await;
        let result = handle_degradation(
            &config,
            &state,
            &runtime,
            "example.com",
            443,
            &retry_config,
            &mut client,
        )
        .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("allow_direct_fallback"));
    }

    #[tokio::test]
    async fn test_handle_degradation_direct_refused_without_self_exemption_when_firewall_live() {
        use crate::config::{AppConfig, DegradationPolicy, Settings};

        let config = AppConfig {
            settings: Settings {
                degradation_policy: DegradationPolicy::Direct,
                allow_direct_fallback: true,
                degradation_delay_secs: 0,
                ..Settings::default()
            },
            ..AppConfig::default()
        };
        let state = crate::state::StateStore::new_for_testing();

        // Firewall is live but no self-exemption mark could be installed:
        // a direct connect would be re-redirected into the daemon (loop).
        let runtime = RuntimeState::new(Some("proxy-a".to_string()));
        runtime.set_firewall_context(true, None).await;
        let empty: Vec<String> = vec![];
        runtime.update_degradation_state(&empty, 0).await;

        let retry_config = RetryConfig::default();
        let mut client = throwaway_client_stream().await;
        let result = handle_degradation(
            &config,
            &state,
            &runtime,
            "example.com",
            443,
            &retry_config,
            &mut client,
        )
        .await;

        let err = result.expect_err("direct fallback must be refused without self-exemption");
        assert!(
            err.to_string().contains("self-exemption"),
            "error should name the missing self-exemption, got: {err}"
        );
    }

    #[test]
    fn test_upstream_proxy_from_config() {
        use crate::config::{ProxyAuth, ProxyConfig};

        let proxy_cfg = ProxyConfig {
            id: "test-proxy".to_string(),
            url: "http://proxy.example.com:8080".to_string(),
            auth: ProxyAuth::default(),
            priority: Some(1),
            health_check_url: None,
            weight: 100,
        };

        let upstream = UpstreamProxy::from_config(&proxy_cfg).expect("should parse");
        assert_eq!(upstream.id, "test-proxy");
        assert_eq!(upstream.host, "proxy.example.com");
        assert_eq!(upstream.port, 8080);
        assert!(upstream.username.is_none());
        assert!(upstream.password.is_none());
    }

    #[test]
    fn test_upstream_proxy_from_config_with_auth() {
        use crate::config::{ProxyAuth, ProxyConfig};

        let proxy_cfg = ProxyConfig {
            id: "auth-proxy".to_string(),
            url: "http://secure.example.com:3128".to_string(),
            auth: ProxyAuth {
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
                username_env: None,
                password_env: None,
            },
            priority: Some(1),
            health_check_url: None,
            weight: 100,
        };

        let upstream = UpstreamProxy::from_config(&proxy_cfg).expect("should parse");
        assert_eq!(upstream.id, "auth-proxy");
        assert_eq!(upstream.host, "secure.example.com");
        assert_eq!(upstream.port, 3128);
        assert_eq!(upstream.username, Some("user".to_string()));
        assert_eq!(upstream.password, Some("pass".to_string()));
    }

    #[test]
    fn test_connection_guard_tracks_metrics() {
        // Create a guard
        let guard = ConnectionGuard::new("test-proxy".to_string());
        assert_eq!(guard.proxy_id, "test-proxy");
        // Guard drop happens at end of scope - metrics are recorded
        // (Actual metrics testing would require checking prometheus counters)
    }

    // Additional degradation policy unit tests

    #[tokio::test]
    async fn test_handle_degradation_try_all_with_no_proxies() {
        use crate::config::{AppConfig, DegradationPolicy, Settings};

        // Create a config with try_all policy but NO proxies configured
        let config = AppConfig {
            settings: Settings {
                degradation_policy: DegradationPolicy::TryAll,
                degradation_delay_secs: 0,
                ..Settings::default()
            },
            proxies: vec![], // No proxies
            ..AppConfig::default()
        };

        let state = crate::state::StateStore::new_for_testing();

        let runtime = RuntimeState::new(None);
        let empty: Vec<String> = vec![];
        runtime.update_degradation_state(&empty, 0).await;
        assert!(runtime.is_degraded().await);

        let retry_config = RetryConfig::default();

        let mut client = throwaway_client_stream().await;
        let result = handle_degradation(
            &config,
            &state,
            &runtime,
            "example.com",
            443,
            &retry_config,
            &mut client,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No proxies"));
    }

    #[tokio::test]
    async fn test_handle_degradation_use_last_with_no_history() {
        use crate::config::{AppConfig, DegradationPolicy, ProxyAuth, ProxyConfig, Settings};

        // Create a config with use_last policy
        let config = AppConfig {
            settings: Settings {
                degradation_policy: DegradationPolicy::UseLast,
                degradation_delay_secs: 0,
                ..Settings::default()
            },
            proxies: vec![
                ProxyConfig {
                    id: "proxy-a".to_string(),
                    url: "http://proxy-a.invalid:8080".to_string(), // Non-routable for test
                    auth: ProxyAuth::default(),
                    priority: Some(1),
                    health_check_url: None,
                    weight: 100,
                },
                ProxyConfig {
                    id: "proxy-b".to_string(),
                    url: "http://proxy-b.invalid:8080".to_string(),
                    auth: ProxyAuth::default(),
                    priority: Some(2),
                    health_check_url: None,
                    weight: 100,
                },
            ],
            ..AppConfig::default()
        };

        // StateStore with NO last_healthy_proxy recorded
        let state = crate::state::StateStore::new_for_testing();
        // Don't record any health checks, so get_last_healthy_proxy returns None

        let runtime = RuntimeState::new(Some("proxy-a".to_string()));
        let empty: Vec<String> = vec![];
        runtime.update_degradation_state(&empty, 0).await;

        let retry_config = RetryConfig::default();

        // Call handle_degradation - use_last should fail since no proxy was ever healthy
        let mut client = throwaway_client_stream().await;
        let result = handle_degradation(
            &config,
            &state,
            &runtime,
            "example.com",
            443,
            &retry_config,
            &mut client,
        )
        .await;

        // Should fail because we can't connect to the invalid proxies
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_degradation_zero_delay_activates_immediately() {
        use crate::config::{AppConfig, DegradationPolicy, Settings};

        // Create a config with fail_closed policy and ZERO delay
        let config = AppConfig {
            settings: Settings {
                degradation_policy: DegradationPolicy::FailClosed,
                degradation_delay_secs: 0, // Immediate activation
                ..Settings::default()
            },
            ..AppConfig::default()
        };

        let state = crate::state::StateStore::new_for_testing();

        let runtime = RuntimeState::new(Some("proxy-a".to_string()));

        // With zero delay, update_degradation_state should immediately activate
        let empty: Vec<String> = vec![];
        runtime.update_degradation_state(&empty, 0).await;

        // Verify degradation is active
        assert!(runtime.is_degraded().await);

        let retry_config = RetryConfig::default();

        let mut client = throwaway_client_stream().await;
        let result = handle_degradation(
            &config,
            &state,
            &runtime,
            "example.com",
            443,
            &retry_config,
            &mut client,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fail_closed"));
    }

    #[tokio::test]
    async fn test_degradation_policy_routing() {
        use crate::config::DegradationPolicy;

        // Test that each policy variant is distinct and recognized
        let policies = [
            DegradationPolicy::FailClosed,
            DegradationPolicy::TryAll,
            DegradationPolicy::UseLast,
            DegradationPolicy::Direct,
        ];

        for policy in policies {
            match policy {
                DegradationPolicy::FailClosed => {
                    assert_eq!(format!("{:?}", policy), "FailClosed");
                }
                DegradationPolicy::TryAll => {
                    assert_eq!(format!("{:?}", policy), "TryAll");
                }
                DegradationPolicy::UseLast => {
                    assert_eq!(format!("{:?}", policy), "UseLast");
                }
                DegradationPolicy::Direct => {
                    assert_eq!(format!("{:?}", policy), "Direct");
                }
            }
        }
    }

    #[tokio::test]
    async fn test_use_last_proxy_forwards_trailer_after_2xx() {
        // REGRESSION: early data the proxy pipelined after the 2xx CONNECT
        // response must reach the client byte-exact before the tunnel phase.
        // With the old code (trailer discarded) this test fails because the
        // client would never receive EARLY42.
        let proxy_addr = spawn_scripted_proxy(
            &[(
                0,
                &b"HTTP/1.1 200 Connection established\r\n\r\nEARLY42"[..],
            )],
            true,
        )
        .await;
        let config = single_proxy_config(proxy_addr);
        let state = crate::state::StateStore::new_for_testing();
        state
            .record_health_check("fake-proxy", true, None, None, 1)
            .await;

        let retry_config = RetryConfig::default();
        let (mut client, mut client_peer) = loopback_pair().await;

        let result = use_last_proxy(
            &config,
            &state,
            "example.com",
            443,
            &retry_config,
            &mut client,
        )
        .await;

        let (_upstream_socket, proxy_id, _upstream) =
            result.expect("use_last_proxy should succeed");
        assert_eq!(proxy_id, "fake-proxy");

        let mut buf = [0u8; b"EARLY42".len()];
        tokio::time::timeout(Duration::from_secs(5), client_peer.read_exact(&mut buf))
            .await
            .expect("timely trailer delivery")
            .expect("peer read");
        assert_eq!(&buf, b"EARLY42");

        // Nothing else was pipelined: a further read must stay empty.
        let mut extra = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(150), client_peer.read(&mut extra)).await {
            Err(_) | Ok(Ok(0)) => {} // timed out or EOF: no extra bytes
            Ok(Ok(n)) => panic!("unexpected extra bytes after trailer: {n}"),
            Ok(Err(e)) => panic!("unexpected peer read error after trailer: {e}"),
        }
    }

    #[tokio::test]
    async fn test_407_yields_err_and_zero_trailer_bytes() {
        // NEGATIVE CONTROL: non-2xx CONNECT response yields Err and writes zero
        // bytes to the client stream, even though the proxy sent trailing bytes.
        let proxy_addr = spawn_scripted_proxy(
            &[(
                0,
                &b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\nDENIED!"[..],
            )],
            false,
        )
        .await;
        let config = single_proxy_config(proxy_addr);
        let state = crate::state::StateStore::new_for_testing();
        state
            .record_health_check("fake-proxy", true, None, None, 1)
            .await;

        let retry_config = RetryConfig::default();
        let (mut client, mut client_peer) = loopback_pair().await;

        let result = use_last_proxy(
            &config,
            &state,
            "example.com",
            443,
            &retry_config,
            &mut client,
        )
        .await;

        assert!(
            result.is_err(),
            "407 CONNECT response must fail the attempt"
        );

        // Client received nothing at all.
        let mut probe = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(150), client_peer.read(&mut probe)).await {
            Err(_) => {} // timed out: zero bytes delivered
            Ok(Ok(n)) => panic!("client must receive zero bytes on failed CONNECT, got {n}"),
            Ok(Err(e)) => panic!("unexpected peer read error on failed CONNECT: {e}"),
        }
    }

    #[tokio::test]
    async fn test_try_all_proxy_header_split_across_reads_forwards_trailer() {
        // Header split across multiple small reads must still parse and forward
        // its post-header bytes through try_all_proxies.
        let proxy_addr = spawn_scripted_proxy(
            &[
                (10, &b"HTTP/1.1 200 Connec"[..]),
                (10, &b"tion established\r\n"[..]),
                (20, &b"\r\nEARLY77"[..]),
            ],
            true,
        )
        .await;

        let config = single_proxy_config(proxy_addr);

        let retry_config = RetryConfig::default();
        let (mut client, mut client_peer) = loopback_pair().await;

        let result = try_all_proxies(&config, "example.com", 443, &retry_config, &mut client).await;

        let (_upstream_socket, proxy_id, _upstream) =
            result.expect("try_all_proxies should succeed");
        assert_eq!(proxy_id, "fake-proxy");

        let mut buf = [0u8; b"EARLY77".len()];
        tokio::time::timeout(Duration::from_secs(5), client_peer.read_exact(&mut buf))
            .await
            .expect("timely trailer delivery")
            .expect("peer read");
        assert_eq!(&buf, b"EARLY77");
    }

    #[tokio::test]
    async fn test_degradation_respects_delay_before_activation() {
        use crate::config::{AppConfig, DegradationPolicy, Settings};

        // Create a config with a non-zero delay
        let config = AppConfig {
            settings: Settings {
                degradation_policy: DegradationPolicy::FailClosed,
                degradation_delay_secs: 60, // Long delay
                ..Settings::default()
            },
            ..AppConfig::default()
        };

        let state = crate::state::StateStore::new_for_testing();

        let runtime = RuntimeState::new(Some("proxy-a".to_string()));

        // Mark all unhealthy but delay hasn't elapsed
        let empty: Vec<String> = vec![];
        runtime.update_degradation_state(&empty, 60).await;

        // Should NOT be degraded yet
        assert!(!runtime.is_degraded().await);

        let retry_config = RetryConfig::default();

        let mut client = throwaway_client_stream().await;
        let result = handle_degradation(
            &config,
            &state,
            &runtime,
            "example.com",
            443,
            &retry_config,
            &mut client,
        )
        .await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // None = within delay period
    }

    #[tokio::test]
    async fn test_degradation_recovery_clears_degraded_state() {
        let runtime = RuntimeState::new(Some("proxy-a".to_string()));

        // Trigger degradation
        let empty: Vec<String> = vec![];
        runtime.update_degradation_state(&empty, 0).await;
        assert!(runtime.is_degraded().await);

        // Recovery - a proxy becomes healthy
        let healthy = vec!["proxy-a".to_string()];
        runtime.update_degradation_state(&healthy, 0).await;

        // Should no longer be degraded
        assert!(!runtime.is_degraded().await);
    }

    #[tokio::test]
    async fn test_degradation_status_tracking() {
        let runtime = RuntimeState::new(Some("proxy-a".to_string()));

        // Initially no degradation status
        let status = runtime.get_degradation_status().await;
        assert!(status.is_none());

        // After all unhealthy with delay, should have status but not active
        let empty: Vec<String> = vec![];
        runtime.update_degradation_state(&empty, 60).await;
        let status = runtime.get_degradation_status().await;
        assert!(status.is_some());
        let status = status.unwrap();
        assert!(!status.active); // Not yet active (delay not elapsed)
                                 // unhealthy_since is a DateTime, not Option - if we have DegradationStatus, tracking has started
        let _ = status.unhealthy_since; // Verify it's accessible (tracking started)
    }

    #[test]
    fn test_retry_config_default_values() {
        let config = RetryConfig::default();

        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff_ms, 100);
        assert_eq!(config.max_backoff_ms, 5000);
    }
}

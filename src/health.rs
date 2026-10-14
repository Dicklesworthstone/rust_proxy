use crate::config::{AppConfig, HealthCheckTarget, ProxyConfig};
use crate::metrics;
use crate::proxy::{read_response_head, try_proxy_connect, RetryConfig, UpstreamProxy};
use crate::state::{HealthStatus, RuntimeState, StateStore};
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
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
    // Health may request a shorter deadline, never a larger transport budget.
    let timeout_dur = Duration::from_millis(timeout_ms.min(10_000));
    let start = Instant::now();

    let upstream = match UpstreamProxy::from_config(proxy) {
        Ok(upstream) => upstream,
        Err(e) => {
            return HealthCheckResult {
                success: false,
                latency_ms: start.elapsed().as_millis() as f64,
                failure_reason: Some(e.to_string()),
            };
        }
    };

    let target = match proxy.health_target(target) {
        Ok(target) => target,
        Err(e) => {
            return HealthCheckResult {
                success: false,
                latency_ms: start.elapsed().as_millis() as f64,
                failure_reason: Some(e.to_string()),
            }
        }
    };
    let result = timeout(timeout_dur, check_proxy_with_target(&upstream, &target)).await;
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

/// Probe the configured health check target DIRECTLY (no proxy).
///
/// Used by `check --validate-health-target` to distinguish "the target is
/// down" from "the proxies are broken": when this probe fails, the target is
/// unreachable from this machine and every proxy health check against it
/// fails for that reason alone.
///
/// `Connect` targets get a plain TCP connect. `Get` URLs get a
/// transport-level connect to the URL's host/port (TLS is not negotiated) —
/// enough to answer "is anything listening there".
pub async fn check_target_reachable(
    timeout_ms: u64,
    target: &HealthCheckTarget,
) -> HealthCheckResult {
    let timeout_dur = Duration::from_millis(timeout_ms);
    let start = Instant::now();

    let addr: String = match target {
        HealthCheckTarget::Connect { host, port } => format!("{host}:{port}"),
        HealthCheckTarget::Get { url } => match probe_address_for_url(url) {
            Ok(addr) => addr,
            Err(e) => {
                return HealthCheckResult {
                    success: false,
                    latency_ms: start.elapsed().as_millis() as f64,
                    failure_reason: Some(e.to_string()),
                };
            }
        },
    };

    let result = timeout(timeout_dur, TcpStream::connect(&addr)).await;
    let latency_ms = start.elapsed().as_millis() as f64;
    match result {
        Ok(Ok(_)) => HealthCheckResult {
            success: true,
            latency_ms,
            failure_reason: None,
        },
        Ok(Err(e)) => HealthCheckResult {
            success: false,
            latency_ms,
            failure_reason: Some(format!("Direct connect to {addr}: {e}")),
        },
        Err(_) => HealthCheckResult {
            success: false,
            latency_ms,
            failure_reason: Some(format!("Direct connect to {addr} timed out")),
        },
    }
}

/// Extract "host:port" from a Get-target URL, defaulting the port by scheme.
fn probe_address_for_url(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL missing host"))?;
    let port = parsed.port_or_known_default().unwrap_or(80);
    Ok(format!("{host}:{port}"))
}

/// Test that the proxy is reachable using the configured health check target
async fn check_proxy_with_target(
    upstream: &UpstreamProxy,
    target: &HealthCheckTarget,
) -> Result<()> {
    match target {
        HealthCheckTarget::Connect { host, port } => {
            // Same credential header, parser and finite establishment budget as forwarding.
            try_proxy_connect(
                upstream,
                host,
                *port,
                &RetryConfig {
                    max_retries: 0,
                    ..RetryConfig::default()
                },
            )
            .await?;
            Ok(())
        }
        HealthCheckTarget::Get { url } => check_proxy_get(upstream, url).await,
    }
}

/// Test that the proxy can perform an HTTP GET request to the specified URL
async fn check_proxy_get(upstream: &UpstreamProxy, url: &str) -> Result<()> {
    let parsed_url = url::Url::parse(url).context("Invalid health GET URL")?;
    let host = parsed_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Missing host in URL"))?;
    let port = parsed_url.port_or_known_default().unwrap_or(80);
    if parsed_url.scheme() == "https" {
        let (stream, early) = try_proxy_connect(
            upstream,
            host,
            port,
            &RetryConfig {
                max_retries: 0,
                ..RetryConfig::default()
            },
        )
        .await?;
        if !early.is_empty() {
            anyhow::bail!("Unexpected bytes before health-check TLS ClientHello");
        }
        // Native trust loading performs filesystem I/O. Keep the async probe's
        // deadline and the daemon's signal supervisor runnable even if it stalls.
        // The executable also bounds blocking-pool shutdown to three seconds.
        let native = tokio::task::spawn_blocking(rustls_native_certs::load_native_certs)
            .await
            .context("Native health TLS trust loader failed")?;
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        for cert in native.certs {
            roots
                .add(cert)
                .context("Invalid native TLS root certificate")?;
        }
        if roots.is_empty() {
            anyhow::bail!("No native TLS certificates available for health GET");
        }
        return check_https_get(stream, &parsed_url, roots).await;
    }
    let mut stream = crate::proxy::connect_daemon_tcp(&upstream.host, upstream.port).await?;
    send_get(&mut stream, &parsed_url, true, &upstream.auth_header()).await
}

async fn check_https_get(
    stream: TcpStream,
    url: &url::Url,
    roots: tokio_rustls::rustls::RootCertStore,
) -> Result<()> {
    let host = url.host_str().context("Missing health GET host")?;
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(
        host.trim_matches(['[', ']']).to_string(),
    )
    .context("Invalid health GET TLS server name")?;
    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
        .context("Health GET TLS validation failed")?;
    // Proxy credentials belong on CONNECT, never on the tunneled origin GET.
    send_get(&mut tls, url, false, "").await
}

async fn send_get<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    url: &url::Url,
    absolute: bool,
    auth: &str,
) -> Result<()> {
    let target = if absolute {
        url.as_str()
    } else {
        &url[url::Position::BeforePath..url::Position::AfterQuery]
    };
    let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
    let request =
        format!("GET {target} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: OpenAI File Downloader, XaiImageApiFetch/1.0\r\nConnection: close\r\n{auth}\r\n");
    stream.write_all(request.as_bytes()).await?;
    let (status, _) = read_response_head(stream).await?;
    if !(200..300).contains(&status) {
        anyhow::bail!("Health GET failed: HTTP status {status}");
    }
    Ok(())
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
    config_rx: watch::Receiver<std::sync::Arc<crate::AppConfig>>,
    state: Arc<StateStore>,
    runtime: RuntimeState,
    mut shutdown: watch::Receiver<bool>,
) {
    let config = config_rx.borrow().clone();
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
                // Hot-reload: adopt the latest validated config each tick.
                let config = config_rx.borrow().clone();
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
    use crate::config::ProxyAuth;
    use base64::Engine as _;
    use tokio::io::AsyncReadExt;

    struct RestoreEnv(&'static str, Option<std::ffi::OsString>);

    impl Drop for RestoreEnv {
        fn drop(&mut self) {
            match &self.1 {
                Some(value) => std::env::set_var(self.0, value),
                None => std::env::remove_var(self.0),
            }
        }
    }

    async fn read_request<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<String> {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).await?;
            bytes.push(byte[0]);
            anyhow::ensure!(bytes.len() <= 16 * 1024, "request exceeded fixture cap");
        }
        Ok(String::from_utf8(bytes)?)
    }

    async fn response_server(
        response: Vec<u8>,
    ) -> Result<(ProxyConfig, tokio::task::JoinHandle<Result<String>>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy = ProxyConfig {
            id: "probe".into(),
            url: format!("http://{}", listener.local_addr()?),
            auth: ProxyAuth::default(),
            priority: None,
            health_check_url: None,
            weight: 100,
        };
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_request(&mut stream).await?;
            // Force a split status token and split final delimiter over real TCP.
            for chunk in response.chunks(2) {
                if stream.write_all(chunk).await.is_err() {
                    break; // Rejection controls may close before the whole oversized head.
                }
                tokio::task::yield_now().await;
            }
            Ok(request)
        });
        Ok((proxy, task))
    }

    #[tokio::test]
    async fn authenticated_probe_sources_and_precedence() -> Result<()> {
        let env_user = "RUST_PROXY_HEALTH_SOURCE_TEST_USER";
        let env_pass = "RUST_PROXY_HEALTH_SOURCE_TEST_PASS";
        let old_user = std::env::var_os(env_user);
        let old_pass = std::env::var_os(env_pass);
        let _user_guard = RestoreEnv(env_user, old_user);
        let _pass_guard = RestoreEnv(env_pass, old_pass);
        std::env::set_var(env_user, "env-user");
        std::env::set_var(env_pass, "env-pass");
        for (source, expected) in [
            ("url", "url-user:url+p:ass"),
            ("config", "config-user:config-pass"),
            ("env", "env-user:env-pass"),
            ("mixed", "env-user:config-pass"),
        ] {
            let (mut proxy, task) =
                response_server(b"HTTP/1.1 200 Established\r\n\r\n".to_vec()).await?;
            proxy.url = proxy
                .url
                .replacen("http://", "http://url-user:url%2Bp%3Aass@", 1);
            if source != "url" {
                proxy.auth.username = Some("config-user".into());
                proxy.auth.password = Some("config-pass".into());
            }
            if source == "env" || source == "mixed" {
                proxy.auth.username_env = Some(env_user.into());
            }
            if source == "env" {
                proxy.auth.password_env = Some(env_pass.into());
            }
            let result = check_proxy_health(&proxy, 1000, &HealthCheckTarget::default()).await;
            assert!(
                result.success,
                "source {source}: {:?}",
                result.failure_reason
            );
            let request = task.await??;
            let token = base64::engine::general_purpose::STANDARD.encode(expected);
            assert!(
                request.contains(&format!("Proxy-Authorization: Basic {token}\r\n")),
                "credential precedence did not reach the endpoint for {source}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn probes_reject_auth_failures_incidental_status_digits_and_large_heads() -> Result<()> {
        let mut oversize = b"HTTP/1.1 200 OK\r\nX-Large: ".to_vec();
        oversize.extend(std::iter::repeat_n(b'x', 16 * 1024));
        oversize.extend_from_slice(b"\r\n\r\n");
        let cases = [
            (b"HTTP/1.1 204 Ready\r\n\r\n".to_vec(), true),
            (b"HTTP/1.1 407 Need auth 200\r\n\r\n".to_vec(), false),
            (b"HTTP/1.1 502 token-200-secret\r\n\r\n".to_vec(), false),
            (b"HTTP/9.9 200 token-200-secret\r\n\r\n".to_vec(), false),
            (b"HTTP/1.1 2000 token-200-secret\r\n\r\n".to_vec(), false),
            (b"HTTP/1.1 200 OK\r\nX: truncated".to_vec(), false),
            (oversize, false),
        ];
        for (response, expected) in cases {
            let (proxy, task) = response_server(response).await?;
            let result = check_proxy_health(&proxy, 2000, &HealthCheckTarget::default()).await;
            assert_eq!(result.success, expected, "exact status/header decision");
            assert!(
                !result
                    .failure_reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("token-200-secret"),
                "untrusted reason phrase leaked"
            );
            task.await??;
        }
        Ok(())
    }

    #[tokio::test]
    async fn silent_probe_uses_its_own_shorter_deadline_and_closes_socket() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let mut proxy = ProxyConfig {
            id: "silent".into(),
            url: format!("http://{}", listener.local_addr()?),
            auth: ProxyAuth::default(),
            priority: None,
            health_check_url: None,
            weight: 100,
        };
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            read_request(&mut stream).await?;
            let mut byte = [0];
            // No fixture deadline: the client must cancel and release its socket.
            Ok::<_, anyhow::Error>(stream.read(&mut byte).await?)
        });
        let started = Instant::now();
        let result = check_proxy_health(&proxy, 200, &HealthCheckTarget::default()).await;
        assert!(!result.success);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(timeout(Duration::from_secs(1), server).await???, 0);
        proxy.auth.username = Some("only-one".into());
        assert!(UpstreamProxy::from_config(&proxy).is_err());
        proxy.auth.password = Some("unused".into());
        proxy.auth.password_env =
            Some("RUST_PROXY_DEFINITELY_MISSING_HEALTH_CREDENTIAL_20261013".into());
        assert!(
            UpstreamProxy::from_config(&proxy).is_err(),
            "missing explicit environment must not fall back"
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_get_is_absolute_authenticated_and_honors_per_proxy_override() -> Result<()> {
        for target in [
            "http://first.invalid:8080/health?probe=1",
            "http://second.invalid/ready",
        ] {
            let (mut proxy, task) = response_server(b"HTTP/1.1 204 Ready\r\n\r\n".to_vec()).await?;
            proxy.auth.username = Some("get-user".into());
            proxy.auth.password = Some("get-pass".into());
            proxy.health_check_url = Some(target.into());
            let result = check_proxy_health(&proxy, 1000, &HealthCheckTarget::default()).await;
            assert!(result.success, "{:?}", result.failure_reason);
            let request = task.await??;
            assert!(
                request.starts_with(&format!("GET {target} HTTP/1.1\r\n")),
                "GET override/absolute form was not sent"
            );
            assert!(request.contains("Proxy-Authorization: Basic "));
        }
        let (mut proxy, task) = response_server(b"HTTP/1.1 407 Auth 200\r\n\r\n".to_vec()).await?;
        proxy.health_check_url = Some("http://first.invalid/health".into());
        assert!(
            !check_proxy_health(&proxy, 1000, &HealthCheckTarget::default())
                .await
                .success
        );
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn https_get_requires_validated_tls_and_origin_get_without_proxy_auth() -> Result<()> {
        use tokio_rustls::rustls::{
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
            RootCertStore, ServerConfig,
        };
        // Public test-only key/certificate for localhost, valid through 2036-10-10.
        // This root is passed only to the fixture helper, never installed in production trust.
        let cert = CertificateDer::from(base64::engine::general_purpose::STANDARD.decode("MIIBUDCCAQKgAwIBAgIULmnM1+XLhtNukcbaA14gGFGiG5EwBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjEwMTMyMzEzMDRaFw0zNjEwMTAyMzEzMDRaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhALYa962bMj17JGFmOxgZH9kXD0ttqdAMMiVNIc6wo7TIo2YwZDAdBgNVHQ4EFgQUH2t/rhROpYaECVM8h2lBBM0uZocwHwYDVR0jBBgwFoAUH2t/rhROpYaECVM8h2lBBM0uZocwFAYDVR0RBA0wC4IJbG9jYWxob3N0MAwGA1UdEwEB/wQCMAAwBQYDK2VwA0EAauAETyQzW6rUFYIv7C9jIZzLq4F9DBsE7tjU2tNt/PLOhOs89yRvf4XuvEsoFng+j4M9kxz3DAzoFmoosk5aBQ==")?);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            base64::engine::general_purpose::STANDARD
                .decode("MC4CAQAwBQYDK2VwBCIEIFiwy4LYMtUWxMvfd8cYBG+nlCvuEXsIyOq3MJSZGwLa")?,
        ));
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key)?,
        );
        let mut roots = RootCertStore::empty();
        roots.add(cert)?;
        for (host, trust, expected) in [
            ("localhost", true, true),
            ("wrong.invalid", true, false),
            ("localhost", false, false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let port = listener.local_addr()?.port();
            let server_config = config.clone();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let request = read_request(&mut stream).await?;
                anyhow::ensure!(
                    request.starts_with("CONNECT "),
                    "missing TLS tunnel request"
                );
                anyhow::ensure!(
                    request.contains("Proxy-Authorization: Basic "),
                    "missing CONNECT authentication"
                );
                stream
                    .write_all(b"HTTP/1.1 200 Established\r\n\r\n")
                    .await?;
                let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(server_config)
                    .accept(stream)
                    .await
                else {
                    return Ok(false);
                };
                let request = read_request(&mut tls).await?;
                anyhow::ensure!(
                    request.starts_with("GET /health?tls=1 HTTP/1.1\r\n"),
                    "origin GET missing"
                );
                anyhow::ensure!(
                    !request.contains("Proxy-Authorization"),
                    "proxy auth leaked to origin"
                );
                tls.write_all(b"HTTP/1.1 204 Healthy\r\n\r\n").await?;
                Ok::<_, anyhow::Error>(true)
            });
            let proxy = ProxyConfig {
                id: "tls".into(),
                url: format!("http://127.0.0.1:{port}"),
                auth: ProxyAuth {
                    username: Some("tls-user".into()),
                    password: Some("tls-pass".into()),
                    ..ProxyAuth::default()
                },
                priority: None,
                health_check_url: None,
                weight: 100,
            };
            let upstream = UpstreamProxy::from_config(&proxy)?;
            let (stream, early) =
                try_proxy_connect(&upstream, host, 443, &RetryConfig::default()).await?;
            assert!(early.is_empty());
            let url = url::Url::parse(&format!("https://{host}/health?tls=1"))?;
            let result = timeout(
                Duration::from_secs(2),
                check_https_get(
                    stream,
                    &url,
                    if trust {
                        roots.clone()
                    } else {
                        RootCertStore::empty()
                    },
                ),
            )
            .await?;
            assert_eq!(result.is_ok(), expected, "TLS trust/name outcome");
            assert_eq!(
                timeout(Duration::from_secs(2), server).await???,
                expected,
                "GET observed only on validated TLS"
            );
        }
        Ok(())
    }

    #[test]
    fn test_probe_address_for_url_defaults_port_by_scheme() {
        assert_eq!(
            probe_address_for_url("https://example.com/health").unwrap(),
            "example.com:443"
        );
        assert_eq!(
            probe_address_for_url("http://example.com:8080/health").unwrap(),
            "example.com:8080"
        );
    }

    #[tokio::test]
    async fn test_check_target_reachable_succeeds_against_local_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = HealthCheckTarget::Connect {
            host: "127.0.0.1".to_string(),
            port,
        };
        let result = check_target_reachable(1000, &target).await;
        assert!(
            result.success,
            "expected success, got {:?}",
            result.failure_reason
        );
    }

    #[test]
    fn test_parse_proxy_address_with_scheme() {
        let endpoint = crate::util::parse_proxy_url("http://proxy.example.com:8080").unwrap();
        assert_eq!(endpoint.host, "proxy.example.com");
        assert_eq!(endpoint.port, 8080);
    }

    #[test]
    fn test_parse_proxy_address_without_scheme() {
        let endpoint = crate::util::parse_proxy_url("proxy.example.com:8080").unwrap();
        assert_eq!(endpoint.port, 8080);
    }

    #[test]
    fn test_parse_proxy_address_default_port() {
        let endpoint = crate::util::parse_proxy_url("http://proxy.example.com").unwrap();
        assert_eq!(endpoint.port, 80);
    }

    #[test]
    fn test_parse_proxy_address_https() {
        assert!(crate::util::parse_proxy_url("https://proxy.example.com").is_err());
    }
}

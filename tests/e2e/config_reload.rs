//! Config hot-reload E2E — proves the watcher -> validated-reload ->
//! watch-bus -> per-connection-snapshot wiring through the real binary.
//!
//! Acceptance under test (wire-config-hot-reload-jmj):
//! 1. Baseline traffic routes via the configured proxy.
//! 2. Editing `config.toml` (swapping the proxy set) takes effect within
//!    watcher poll + debounce budget WITHOUT a process restart.
//! 3. An invalid config edit is rejected: the daemon keeps serving with the
//!    last-known-good configuration and logs why.
//!
//! NO-CLAIM: `RUST_PROXY_TEST_MODE=1` skips all firewall mutations, so the
//! ipset-sync leg of reload pickup is NOT exercised here; command-generation
//! unit tests do not establish that runtime leg. The observable used is
//! which upstream mock serves each tunneled connection, which exercises the
//! exact per-accept `config_rx.borrow()` snapshot the production path uses.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common::mock_proxy::{MockBehavior, MockError, MockProxy};

/// Distinctive payload relayed through the daemon under test.
const PAYLOAD: &[u8] = b"rust-proxy-config-reload-e2e/9876543210";

/// The injected original destination carried through the upstream CONNECT.
const ORIGINAL_DST: &str = "api.reload-test.invalid:443";

/// Watcher polls every 500 ms with a 500 ms debounce; budget generously.
const RELOAD_BUDGET: Duration = Duration::from_secs(10);

fn require_non_root() {
    if unsafe { libc::geteuid() } == 0 {
        // ubs:ignore[rust.ownership.panic-macro] — deliberately fails when the rootless privilege negative control would be invalid.
        panic!("test-seam reload tests must run as a non-root user");
    }
}

fn proxy_binary() -> PathBuf {
    PathBuf::from(
        std::env::var("CARGO_BIN_EXE_rust_proxy")
            .expect("CARGO_BIN_EXE_rust_proxy must be set by the cargo test harness"),
    )
}

fn free_listen_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe listener")
        .local_addr()
        .expect("probe local addr")
        .port()
}

struct ReloadHome {
    temp: TempDir,
    config_path: PathBuf,
}

/// Isolated HOME whose default config path holds `active_proxy` pointing at
/// exactly one mock; returns the config path so tests can rewrite it live.
fn write_test_config(mock_port: u16, listen_port: u16, proxy_id: &str) -> Result<ReloadHome> {
    let temp = TempDir::new().context("create temp HOME")?;
    let config_dir = temp.path().join(".config").join("rust_proxy");
    std::fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.toml");
    std::fs::write(
        &config_path,
        render_config(mock_port, listen_port, proxy_id),
    )?;
    Ok(ReloadHome { temp, config_path })
}

fn render_config(mock_port: u16, listen_port: u16, proxy_id: &str) -> String {
    format!(
        "active_proxy = \"{proxy_id}\"\n\
         targets = [\"reload-test.invalid\"]\n\
         \n\
         [[proxies]]\n\
         id = \"{proxy_id}\"\n\
         url = \"http://127.0.0.1:{mock_port}\"\n\
         \n\
         [settings]\n\
         listen_port = {listen_port}\n\
         dns_refresh_secs = 3600\n\
         ping_interval_secs = 3600\n\
         ping_timeout_ms = 1000\n\
         ipset_name = \"reload_e2e_ipset\"\n\
         chain_name = \"RELOAD_E2E_CHAIN\"\n\
         include_aws_ip_ranges = false\n\
         include_cloudflare_ip_ranges = false\n\
         include_google_ip_ranges = false\n\
         metrics_enabled = false\n\
         health_check_enabled = false\n",
        proxy_id = proxy_id,
        mock_port = mock_port,
        listen_port = listen_port,
    )
}

/// Kills the daemon on scope exit — including test panics. A dropped
/// `std::process::Child` is NOT terminated, and a leaked daemon would serve
/// stale configs to later tests (and poison their port probes).
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_daemon(home: &ReloadHome, stderr_file: &Path) -> Result<Child> {
    let stderr = std::fs::File::create(stderr_file)?;
    Command::new(proxy_binary())
        .args(["daemon"])
        .env("HOME", home.temp.path())
        .env("XDG_CONFIG_HOME", home.temp.path().join(".config"))
        .env("XDG_STATE_HOME", home.temp.path().join(".state"))
        .env("RUST_LOG", "debug")
        .env("RUST_PROXY_TEST_MODE", "1")
        .env("RUST_PROXY_TEST_ORIGINAL_DST", ORIGINAL_DST)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .context("spawn rust_proxy daemon")
}

fn read_stderr(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

async fn wait_for_listener(addr: std::net::SocketAddr) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("daemon listener never came up at {}", addr);
        }
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Require useful byte-exact traffic; a failed attempt is never a success.
async fn tunnel_attempt(addr: std::net::SocketAddr) -> Result<()> {
    let mut client = TcpStream::connect(addr).await?;
    client.write_all(PAYLOAD).await?;
    client.flush().await?;
    let mut echoed = vec![0u8; PAYLOAD.len()];
    tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut echoed)).await??;
    anyhow::ensure!(echoed == PAYLOAD, "reload tunnel corrupted the payload");
    Ok(())
}

fn assert_alive(child: &mut Child, context: &str) {
    match child.try_wait() {
        Ok(None) => {}
        // ubs:ignore[rust.ownership.panic-macro] — fails the test if the supervised daemon exited before the required phase.
        Ok(Some(status)) => panic!("daemon exited unexpectedly ({context}): {status}"),
        // ubs:ignore[rust.ownership.panic-macro] — fails the test when process status cannot be checked.
        Err(err) => panic!("daemon wait failed ({context}): {err}"),
    }
}

/// POSITIVE: an edited config (proxy set swapped) is honored by NEW
/// connections without restarting the daemon.
#[tokio::test]
async fn config_edit_swaps_proxy_set_without_restart() -> Result<()> {
    require_non_root();

    let mock_a = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let mock_b = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let listen_port = free_listen_port();
    let home = write_test_config(mock_a.port, listen_port, "mock-a")?;
    let workdir = TempDir::new()?;
    let stderr_path = workdir.path().join("daemon.stderr.log");

    let mut child = ChildGuard(spawn_daemon(&home, &stderr_path)?);
    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{listen_port}").parse()?;
    if let Err(err) = wait_for_listener(listen_addr).await {
        // ubs:ignore[rust.ownership.panic-macro] — preserves the startup failure assertion and its actual daemon diagnostics.
        panic!(
            "daemon failed to boot: {err:#}\n--- stderr ---\n{}",
            read_stderr(&stderr_path)
        );
    }

    // Baseline: traffic reaches mock-a only.
    tunnel_attempt(listen_addr)
        .await
        .with_context(|| format!("baseline tunnel failed\n{}", read_stderr(&stderr_path)))?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while mock_a.get_requests().is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .with_context(|| {
        format!(
            "baseline CONNECT never reached mock-a\n{}",
            read_stderr(&stderr_path)
        )
    })?;
    assert!(mock_b.get_requests().is_empty());

    // Edit the config on disk: swap the proxy set to mock-b.
    std::fs::write(
        &home.config_path,
        render_config(mock_b.port, listen_port, "mock-b"),
    )?;

    // Poll until some connection lands on mock-b (watcher poll 500ms +
    // debounce 500ms; budget covers scheduler jitter).
    let deadline = tokio::time::Instant::now() + RELOAD_BUDGET;
    while mock_b.get_requests().is_empty() {
        assert_alive(&mut child.0, "while awaiting reload pickup");
        if tokio::time::Instant::now() >= deadline {
            // ubs:ignore[rust.ownership.panic-macro] — fails the reload acceptance test at its unchanged deadline.
            panic!(
                "hot-reloaded proxy set never took effect\n--- stderr ---\n{}",
                read_stderr(&stderr_path)
            );
        }
        tunnel_attempt(listen_addr).await.with_context(|| {
            format!("tunnel failed during reload\n{}", read_stderr(&stderr_path))
        })?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // No restart happened: same process, listener served throughout, and the
    // startup log appears exactly once.
    assert_alive(&mut child.0, "after reload pickup");
    let stderr = read_stderr(&stderr_path);
    assert_eq!(
        stderr.matches("transparent proxy listening on").count(),
        1,
        "listener must have started exactly once (no restart)"
    );
    assert!(
        !stderr.contains("panicked"),
        "daemon must not panic across a valid reload"
    );

    Ok(())
}

/// Retain two healthy proxies so a priority fallback cannot masquerade as
/// active-only reload. Recovery must return to the newly selected origin.
#[tokio::test]
async fn active_only_edit_switches_between_two_retained_healthy_proxies() -> Result<()> {
    require_non_root();
    let mock_a = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let mock_b = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let listen_port = free_listen_port();
    let home = write_test_config(mock_a.port, listen_port, "mock-a")?;
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&home.config_path)?)?;
    let mut second = toml::Table::new();
    second.insert("id".into(), "mock-b".into());
    second.insert(
        "url".into(),
        format!("http://127.0.0.1:{}", mock_b.port).into(),
    );
    second.insert("priority".into(), 0.into());
    config["proxies"]
        .as_array_mut()
        .unwrap()
        .push(second.into());
    let settings = config["settings"].as_table_mut().unwrap();
    settings.insert("health_check_enabled".into(), true.into());
    settings.insert("health_check_interval_secs".into(), 1.into());
    settings.insert("consecutive_failures_threshold".into(), 1.into());
    settings.insert("failback_delay_secs".into(), 1.into());
    settings.insert(
        "health_check_target".into(),
        "CONNECT health.reload.invalid:443".into(),
    );
    std::fs::write(&home.config_path, toml::to_string(&config)?)?;
    let work = tempfile::tempdir()?.keep();
    let log = work.join("daemon.stderr");
    let mut child = ChildGuard(spawn_daemon(&home, &log)?);
    let pid = child.0.id();
    let addr = ([127, 0, 0, 1], listen_port).into();
    wait_for_listener(addr).await?;
    let health_request = "CONNECT health.reload.invalid:443 HTTP/1.1";
    let ready = tokio::time::Instant::now() + Duration::from_secs(5);
    while ![&mock_a, &mock_b].iter().all(|proxy| {
        proxy
            .get_requests()
            .iter()
            .any(|request| request.request_line == health_request)
    }) {
        anyhow::ensure!(
            tokio::time::Instant::now() < ready,
            "both health probes did not complete: {}",
            read_stderr(&log)
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let traffic_count = |proxy: &MockProxy| {
        proxy
            .get_requests()
            .iter()
            .filter(|request| request.request_line == format!("CONNECT {ORIGINAL_DST} HTTP/1.1"))
            .count()
    };
    tunnel_attempt(addr).await?;
    assert!(traffic_count(&mock_a) >= 1);
    assert_eq!(
        traffic_count(&mock_b),
        0,
        "higher-priority retained B must not replace active A"
    );
    // This is the sole changed field. Keeping both proxy identities makes a
    // priority fallback unable to substitute for a rebased active selection.
    config["active_proxy"] = "mock-b".into();
    std::fs::write(&home.config_path, toml::to_string(&config)?)?;
    let deadline = tokio::time::Instant::now() + RELOAD_BUDGET;
    while traffic_count(&mock_b) == 0 {
        assert_alive(&mut child.0, "active-only reload");
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "active-only edit never selected retained B; log={}: {}",
            log.display(),
            read_stderr(&log)
        );
        tunnel_attempt(addr).await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let before_a = traffic_count(&mock_a);
    let before_b = traffic_count(&mock_b);
    for _ in 0..3 {
        tunnel_attempt(addr).await?;
    }
    assert_eq!(traffic_count(&mock_a), before_a);
    assert_eq!(traffic_count(&mock_b), before_b + 3);
    mock_b.set_behavior(MockBehavior::Failing {
        error: MockError::AuthRequired,
    });
    let deadline = tokio::time::Instant::now() + RELOAD_BUDGET;
    while !read_stderr(&log).contains("Failover performed") {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "rebased B never failed over: {}",
            read_stderr(&log)
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let before_a = traffic_count(&mock_a);
    let before_b = traffic_count(&mock_b);
    for _ in 0..3 {
        tunnel_attempt(addr).await?;
    }
    assert_eq!(traffic_count(&mock_a), before_a + 3);
    assert_eq!(traffic_count(&mock_b), before_b);
    mock_b.set_behavior(MockBehavior::TunnelEcho);
    let deadline = tokio::time::Instant::now() + RELOAD_BUDGET;
    while !read_stderr(&log).contains("Failback triggered - returning to original proxy") {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "recovered B never became the failback origin: {}",
            read_stderr(&log)
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let stderr = read_stderr(&log);
    assert!(
        stderr.lines().any(|line| line
            .contains("Failback triggered - returning to original proxy")
            && line.contains("mock-b")),
        "{stderr}"
    );
    let before_a = traffic_count(&mock_a);
    let before_b = traffic_count(&mock_b);
    for _ in 0..3 {
        tunnel_attempt(addr).await?;
    }
    assert_eq!(traffic_count(&mock_a), before_a);
    assert_eq!(traffic_count(&mock_b), before_b + 3);
    assert_eq!(child.0.id(), pid);
    assert_eq!(
        read_stderr(&log)
            .matches("transparent proxy listening on")
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn invalid_config_edit_keeps_last_known_good() -> Result<()> {
    require_non_root();

    let mock_a = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let listen_port = free_listen_port();
    let home = write_test_config(mock_a.port, listen_port, "mock-a")?;
    let workdir = TempDir::new()?;
    let stderr_path = workdir.path().join("daemon.stderr.log");

    let mut child = ChildGuard(spawn_daemon(&home, &stderr_path)?);
    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{listen_port}").parse()?;
    wait_for_listener(listen_addr).await?;

    // Break the config on disk.
    std::fs::write(&home.config_path, "not valid toml {{{{ nope")?;

    // Give the watcher ample time to observe and REJECT the change.
    tokio::time::sleep(RELOAD_BUDGET.min(Duration::from_secs(4))).await;

    // Daemon alive, still serving, routed to the original proxy.
    assert_alive(&mut child.0, "after invalid config edit");
    tunnel_attempt(listen_addr)
        .await
        .with_context(|| format!("last-good tunnel failed\n{}", read_stderr(&stderr_path)))?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while mock_a.get_requests().is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("last-known-good config stopped serving after invalid edit")?;

    let stderr = read_stderr(&stderr_path);
    assert!(
        stderr.contains("keeping last-known-good"),
        "expected rejection warning on stderr\n--- stderr ---\n{stderr}"
    );

    Ok(())
}

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
//! ipset-sync leg of reload pickup is NOT exercised here (that behavior is
//! pinned by unit golden tests over `sync_ipset`). The observable used is
//! which upstream mock serves each tunneled connection, which exercises the
//! exact per-accept `config_rx.borrow()` snapshot the production path uses.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common::mock_proxy::{MockBehavior, MockProxy};

/// Distinctive payload relayed through the daemon under test.
const PAYLOAD: &[u8] = b"rust-proxy-config-reload-e2e/9876543210";

/// The injected original destination carried through the upstream CONNECT.
const ORIGINAL_DST: &str = "api.reload-test.invalid:443";

/// Watcher polls every 500 ms with a 500 ms debounce; budget generously.
const RELOAD_BUDGET: Duration = Duration::from_secs(10);

fn require_non_root() {
    if unsafe { libc::geteuid() } == 0 {
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

/// One tunnel attempt through the listener; returns when the echo round trip
/// completes or errors/times out (callers treat both as "attempted").
async fn tunnel_attempt(addr: std::net::SocketAddr) {
    let mut client = match TcpStream::connect(addr).await {
        Ok(c) => c,
        Err(_) => return,
    };
    if client.write_all(PAYLOAD).await.is_err() {
        return;
    }
    let _ = client.flush().await;
    let mut echoed = vec![0u8; PAYLOAD.len()];
    let _ = tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut echoed)).await;
}

fn assert_alive(child: &mut Child, context: &str) {
    match child.try_wait() {
        Ok(None) => {}
        Ok(Some(status)) => panic!("daemon exited unexpectedly ({context}): {status}"),
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
        panic!(
            "daemon failed to boot: {err:#}\n--- stderr ---\n{}",
            read_stderr(&stderr_path)
        );
    }

    // Baseline: traffic reaches mock-a only.
    tunnel_attempt(listen_addr).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while mock_a.get_requests().is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("baseline CONNECT never reached mock-a")?;
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
            panic!(
                "hot-reloaded proxy set never took effect\n--- stderr ---\n{}",
                read_stderr(&stderr_path)
            );
        }
        tunnel_attempt(listen_addr).await;
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

/// NEGATIVE: an invalid config edit is rejected — daemon stays alive on the
/// last-known-good config and keeps routing.
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
    tunnel_attempt(listen_addr).await;
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

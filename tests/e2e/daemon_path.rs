//! Daemon-path E2E: first true traffic test through the real binary.
//!
//! These tests exercise the runtime-gated rootless test seam:
//! - `RUST_PROXY_TEST_MODE=1` skips the root requirement, all firewall
//!   mutations, background refresh/ping tasks, and the metrics server.
//! - `RUST_PROXY_TEST_ORIGINAL_DST=host:port` stands in for the
//!   SO_ORIGINAL_DST lookup that only iptables REDIRECT can provide.
//!
//! NO-CLAIM: this proves the daemon-path wiring (env-gated seam -> CONNECT ->
//! byte-exact tunnel relay), NOT real SO_ORIGINAL_DST or iptables behavior on
//! a root box.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common::mock_proxy::{MockBehavior, MockProxy};

/// Distinctive payload relayed through the daemon under test.
const PAYLOAD: &[u8] = b"rust-proxy-daemon-seam-e2e-payload/0123456789";

/// The injected original destination carried through the upstream CONNECT.
const ORIGINAL_DST: &str = "api.seam-test.invalid:443";

/// These tests exercise the non-root gate itself; running them as root would
/// make the negative control meaningless (and would touch real firewall
/// state in the positive path). Fail loudly instead of silently skipping.
fn require_non_root() {
    if unsafe { libc::geteuid() } == 0 {
        panic!("daemon-path seam tests must run as a non-root user");
    }
}

/// Path to the freshly built rust_proxy binary (cargo test harness).
fn proxy_binary() -> PathBuf {
    PathBuf::from(
        std::env::var("CARGO_BIN_EXE_rust_proxy")
            .expect("CARGO_BIN_EXE_rust_proxy must be set by the cargo test harness"),
    )
}

/// Reserve a free TCP port by binding and releasing an OS-assigned listener.
fn free_listen_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe listener")
        .local_addr()
        .expect("probe local addr")
        .port()
}

struct TestHome {
    _temp: TempDir,
}

/// Create an isolated HOME whose default config path holds a single-proxy
/// configuration pointing at the given mock, listening on `listen_port`.
fn write_test_config(mock_port: u16, listen_port: u16) -> Result<TestHome> {
    let temp = TempDir::new().context("create temp HOME")?;
    let config_dir = temp.path().join(".config").join("rust_proxy");
    std::fs::create_dir_all(&config_dir)?;

    let config = format!(
        "active_proxy = \"mock\"\n\
         targets = [\"seam-test.invalid\"]\n\
         \n\
         [[proxies]]\n\
         id = \"mock\"\n\
         url = \"http://127.0.0.1:{mock_port}\"\n\
         \n\
         [settings]\n\
         listen_port = {listen_port}\n\
         dns_refresh_secs = 3600\n\
         ping_interval_secs = 3600\n\
         ping_timeout_ms = 1000\n\
         ipset_name = \"test-seam-ipset\"\n\
         chain_name = \"TEST_SEAM_CHAIN\"\n\
         include_aws_ip_ranges = false\n\
         include_cloudflare_ip_ranges = false\n\
         include_google_ip_ranges = false\n\
         metrics_enabled = false\n\
         health_check_enabled = false\n",
        mock_port = mock_port,
        listen_port = listen_port,
    );
    std::fs::write(config_dir.join("config.toml"), config)?;
    Ok(TestHome { _temp: temp })
}

/// Spawn the real binary as `daemon` with the isolated HOME. When `test_mode`
/// is true the runtime seam envs are injected; otherwise the daemon runs its
/// production startup path (which refuses non-root users).
fn spawn_daemon(home: &TestHome, test_mode: bool, stderr_file: &Path) -> Result<Child> {
    let stderr = std::fs::File::create(stderr_file)?;
    let mut cmd = Command::new(proxy_binary());
    cmd.args(["daemon"])
        .env("HOME", home._temp.path())
        .env("XDG_CONFIG_HOME", home._temp.path().join(".config"))
        .env("XDG_STATE_HOME", home._temp.path().join(".state"))
        .env("RUST_LOG", "debug")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr));
    if test_mode {
        cmd.env("RUST_PROXY_TEST_MODE", "1")
            .env("RUST_PROXY_TEST_ORIGINAL_DST", ORIGINAL_DST);
    }
    cmd.spawn().context("spawn rust_proxy daemon")
}

fn read_stderr(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Wait until the daemon's transparent-proxy listener accepts connections.
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

/// POSITIVE: with RUST_PROXY_TEST_MODE=1 the full daemon boots unprivileged,
/// the seam substitutes the injected original destination, the upstream mock
/// receives `CONNECT api.seam-test.invalid:443`, and the client's bytes come
/// back through the established tunnel byte-exact.
#[tokio::test]
async fn test_mode_daemon_relays_tunnel_traffic_as_non_root() -> Result<()> {
    require_non_root();

    let mock = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let listen_port = free_listen_port();
    let home = write_test_config(mock.port, listen_port)?;
    let workdir = TempDir::new()?;
    let stderr_path = workdir.path().join("daemon.stderr.log");

    let mut child = spawn_daemon(&home, true, &stderr_path)?;
    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{listen_port}").parse()?;

    // The daemon must stay alive (root bypass worked) and serve the listener.
    let listener_result = wait_for_listener(listen_addr).await;
    if let Err(err) = listener_result {
        let _ = child.kill();
        panic!(
            "daemon failed to serve listener: {err:#}\n--- stderr ---\n{}",
            read_stderr(&stderr_path)
        );
    }

    // Client -> daemon listener -> mock tunnel -> back. Byte-exact relay.
    let mut client = TcpStream::connect(listen_addr).await?;
    client.write_all(PAYLOAD).await?;
    client.flush().await?;
    let mut echoed = vec![0u8; PAYLOAD.len()];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut echoed))
        .await
        .context("tunnel echo timed out")??;

    // Clean shutdown regardless of assertion outcome below.
    let shutdown = graceful_shutdown(&mut child);

    assert_eq!(
        echoed, PAYLOAD,
        "client bytes must survive the daemon->mock round trip byte-exact"
    );
    let saw_connect = mock.get_requests().iter().any(|r| {
        r.request_line
            .starts_with(&format!("CONNECT {ORIGINAL_DST}"))
    });
    assert!(
        saw_connect,
        "mock proxy must observe CONNECT {}: got {:?}",
        ORIGINAL_DST,
        mock.get_requests()
            .iter()
            .map(|r| r.request_line.clone())
            .collect::<Vec<_>>()
    );
    shutdown?;

    Ok(())
}

/// PLANTED NEGATIVE CONTROL: identical setup WITHOUT RUST_PROXY_TEST_MODE.
/// The gate must gate: the production path requires root, so the daemon exits
/// nonzero immediately with a root-related error on stderr.
#[tokio::test]
async fn without_test_mode_daemon_refuses_non_root() -> Result<()> {
    require_non_root();

    let mock = MockProxy::new(0, MockBehavior::Healthy { latency_ms: 0 }).await?;
    let listen_port = free_listen_port();
    let home = write_test_config(mock.port, listen_port)?;
    let workdir = TempDir::new()?;
    let stderr_path = workdir.path().join("daemon.stderr.log");

    let mut child = spawn_daemon(&home, false, &stderr_path)?;

    // Must exit promptly as non-root; no lingering process, no listener.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    panic!(
                        "daemon without RUST_PROXY_TEST_MODE kept running as non-root \
                         (root bypass leaked)\n--- stderr ---\n{}",
                        read_stderr(&stderr_path)
                    );
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };

    let stderr = read_stderr(&stderr_path);
    assert!(
        !status.success(),
        "non-root daemon must exit nonzero without test mode"
    );
    assert!(
        stderr.contains("root"),
        "stderr must mention the root requirement, got: {stderr}"
    );

    Ok(())
}

/// SIGTERM the daemon and require it to exit within a bounded window.
fn graceful_shutdown(child: &mut Child) -> Result<std::process::ExitStatus> {
    let pid = child.id().to_string();
    std::process::Command::new("kill")
        .args(["-TERM", &pid])
        .output()
        .context("send SIGTERM to daemon")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    anyhow::bail!("daemon did not shut down within 5s of SIGTERM");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

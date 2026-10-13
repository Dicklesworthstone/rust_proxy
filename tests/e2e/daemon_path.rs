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
        // ubs:ignore[rust.ownership.panic-macro] — deliberately fails the test when its negative privilege control would be invalid.
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
         ipset_name = \"test_seam_ipset\"\n\
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
        // ubs:ignore[rust.ownership.panic-macro] — fails the traffic test when daemon startup did not succeed.
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
                    // ubs:ignore[rust.ownership.panic-macro] — fails the planted negative when the production root gate leaks.
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
    shutdown_with_signal(child, "-TERM")
}

fn shutdown_with_signal(child: &mut Child, signal: &str) -> Result<std::process::ExitStatus> {
    let pid = child.id().to_string();
    let sent = std::process::Command::new("kill")
        .args([signal, &pid])
        .output()
        .context("send stop signal to daemon")?;
    anyhow::ensure!(sent.status.success(), "stop signal failed: {:?}", sent);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                anyhow::ensure!(status.success(), "daemon stop must exit normally: {status}");
                return Ok(status);
            }
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

/// A HUP must reload and return to supervision, including while a tunnel is
/// open. Require three distinct acknowledgements and new byte-exact tunnels.
#[tokio::test]
async fn repeated_sighup_keeps_process_and_tunnels_alive() -> Result<()> {
    require_non_root();
    let mock = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let listen_port = free_listen_port();
    let home = write_test_config(mock.port, listen_port)?;
    let logs = TempDir::new()?;
    let stderr_path = logs.path().join("daemon.stderr.log");
    let mut child = spawn_daemon(&home, true, &stderr_path)?;
    let addr = format!("127.0.0.1:{listen_port}").parse()?;
    let exercise = async {
        wait_for_listener(addr).await?;
        let mut retained = TcpStream::connect(addr).await?;
        for generation in 1..=3 {
            let sent = Command::new("kill")
                .args(["-HUP", &child.id().to_string()])
                .output()?;
            anyhow::ensure!(sent.status.success(), "SIGHUP delivery failed");
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            while read_stderr(&stderr_path)
                .matches("Configuration hot-reloaded")
                .count()
                < generation
            {
                anyhow::ensure!(
                    tokio::time::Instant::now() < deadline,
                    "reload not acknowledged: {}",
                    read_stderr(&stderr_path)
                );
                anyhow::ensure!(child.try_wait()?.is_none(), "SIGHUP terminated daemon");
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            for client in [&mut retained, &mut TcpStream::connect(addr).await?] {
                client.write_all(PAYLOAD).await?;
                let mut echoed = vec![0; PAYLOAD.len()];
                tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut echoed))
                    .await??;
                assert_eq!(echoed, PAYLOAD);
            }
            anyhow::ensure!(child.try_wait()?.is_none(), "daemon stopped after reload");
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let stopped = graceful_shutdown(&mut child);
    exercise?;
    stopped?;
    assert!(read_stderr(&stderr_path).contains("test mode: skipping iptables cleanup"));
    Ok(())
}

#[tokio::test]
async fn sigint_and_sigterm_drain_an_open_tunnel_and_exit_normally() -> Result<()> {
    require_non_root();
    for signal in ["-INT", "-TERM"] {
        let mock = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
        let listen_port = free_listen_port();
        let home = write_test_config(mock.port, listen_port)?;
        let logs = TempDir::new()?;
        let stderr_path = logs.path().join("daemon.stderr.log");
        let mut child = spawn_daemon(&home, true, &stderr_path)?;
        let addr = format!("127.0.0.1:{listen_port}").parse()?;
        if let Err(err) = wait_for_listener(addr).await {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err.context(read_stderr(&stderr_path)));
        }
        let mut client = TcpStream::connect(addr).await?;
        client.write_all(PAYLOAD).await?;
        let mut echoed = vec![0; PAYLOAD.len()];
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut echoed)).await??;
        assert_eq!(echoed, PAYLOAD);
        shutdown_with_signal(&mut child, signal)?;
        let stderr = read_stderr(&stderr_path);
        assert!(
            stderr.contains("test mode: skipping iptables cleanup"),
            "{stderr}"
        );
        assert!(
            stderr.contains("Tunnel drain budget expired"),
            "open tunnel must be bounded: {stderr}"
        );
        assert!(
            TcpStream::connect(addr).await.is_err(),
            "listener survived shutdown"
        );
    }
    Ok(())
}

#[tokio::test]
async fn occupied_listener_and_invalid_config_fail_startup() -> Result<()> {
    require_non_root();
    let mock = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = occupied.local_addr()?.port();
    for invalid in [false, true] {
        let home = write_test_config(mock.port, port)?;
        if invalid {
            let path = home._temp.path().join(".config/rust_proxy/config.toml");
            let config = std::fs::read_to_string(&path)?.replace(
                "health_check_enabled = false",
                "health_check_enabled = true\nhealth_check_interval_secs = 0",
            );
            std::fs::write(path, config)?;
        }
        let logs = TempDir::new()?;
        let stderr_path = logs.path().join("daemon.stderr.log");
        let mut child = spawn_daemon(&home, true, &stderr_path)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("startup failure did not terminate daemon");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert!(!status.success());
        let expected = if invalid {
            "Invalid daemon configuration"
        } else {
            "Failed to bind"
        };
        assert!(
            read_stderr(&stderr_path).contains(expected),
            "{}",
            read_stderr(&stderr_path)
        );
        assert!(mock.get_requests().is_empty());
    }
    Ok(())
}

/// Exercise the production upstream-resolution guard through the rootless
/// startup path. This checks resolver refusal, not firewall installation.
#[tokio::test]
async fn unresolved_upstream_refuses_startup_without_opening_listener() -> Result<()> {
    require_non_root();
    let mock = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let port = free_listen_port();
    let home = write_test_config(mock.port, port)?;
    let path = home._temp.path().join(".config/rust_proxy/config.toml");
    let config = std::fs::read_to_string(&path)?.replace(
        &format!("http://127.0.0.1:{}", mock.port),
        &format!("http://unresolvable-upstream.invalid:{}", mock.port),
    );
    std::fs::write(path, config)?;
    let logs = TempDir::new()?;
    let stderr_path = logs.path().join("daemon.stderr.log");
    let mut child = spawn_daemon(&home, true, &stderr_path)?;
    // Native lookup: two five-second attempts plus 100ms backoff, then the
    // three-second blocking-pool shutdown limit. No upstream server deadline
    // can satisfy this assertion on the daemon's own startup guard.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("unresolved upstream did not terminate startup");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert!(!status.success());
    let stderr = read_stderr(&stderr_path);
    assert!(stderr.contains("Refusing to start"), "{stderr}");
    assert!(
        stderr.contains("Fix name resolution, then retry"),
        "{stderr}"
    );
    assert!(mock.get_requests().is_empty());
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    Ok(())
}

/// Saturate the actual daemon's establishment slots with peers that never
/// reply. The daemon's deadline, not a server deadline, must release capacity.
/// The original destination still uses the documented rootless seam.
#[tokio::test]
async fn establishment_admission_recovers_after_silent_peer_timeouts() -> Result<()> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::task::JoinSet;
    require_non_root();
    const ADMISSION_LIMIT: usize = 256;
    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_port = upstream.local_addr()?.port();
    let requests = Arc::new(AtomicUsize::new(0));
    let echo_enabled = Arc::new(AtomicBool::new(false));
    let counted = requests.clone();
    let echo = echo_enabled.clone();
    let server: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
        let mut clients = JoinSet::new();
        loop {
            tokio::select! {
                accepted = upstream.accept() => {
                    let (mut socket, _) = accepted?;
                    let counted = counted.clone();
                    let echo = echo.clone();
                    clients.spawn(async move {
                        let mut head = Vec::new();
                        let mut bytes = [0; 4096];
                        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                            let n = socket.read(&mut bytes).await?;
                            anyhow::ensure!(n > 0 && head.len() + n <= 16 * 1024, "invalid CONNECT request");
                            head.extend_from_slice(&bytes[..n]);
                        }
                        anyhow::ensure!(head.starts_with(format!("CONNECT {ORIGINAL_DST} ").as_bytes()), "wrong destination");
                        let echo_this_connection = echo.load(Ordering::SeqCst);
                        counted.fetch_add(1, Ordering::SeqCst);
                        if echo_this_connection {
                            socket.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nEARLY42").await?;
                        }
                        loop {
                            let n = socket.read(&mut bytes).await?;
                            if n == 0 { break; }
                            if echo_this_connection { socket.write_all(&bytes[..n]).await?; }
                        }
                        Ok::<(), anyhow::Error>(())
                    });
                }
                result = clients.join_next(), if !clients.is_empty() => {
                    result.context("missing server task")???;
                }
            }
        }
    });
    let port = free_listen_port();
    let home = write_test_config(upstream_port, port)?;
    let logs = TempDir::new()?;
    let stderr_path = logs.path().join("daemon.stderr.log");
    let mut child = spawn_daemon(&home, true, &stderr_path)?;
    let addr = format!("127.0.0.1:{port}").parse()?;
    let exercise = async {
        wait_for_listener(addr).await?;
        let mut clients = Vec::new();
        // The readiness connection occupies one silent establishment slot.
        for _ in 1..ADMISSION_LIMIT {
            clients.push(TcpStream::connect(addr).await?);
        }
        let filled_by = tokio::time::Instant::now() + Duration::from_secs(5);
        while requests.load(Ordering::SeqCst) < ADMISSION_LIMIT {
            anyhow::ensure!(
                tokio::time::Instant::now() < filled_by,
                "admission slots did not fill: {}",
                read_stderr(&stderr_path)
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(requests.load(Ordering::SeqCst), ADMISSION_LIMIT);
        echo_enabled.store(true, Ordering::SeqCst);
        let mut queued = TcpStream::connect(addr).await?;
        queued.write_all(PAYLOAD).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            requests.load(Ordering::SeqCst),
            ADMISSION_LIMIT,
            "outstanding establishment work exceeded the admission cap"
        );
        let expected = [b"EARLY42".as_slice(), PAYLOAD].concat();
        let mut echoed = vec![0; expected.len()];
        tokio::time::timeout(Duration::from_secs(12), queued.read_exact(&mut echoed)).await??;
        assert_eq!(
            echoed, expected,
            "timeout must release slots and preserve early bytes before the client payload"
        );
        assert!(requests.load(Ordering::SeqCst) > ADMISSION_LIMIT);
        assert!(read_stderr(&stderr_path).contains("CONNECT establishment timed out"));
        // Establishment deadlines must not become an idle timeout on an
        // established tunnel. Exercise it again after a full ten-second budget.
        tokio::time::sleep(Duration::from_secs(11)).await;
        queued.write_all(PAYLOAD).await?;
        let mut later = vec![0; PAYLOAD.len()];
        tokio::time::timeout(Duration::from_secs(3), queued.read_exact(&mut later)).await??;
        assert_eq!(
            later, PAYLOAD,
            "established tunnel was expired by the handshake budget"
        );
        drop(clients);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let stopped = graceful_shutdown(&mut child);
    server.abort();
    let _ = server.await;
    exercise?;
    stopped?;
    Ok(())
}

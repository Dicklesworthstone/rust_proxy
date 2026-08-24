//! Activation-routing and health-failure-failover E2E proofs.
//!
//! Drives the real binary through the runtime-gated rootless seam:
//! - `RUST_PROXY_TEST_MODE=1` skips root/firewall/background-refresh/ping.
//! - `RUST_PROXY_TEST_ORIGINAL_DST=host:port` stands in for SO_ORIGINAL_DST.
//!
//! T1 POSITIVE (`activation_routes_traffic`): strategy=single with TWO proxies
//! (alpha priority 50, beta priority 100), health checks disabled so
//! `active_proxy` is the ONLY steering force. Every proxied connection must go
//! to the activated proxy (beta), not the min-priority proxy (alpha).
//!
//! T1 PLANTED NEGATIVE (`activation_tracking_negative_alpha_companion`):
//! identical config but `active_proxy = "alpha"` routes everything to alpha.
//! Pre-seam code ignored `activate` and always routed min-priority (alpha), so
//! it PASSES this companion but FAILS the beta positive above; together they
//! prove routing tracks activation rather than an array-order/priority accident.
//!
//! T2 (`health_failure_excludes_and_failovers`): the active proxy fails its
//! CONNECT behavior (and therefore its health probes) from startup; after
//! `consecutive_failures_threshold` failed probes the daemon must exclude it,
//! fail over to the healthy secondary, and serve successful tunnels through it
//! while staying alive throughout.
//!
//! NO-CLAIM: these tests prove daemon-path routing/failover behavior through
//! the test seam only. They make NO claim about ipset/iptables rule placement,
//! resolver behavior, or exact failover-tick timing — only eventuality and
//! ordering (some traffic reaches the failing proxy before exclusion; the
//! surviving proxy serves successful tunnels afterwards).

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common::mock_proxy::{MockBehavior, MockError, MockProxy};

/// Distinctive payload relayed through the daemon under test.
const PAYLOAD: &[u8] = b"rust-proxy-routing-failover-e2e-payload/9876543210";

/// The injected original destination carried through the upstream CONNECT.
const ORIGINAL_DST: &str = "seam-routing-test.invalid:443";

/// Request-line prefix of a CLIENT-driven CONNECT (as opposed to a health
/// probe CONNECT, which targets [`PROBE_TARGET`]).
const CLIENT_CONNECT_PREFIX: &str = "CONNECT seam-routing-test.invalid:443";

/// Health-check target used by the T2 config. Its CONNECT request lines are
/// visually distinct from client CONNECTs, letting assertions discriminate
/// probe pollution from real tunneled traffic in the mock request log.
const PROBE_TARGET: &str = "probe-target.invalid:80";

/// Number of sequential client connections driven by the T1 cases.
const T1_CONNECTIONS: usize = 4;

/// Minimum successful tunnels required from the surviving proxy in T2.
const T2_MIN_TUNNELS: usize = 3;

/// Minimum total client connections driven in the T2 bounded window.
const T2_MIN_ATTEMPTS: usize = 5;

/// Hard upper bound on the T2 drive window.
const T2_WINDOW: Duration = Duration::from_secs(8);

/// These tests exercise the non-root gate itself; running them as root would
/// make the seam meaningless (and would touch real firewall state). Fail
/// loudly instead of silently skipping.
fn require_non_root() {
    if unsafe { libc::geteuid() } == 0 {
        panic!("routing/failover seam tests must run as a non-root user");
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

/// Persist a config.toml into an isolated HOME.
fn write_config(config: String) -> Result<TestHome> {
    let temp = TempDir::new().context("create temp HOME")?;
    let config_dir = temp.path().join(".config").join("rust_proxy");
    std::fs::create_dir_all(&config_dir)?;
    std::fs::write(config_dir.join("config.toml"), config)?;
    Ok(TestHome { _temp: temp })
}

/// Two-proxy config for the T1 activation cases: health checks fully
/// disabled so `active_proxy` is the only steering force.
fn activation_config(
    active_id: &str,
    alpha_port: u16,
    beta_port: u16,
    listen_port: u16,
) -> Result<TestHome> {
    let config = format!(
        "active_proxy = \"{active_id}\"\n\
         targets = [\"seam-routing-test.invalid\"]\n\
         \n\
         [[proxies]]\n\
         id = \"alpha\"\n\
         url = \"http://127.0.0.1:{alpha_port}\"\n\
         priority = 50\n\
         \n\
         [[proxies]]\n\
         id = \"beta\"\n\
         url = \"http://127.0.0.1:{beta_port}\"\n\
         priority = 100\n\
         \n\
         [settings]\n\
         listen_port = {listen_port}\n\
         load_balance_strategy = \"single\"\n\
         dns_refresh_secs = 3600\n\
         ping_interval_secs = 3600\n\
         ping_timeout_ms = 1000\n\
         ipset_name = \"test-routing-ipset\"\n\
         chain_name = \"TEST_ROUTING_CHAIN\"\n\
         include_aws_ip_ranges = false\n\
         include_cloudflare_ip_ranges = false\n\
         include_google_ip_ranges = false\n\
         metrics_enabled = false\n\
         health_check_enabled = false\n",
    );
    write_config(config)
}

/// Two-proxy config for T2: the activated `primary` fails from startup, the
/// healthy `secondary` must take over once health checks exclude the primary.
///
/// `connect_max_retries = 0` keeps per-connection failures fast so the whole
/// scenario stays inside the 8s bounded window. The probe target host differs
/// from the client ORIGINAL_DST so probe CONNECTs are distinguishable in the
/// mock request logs.
fn failover_config(primary_port: u16, secondary_port: u16, listen_port: u16) -> Result<TestHome> {
    let config = format!(
        "active_proxy = \"primary\"\n\
         targets = [\"seam-routing-test.invalid\"]\n\
         \n\
         [[proxies]]\n\
         id = \"primary\"\n\
         url = \"http://127.0.0.1:{primary_port}\"\n\
         priority = 50\n\
         \n\
         [[proxies]]\n\
         id = \"secondary\"\n\
         url = \"http://127.0.0.1:{secondary_port}\"\n\
         priority = 100\n\
         \n\
         [settings]\n\
         listen_port = {listen_port}\n\
         load_balance_strategy = \"single\"\n\
         dns_refresh_secs = 3600\n\
         ping_interval_secs = 3600\n\
         ping_timeout_ms = 1000\n\
         ipset_name = \"test-failover-ipset\"\n\
         chain_name = \"TEST_FAILOVER_CHAIN\"\n\
         include_aws_ip_ranges = false\n\
         include_cloudflare_ip_ranges = false\n\
         include_google_ip_ranges = false\n\
         metrics_enabled = false\n\
         health_check_enabled = true\n\
         health_check_interval_secs = 1\n\
         health_check_timeout_ms = 2000\n\
         consecutive_failures_threshold = 2\n\
         auto_failover = true\n\
         auto_failback = false\n\
         health_check_target = \"CONNECT {probe_target}\"\n\
         connect_max_retries = 0\n",
        probe_target = PROBE_TARGET,
    );
    write_config(config)
}

/// Spawn the real binary as `daemon` under the runtime test seam.
fn spawn_daemon(home: &TestHome, stderr_file: &Path) -> Result<Child> {
    let stderr = std::fs::File::create(stderr_file)?;
    Command::new(proxy_binary())
        .args(["daemon"])
        .env("HOME", home._temp.path())
        .env("XDG_CONFIG_HOME", home._temp.path().join(".config"))
        .env("XDG_STATE_HOME", home._temp.path().join(".state"))
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

/// Wait until the daemon's transparent-proxy listener accepts connections.
async fn wait_for_listener(addr: SocketAddr) -> Result<()> {
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

/// Drive one client connection through the daemon: connect, send the payload,
/// and require the byte-exact echo back. Returns false when the attempt fails
/// or exceeds `budget` (e.g. routed to the failing proxy pre-failover).
async fn drive_tunnel(addr: SocketAddr, budget: Duration) -> Result<bool> {
    let io = async {
        let mut client = TcpStream::connect(addr).await?;
        client.write_all(PAYLOAD).await?;
        client.flush().await?;
        let mut echoed = vec![0u8; PAYLOAD.len()];
        client.read_exact(&mut echoed).await?;
        Ok::<bool, std::io::Error>(echoed == PAYLOAD)
    };
    match tokio::time::timeout(budget, io).await {
        Ok(res) => Ok(res.context("tunnel io error")?),
        Err(_elapsed) => Ok(false),
    }
}

/// Count logged requests whose request line starts with the client CONNECT
/// prefix (excludes health-probe CONNECTs, which target PROBE_TARGET).
fn client_connect_count(mock: &MockProxy) -> usize {
    mock.get_requests()
        .iter()
        .filter(|r| r.request_line.starts_with(CLIENT_CONNECT_PREFIX))
        .count()
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

/// Outcome of a T1 activation case.
struct ActivationOutcome {
    /// Connections whose payload came back byte-exact.
    echoed_ok: usize,
    /// Client CONNECTs observed by the min-priority mock (alpha).
    connects_alpha: usize,
    /// Client CONNECTs observed by the high-priority mock (beta).
    connects_beta: usize,
}

/// Run one T1 case end-to-end: boot the daemon with `active_id` activated,
/// drive sequential client connections, and collect routing evidence.
///
/// With health checks disabled both proxies stay Healthy/Unknown forever, so
/// Single-strategy selection is steered exclusively by the activated proxy
/// (RuntimeState.effective_proxy -> select_single preference).
async fn drive_activation_case(active_id: &str) -> Result<ActivationOutcome> {
    let mock_alpha = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let mock_beta = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let listen_port = free_listen_port();
    let home = activation_config(active_id, mock_alpha.port, mock_beta.port, listen_port)?;
    let workdir = TempDir::new()?;
    let stderr_path = workdir.path().join("daemon.stderr.log");

    let mut child = spawn_daemon(&home, &stderr_path)?;
    let listen_addr: SocketAddr = format!("127.0.0.1:{listen_port}").parse()?;
    let listener_result = wait_for_listener(listen_addr).await;
    if let Err(err) = listener_result {
        let _ = child.kill();
        panic!(
            "daemon failed to serve listener: {err:#}\n--- stderr ---\n{}",
            read_stderr(&stderr_path)
        );
    }

    let mut outcome = ActivationOutcome {
        echoed_ok: 0,
        connects_alpha: 0,
        connects_beta: 0,
    };
    for i in 0..T1_CONNECTIONS {
        let ok = drive_tunnel(listen_addr, Duration::from_secs(5)).await?;
        assert!(
            ok,
            "connection {} of {} must relay byte-exact through the activated proxy",
            i + 1,
            T1_CONNECTIONS
        );
        outcome.echoed_ok += 1;
        assert!(
            child.try_wait()?.is_none(),
            "daemon exited mid-run\n--- stderr ---\n{}",
            read_stderr(&stderr_path)
        );
    }

    let shutdown = graceful_shutdown(&mut child);
    outcome.connects_alpha = client_connect_count(&mock_alpha);
    outcome.connects_beta = client_connect_count(&mock_beta);
    shutdown?;

    Ok(outcome)
}

/// T1 POSITIVE: `active_proxy = "beta"` (priority 100) must route EVERY
/// proxied connection to beta; the min-priority alpha (priority 50) sees zero
/// proxied connects. Pre-seam code ignored activation and always picked the
/// min-priority proxy (alpha), so it fails exactly here.
#[tokio::test]
async fn activation_routes_traffic() -> Result<()> {
    require_non_root();

    let outcome = drive_activation_case("beta").await?;
    assert_eq!(
        outcome.echoed_ok, T1_CONNECTIONS,
        "all {} connections must succeed through the activated proxy",
        T1_CONNECTIONS
    );
    assert!(
        outcome.connects_beta >= T1_CONNECTIONS,
        "activated proxy beta must observe a CONNECT for every driven connection; \
             got alpha={} beta={} (the listener-readiness probe connection is itself \
             routed by the seam, so the activated mock may legitimately log one extra)",
        outcome.connects_alpha,
        outcome.connects_beta
    );
    assert_eq!(
        outcome.connects_alpha, 0,
        "min-priority alpha must NOT receive any proxied connects when beta is activated \
             (activation, not priority order, must steer routing)"
    );

    Ok(())
}

/// T1 PLANTED NEGATIVE companion: identical config but `active_proxy =
/// "alpha"`. Rationale: pre-change code routed min-priority unconditionally,
/// so it passes this case while failing the beta positive above. Requiring
/// BOTH directions proves the daemon tracks activation state rather than
/// winning by array-order/priority accident.
#[tokio::test]
async fn activation_tracking_negative_alpha_companion() -> Result<()> {
    require_non_root();

    let outcome = drive_activation_case("alpha").await?;
    assert_eq!(
        outcome.echoed_ok, T1_CONNECTIONS,
        "all {} connections must succeed through the activated proxy",
        T1_CONNECTIONS
    );
    assert!(
        outcome.connects_alpha >= T1_CONNECTIONS,
        "activated proxy alpha must observe a CONNECT for every driven connection; \
             got alpha={} beta={} (the listener-readiness probe connection may add one)",
        outcome.connects_alpha,
        outcome.connects_beta
    );
    assert_eq!(
        outcome.connects_beta, 0,
        "non-activated beta must NOT receive any proxied connects when alpha is activated"
    );

    Ok(())
}

/// T2: the activated primary fails CONNECTs (and therefore health probes)
/// from startup. Within the bounded window the daemon must:
///   1. still route some client attempts to the primary BEFORE exclusion
///      (proves pre-failover steering followed active_proxy), then
///   2. exclude the primary after `consecutive_failures_threshold` failed
///      probes, fail over, and serve successful tunnels through the secondary
///      (`>= T2_MIN_TUNNELS` byte-exact), while
///   3. staying alive throughout.
///
/// NO-CLAIM on exact failover-tick timing: only eventuality/ordering is
/// asserted, inside the hard 8s window.
///
/// Probe-pollution discrimination: health probes CONNECT to
/// `probe-target.invalid:80` while client tunnels CONNECT to
/// `seam-routing-test.invalid:443`; assertions count only request lines with
/// the client prefix, so probe traffic never inflates routing evidence.
/// Additionally, a probe connection can never produce a counted tunnel: only
/// client attempts carry the payload whose byte-exact echo is required.
#[tokio::test]
async fn health_failure_excludes_and_failovers() -> Result<()> {
    require_non_root();

    // Primary fails every request from the start. MockError::Timeout makes the
    // mock hold each failed exchange open, which stretches the daemon's health
    // rounds to health_check_timeout_ms each and guarantees a deterministic
    // pre-exclusion window (two failed rounds needed at threshold 2) during
    // which client attempts reach the primary.
    let primary = MockProxy::new(
        0,
        MockBehavior::Failing {
            error: MockError::Timeout,
        },
    )
    .await?;
    let secondary = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let listen_port = free_listen_port();
    let home = failover_config(primary.port, secondary.port, listen_port)?;
    let workdir = TempDir::new()?;
    let stderr_path = workdir.path().join("daemon.stderr.log");
    let mut child = spawn_daemon(&home, &stderr_path)?;
    let listen_addr: SocketAddr = format!("127.0.0.1:{listen_port}").parse()?;
    let listener_result = wait_for_listener(listen_addr).await;
    if let Err(err) = listener_result {
        let _ = child.kill();
        panic!(
            "daemon failed to serve listener: {err:#}\n--- stderr ---\n{}",
            read_stderr(&stderr_path)
        );
    }

    // Bounded adaptive drive: early attempts may land on the not-yet-excluded
    // primary and fail (counted as attempts); once the health loop excludes
    // the primary and fails over, attempts must start succeeding byte-exact
    // through the secondary.
    let started = std::time::Instant::now();
    let mut attempts = 0usize;
    let mut successes = 0usize;
    while attempts < T2_MIN_ATTEMPTS
        || (successes < T2_MIN_TUNNELS && started.elapsed() < T2_WINDOW)
    {
        if started.elapsed() >= T2_WINDOW {
            break;
        }
        attempts += 1;
        if drive_tunnel(listen_addr, Duration::from_millis(1200)).await? {
            successes += 1;
        }
        assert!(
            child.try_wait()?.is_none(),
            "daemon exited during failover window\n--- stderr ---\n{}",
            read_stderr(&stderr_path)
        );
    }

    let stderr = read_stderr(&stderr_path);
    let shutdown_result = graceful_shutdown(&mut child);

    assert!(
        attempts >= T2_MIN_ATTEMPTS,
        "must drive at least {} client connections within the bounded window; drove {}",
        T2_MIN_ATTEMPTS,
        attempts
    );
    assert!(
        successes >= T2_MIN_TUNNELS,
        "secondary must serve at least {} successful tunnels within {:?}; got {} \
             after {} attempts\n--- stderr ---\n{}",
        T2_MIN_TUNNELS,
        T2_WINDOW,
        successes,
        attempts,
        stderr
    );
    shutdown_result?;

    // Routing evidence, probe-pollution-free (client-prefix filtered).
    let primary_client_connects = client_connect_count(&primary);
    let secondary_client_connects = client_connect_count(&secondary);
    assert!(
        primary_client_connects >= 1,
        "the failing primary (initially active) must have received at least one client \
             CONNECT attempt before exclusion; client-target CONNECTs observed: {}",
        primary_client_connects
    );
    assert!(
        secondary_client_connects >= successes,
        "every successful tunnel must correspond to a client CONNECT at the secondary; \
             secondary client CONNECTs={}, successful tunnels={}",
        secondary_client_connects,
        successes
    );
    assert!(
        secondary_client_connects >= T2_MIN_TUNNELS,
        "secondary must observe at least {} client CONNECTs; got {}",
        T2_MIN_TUNNELS,
        secondary_client_connects
    );

    Ok(())
}

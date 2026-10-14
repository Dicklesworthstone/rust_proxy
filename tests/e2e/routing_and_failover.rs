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
use std::time::{Duration, Instant};
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
        // ubs:ignore[rust.ownership.panic-macro] — deliberately fails when the rootless test's privilege control would be invalid.
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
         ipset_name = \"test_routing_ipset\"\n\
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
         ipset_name = \"test_failover_ipset\"\n\
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
    spawn_daemon_with_env(home, stderr_file, &[])
}

fn spawn_daemon_with_env(
    home: &TestHome,
    stderr_file: &Path,
    variables: &[(&str, &str)],
) -> Result<Child> {
    let stderr = std::fs::File::create(stderr_file)?;
    Command::new(proxy_binary())
        .args(["daemon"])
        .env("HOME", home._temp.path())
        .env("XDG_CONFIG_HOME", home._temp.path().join(".config"))
        .env("XDG_STATE_HOME", home._temp.path().join(".state"))
        .env("RUST_LOG", "debug")
        .env("RUST_PROXY_TEST_MODE", "1")
        .env("RUST_PROXY_TEST_ORIGINAL_DST", ORIGINAL_DST)
        .envs(variables.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .context("spawn rust_proxy daemon")
}

struct ManagedDaemon(Child);

impl Drop for ManagedDaemon {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

const RUNTIME_SECRETS: &[&str] = &[
    "runtime-user-secret",
    "runtime-password-secret",
    "global-health-path-secret",
    "global-health-query-secret",
    "proxy-health-path-secret",
    "proxy-health-query-secret",
];

fn runtime_config_path(home: &TestHome) -> PathBuf {
    home._temp.path().join(".config/rust_proxy/config.toml")
}

fn runtime_snapshot_path(home: &TestHome) -> PathBuf {
    home._temp.path().join(".state/rust_proxy/runtime.json")
}

fn runtime_boot_nanos() -> Result<u64> {
    let mut clock = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock is writable; CLOCK_BOOTTIME is read without changing
    // process or system clocks. Only negative-fixture age is refreshed here.
    anyhow::ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut clock) } == 0,
        "read boot clock: {}",
        std::io::Error::last_os_error()
    );
    Ok(u64::try_from(clock.tv_sec)? * 1_000_000_000 + u64::try_from(clock.tv_nsec)?)
}

/// Keep the real daemon streams and fixtures for failed-gate diagnosis. These
/// observations use the rootless seam, never live kernel routing.
fn spawn_runtime_daemon(home: &TestHome) -> Result<ManagedDaemon> {
    let child = Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
        .arg("daemon")
        .env("HOME", home._temp.path())
        .env("XDG_CONFIG_HOME", home._temp.path().join(".config"))
        .env("XDG_STATE_HOME", home._temp.path().join(".state"))
        .env("RUST_PROXY_CONFIG", runtime_config_path(home))
        .env(
            "RUST_PROXY_STATE_DIR",
            home._temp.path().join(".state/rust_proxy"),
        )
        .env("RUST_PROXY_TEST_MODE", "1")
        .env("RUST_PROXY_TEST_ORIGINAL_DST", ORIGINAL_DST)
        .env("RUST_LOG", "debug")
        .stdout(std::fs::File::create(
            home._temp.path().join("runtime-daemon.stdout.log"),
        )?)
        .stderr(std::fs::File::create(
            home._temp.path().join("runtime-daemon.stderr.log"),
        )?)
        .spawn()
        .context("spawn observed rootless daemon")?;
    Ok(ManagedDaemon(child))
}

fn runtime_cli_raw(home: &TestHome, args: &[&str]) -> Result<std::process::Output> {
    let output = Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
        .args(args)
        .env("HOME", home._temp.path())
        .env("XDG_CONFIG_HOME", home._temp.path().join(".config"))
        .env("XDG_STATE_HOME", home._temp.path().join(".state"))
        .env("RUST_PROXY_CONFIG", runtime_config_path(home))
        .env(
            "RUST_PROXY_STATE_DIR",
            home._temp.path().join(".state/rust_proxy"),
        )
        .env_remove("RUST_PROXY_OUTPUT_FORMAT")
        .env_remove("TOON_DEFAULT_FORMAT")
        .output()?;
    eprintln!(
        "RUNTIME CLI {args:?}: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!bytes.contains(&0x1b), "machine CLI emitted an ANSI escape");
        for secret in RUNTIME_SECRETS {
            assert!(
                !String::from_utf8_lossy(bytes).contains(secret),
                "machine CLI emitted {secret}"
            );
        }
    }
    Ok(output)
}

fn runtime_cli(home: &TestHome, args: &[&str]) -> Result<serde_json::Value> {
    let output = runtime_cli_raw(home, args)?;
    assert_eq!(output.status.code(), Some(0), "{args:?}");
    // Both decoders receive every stdout byte: prose, prefixes and trailing
    // non-machine content cannot be trimmed away to manufacture a pass.
    if args.contains(&"toon") {
        Ok(toon_rust::try_decode(std::str::from_utf8(&output.stdout)?, None)?.into())
    } else {
        Ok(serde_json::from_slice(&output.stdout)?)
    }
}

async fn wait_runtime(
    home: &TestHome,
    daemon: &mut ManagedDaemon,
    predicate: impl Fn(&serde_json::Value) -> bool,
) -> Result<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        anyhow::ensure!(daemon.0.try_wait()?.is_none(), "observed daemon exited");
        let status = runtime_cli(home, &["status", "--json"])?;
        if predicate(&status) {
            return Ok(status);
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "runtime state never reached the requested observation: {status}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn runtime_signal(daemon: &ManagedDaemon, signal: &str) -> Result<()> {
    let output = Command::new("kill")
        .args([signal, &daemon.0.id().to_string()])
        .output()?;
    eprintln!(
        "runtime control {signal}: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    anyhow::ensure!(output.status.success(), "process control failed");
    Ok(())
}

async fn assert_runtime_tunnels(
    address: SocketAddr,
    selected: &MockProxy,
    excluded: &MockProxy,
) -> Result<()> {
    let before = (
        client_connect_count(selected),
        client_connect_count(excluded),
    );
    for _ in 0..3 {
        anyhow::ensure!(
            drive_tunnel(address, Duration::from_secs(3)).await?,
            "observed serving proxy did not echo the complete payload"
        );
    }
    assert_eq!(client_connect_count(selected), before.0 + 3);
    assert_eq!(client_connect_count(excluded), before.1);
    Ok(())
}

fn assert_runtime_not_ready(home: &TestHome, expected: &str) -> Result<()> {
    for args in [
        vec!["status", "--json"],
        vec!["status", "--format", "toon"],
        vec![
            "test",
            "seam-routing-test.invalid",
            "--no-dns",
            "--json",
            "--verbose",
        ],
        vec![
            "test",
            "seam-routing-test.invalid",
            "--no-dns",
            "--format",
            "toon",
            "--verbose",
        ],
    ] {
        let output = runtime_cli(home, &args)?;
        assert_eq!(output["daemon_running"], false);
        assert_eq!(output["daemon"]["status"], expected);
        if args[0] == "test" {
            assert_eq!(output["prediction_basis"], "configured_config_prediction");
            assert!(output["live_ipset_match"].is_null());
        } else {
            assert!(output["effective_proxy"].is_null());
            assert!(output["applied_proxy"].is_null());
        }
    }
    Ok(())
}

#[tokio::test]
async fn runtime_observation_failover_recovery_matches_byte_exact_recipients() -> Result<()> {
    use base64::Engine as _;
    require_non_root();
    let token = base64::engine::general_purpose::STANDARD
        .encode("runtime-user-secret:runtime-password-secret");
    let primary = MockProxy::new(
        0,
        MockBehavior::AuthenticatedTunnelEcho {
            token: token.clone(),
        },
    )
    .await?;
    let secondary = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let port = free_listen_port();
    let mut home = failover_config(primary.port, secondary.port, port)?;
    home._temp.disable_cleanup(true);
    eprintln!("runtime failover fixtures: {}", home._temp.path().display());
    let mut config: toml::Value =
        toml::from_str(&std::fs::read_to_string(runtime_config_path(&home))?)?;
    config["settings"]["auto_failback"] = true.into();
    config["settings"]
        .as_table_mut()
        .context("settings fixture")?
        .insert("failback_delay_secs".into(), 1.into());
    config["proxies"][0]["url"] = format!(
        "http://runtime-user-secret:runtime-password-secret@127.0.0.1:{}",
        primary.port
    )
    .into();
    std::fs::write(runtime_config_path(&home), toml::to_string(&config)?)?;
    let mut daemon = spawn_runtime_daemon(&home)?;
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let initial = wait_runtime(&home, &mut daemon, |status| {
        status["daemon_running"] == true && status["effective_proxy"] == "primary"
    })
    .await?;
    assert_eq!(initial["configured_proxy"], "primary");
    assert_eq!(initial["applied_proxy"], "primary");
    assert_eq!(
        initial["daemon"]["snapshot"]["identity"]["pid"],
        daemon.0.id()
    );
    assert_eq!(initial["daemon"]["snapshot"]["test_mode"], true);
    assert_eq!(initial["rules_active"], false);
    assert_runtime_tunnels(address, &primary, &secondary).await?;

    primary.set_behavior(MockBehavior::Failing {
        error: MockError::AuthRequired,
    });
    let failed_over = wait_runtime(&home, &mut daemon, |status| {
        status["daemon_running"] == true && status["effective_proxy"] == "secondary"
    })
    .await?;
    assert_eq!(failed_over["configured_proxy"], "primary");
    assert_eq!(failed_over["applied_proxy"], "primary");
    assert_eq!(failed_over["proxy_health_source"], "live_runtime");
    assert_eq!(
        failed_over["daemon"]["snapshot"]["runtime"]["original_proxy"],
        "primary"
    );
    assert_eq!(
        failed_over["daemon"]["snapshot"]["runtime"]["is_failed_over"],
        true
    );
    assert_runtime_tunnels(address, &secondary, &primary).await?;
    for args in [
        vec![
            "test",
            "seam-routing-test.invalid",
            "--no-dns",
            "--json",
            "--verbose",
        ],
        vec![
            "test",
            "seam-routing-test.invalid",
            "--no-dns",
            "--format",
            "toon",
            "--verbose",
        ],
    ] {
        let prediction = runtime_cli(&home, &args)?;
        assert_eq!(prediction["daemon_running"], true);
        assert_eq!(prediction["active_proxy"]["id"], "secondary");
        assert_eq!(prediction["applied_proxy"], "primary");
        assert_eq!(prediction["effective_proxy"], "secondary");
        assert_eq!(prediction["prediction_basis"], "applied_config_prediction");
        assert!(prediction["live_ipset_match"].is_null());
    }

    primary.set_behavior(MockBehavior::AuthenticatedTunnelEcho { token });
    let recovered = wait_runtime(&home, &mut daemon, |status| {
        status["daemon_running"] == true
            && status["effective_proxy"] == "primary"
            && status["daemon"]["snapshot"]["runtime"]["is_failed_over"] == false
    })
    .await?;
    assert_eq!(recovered["configured_proxy"], "primary");
    assert_eq!(recovered["applied_proxy"], "primary");
    assert_runtime_tunnels(address, &primary, &secondary).await?;
    let toon = runtime_cli(&home, &["status", "--format", "toon"])?;
    assert_eq!(toon["effective_proxy"], "primary");
    assert_eq!(toon["daemon_running"], true);
    assert!(graceful_shutdown(&mut daemon.0)?.success());
    Ok(())
}

#[tokio::test]
async fn runtime_observation_reloads_keep_applied_truth_and_machine_secrets_out() -> Result<()> {
    require_non_root();
    let alpha = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let beta = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let port = free_listen_port();
    let mut home = activation_config("beta", alpha.port, beta.port, port)?;
    home._temp.disable_cleanup(true);
    eprintln!("runtime reload fixtures: {}", home._temp.path().display());
    let config_path = runtime_config_path(&home);
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&config_path)?)?;
    config["proxies"][1]["url"] = format!(
        "http://runtime-user-secret:runtime-password-secret@127.0.0.1:{}",
        beta.port
    )
    .into();
    config["proxies"][1]
        .as_table_mut()
        .context("proxy fixture")?
        .insert(
            "health_check_url".into(),
            format!(
                "http://127.0.0.1:{}/proxy-health-path-secret?token=proxy-health-query-secret",
                beta.port
            )
            .into(),
        );
    config["settings"].as_table_mut().context("settings fixture")?.insert(
        "health_check_target".into(),
        format!("GET http://127.0.0.1:{}/global-health-path-secret?token=global-health-query-secret", beta.port).into(),
    );
    // Health is disabled: the echo upstream is a forwarding fixture, never
    // presented as a successful GET-health implementation.
    std::fs::write(&config_path, toml::to_string(&config)?)?;
    let mut daemon = spawn_runtime_daemon(&home)?;
    let initial = wait_runtime(&home, &mut daemon, |status| {
        status["daemon_running"] == true
    })
    .await?;
    let applied = initial["daemon"]["snapshot"]["applied"].clone();
    let generation = applied["config_generation"]
        .as_u64()
        .context("config generation")?;
    assert!(generation > 0);
    assert_eq!(initial["effective_proxy"], "beta");
    assert_runtime_tunnels(SocketAddr::from(([127, 0, 0, 1], port)), &beta, &alpha).await?;
    let snapshot = std::fs::read_to_string(runtime_snapshot_path(&home))?;
    for secret in RUNTIME_SECRETS {
        assert!(
            !snapshot.contains(secret),
            "persisted runtime snapshot leaked {secret}"
        );
    }

    std::fs::write(&config_path, "[[proxies]\n")?;
    let rejected = wait_runtime(&home, &mut daemon, |status| {
        status["daemon"]["snapshot"]["applied"]["last_reload_result"] == "rejected"
    })
    .await?;
    assert_eq!(rejected["daemon_running"], true);
    assert!(rejected["configured_proxy"].is_null());
    assert!(rejected["configured_config_error"]
        .as_str()
        .is_some_and(|error| error.contains("Failed parsing config")));
    assert_eq!(rejected["applied_proxy"], "beta");
    assert_eq!(rejected["effective_proxy"], "beta");
    assert_eq!(
        rejected["daemon"]["snapshot"]["applied"]["config_generation"],
        generation
    );
    assert_eq!(
        rejected["daemon"]["snapshot"]["applied"]["config"],
        applied["config"]
    );
    for args in [
        vec!["status", "--format", "toon"],
        vec![
            "test",
            "seam-routing-test.invalid",
            "--no-dns",
            "--json",
            "--verbose",
        ],
        vec![
            "test",
            "seam-routing-test.invalid",
            "--no-dns",
            "--format",
            "toon",
            "--verbose",
        ],
    ] {
        let output = runtime_cli(&home, &args)?;
        assert_eq!(output["daemon_running"], true);
        if args[0] == "test" {
            assert_eq!(output["prediction_basis"], "applied_config_prediction");
            assert_eq!(output["would_proxy"], true);
            assert!(output["live_ipset_match"].is_null());
            assert_eq!(output["resolved_ips"], serde_json::json!([]));
        }
    }
    let quiet = runtime_cli_raw(
        &home,
        &[
            "test",
            "seam-routing-test.invalid",
            "--no-dns",
            "--json",
            "--verbose",
            "--quiet",
        ],
    )?;
    assert_eq!(quiet.status.code(), Some(2));
    assert!(quiet.stdout.is_empty());
    assert!(String::from_utf8_lossy(&quiet.stderr).contains("unexpected argument '--quiet'"));
    assert_runtime_tunnels(SocketAddr::from(([127, 0, 0, 1], port)), &beta, &alpha).await?;

    let settings = config["settings"]
        .as_table_mut()
        .context("settings fixture")?;
    let restart_fields = [
        (
            "listen_port",
            toml::Value::Integer(i64::from(free_listen_port())),
        ),
        ("chain_name", "REQUESTED_RESTART_CHAIN".into()),
        ("ipset_name", "requested_restart_set".into()),
        ("metrics_bind", "127.0.0.2".into()),
        (
            "metrics_port",
            toml::Value::Integer(i64::from(free_listen_port())),
        ),
        ("metrics_path", "/requested-runtime-metrics".into()),
        ("metrics_enabled", true.into()),
    ];
    for (name, value) in &restart_fields {
        settings.insert((*name).into(), value.clone());
    }
    std::fs::write(&config_path, toml::to_string(&config)?)?;
    let reloaded = wait_runtime(&home, &mut daemon, |status| {
        status["daemon"]["snapshot"]["applied"]["last_reload_result"] == "applied"
            && status["daemon"]["snapshot"]["applied"]["pending_restart_fields"]
                .as_array()
                .is_some_and(|fields| fields.len() == 7)
    })
    .await?;
    let reloaded_applied = &reloaded["daemon"]["snapshot"]["applied"];
    assert!(
        reloaded_applied["config_generation"]
            .as_u64()
            .context("reloaded generation")?
            > generation
    );
    let pending = reloaded_applied["pending_restart_fields"]
        .as_array()
        .context("restart fields")?;
    assert_eq!(pending.len(), 7);
    let requested: toml::Value = toml::from_str(&std::fs::read_to_string(&config_path)?)?;
    for (field, value) in &restart_fields {
        assert!(pending
            .iter()
            .any(|pending| pending.as_str() == Some(*field)));
        assert_eq!(
            reloaded_applied["config"]["settings"][*field],
            applied["config"]["settings"][*field]
        );
        assert_eq!(requested["settings"][*field], *value);
    }
    assert_eq!(reloaded["applied_proxy"], "beta");
    assert_eq!(reloaded["effective_proxy"], "beta");
    assert_runtime_tunnels(SocketAddr::from(([127, 0, 0, 1], port)), &beta, &alpha).await?;
    assert!(graceful_shutdown(&mut daemon.0)?.success());
    Ok(())
}

#[tokio::test]
async fn runtime_observation_identity_freshness_and_unrelated_listener_controls() -> Result<()> {
    require_non_root();
    let alpha = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let beta = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let unrelated = std::net::TcpListener::bind("127.0.0.1:0")?;
    let mut absent = activation_config(
        "beta",
        alpha.port,
        beta.port,
        unrelated.local_addr()?.port(),
    )?;
    absent._temp.disable_cleanup(true);
    eprintln!(
        "runtime absent/unrelated fixtures: {}",
        absent._temp.path().display()
    );
    assert_runtime_not_ready(&absent, "absent")?;
    unrelated.set_nonblocking(true)?;
    assert_eq!(
        unrelated.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );

    let port = free_listen_port();
    let mut home = activation_config("beta", alpha.port, beta.port, port)?;
    home._temp.disable_cleanup(true);
    eprintln!("runtime identity fixtures: {}", home._temp.path().display());
    let mut daemon = spawn_runtime_daemon(&home)?;
    let initial = wait_runtime(&home, &mut daemon, |status| {
        status["daemon_running"] == true
    })
    .await?;
    assert_eq!(initial["daemon"]["status"], "ready");
    assert_runtime_tunnels(SocketAddr::from(([127, 0, 0, 1], port)), &beta, &alpha).await?;
    runtime_signal(&daemon, "-STOP")?;
    // Freeze the actual publisher before planting negatives; no racing
    // heartbeat can accidentally restore the positive fixture.
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(runtime_snapshot_path(&home))?)?;
    let mut reused = original.clone();
    reused["identity"]["start_ticks"] = (original["identity"]["start_ticks"]
        .as_u64()
        .context("start ticks")?
        + 1)
    .into();
    std::fs::write(runtime_snapshot_path(&home), serde_json::to_vec(&reused)?)?;
    assert_runtime_not_ready(&home, "dead")?;
    // This mismatched start-time is a PID-reuse surrogate negative, not a
    // claim that the kernel was forced to reuse a PID during this test.
    let mut foreign = original.clone();
    foreign["config_path"] = home
        ._temp
        .path()
        .join("other-config.toml")
        .to_string_lossy()
        .into_owned()
        .into();
    std::fs::write(runtime_snapshot_path(&home), serde_json::to_vec(&foreign)?)?;
    assert_runtime_not_ready(&home, "foreign")?;

    let sleeper = ManagedDaemon(Command::new("sleep").arg("30").spawn()?);
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", sleeper.0.id()))?;
    let start_ticks: u64 = stat
        .rsplit_once(')')
        .context("sleep stat delimiter")?
        .1
        .split_whitespace()
        .nth(19)
        .context("sleep start ticks")?
        .parse()?;
    let mut wrong_owner = original.clone();
    wrong_owner["identity"]["pid"] = sleeper.0.id().into();
    wrong_owner["identity"]["start_ticks"] = start_ticks.into();
    wrong_owner["captured_boot_nanos"] = runtime_boot_nanos()?.into();
    std::fs::write(
        runtime_snapshot_path(&home),
        serde_json::to_vec(&wrong_owner)?,
    )?;
    assert_runtime_not_ready(&home, "listener_missing")?;

    let mut stopped = original.clone();
    stopped["ready"] = false.into();
    stopped["captured_boot_nanos"] = runtime_boot_nanos()?.into();
    std::fs::write(runtime_snapshot_path(&home), serde_json::to_vec(&stopped)?)?;
    assert_runtime_not_ready(&home, "stopped")?;
    std::fs::write(runtime_snapshot_path(&home), b"{not-json")?;
    assert_runtime_not_ready(&home, "unavailable")?;

    let mut stale = original.clone();
    // A future wall clock must not make an actually stale boot-clock sample
    // fresh. Leave captured_boot_nanos untouched and wait across the real gate.
    stale["captured_at"] = "9999-12-31T23:59:59Z".into();
    std::fs::write(runtime_snapshot_path(&home), serde_json::to_vec(&stale)?)?;
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_runtime_not_ready(&home, "stale")?;
    let stale_status = runtime_cli(&home, &["status", "--json"])?;
    assert!(
        stale_status["daemon"]["age_ms"]
            .as_u64()
            .context("stale age")?
            >= 5000
    );
    runtime_signal(&daemon, "-CONT")?;
    let refreshed = wait_runtime(&home, &mut daemon, |status| {
        status["daemon_running"] == true
    })
    .await?;
    assert_eq!(refreshed["daemon"]["status"], "ready");
    assert_runtime_tunnels(SocketAddr::from(([127, 0, 0, 1], port)), &beta, &alpha).await?;
    runtime_signal(&daemon, "-KILL")?;
    let killed = daemon.0.wait()?;
    assert!(!killed.success());
    assert_runtime_not_ready(&home, "dead")?;
    Ok(())
}

#[tokio::test]
async fn authentication_sources_establish_real_byte_exact_daemon_tunnels() -> Result<()> {
    use base64::Engine as _;
    require_non_root();
    for source in ["url", "config", "env", "mixed"] {
        let expected = match source {
            "url" => "url-user:url+pass",
            "config" => "config-user:config-pass",
            "env" => "env-user:env-pass",
            _ => "env-user:config-pass",
        };
        let primary = MockProxy::new(
            0,
            MockBehavior::AuthenticatedTunnelEcho {
                token: base64::engine::general_purpose::STANDARD.encode(expected),
            },
        )
        .await?;
        let secondary = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
        let port = free_listen_port();
        let home = activation_config("alpha", primary.port, secondary.port, port)?;
        let path = home._temp.path().join(".config/rust_proxy/config.toml");
        let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
        let proxy = config["proxies"][0]
            .as_table_mut()
            .context("proxy fixture table")?;
        proxy.insert(
            "url".into(),
            format!("http://url-user:url%2Bpass@127.0.0.1:{}", primary.port).into(),
        );
        if source != "url" {
            let mut auth = toml::Table::new();
            auth.insert("username".into(), "config-user".into());
            auth.insert("password".into(), "config-pass".into());
            if source == "env" || source == "mixed" {
                auth.insert("username_env".into(), "RUST_PROXY_E2E_AUTH_USER".into());
            }
            if source == "env" {
                auth.insert("password_env".into(), "RUST_PROXY_E2E_AUTH_PASS".into());
            }
            proxy.insert("auth".into(), auth.into());
        }
        std::fs::write(path, toml::to_string(&config)?)?;
        let stderr = home._temp.path().join("daemon.stderr");
        let mut daemon = ManagedDaemon(spawn_daemon_with_env(
            &home,
            &stderr,
            &[
                ("RUST_PROXY_E2E_AUTH_USER", "env-user"),
                ("RUST_PROXY_E2E_AUTH_PASS", "env-pass"),
            ],
        )?);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        // TCP readiness connections themselves create CONNECTs under this seam.
        // Wait on the daemon's post-bind marker so only the three payload clients
        // enter the endpoint's forwarding denominator.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !read_stderr(&stderr).contains("transparent proxy listening")
            && Instant::now() < deadline
        {
            anyhow::ensure!(
                daemon.0.try_wait()?.is_none(),
                "auth daemon exited before startup"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        anyhow::ensure!(
            read_stderr(&stderr).contains("transparent proxy listening"),
            "auth daemon startup marker absent"
        );
        for _ in 0..3 {
            assert!(
                drive_tunnel(addr, Duration::from_secs(2)).await?,
                "source {source} did not produce a byte-exact authenticated tunnel"
            );
        }
        assert!(graceful_shutdown(&mut daemon.0)?.success());
        assert_eq!(
            client_connect_count(&primary),
            3,
            "primary forwarding evidence for {source}"
        );
        assert_eq!(
            client_connect_count(&secondary),
            0,
            "a wrong credential must not pass by selecting another proxy"
        );
        let output = read_stderr(&stderr);
        for secret in [
            "url-user",
            "url+pass",
            "config-user",
            "config-pass",
            "env-user",
            "env-pass",
        ] {
            assert!(
                !output.contains(secret),
                "daemon emitted a credential token for {source}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn auth_failure_excludes_proxy_and_authenticated_recovery_fails_back() -> Result<()> {
    use base64::Engine as _;
    require_non_root();
    let token = base64::engine::general_purpose::STANDARD.encode("recovered-user:recovered-pass");
    let primary = MockProxy::new(
        0,
        MockBehavior::AuthenticatedTunnelEcho {
            // ubs:ignore[rust.security.hardcoded-secrets] — intentionally incorrect public test token; controls 407 exclusion, never a usable credential.
            token: "deliberately-wrong-token".into(),
        },
    )
    .await?;
    let secondary = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let port = free_listen_port();
    let home = failover_config(primary.port, secondary.port, port)?;
    let path = home._temp.path().join(".config/rust_proxy/config.toml");
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&path)?)?;
    config["settings"]["auto_failback"] = true.into();
    config["settings"]
        .as_table_mut()
        .context("settings fixture table")?
        .insert("failback_delay_secs".into(), 2.into());
    config["proxies"][0]["url"] = format!(
        "http://recovered-user:recovered-pass@127.0.0.1:{}",
        primary.port
    )
    .into();
    std::fs::write(path, toml::to_string(&config)?)?;
    let stderr = home._temp.path().join("daemon.stderr");
    let mut daemon = ManagedDaemon(spawn_daemon(&home, &stderr)?);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let startup_deadline = Instant::now() + Duration::from_secs(5);
    while !read_stderr(&stderr).contains("transparent proxy listening")
        && Instant::now() < startup_deadline
    {
        anyhow::ensure!(
            daemon.0.try_wait()?.is_none(),
            "auth recovery daemon exited before startup"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::ensure!(
        read_stderr(&stderr).contains("transparent proxy listening"),
        "auth recovery daemon startup marker absent"
    );
    let deadline = Instant::now() + Duration::from_secs(8);
    while !read_stderr(&stderr).contains("Failover triggered") && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        read_stderr(&stderr).contains("Failover triggered"),
        "407 never excluded the primary"
    );
    let bad_before = client_connect_count(&primary);
    let secondary_before = client_connect_count(&secondary);
    for _ in 0..3 {
        assert!(
            drive_tunnel(addr, Duration::from_secs(2)).await?,
            "alternative did not relay byte-exact after auth exclusion"
        );
    }
    assert_eq!(
        client_connect_count(&primary),
        bad_before,
        "excluded proxy still selected"
    );
    assert_eq!(client_connect_count(&secondary), secondary_before + 3);
    let recovered_at = Instant::now();
    primary.set_behavior(MockBehavior::AuthenticatedTunnelEcho { token });
    while !read_stderr(&stderr).contains("Failback triggered")
        && recovered_at.elapsed() < Duration::from_secs(8)
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let log = read_stderr(&stderr);
    assert!(
        log.contains("Failback triggered"),
        "authenticated recovery did not restore original proxy"
    );
    assert!(
        recovered_at.elapsed() >= Duration::from_secs(2),
        "failback skipped the configured recovery delay"
    );
    let primary_before = client_connect_count(&primary);
    let secondary_before = client_connect_count(&secondary);
    for _ in 0..3 {
        assert!(
            drive_tunnel(addr, Duration::from_secs(2)).await?,
            "recovered original did not relay byte-exact"
        );
    }
    assert_eq!(client_connect_count(&primary), primary_before + 3);
    assert_eq!(client_connect_count(&secondary), secondary_before);
    assert!(graceful_shutdown(&mut daemon.0)?.success());
    let log = read_stderr(&stderr);
    assert!(
        !log.contains("recovered-user") && !log.contains("recovered-pass"),
        "auth recovery log leaked credentials"
    );
    Ok(())
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
        // ubs:ignore[rust.ownership.panic-macro] — fails activation proof if its actual daemon never started.
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

/// Observe which real loopback CONNECT server receives each byte-exact
/// daemon tunnel. No health or ping samples exist in these cases.
#[tokio::test]
async fn daemon_load_balancing_routes_without_samples_and_with_boundary_weights() -> Result<()> {
    require_non_root();
    const CONNECTIONS: usize = 12;
    for (strategy, alpha_weight, beta_weight, expected) in [
        ("least_latency", 100, 100, (12, 0)),
        ("round_robin", 100, 100, (6, 6)),
        ("weighted", 3, 1, (9, 3)),
        ("weighted", 0, 7, (0, 12)),
        ("weighted", 0, 0, (12, 0)),
        ("weighted", u32::MAX, u32::MAX, (12, 0)),
    ] {
        let alpha = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
        let beta = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
        let port = free_listen_port();
        let home = activation_config("beta", alpha.port, beta.port, port)?;
        let path = home._temp.path().join(".config/rust_proxy/config.toml");
        let config = std::fs::read_to_string(&path)?
            .replace(
                "load_balance_strategy = \"single\"",
                &format!("load_balance_strategy = \"{strategy}\""),
            )
            .replace(
                "priority = 50",
                &format!("priority = 50\nweight = {alpha_weight}"),
            )
            .replace(
                "priority = 100",
                &format!("priority = 100\nweight = {beta_weight}"),
            );
        std::fs::write(path, config)?;
        let logs = TempDir::new()?;
        let stderr_path = logs.path().join("daemon.stderr.log");
        let mut child = spawn_daemon(&home, &stderr_path)?;
        let addr = format!("127.0.0.1:{port}").parse()?;
        let exercise = async {
            wait_for_listener(addr).await?;
            // Account for the readiness connection before setting the client
            // denominator. It cannot count as one of the 12 echoed payloads.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            while client_connect_count(&alpha) + client_connect_count(&beta) == 0 {
                anyhow::ensure!(
                    tokio::time::Instant::now() < deadline,
                    "readiness CONNECT missing"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let before = (client_connect_count(&alpha), client_connect_count(&beta));
            for _ in 0..CONNECTIONS {
                anyhow::ensure!(
                    drive_tunnel(addr, Duration::from_secs(3)).await?,
                    "{strategy} tunnel failed: {}",
                    read_stderr(&stderr_path)
                );
                anyhow::ensure!(
                    child.try_wait()?.is_none(),
                    "daemon stopped under {strategy}"
                );
            }
            let observed = (
                client_connect_count(&alpha) - before.0,
                client_connect_count(&beta) - before.1,
            );
            assert_eq!(
                observed, expected,
                "strategy={strategy}, weights={alpha_weight}:{beta_weight}"
            );
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let stopped = graceful_shutdown(&mut child);
        exercise?;
        anyhow::ensure!(stopped?.success(), "daemon stop failed");
    }
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
        // ubs:ignore[rust.ownership.panic-macro] — fails failover proof if its actual daemon never started.
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

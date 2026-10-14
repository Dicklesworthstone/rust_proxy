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
    let mut temp = TempDir::new().context("create temp HOME")?;
    temp.disable_cleanup(true);
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
        .env("RUST_PROXY_CONFIG", &home.config_path)
        .env(
            "RUST_PROXY_STATE_DIR",
            home.temp.path().join(".state/rust_proxy"),
        )
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

async fn wait_for_listener(
    addr: std::net::SocketAddr,
    home: &ReloadHome,
    child: &mut ChildGuard,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("daemon listener never came up at {}", addr);
        }
        anyhow::ensure!(
            child.0.try_wait()?.is_none(),
            "daemon exited before owned listener readiness"
        );
        let status = reload_fields_status(home)?;
        if status["daemon_running"] == true
            && status["daemon"]["snapshot"]["identity"]["pid"] == child.0.id()
            && TcpStream::connect(addr).await.is_ok()
        {
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

fn reload_fields_spawn(home: &ReloadHome) -> Result<ChildGuard> {
    eprintln!("reload field fixtures: {}", home.temp.path().display());
    let child = Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
        .arg("daemon")
        .env("HOME", home.temp.path())
        .env("XDG_CONFIG_HOME", home.temp.path().join(".config"))
        .env("XDG_STATE_HOME", home.temp.path().join(".state"))
        .env("RUST_PROXY_CONFIG", &home.config_path)
        .env(
            "RUST_PROXY_STATE_DIR",
            home.temp.path().join(".state/rust_proxy"),
        )
        .env("RUST_PROXY_TEST_MODE", "1")
        .env("RUST_PROXY_TEST_ORIGINAL_DST", ORIGINAL_DST)
        .env("RUST_LOG", "debug")
        .stdout(std::fs::File::create(
            home.temp.path().join("fields-daemon.stdout.log"),
        )?)
        .stderr(std::fs::File::create(
            home.temp.path().join("fields-daemon.stderr.log"),
        )?)
        .spawn()?;
    Ok(ChildGuard(child))
}

fn reload_fields_status(home: &ReloadHome) -> Result<serde_json::Value> {
    let output = Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
        .args(["status", "--json"])
        .env("RUST_PROXY_CONFIG", &home.config_path)
        .env(
            "RUST_PROXY_STATE_DIR",
            home.temp.path().join(".state/rust_proxy"),
        )
        .env_remove("RUST_PROXY_OUTPUT_FORMAT")
        .env_remove("TOON_DEFAULT_FORMAT")
        .output()?;
    eprintln!(
        "reload fields status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(!output.stdout.contains(&0x1b));
    assert!(!output.stderr.contains(&0x1b));
    Ok(serde_json::from_slice(&output.stdout)?)
}

async fn reload_fields_wait(
    home: &ReloadHome,
    child: &mut ChildGuard,
    predicate: impl Fn(&serde_json::Value) -> bool,
) -> Result<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + RELOAD_BUDGET;
    loop {
        assert_alive(&mut child.0, "per-field observation");
        let status = reload_fields_status(home)?;
        if status["daemon_running"] == true && predicate(&status) {
            assert_eq!(
                status["daemon"]["snapshot"]["identity"]["pid"],
                child.0.id()
            );
            return Ok(status);
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "per-field observation missed the original reload budget: {status}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn reload_fields_generation(status: &serde_json::Value) -> Result<u64> {
    status["daemon"]["snapshot"]["applied"]["config_generation"]
        .as_u64()
        .context("live applied generation")
}

fn reload_fields_health<'a>(
    status: &'a serde_json::Value,
    id: &str,
) -> Option<&'a serde_json::Value> {
    status["proxy_health"]
        .as_array()?
        .iter()
        .find(|health| health["id"] == id)
}

fn reload_fields_requested_match(
    requested: &serde_json::Value,
    applied: &serde_json::Value,
) -> bool {
    match requested {
        serde_json::Value::Object(fields) => fields.iter().all(|(name, value)| {
            applied
                .get(name)
                .is_some_and(|actual| reload_fields_requested_match(value, actual))
        }),
        serde_json::Value::Array(values) => applied.as_array().is_some_and(|actual| {
            values.len() == actual.len()
                && values
                    .iter()
                    .zip(actual)
                    .all(|(wanted, actual)| reload_fields_requested_match(wanted, actual))
        }),
        _ => requested == applied,
    }
}

async fn reload_fields_apply(
    home: &ReloadHome,
    child: &mut ChildGuard,
    config: &toml::Value,
    previous: u64,
    phase: &str,
) -> Result<serde_json::Value> {
    let bytes = toml::to_string(config)?;
    let requested = serde_json::to_value(config)?;
    eprintln!("reload phase {phase}, requested fields:\n{bytes}");
    std::fs::write(&home.config_path, bytes)?;
    // A queued earlier watcher event can advance generation. Require this
    // edit's complete explicit field set before starting the behavioral
    // oracle; configuration acknowledgement alone is never the proof.
    reload_fields_wait(home, child, |status| {
        status["daemon"]["snapshot"]["applied"]["last_reload_result"] == "applied"
            && reload_fields_generation(status).is_ok_and(|generation| generation > previous)
            && reload_fields_requested_match(
                &requested,
                &status["daemon"]["snapshot"]["applied"]["config"],
            )
    })
    .await
}

fn reload_fields_client_count(proxy: &MockProxy) -> usize {
    proxy
        .get_requests()
        .iter()
        .filter(|request| request.request_line == format!("CONNECT {ORIGINAL_DST} HTTP/1.1"))
        .count()
}

async fn reload_fields_traffic(
    addr: std::net::SocketAddr,
    recipients: &[(&MockProxy, usize)],
    phase: &str,
) -> Result<()> {
    let before: Vec<_> = recipients
        .iter()
        .map(|(proxy, _)| reload_fields_client_count(proxy))
        .collect();
    let attempts: usize = recipients.iter().map(|(_, count)| count).sum();
    for _ in 0..attempts {
        tunnel_attempt(addr).await?;
    }
    for ((proxy, expected), previous) in recipients.iter().zip(before) {
        let observed = reload_fields_client_count(proxy) - previous;
        eprintln!(
            "{phase}: client tunnels port={} expected={expected} observed={observed}",
            proxy.port
        );
        assert_eq!(observed, *expected, "recipient mismatch during {phase}");
    }
    Ok(())
}

fn reload_fields_add_proxy(
    config: &mut toml::Value,
    id: &str,
    port: u16,
    priority: u32,
) -> Result<()> {
    let mut proxy = toml::Table::new();
    proxy.insert("id".into(), id.into());
    proxy.insert("url".into(), format!("http://127.0.0.1:{port}").into());
    proxy.insert("priority".into(), i64::from(priority).into());
    proxy.insert("weight".into(), 1.into());
    config["proxies"]
        .as_array_mut()
        .context("proxy fixture array")?
        .push(proxy.into());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_fields_strategy_priority_weights_and_removed_healthy_proxy() -> Result<()> {
    require_non_root();
    let alpha = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let beta = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let gamma = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let port = free_listen_port();
    let addr = ([127, 0, 0, 1], port).into();
    let mut home = write_test_config(alpha.port, port, "alpha")?;
    home.temp.disable_cleanup(true);
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&home.config_path)?)?;
    config["proxies"][0]
        .as_table_mut()
        .context("alpha fixture")?
        .insert("priority".into(), 100.into());
    reload_fields_add_proxy(&mut config, "beta", beta.port, 20)?;
    reload_fields_add_proxy(&mut config, "gamma", gamma.port, 30)?;
    let settings = config["settings"]
        .as_table_mut()
        .context("settings fixture")?;
    settings.insert("health_check_enabled".into(), true.into());
    settings.insert("health_check_interval_secs".into(), 1.into());
    settings.insert("consecutive_failures_threshold".into(), 1.into());
    settings.insert("failback_delay_secs".into(), 1.into());
    settings.insert(
        "health_check_target".into(),
        "CONNECT fields-health.invalid:443".into(),
    );
    std::fs::write(&home.config_path, toml::to_string(&config)?)?;
    let mut child = reload_fields_spawn(&home)?;
    let mut status = reload_fields_wait(&home, &mut child, |status| {
        ["alpha", "beta", "gamma"].iter().all(|id| {
            reload_fields_health(status, id).is_some_and(|health| health["status"] == "healthy")
        })
    })
    .await?;
    reload_fields_traffic(
        addr,
        &[(&alpha, 6), (&beta, 0), (&gamma, 0)],
        "single baseline",
    )
    .await?;
    reload_fields_traffic(
        addr,
        &[(&alpha, 6), (&beta, 0), (&gamma, 0)],
        "unchanged single companion",
    )
    .await?;

    // Change only priorities; active alpha still wins until it becomes
    // unusable. Its replacement must follow the NEW priority ordering.
    config["proxies"][1]["priority"] = 40.into();
    config["proxies"][2]["priority"] = 10.into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "priority gamma first",
    )
    .await?;
    alpha.set_behavior(MockBehavior::Failing {
        error: MockError::AuthRequired,
    });
    reload_fields_wait(&home, &mut child, |status| {
        status["effective_proxy"] == "gamma"
    })
    .await?;
    reload_fields_traffic(
        addr,
        &[(&alpha, 0), (&beta, 0), (&gamma, 6)],
        "new gamma priority failover",
    )
    .await?;
    alpha.set_behavior(MockBehavior::TunnelEcho);
    reload_fields_wait(&home, &mut child, |status| {
        status["effective_proxy"] == "alpha"
    })
    .await?;
    reload_fields_traffic(
        addr,
        &[(&alpha, 3), (&beta, 0), (&gamma, 0)],
        "priority recovery alpha",
    )
    .await?;
    config["proxies"][1]["priority"] = 5.into();
    config["proxies"][2]["priority"] = 40.into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "priority beta first",
    )
    .await?;
    alpha.set_behavior(MockBehavior::Failing {
        error: MockError::AuthRequired,
    });
    reload_fields_wait(&home, &mut child, |status| {
        status["effective_proxy"] == "beta"
    })
    .await?;
    reload_fields_traffic(
        addr,
        &[(&alpha, 0), (&beta, 6), (&gamma, 0)],
        "new beta priority failover",
    )
    .await?;
    alpha.set_behavior(MockBehavior::TunnelEcho);
    reload_fields_wait(&home, &mut child, |status| {
        status["effective_proxy"] == "alpha"
    })
    .await?;
    reload_fields_traffic(
        addr,
        &[(&alpha, 3), (&beta, 0), (&gamma, 0)],
        "second priority recovery alpha",
    )
    .await?;

    config["settings"]
        .as_table_mut()
        .context("settings fixture")?
        .insert("load_balance_strategy".into(), "round_robin".into());
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "single to round robin",
    )
    .await?;
    reload_fields_traffic(addr, &[(&alpha, 4), (&beta, 4), (&gamma, 4)], "round robin").await?;
    config["settings"]["load_balance_strategy"] = "weighted".into();
    config["proxies"][0]
        .as_table_mut()
        .context("alpha fixture")?
        .insert("weight".into(), 0.into());
    config["proxies"][1]["weight"] = 3.into();
    config["proxies"][2]["weight"] = 1.into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "weighted 0:3:1",
    )
    .await?;
    reload_fields_traffic(
        addr,
        &[(&alpha, 0), (&beta, 9), (&gamma, 3)],
        "weighted 0:3:1",
    )
    .await?;
    config["proxies"][1]["weight"] = 0.into();
    config["proxies"][2]["weight"] = 7.into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "weighted zero exclusions",
    )
    .await?;
    reload_fields_traffic(
        addr,
        &[(&alpha, 0), (&beta, 0), (&gamma, 6)],
        "weighted 0:0:7",
    )
    .await?;
    let generation = reload_fields_generation(&status)?;
    std::fs::write(&home.config_path, "[[proxies]\n")?;
    let rejected = reload_fields_wait(&home, &mut child, |status| {
        status["daemon"]["snapshot"]["applied"]["last_reload_result"] == "rejected"
    })
    .await?;
    assert_eq!(reload_fields_generation(&rejected)?, generation);
    reload_fields_traffic(
        addr,
        &[(&alpha, 0), (&beta, 0), (&gamma, 6)],
        "invalid edit preserves weights",
    )
    .await?;

    assert!(reload_fields_health(&rejected, "gamma")
        .is_some_and(|health| health["status"] == "healthy"));
    config["proxies"]
        .as_array_mut()
        .context("proxy fixture array")?
        .remove(2);
    config["proxies"][1]["weight"] = 7.into();
    let removed = reload_fields_apply(
        &home,
        &mut child,
        &config,
        generation,
        "remove formerly healthy gamma",
    )
    .await?;
    assert!(reload_fields_health(&removed, "gamma").is_none());
    reload_fields_traffic(
        addr,
        &[(&alpha, 0), (&beta, 6), (&gamma, 0)],
        "removed gamma never selected",
    )
    .await?;
    assert_eq!(
        read_stderr(&home.temp.path().join("fields-daemon.stderr.log"))
            .matches("transparent proxy listening on")
            .count(),
        1
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_fields_health_target_cadence_timeout_threshold_disable_and_recovery() -> Result<()>
{
    require_non_root();
    let alpha = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let beta = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let port = free_listen_port();
    let addr = ([127, 0, 0, 1], port).into();
    let mut home = write_test_config(alpha.port, port, "alpha")?;
    home.temp.disable_cleanup(true);
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&home.config_path)?)?;
    reload_fields_add_proxy(&mut config, "beta", beta.port, 100)?;
    let settings = config["settings"]
        .as_table_mut()
        .context("settings fixture")?;
    for (field, value) in [
        ("health_check_enabled", true.into()),
        ("health_check_interval_secs", 4.into()),
        ("health_check_timeout_ms", 3000.into()),
        ("consecutive_failures_threshold", 3.into()),
        ("failback_delay_secs", 1.into()),
        (
            "health_check_target",
            "CONNECT old.fields-health.invalid:443".into(),
        ),
    ] {
        settings.insert(field.into(), value);
    }
    std::fs::write(&home.config_path, toml::to_string(&config)?)?;
    let mut child = reload_fields_spawn(&home)?;
    let mut status = reload_fields_wait(&home, &mut child, |status| {
        ["alpha", "beta"].iter().all(|id| {
            reload_fields_health(status, id).is_some_and(|health| health["status"] == "healthy")
        })
    })
    .await?;
    reload_fields_traffic(addr, &[(&alpha, 3), (&beta, 0)], "healthy old probe target").await?;
    let old_target = "CONNECT old.fields-health.invalid:443 HTTP/1.1";
    assert!([&alpha, &beta].iter().all(|proxy| proxy
        .get_requests()
        .iter()
        .any(|request| request.request_line == old_target)));
    config["settings"]["health_check_target"] = "CONNECT new.fields-health.invalid:443".into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "health target only",
    )
    .await?;
    let new_target = "CONNECT new.fields-health.invalid:443 HTTP/1.1";
    reload_fields_wait(&home, &mut child, |status| {
        ["alpha", "beta"].iter().all(|id| {
            reload_fields_health(status, id).is_some_and(|health| health["status"] == "healthy")
        }) && [&alpha, &beta].iter().all(|proxy| {
            proxy
                .get_requests()
                .iter()
                .any(|request| request.request_line == new_target)
        })
    })
    .await?;
    let old_counts: Vec<_> = [&alpha, &beta]
        .iter()
        .map(|proxy| {
            proxy
                .get_requests()
                .iter()
                .filter(|request| request.request_line == old_target)
                .count()
        })
        .collect();
    config["settings"]["health_check_interval_secs"] = 1.into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "health interval 4 to 1",
    )
    .await?;
    let since = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + RELOAD_BUDGET;
    loop {
        let enough = [&alpha, &beta].iter().all(|proxy| {
            proxy
                .get_requests()
                .iter()
                .filter(|request| request.request_line == new_target && request.timestamp >= since)
                .count()
                >= 2
        });
        if enough {
            break;
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "new interval never produced two probes per recipient"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    for (proxy, old_count) in [&alpha, &beta].iter().zip(old_counts) {
        let requests = proxy.get_requests();
        let times: Vec<_> = requests
            .iter()
            .filter(|request| request.request_line == new_target && request.timestamp >= since)
            .map(|request| request.timestamp)
            .collect();
        let gap = times[1].duration_since(times[0]);
        eprintln!(
            "health interval port={} gap={gap:?}, old=4s new=1s",
            proxy.port
        );
        assert!(gap >= Duration::from_millis(900) && gap < Duration::from_secs(4));
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.request_line == old_target)
                .count(),
            old_count
        );
    }

    config["settings"]["health_check_timeout_ms"] = 500.into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "health timeout 3000 to 500",
    )
    .await?;
    reload_fields_wait(&home, &mut child, |status| {
        reload_fields_health(status, "alpha").is_some_and(|health| health["status"] == "healthy")
    })
    .await?;
    let log_path = home.temp.path().join("fields-daemon.stderr.log");
    let before = read_stderr(&log_path).len();
    alpha.set_behavior(MockBehavior::Failing {
        error: MockError::Timeout,
    });
    let tolerated = reload_fields_wait(&home, &mut child, |status| {
        reload_fields_health(status, "alpha").is_some_and(|health| {
            health["status"] == "healthy"
                && health["consecutive_failures"]
                    .as_u64()
                    .is_some_and(|count| (1..3).contains(&count))
        })
    })
    .await?;
    assert_eq!(tolerated["effective_proxy"], "alpha");
    let log = read_stderr(&log_path);
    let failed = log[before..]
        .lines()
        .find(|line| line.contains("Health check completed proxy_id=alpha success=false"))
        .context("actual timeout completion")?;
    let latency: f64 = failed
        .split("latency_ms=")
        .nth(1)
        .context("timeout latency")?
        .split_whitespace()
        .next()
        .context("latency value")?
        .parse()?;
    eprintln!("actual hung-probe completion: {failed}");
    assert!(
        (490.0..2500.0).contains(&latency),
        "new 500ms timeout was not observed: {latency}"
    );
    config["settings"]["consecutive_failures_threshold"] = 1.into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "threshold 3 to 1",
    )
    .await?;
    reload_fields_wait(&home, &mut child, |status| {
        status["effective_proxy"] == "beta"
            && reload_fields_health(status, "alpha").is_some_and(|health| {
                health["status"] == "unhealthy"
                    && health["consecutive_failures"]
                        .as_u64()
                        .is_some_and(|count| (1..3).contains(&count))
            })
    })
    .await?;
    reload_fields_traffic(
        addr,
        &[(&alpha, 0), (&beta, 3)],
        "new threshold excludes hung alpha",
    )
    .await?;
    alpha.set_behavior(MockBehavior::TunnelEcho);
    reload_fields_wait(&home, &mut child, |status| {
        status["effective_proxy"] == "alpha"
            && reload_fields_health(status, "alpha").is_some_and(|health| {
                health["status"] == "healthy" && health["consecutive_failures"] == 0
            })
    })
    .await?;
    reload_fields_traffic(addr, &[(&alpha, 3), (&beta, 0)], "health recovery").await?;

    config["settings"]["health_check_enabled"] = false.into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "disable health",
    )
    .await?;
    let before_probes: Vec<_> = [&alpha, &beta]
        .iter()
        .map(|proxy| {
            proxy
                .get_requests()
                .iter()
                .filter(|request| request.request_line == new_target)
                .count()
        })
        .collect();
    tokio::time::sleep(Duration::from_secs(3)).await;
    for (proxy, before) in [&alpha, &beta].iter().zip(before_probes) {
        assert_eq!(
            proxy
                .get_requests()
                .iter()
                .filter(|request| request.request_line == new_target)
                .count(),
            before
        );
    }
    reload_fields_traffic(
        addr,
        &[(&alpha, 3), (&beta, 0)],
        "health disabled still forwards",
    )
    .await?;
    config["settings"]["health_check_enabled"] = true.into();
    reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "reenable health",
    )
    .await?;
    reload_fields_wait(&home, &mut child, |status| {
        ["alpha", "beta"].iter().all(|id| {
            reload_fields_health(status, id).is_some_and(|health| health["status"] == "healthy")
        })
    })
    .await?;
    reload_fields_traffic(
        addr,
        &[(&alpha, 3), (&beta, 0)],
        "reenabled health forwards",
    )
    .await?;
    Ok(())
}

async fn reload_fields_refused_attempt(
    home: &ReloadHome,
    addr: std::net::SocketAddr,
    refused_port: u16,
    delays: &[u64],
) -> Result<()> {
    let log_path = home.temp.path().join("fields-daemon.stderr.log");
    let before = read_stderr(&log_path).len();
    let started = std::time::Instant::now();
    let mut client = TcpStream::connect(addr).await?;
    client.write_all(PAYLOAD).await?;
    let mut byte = [0];
    let terminal = tokio::time::timeout(RELOAD_BUDGET, client.read(&mut byte)).await?;
    assert!(
        matches!(terminal, Ok(0) | Err(_)),
        "refused upstream returned payload data"
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(delays.iter().sum()));
    let final_error = format!(
        "Failed to connect to upstream 127.0.0.1:{refused_port} after {} attempts",
        delays.len() + 1
    );
    let deadline = tokio::time::Instant::now() + RELOAD_BUDGET;
    loop {
        let log = read_stderr(&log_path);
        let phase = &log[before..];
        if phase.contains(&final_error) {
            let retries: Vec<_> = phase
                .lines()
                .filter(|line| line.contains("retrying in"))
                .collect();
            assert_eq!(retries.len(), delays.len());
            for (index, (line, delay)) in retries.iter().zip(delays).enumerate() {
                assert!(
                    line.contains(&format!(
                        "(attempt {}/{}), retrying in {delay}ms",
                        index + 1,
                        delays.len() + 1
                    )),
                    "{line}"
                );
                assert!(
                    line.contains("Connection refused"),
                    "not actual TCP refusal: {line}"
                );
            }
            assert!(phase.contains("Connection refused"));
            eprintln!("refused TCP port={refused_port}, attempts={}, delays={delays:?}, elapsed={elapsed:?}\n{phase}", delays.len() + 1);
            return Ok(());
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "terminal TCP retry observation absent"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_fields_retry_limits_initial_backoff_and_cap_reach_real_tcp() -> Result<()> {
    require_non_root();
    let alpha = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let port = free_listen_port();
    let addr = ([127, 0, 0, 1], port).into();
    let mut home = write_test_config(alpha.port, port, "alpha")?;
    home.temp.disable_cleanup(true);
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&home.config_path)?)?;
    let settings = config["settings"]
        .as_table_mut()
        .context("settings fixture")?;
    settings.insert("connect_max_retries".into(), 0.into());
    settings.insert("connect_initial_backoff_ms".into(), 200.into());
    settings.insert("connect_max_backoff_ms".into(), 300.into());
    std::fs::write(&home.config_path, toml::to_string(&config)?)?;
    let mut child = reload_fields_spawn(&home)?;
    let mut status = reload_fields_wait(&home, &mut child, |_| true).await?;
    reload_fields_traffic(addr, &[(&alpha, 3)], "retry baseline successful tunnel").await?;
    // A genuinely bound, non-listening socket reserves the port while the
    // kernel refuses connect; no fixture fabricates ECONNREFUSED.
    let refused = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    refused.bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 0)).into())?;
    let refused_port = refused
        .local_addr()?
        .as_socket()
        .context("reserved refused address")?
        .port();
    config["proxies"][0]["url"] = format!("http://127.0.0.1:{refused_port}").into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "real refused endpoint, zero retries",
    )
    .await?;
    reload_fields_refused_attempt(&home, addr, refused_port, &[]).await?;
    config["settings"]["connect_max_retries"] = 3.into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "retry limit 0 to 3",
    )
    .await?;
    reload_fields_refused_attempt(&home, addr, refused_port, &[200, 300, 300]).await?;
    config["settings"]["connect_max_retries"] = 1.into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "retry limit 3 to 1",
    )
    .await?;
    reload_fields_refused_attempt(&home, addr, refused_port, &[200]).await?;
    config["settings"]["connect_max_retries"] = 3.into();
    config["settings"]["connect_initial_backoff_ms"] = 70.into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "retry initial backoff 200 to 70",
    )
    .await?;
    reload_fields_refused_attempt(&home, addr, refused_port, &[70, 140, 280]).await?;
    config["settings"]["connect_max_backoff_ms"] = 90.into();
    status = reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "retry cap 300 to 90",
    )
    .await?;
    reload_fields_refused_attempt(&home, addr, refused_port, &[70, 90, 90]).await?;
    config["proxies"][0]["url"] = format!("http://127.0.0.1:{}", alpha.port).into();
    reload_fields_apply(
        &home,
        &mut child,
        &config,
        reload_fields_generation(&status)?,
        "retry successful endpoint recovery",
    )
    .await?;
    reload_fields_traffic(addr, &[(&alpha, 3)], "retry final successful tunnel").await?;
    Ok(())
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
    if let Err(err) = wait_for_listener(listen_addr, &home, &mut child).await {
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
    wait_for_listener(addr, &home, &mut child).await?;
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
async fn reload_fields_unrelated_listener_cannot_satisfy_owned_startup_gate() -> Result<()> {
    require_non_root();
    let proxy = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let unrelated = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = unrelated.local_addr()?;
    let home = write_test_config(proxy.port, address.port(), "occupied-gate-control")?;
    let logs = TempDir::new()?.keep();
    let stderr = logs.join("occupied-startup.stderr.log");
    let mut child = ChildGuard(spawn_daemon(&home, &stderr)?);
    // The old TCP-only gate accepts this real foreign socket. Ownership must
    // still refuse it, without widening the existing five-second startup bound.
    assert!(TcpStream::connect(address).await.is_ok());
    assert!(wait_for_listener(address, &home, &mut child).await.is_err());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait()? {
            assert!(!status.success());
            break;
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "occupied-listener child did not refuse startup"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let diagnostic = read_stderr(&stderr);
    eprintln!(
        "occupied startup fixture {}, log {}:\n{diagnostic}",
        home.temp.path().display(),
        stderr.display()
    );
    assert!(diagnostic.contains("Failed to bind"), "{diagnostic}");
    let status = reload_fields_status(&home)?;
    assert_eq!(status["daemon_running"], false);
    assert_eq!(status["daemon"]["status"], "absent");
    assert_eq!(reload_fields_client_count(&proxy), 0);
    Ok(())
}

#[tokio::test]
async fn invalid_config_edit_keeps_last_known_good() -> Result<()> {
    require_non_root();

    let mock_a = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let listen_port = free_listen_port();
    let mut home = write_test_config(mock_a.port, listen_port, "mock-a")?;
    home.temp.disable_cleanup(true);
    let workdir = TempDir::new()?.keep();
    let stderr_path = workdir.join("daemon.stderr.log");
    eprintln!(
        "invalid reload fixture: {}, daemon log: {}",
        home.temp.path().display(),
        stderr_path.display()
    );

    let mut child = ChildGuard(spawn_daemon(&home, &stderr_path)?);
    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{listen_port}").parse()?;
    wait_for_listener(listen_addr, &home, &mut child).await?;

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

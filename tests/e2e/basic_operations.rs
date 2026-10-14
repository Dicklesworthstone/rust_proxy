//! Basic E2E tests for rust_proxy CLI operations.
//!
//! Tests the fundamental CLI commands without daemon functionality.

use crate::common::assertions::*;
use crate::common::fixtures;
use crate::common::mock_proxy::{MockBehavior, MockProxy};
use crate::common::TestHarness;

#[tokio::test]
async fn daemon_final_flush_preserves_real_cli_activation_and_exact_traffic() -> anyhow::Result<()>
{
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    anyhow::ensure!(
        unsafe { libc::geteuid() } != 0,
        "persistence daemon seam requires non-root"
    );
    let harness = TestHarness::new().await?;
    let proxy = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
    let mut proxies = Vec::new();
    for id in ["first", "second"] {
        let mut entry = toml::Table::new();
        entry.insert("id".into(), id.into());
        entry.insert("url".into(), proxy.url().into());
        proxies.push(toml::Value::Table(entry));
    }
    let root = config.as_table_mut().unwrap();
    root.insert("proxies".into(), proxies.into());
    root.insert("active_proxy".into(), "first".into());
    root.insert(
        "targets".into(),
        vec![toml::Value::String("persistence.target.invalid".into())].into(),
    );
    let settings = config["settings"].as_table_mut().unwrap();
    settings.insert("metrics_enabled".into(), false.into());
    settings.insert("health_check_enabled".into(), false.into());
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    assert!(harness.run_command(&["activate", "first"]).success);
    let work = tempfile::tempdir()?.keep();
    let log = work.join("daemon.stderr");
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
        .arg("daemon")
        .env("RUST_PROXY_CONFIG", &harness.config_path)
        .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
        .env("RUST_PROXY_TEST_MODE", "1")
        .env(
            "RUST_PROXY_TEST_ORIGINAL_DST",
            "persistence.target.invalid:443",
        )
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(&log)?)
        .spawn()?;
    struct OwnedDaemon(std::process::Child);
    impl Drop for OwnedDaemon {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    let mut daemon = OwnedDaemon(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::fs::read_to_string(&log)?.contains("transparent proxy listening") {
        anyhow::ensure!(
            daemon.0.try_wait()?.is_none(),
            "daemon exited before persistence proof"
        );
        anyhow::ensure!(
            Instant::now() < deadline,
            "persistence daemon startup exceeded budget"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let payload = b"persistence-counter-delta-payload";
    for _ in 0..3 {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut client =
                tokio::net::TcpStream::connect(("127.0.0.1", harness.listen_port())).await?;
            client.write_all(payload).await?;
            let mut echoed = vec![0; payload.len()];
            client.read_exact(&mut echoed).await?;
            anyhow::ensure!(echoed == payload, "persistence tunnel payload mismatch");
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    }
    assert!(harness.run_command(&["activate", "second"]).success);
    let path = harness.state_dir.join("state.json");
    let before: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let activation = before["proxies"]["second"]["activated_at"].clone();
    assert!(activation.is_string());
    assert_eq!(
        before["proxies"]["first"]["bytes_sent"], 0,
        "traffic must still be dirty in the daemon cache"
    );
    // SAFETY: positive PID of the live child owned by this test, ordinary SIGTERM.
    anyhow::ensure!(
        unsafe { libc::kill(daemon.0.id() as libc::pid_t, libc::SIGTERM) } == 0,
        "cannot terminate persistence daemon"
    );
    let shutdown = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = daemon.0.try_wait()? {
            assert!(status.success(), "daemon persistence exit failed");
            break;
        }
        anyhow::ensure!(
            Instant::now() < shutdown,
            "final persistence flush exceeded lifetime budget"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    assert_eq!(after["proxies"]["second"]["activated_at"], activation);
    assert_eq!(after["proxies"]["first"]["bytes_sent"], 3 * payload.len());
    assert_eq!(
        after["proxies"]["first"]["bytes_received"],
        3 * payload.len()
    );
    assert_eq!(
        proxy.request_count(),
        3,
        "readiness cannot inflate the traffic denominator"
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_config_mutations_wait_for_transaction_and_preserve_both_operations(
) -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;
    use std::time::Duration;
    let harness = TestHarness::new().await?;
    let original = std::fs::read(&harness.config_path)?;
    let directory = std::fs::File::open(harness.config_path.parent().unwrap())?;
    // SAFETY: live directory descriptor; the controller owns this exclusive gate.
    anyhow::ensure!(
        unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "cannot gate config transactions"
    );
    let launch = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
            .args(args)
            .env("RUST_PROXY_CONFIG", &harness.config_path)
            .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
    };
    let mut target = launch(&["targets", "add", "first.concurrent.invalid"])?;
    let mut proxy = launch(&[
        "proxy",
        "add",
        "second-concurrent",
        "http://127.0.0.1:12345",
    ])?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let both_waiting = target.try_wait()?.is_none() && proxy.try_wait()?.is_none();
    let unchanged = std::fs::read(&harness.config_path)? == original;
    drop(directory);
    let target = target.wait_with_output()?;
    let proxy = proxy.wait_with_output()?;
    assert!(
        both_waiting && unchanged,
        "mutations bypassed the exclusive transaction gate"
    );
    assert!(
        target.status.success(),
        "target command: {}",
        String::from_utf8_lossy(&target.stderr)
    );
    assert!(
        proxy.status.success(),
        "proxy command: {}",
        String::from_utf8_lossy(&proxy.stderr)
    );
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
    assert!(config["targets"]
        .as_array()
        .unwrap()
        .iter()
        .any(|target| target.as_str() == Some("first.concurrent.invalid")));
    assert!(config["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .any(|proxy| proxy["id"].as_str() == Some("second-concurrent")));
    Ok(())
}

#[tokio::test]
async fn busy_config_transaction_fails_without_changing_last_good_bytes() -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;
    let harness = TestHarness::new().await?;
    let original = std::fs::read(&harness.config_path)?;
    let directory = std::fs::File::open(harness.config_path.parent().unwrap())?;
    // SAFETY: live test-owned directory descriptor, released by File drop.
    anyhow::ensure!(
        unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "cannot hold busy transaction control"
    );
    // The controller NEVER releases the lock to produce success; the product
    // must emit its own bounded failure while the file remains unchanged.
    let started = std::time::Instant::now();
    let result = harness.run_command(&["targets", "add", "must-not-publish.invalid"]);
    drop(directory);
    assert!(!result.success);
    assert!(result
        .stderr
        .contains("Persistence transaction busy after two seconds"));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(std::fs::read(&harness.config_path)?, original);
    let recovered = harness.run_command(&["targets", "add", "must-not-publish.invalid"]);
    assert!(
        recovered.success,
        "lock remained stranded: {}",
        recovered.stderr
    );
    Ok(())
}

/// Child-only trust environment: never affect concurrent feed-client tests.
/// The trust FIFO has no writer or fixture timeout. Only the product's probe
/// deadline and bounded runtime shutdown can produce the asserted result.
#[tokio::test]
async fn stalled_native_trust_read_cannot_block_health_deadline() -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let harness = TestHarness::new().await?;
    let work = tempfile::tempdir()?.keep();
    let fifo = work.join("stalled-trust.pem");
    let path = std::ffi::CString::new(fifo.as_os_str().as_bytes())?;
    // SAFETY: live NUL-terminated test-owned pathname and ordinary mode bits.
    anyhow::ensure!(
        unsafe { libc::mkfifo(path.as_ptr(), 0o600) } == 0,
        "failed creating private trust FIFO"
    );
    let empty_roots = work.join("empty-trust-dir");
    std::fs::create_dir(&empty_roots)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    assert!(
        harness
            .run_command(&["proxy", "add", "trust-probe", &url])
            .success
    );
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
    let settings = config["settings"].as_table_mut().unwrap();
    settings.insert(
        "health_check_target".into(),
        "GET https://localhost/health".into(),
    );
    settings.insert("health_check_timeout_ms".into(), 200.into());
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    let endpoint = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).await?;
            request.push(byte[0]);
            anyhow::ensure!(
                request.len() <= 16 * 1024,
                "trust probe request exceeded fixture cap"
            );
        }
        anyhow::ensure!(
            request.starts_with(b"CONNECT localhost:443 HTTP/1.1\r\n"),
            "trust fixture did not receive CONNECT"
        );
        stream
            .write_all(b"HTTP/1.1 200 Established\r\n\r\n")
            .await?;
        Ok::<_, anyhow::Error>(())
    });
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
        .args(["check", "--json", "--test-connectivity"])
        .env("RUST_PROXY_CONFIG", &harness.config_path)
        .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
        .env("SSL_CERT_FILE", &fifo)
        .env("SSL_CERT_DIR", &empty_roots)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < Duration::from_secs(6) => {
                tokio::time::sleep(Duration::from_millis(25)).await
            }
            outcome => {
                let _ = child.kill();
                let output = child.wait_with_output()?;
                endpoint.abort();
                anyhow::bail!("trust probe exceeded product lifetime or failed polling: {outcome:?}; stderr: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
    }
    let output = child.wait_with_output()?;
    assert!(output.status.success(), "trust probe CLI failed");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["connectivity"][0]["status"], "timeout");
    assert_eq!(report["connectivity"][0]["error"], "Connection timeout");
    assert!(start.elapsed() < Duration::from_secs(6));
    tokio::time::timeout(Duration::from_secs(1), endpoint).await???;
    Ok(())
}

#[tokio::test]
async fn proxy_credentials_are_redacted_without_modifying_persisted_configuration(
) -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;
    assert!(
        harness
            .run_command(&["proxy", "add", "secret-test", "http://127.0.0.1:12345"])
            .success
    );
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
    config["proxies"][0]["url"] =
        "http://distinct-url-user:distinct-url-password@127.0.0.1:12345".into();
    let mut auth = toml::Table::new();
    auth.insert("username".into(), "distinct-config-user".into());
    auth.insert("password".into(), "distinct-config-password".into());
    config["proxies"][0]["auth"] = auth.into();
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    let original = std::fs::read(&harness.config_path)?;
    for args in [
        vec!["proxy", "list"],
        vec!["list", "--json"],
        vec!["list", "--format", "toon"],
        vec!["list"],
        vec!["status", "--json"],
        vec!["check", "--json"],
        vec!["test", "example.invalid", "--json", "--verbose", "--no-dns"],
    ] {
        let result = harness.run_command(&args);
        assert!(result.success, "command failed: {args:?}");
        let output = format!("{}{}", result.stdout, result.stderr);
        for secret in [
            "distinct-url-user",
            "distinct-url-password",
            "distinct-config-user",
            "distinct-config-password",
        ] {
            assert!(
                !output.contains(secret),
                "command leaked a credential token: {args:?}"
            );
        }
    }
    assert_eq!(
        std::fs::read(&harness.config_path)?,
        original,
        "display redaction changed usable config"
    );
    // Even invalid URL/TOML errors must not echo the original credential line.
    config["proxies"][0]["url"] =
        "http://distinct-url-user:distinct-url-password@bad host:12345".into();
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    let invalid = harness.run_command(&["check", "--json"]);
    assert!(!invalid.success);
    assert!(!format!("{}{}", invalid.stdout, invalid.stderr).contains("distinct-url-password"));
    std::fs::write(&harness.config_path, "[[proxies]]\nid = \"broken\"\nurl = \"http://distinct-url-user:distinct-url-password@broken\n")?;
    let invalid = harness.run_command(&["list", "--json"]);
    assert!(!invalid.success);
    assert!(!format!("{}{}", invalid.stdout, invalid.stderr).contains("distinct-url-password"));
    Ok(())
}

#[tokio::test]
async fn unsupported_proxy_transport_and_incomplete_auth_fail_before_listener_admission(
) -> anyhow::Result<()> {
    for (url, username) in [
        ("https://127.0.0.1:12345", None),
        ("http://127.0.0.1:12345", Some("partial-auth-user")),
    ] {
        let harness = TestHarness::new().await?;
        assert!(
            harness
                .run_command(&["proxy", "add", "rejected", url])
                .success
        );
        assert!(harness.run_command(&["activate", "rejected"]).success);
        let mut config: toml::Value =
            toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
        if let Some(username) = username {
            let mut auth = toml::Table::new();
            auth.insert("username".into(), username.into());
            config["proxies"][0]["auth"] = auth.into();
        }
        std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
        let before = std::fs::read(&harness.config_path)?;
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
            .arg("daemon")
            .env("RUST_PROXY_CONFIG", &harness.config_path)
            .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
            .env("RUST_PROXY_TEST_MODE", "1")
            .output()?;
        assert!(!result.status.success());
        assert!(
            std::net::TcpStream::connect(("127.0.0.1", harness.listen_port())).is_err(),
            "rejected endpoint opened a listener"
        );
        assert_eq!(std::fs::read(&harness.config_path)?, before);
        let output = String::from_utf8(result.stderr)?;
        assert!(!output.contains("partial-auth-user"));
    }
    Ok(())
}

/// Test that the test harness can be created
#[tokio::test]
async fn test_harness_creation() {
    let harness = TestHarness::new().await;
    assert!(harness.is_ok(), "Failed to create test harness");
    let harness = harness.unwrap();
    assert!(harness.config_path.exists());
    assert!(harness.state_dir.exists());
    harness.cleanup().await;
}

/// Test that we can create a mock proxy server
#[tokio::test]
async fn test_mock_proxy_creation() {
    let mock = MockProxy::new(0, MockBehavior::Healthy { latency_ms: 0 }).await;
    assert!(mock.is_ok(), "Failed to create mock proxy");
    let mock = mock.unwrap();
    assert!(mock.port > 0);
    assert!(!mock.url().is_empty());
}

/// Test that config fixtures generate valid TOML
#[test]
fn test_fixtures_are_valid_toml() {
    let configs = [
        fixtures::minimal_config(12345),
        fixtures::single_proxy_config(12345, "http://localhost:8080"),
        fixtures::multi_proxy_config(12345, &["http://localhost:8080", "http://localhost:8081"]),
        fixtures::config_with_health_check(12345, "http://localhost:8080", 5, 3),
        fixtures::config_with_failover(12345, "http://localhost:8080", "http://localhost:8081", 30),
    ];

    for (i, config) in configs.iter().enumerate() {
        let result: Result<toml::Value, _> = toml::from_str(config);
        assert!(
            result.is_ok(),
            "Fixture {} failed to parse as TOML: {:?}",
            i,
            result.err()
        );
    }
}

/// Test the assertion helpers
#[test]
fn test_assertion_json_path() {
    let json: serde_json::Value = serde_json::json!({
        "name": "test",
        "nested": {
            "value": 42,
            "array": [1, 2, 3]
        }
    });

    assert_json_field_exists(&json, "name", "name should exist");
    assert_json_field_exists(&json, "nested.value", "nested.value should exist");
    assert_json_field_is_string(&json, "name", "name should be string");
    assert_json_field_is_array(&json, "nested.array", "nested.array should be array");
    assert_json_array_len(&json, "nested.array", 3, "array should have 3 elements");
}

/// Test TOON output round-trip for list output
#[tokio::test]
async fn test_list_toon_roundtrip() {
    let harness = TestHarness::new().await.expect("Failed to create harness");

    let json_result = harness.run_command(&["list", "--format", "json"]);
    assert!(
        json_result.success,
        "list --format json failed: {}",
        json_result.stderr
    );

    let toon_result = harness.run_command(&["list", "--format", "toon"]);
    assert!(
        toon_result.success,
        "list --format toon failed: {}",
        toon_result.stderr
    );

    let decoded =
        toon_rust::try_decode(&toon_result.stdout, None).expect("Failed to decode TOON output");
    let expected: serde_json::Value =
        serde_json::from_str(&json_result.stdout).expect("Failed to parse JSON output");
    assert_eq!(decoded, expected.into());

    harness.cleanup().await;
}

/// Different requested state directories must isolate actual CLI writes even
/// when both processes inherit the same HOME and XDG defaults.
#[tokio::test]
async fn explicit_state_directories_isolate_cli_activation_and_statistics() -> anyhow::Result<()> {
    let first = TestHarness::new().await?;
    let second = TestHarness::new().await?;
    for (harness, id) in [(&first, "isolated-first"), (&second, "isolated-second")] {
        for args in [
            vec!["proxy", "add", id, "http://127.0.0.1:12345"],
            vec!["activate", id],
        ] {
            let result = harness.run_command(&args);
            assert!(result.success, "{args:?}: {}", result.stderr);
        }
        assert!(harness.state_dir.join("state.json").is_file());
    }
    let first_stats = first.run_command(&["list", "--json"]).json()?["stats"].clone();
    let second_stats = second.run_command(&["list", "--json"]).json()?["stats"].clone();
    assert_eq!(first_stats["proxies"].as_object().unwrap().len(), 1);
    assert_eq!(second_stats["proxies"].as_object().unwrap().len(), 1);
    assert!(first_stats["proxies"]["isolated-first"]["activated_at"].is_string());
    assert!(first_stats["proxies"]["isolated-second"].is_null());
    assert!(second_stats["proxies"]["isolated-second"]["activated_at"].is_string());
    assert!(second_stats["proxies"]["isolated-first"].is_null());
    Ok(())
}

/// Real CLI mutations and diagnostics; the no-DNS path establishes config
/// identity only. Kernel interception is qualified separately.
#[tokio::test]
async fn custom_domain_onboarding_has_truthful_provider_and_canonical_identity(
) -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;
    for args in [
        vec!["init"],
        vec!["proxy", "add", "customer-proxy", "http://127.0.0.1:12345"],
        vec!["targets", "add", "Customer.Example.Invalid."],
        vec!["activate", "customer-proxy"],
        vec![
            "targets",
            "add",
            "hinted.example.invalid",
            "--provider",
            "cloudflare",
        ],
        vec!["targets", "add", "API.OpenAI.com."],
    ] {
        let result = harness.run_command(&args);
        assert!(result.success, "{args:?}: {}", result.stderr);
    }
    let check = harness.run_command(&["check", "--json"]);
    assert!(check.success, "{} {}", check.stdout, check.stderr);
    check.json()?;

    let listed = harness.run_command(&["targets", "list", "--json"]);
    assert!(listed.success, "{}", listed.stderr);
    let targets = listed.json()?;
    assert_eq!(targets[0]["domain"], "customer.example.invalid");
    assert!(targets[0]["provider"].is_null());
    assert_eq!(targets[1]["provider"], "cloudflare");
    assert_eq!(targets[2]["provider"], "openai");

    let test = harness.run_command(&[
        "test",
        "Customer.Example.Invalid.",
        "--json",
        "--verbose",
        "--no-dns",
    ]);
    assert!(test.success, "{}", test.stderr);
    let decision = test.json()?;
    assert_eq!(decision["domain"], "customer.example.invalid");
    assert_eq!(decision["would_proxy"], true);
    assert!(decision["routing_decision"]["target_provider"].is_null());
    assert_eq!(decision["active_proxy"]["id"], "customer-proxy");

    let toon = harness.run_command(&["targets", "list", "--format", "toon"]);
    assert!(toon.success, "{}", toon.stderr);
    assert_eq!(toon_rust::try_decode(&toon.stdout, None)?, targets.into());

    let before = std::fs::read(&harness.config_path)?;
    for domain in [
        "CUSTOMER.EXAMPLE.INVALID",
        "https://bad.invalid",
        "bad.invalid:443",
        "bad..invalid",
        "*.bad.invalid",
        "bad.invalid/path",
    ] {
        let result = harness.run_command(&["targets", "add", domain]);
        assert!(!result.success, "accepted {domain}");
        assert_eq!(
            std::fs::read(&harness.config_path)?,
            before,
            "failed mutation changed config"
        );
    }
    let removed = harness.run_command(&["targets", "remove", "CUSTOMER.EXAMPLE.INVALID."]);
    assert!(removed.success, "{}", removed.stderr);
    let direct = harness.run_command(&["test", "customer.example.invalid", "--json", "--no-dns"]);
    assert_eq!(direct.json()?["would_proxy"], false);
    Ok(())
}

/// Fault-injected executables prove CLI error classification and config
/// preservation. They do not establish kernel rule removal.
#[tokio::test]
async fn deactivate_reports_permission_failure_and_accepts_confirmed_absence() -> anyhow::Result<()>
{
    use std::os::unix::fs::PermissionsExt;
    let harness = TestHarness::new().await?;
    let added = harness.run_command(&["proxy", "add", "upstream", "http://127.0.0.1:12345"]);
    assert!(added.success, "{}", added.stderr);
    let activated = harness.run_command(&["activate", "upstream"]);
    assert!(activated.success, "{}", activated.stderr);
    let before = std::fs::read(&harness.config_path)?;
    let bin_dir = harness.temp_dir.path().join("fault-tools");
    std::fs::create_dir(&bin_dir)?;
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
            .arg("deactivate")
            .env("RUST_PROXY_CONFIG", &harness.config_path)
            .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
            .env("PATH", &bin_dir)
            .output()
    };
    for (name, message, code) in [
        (
            "iptables",
            "Could not fetch rule set generation id: Permission denied",
            4,
        ),
        ("ipset", "Permission denied", 1),
    ] {
        let path = bin_dir.join(name);
        std::fs::write(
            &path,
            format!("#!/bin/sh\nprintf '%s\\n' '{message}' >&2\nexit {code}\n"),
        )?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    let denied = run()?;
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("Permission denied"));
    assert!(!String::from_utf8_lossy(&denied.stdout).contains("deactivated"));
    assert_eq!(std::fs::read(&harness.config_path)?, before);
    for (name, message) in [
        ("iptables", "No chain/target/match by that name."),
        ("ipset", "The set with the given name does not exist"),
    ] {
        std::fs::write(
            bin_dir.join(name),
            format!("#!/bin/sh\nprintf '%s\\n' '{message}' >&2\nexit 1\n"),
        )?;
    }
    let absent = run()?;
    assert!(
        absent.status.success(),
        "{}",
        String::from_utf8_lossy(&absent.stderr)
    );
    assert!(String::from_utf8_lossy(&absent.stdout).contains("deactivated"));
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
    assert!(config.get("active_proxy").is_none());
    assert_eq!(config["settings"]["routing_enabled"].as_bool(), Some(false));
    assert!(harness.run_command(&["activate", "upstream"]).success);
    let reactivated: toml::Value = toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
    assert_eq!(
        reactivated["settings"]["routing_enabled"].as_bool(),
        Some(true)
    );
    Ok(())
}

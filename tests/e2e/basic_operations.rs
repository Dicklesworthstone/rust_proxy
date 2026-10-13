//! Basic E2E tests for rust_proxy CLI operations.
//!
//! Tests the fundamental CLI commands without daemon functionality.

use crate::common::assertions::*;
use crate::common::fixtures;
use crate::common::mock_proxy::{MockBehavior, MockProxy};
use crate::common::TestHarness;

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
    Ok(())
}

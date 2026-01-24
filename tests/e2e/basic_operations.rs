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
    let configs = vec![
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

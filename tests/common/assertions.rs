//! Custom assertion helpers for E2E tests.
//!
//! Provides domain-specific assertions that produce clear error messages.

use crate::common::CommandResult;
use serde_json::Value;

/// Assert that a command succeeded
pub fn assert_success(result: &CommandResult, context: &str) {
    assert!(
        result.success,
        "{}: Command failed with exit code {}\nstdout: {}\nstderr: {}",
        context, result.exit_code, result.stdout, result.stderr
    );
}

/// Assert that a command failed
pub fn assert_failure(result: &CommandResult, context: &str) {
    assert!(
        !result.success,
        "{}: Expected command to fail but it succeeded\nstdout: {}\nstderr: {}",
        context, result.stdout, result.stderr
    );
}

/// Assert that stdout contains a specific string
pub fn assert_stdout_contains(result: &CommandResult, expected: &str, context: &str) {
    assert!(
        result.stdout.contains(expected),
        "{}: Expected stdout to contain '{}'\nActual stdout: {}",
        context,
        expected,
        result.stdout
    );
}

/// Assert that stderr contains a specific string
pub fn assert_stderr_contains(result: &CommandResult, expected: &str, context: &str) {
    assert!(
        result.stderr.contains(expected),
        "{}: Expected stderr to contain '{}'\nActual stderr: {}",
        context,
        expected,
        result.stderr
    );
}

/// Assert that stdout does not contain a specific string
pub fn assert_stdout_not_contains(result: &CommandResult, unexpected: &str, context: &str) {
    assert!(
        !result.stdout.contains(unexpected),
        "{}: Expected stdout to NOT contain '{}'\nActual stdout: {}",
        context,
        unexpected,
        result.stdout
    );
}

/// Assert JSON field equals expected value
pub fn assert_json_field_eq(json: &Value, path: &str, expected: &str, context: &str) {
    let actual = json_path_get(json, path);
    let expected_val: Value =
        serde_json::from_str(expected).unwrap_or_else(|_| Value::String(expected.to_string()));

    assert_eq!(
        actual,
        Some(&expected_val),
        "{}: JSON path '{}' expected {:?}, got {:?}",
        context,
        path,
        expected,
        actual
    );
}

/// Assert JSON field exists
pub fn assert_json_field_exists(json: &Value, path: &str, context: &str) {
    assert!(
        json_path_get(json, path).is_some(),
        "{}: Expected JSON path '{}' to exist\nJSON: {}",
        context,
        path,
        serde_json::to_string_pretty(json).unwrap_or_default()
    );
}

/// Assert JSON field is a specific type
pub fn assert_json_field_is_string(json: &Value, path: &str, context: &str) {
    let value = json_path_get(json, path);
    assert!(
        value.map(|v| v.is_string()).unwrap_or(false),
        "{}: Expected JSON path '{}' to be a string\nActual: {:?}",
        context,
        path,
        value
    );
}

/// Assert JSON field is an array
pub fn assert_json_field_is_array(json: &Value, path: &str, context: &str) {
    let value = json_path_get(json, path);
    assert!(
        value.map(|v| v.is_array()).unwrap_or(false),
        "{}: Expected JSON path '{}' to be an array\nActual: {:?}",
        context,
        path,
        value
    );
}

/// Assert JSON array has expected length
pub fn assert_json_array_len(json: &Value, path: &str, expected_len: usize, context: &str) {
    let value = json_path_get(json, path);
    let actual_len = value
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    assert_eq!(
        actual_len, expected_len,
        "{}: Expected array at '{}' to have length {}, got {}",
        context, path, expected_len, actual_len
    );
}

/// Assert proxy health status
pub fn assert_proxy_health(json: &Value, proxy_id: &str, expected_status: &str, context: &str) {
    let path = format!("proxies.{}.health_status", proxy_id);
    let status = json_path_get(json, &path);
    let actual = status.and_then(|v| v.as_str()).unwrap_or("unknown");

    assert_eq!(
        actual, expected_status,
        "{}: Expected proxy '{}' health to be '{}', got '{}'",
        context, proxy_id, expected_status, actual
    );
}

/// Assert effective proxy matches expected
pub fn assert_effective_proxy(json: &Value, expected_proxy: &str, context: &str) {
    let effective = json_path_get(json, "effective_proxy");
    let actual = effective.and_then(|v| v.as_str()).unwrap_or("");

    assert_eq!(
        actual, expected_proxy,
        "{}: Expected effective proxy '{}', got '{}'",
        context, expected_proxy, actual
    );
}

/// Assert that a proxy is listed in the configuration
pub fn assert_proxy_exists(json: &Value, proxy_id: &str, context: &str) {
    let proxies = json_path_get(json, "proxies");
    let exists = proxies
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .any(|p| p.get("id").and_then(|i| i.as_str()) == Some(proxy_id))
        })
        .unwrap_or(false);

    // Also check if it's an object with the proxy id as a key
    let exists_as_key = proxies
        .and_then(|v| v.as_object())
        .map(|obj| obj.contains_key(proxy_id))
        .unwrap_or(false);

    assert!(
        exists || exists_as_key,
        "{}: Expected proxy '{}' to exist in proxies list\nProxies: {:?}",
        context,
        proxy_id,
        proxies
    );
}

/// Assert that a target domain is listed
pub fn assert_target_exists(json: &Value, domain: &str, context: &str) {
    let targets = json_path_get(json, "targets");
    let exists = targets
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().any(|t| {
                t.get("domain").and_then(|d| d.as_str()) == Some(domain)
                    || t.as_str() == Some(domain)
            })
        })
        .unwrap_or(false);

    assert!(
        exists,
        "{}: Expected target '{}' to exist in targets list\nTargets: {:?}",
        context, domain, targets
    );
}

/// Simple JSON path getter (supports dot notation only)
fn json_path_get<'a>(json: &'a Value, path: &str) -> Option<&'a Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = json;

    for part in parts {
        // Try as object key first
        if let Some(obj) = current.as_object() {
            if let Some(value) = obj.get(part) {
                current = value;
                continue;
            }
        }

        // Try as array index
        if let Ok(idx) = part.parse::<usize>() {
            if let Some(arr) = current.as_array() {
                if let Some(value) = arr.get(idx) {
                    current = value;
                    continue;
                }
            }
        }

        return None;
    }

    Some(current)
}

/// Assert that two durations are approximately equal (within tolerance)
pub fn assert_duration_approx(actual_ms: u64, expected_ms: u64, tolerance_ms: u64, context: &str) {
    let diff = if actual_ms > expected_ms {
        actual_ms - expected_ms
    } else {
        expected_ms - actual_ms
    };

    assert!(
        diff <= tolerance_ms,
        "{}: Expected duration ~{}ms (+/- {}ms), got {}ms",
        context,
        expected_ms,
        tolerance_ms,
        actual_ms
    );
}

/// Assert that a condition becomes true within a timeout
pub async fn assert_eventually<F>(
    mut condition: F,
    timeout_ms: u64,
    poll_interval_ms: u64,
    context: &str,
) where
    F: FnMut() -> bool,
{
    use std::time::{Duration, Instant};
    use tokio::time::sleep;

    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let poll = Duration::from_millis(poll_interval_ms);

    while start.elapsed() < timeout {
        if condition() {
            return;
        }
        sleep(poll).await;
    }

    panic!(
        "{}: Condition did not become true within {}ms",
        context, timeout_ms
    );
}

/// Macro for convenient test assertion with automatic context
#[macro_export]
macro_rules! assert_cmd_success {
    ($result:expr) => {
        $crate::common::assertions::assert_success(&$result, concat!(file!(), ":", line!()))
    };
    ($result:expr, $context:expr) => {
        $crate::common::assertions::assert_success(&$result, $context)
    };
}

#[macro_export]
macro_rules! assert_cmd_failure {
    ($result:expr) => {
        $crate::common::assertions::assert_failure(&$result, concat!(file!(), ":", line!()))
    };
    ($result:expr, $context:expr) => {
        $crate::common::assertions::assert_failure(&$result, $context)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_path_get_simple() {
        let json: Value = serde_json::json!({
            "name": "test",
            "nested": {
                "value": 42
            }
        });

        assert_eq!(
            json_path_get(&json, "name"),
            Some(&Value::String("test".to_string()))
        );
        assert_eq!(
            json_path_get(&json, "nested.value"),
            Some(&Value::Number(42.into()))
        );
        assert_eq!(json_path_get(&json, "missing"), None);
    }

    #[test]
    fn test_json_path_get_array() {
        let json: Value = serde_json::json!({
            "items": ["a", "b", "c"]
        });

        assert_eq!(
            json_path_get(&json, "items.0"),
            Some(&Value::String("a".to_string()))
        );
        assert_eq!(
            json_path_get(&json, "items.2"),
            Some(&Value::String("c".to_string()))
        );
        assert_eq!(json_path_get(&json, "items.5"), None);
    }

    #[test]
    fn test_assert_duration_approx_passes() {
        assert_duration_approx(100, 100, 10, "exact match");
        assert_duration_approx(105, 100, 10, "within tolerance");
        assert_duration_approx(95, 100, 10, "within tolerance below");
    }

    #[test]
    #[should_panic(expected = "Expected duration")]
    fn test_assert_duration_approx_fails() {
        assert_duration_approx(120, 100, 10, "outside tolerance");
    }
}

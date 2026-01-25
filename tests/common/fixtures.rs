//! Test fixtures for E2E tests.
//!
//! Provides configuration templates and test data generators.

#![expect(dead_code)]

/// Generate a minimal configuration for testing
pub fn minimal_config(listen_port: u16) -> String {
    format!(
        r#"# Minimal test configuration

[settings]
listen_port = {listen_port}
dns_refresh_secs = 60
ping_interval_secs = 30
ping_timeout_ms = 1000
ipset_name = "rust_proxy_test"
chain_name = "RUST_PROXY_TEST"
include_aws_ip_ranges = false
include_cloudflare_ip_ranges = false
include_google_ip_ranges = false
connect_max_retries = 2
connect_initial_backoff_ms = 50
connect_max_backoff_ms = 1000
health_check_enabled = false
metrics_enabled = false
"#
    )
}

/// Generate a configuration with a single proxy
pub fn single_proxy_config(listen_port: u16, proxy_url: &str) -> String {
    format!(
        r#"# Single proxy test configuration
active_proxy = "test-proxy"

[[proxies]]
id = "test-proxy"
url = "{proxy_url}"

[[targets]]
domain = "example.com"

[settings]
listen_port = {listen_port}
dns_refresh_secs = 60
ping_interval_secs = 30
ping_timeout_ms = 1000
ipset_name = "rust_proxy_test"
chain_name = "RUST_PROXY_TEST"
include_aws_ip_ranges = false
include_cloudflare_ip_ranges = false
include_google_ip_ranges = false
connect_max_retries = 2
connect_initial_backoff_ms = 50
connect_max_backoff_ms = 1000
health_check_enabled = false
metrics_enabled = false
"#
    )
}

/// Generate a configuration with multiple proxies
pub fn multi_proxy_config(listen_port: u16, proxy_urls: &[&str]) -> String {
    let proxies: String = proxy_urls
        .iter()
        .enumerate()
        .map(|(i, url)| {
            format!(
                r#"
[[proxies]]
id = "proxy-{}"
url = "{}"
priority = {}
"#,
                i + 1,
                url,
                i + 1
            )
        })
        .collect();

    format!(
        r#"# Multi-proxy test configuration
active_proxy = "proxy-1"

{proxies}

[[targets]]
domain = "example.com"

[settings]
listen_port = {listen_port}
dns_refresh_secs = 60
ping_interval_secs = 30
ping_timeout_ms = 1000
ipset_name = "rust_proxy_test"
chain_name = "RUST_PROXY_TEST"
include_aws_ip_ranges = false
include_cloudflare_ip_ranges = false
include_google_ip_ranges = false
connect_max_retries = 2
connect_initial_backoff_ms = 50
connect_max_backoff_ms = 1000
health_check_enabled = false
metrics_enabled = false
"#
    )
}

/// Generate a configuration with health checking enabled
pub fn config_with_health_check(
    listen_port: u16,
    proxy_url: &str,
    interval_secs: u64,
    threshold: u32,
) -> String {
    format!(
        r#"# Health check test configuration
active_proxy = "test-proxy"

[[proxies]]
id = "test-proxy"
url = "{proxy_url}"

[[targets]]
domain = "example.com"

[settings]
listen_port = {listen_port}
dns_refresh_secs = 60
ping_interval_secs = 30
ping_timeout_ms = 1000
ipset_name = "rust_proxy_test"
chain_name = "RUST_PROXY_TEST"
include_aws_ip_ranges = false
include_cloudflare_ip_ranges = false
include_google_ip_ranges = false
connect_max_retries = 2
connect_initial_backoff_ms = 50
connect_max_backoff_ms = 1000

# Health check settings
health_check_enabled = true
health_check_interval_secs = {interval_secs}
health_check_timeout_ms = 2000
consecutive_failures_threshold = {threshold}

metrics_enabled = false
"#
    )
}

/// Generate a configuration with failover enabled
pub fn config_with_failover(
    listen_port: u16,
    primary_url: &str,
    secondary_url: &str,
    failback_delay_secs: u64,
) -> String {
    format!(
        r#"# Failover test configuration
active_proxy = "primary"

[[proxies]]
id = "primary"
url = "{primary_url}"
priority = 1

[[proxies]]
id = "secondary"
url = "{secondary_url}"
priority = 2

[[targets]]
domain = "example.com"

[settings]
listen_port = {listen_port}
dns_refresh_secs = 60
ping_interval_secs = 30
ping_timeout_ms = 1000
ipset_name = "rust_proxy_test"
chain_name = "RUST_PROXY_TEST"
include_aws_ip_ranges = false
include_cloudflare_ip_ranges = false
include_google_ip_ranges = false
connect_max_retries = 2
connect_initial_backoff_ms = 50
connect_max_backoff_ms = 1000

# Health check and failover settings
health_check_enabled = true
health_check_interval_secs = 2
health_check_timeout_ms = 2000
consecutive_failures_threshold = 2
auto_failover = true
auto_failback = true
failback_delay_secs = {failback_delay_secs}

metrics_enabled = false
"#
    )
}

/// Generate a configuration with load balancing
pub fn config_with_load_balancing(
    listen_port: u16,
    proxy_urls: &[(&str, u32)], // (url, weight)
    strategy: &str,
) -> String {
    let proxies: String = proxy_urls
        .iter()
        .enumerate()
        .map(|(i, (url, weight))| {
            format!(
                r#"
[[proxies]]
id = "proxy-{}"
url = "{}"
weight = {}
"#,
                i + 1,
                url,
                weight
            )
        })
        .collect();

    format!(
        r#"# Load balancing test configuration
active_proxy = "proxy-1"

{proxies}

[[targets]]
domain = "example.com"

[settings]
listen_port = {listen_port}
dns_refresh_secs = 60
ping_interval_secs = 30
ping_timeout_ms = 1000
ipset_name = "rust_proxy_test"
chain_name = "RUST_PROXY_TEST"
include_aws_ip_ranges = false
include_cloudflare_ip_ranges = false
include_google_ip_ranges = false
connect_max_retries = 2
connect_initial_backoff_ms = 50
connect_max_backoff_ms = 1000

# Load balancing settings
load_balance_strategy = "{strategy}"
health_check_enabled = true
health_check_interval_secs = 5
health_check_timeout_ms = 2000
consecutive_failures_threshold = 3

metrics_enabled = false
"#
    )
}

/// Generate a configuration with metrics enabled
pub fn config_with_metrics(listen_port: u16, proxy_url: &str, metrics_port: u16) -> String {
    format!(
        r#"# Metrics test configuration
active_proxy = "test-proxy"

[[proxies]]
id = "test-proxy"
url = "{proxy_url}"

[[targets]]
domain = "example.com"

[settings]
listen_port = {listen_port}
dns_refresh_secs = 60
ping_interval_secs = 30
ping_timeout_ms = 1000
ipset_name = "rust_proxy_test"
chain_name = "RUST_PROXY_TEST"
include_aws_ip_ranges = false
include_cloudflare_ip_ranges = false
include_google_ip_ranges = false
connect_max_retries = 2
connect_initial_backoff_ms = 50
connect_max_backoff_ms = 1000

# Metrics settings
metrics_enabled = true
metrics_port = {metrics_port}
metrics_path = "/metrics"
metrics_bind = "127.0.0.1"

health_check_enabled = false
"#
    )
}

/// Generate a configuration with degradation policy
pub fn config_with_degradation(
    listen_port: u16,
    proxy_urls: &[&str],
    policy: &str,
    delay_secs: u64,
) -> String {
    let proxies: String = proxy_urls
        .iter()
        .enumerate()
        .map(|(i, url)| {
            format!(
                r#"
[[proxies]]
id = "proxy-{}"
url = "{}"
priority = {}
"#,
                i + 1,
                url,
                i + 1
            )
        })
        .collect();

    format!(
        r#"# Degradation test configuration
active_proxy = "proxy-1"

{proxies}

[[targets]]
domain = "example.com"

[settings]
listen_port = {listen_port}
dns_refresh_secs = 60
ping_interval_secs = 30
ping_timeout_ms = 1000
ipset_name = "rust_proxy_test"
chain_name = "RUST_PROXY_TEST"
include_aws_ip_ranges = false
include_cloudflare_ip_ranges = false
include_google_ip_ranges = false
connect_max_retries = 2
connect_initial_backoff_ms = 50
connect_max_backoff_ms = 1000

# Health and degradation settings
health_check_enabled = true
health_check_interval_secs = 2
health_check_timeout_ms = 2000
consecutive_failures_threshold = 2
auto_failover = true
degradation_policy = "{policy}"
degradation_delay_secs = {delay_secs}
allow_direct_fallback = false

metrics_enabled = false
"#
    )
}

/// Generate a configuration with multiple targets
pub fn config_with_targets(listen_port: u16, proxy_url: &str, targets: &[&str]) -> String {
    let targets_toml: String = targets
        .iter()
        .map(|domain| {
            format!(
                r#"
[[targets]]
domain = "{}"
"#,
                domain
            )
        })
        .collect();

    format!(
        r#"# Multiple targets test configuration
active_proxy = "test-proxy"

[[proxies]]
id = "test-proxy"
url = "{proxy_url}"

{targets_toml}

[settings]
listen_port = {listen_port}
dns_refresh_secs = 60
ping_interval_secs = 30
ping_timeout_ms = 1000
ipset_name = "rust_proxy_test"
chain_name = "RUST_PROXY_TEST"
include_aws_ip_ranges = false
include_cloudflare_ip_ranges = false
include_google_ip_ranges = false
connect_max_retries = 2
connect_initial_backoff_ms = 50
connect_max_backoff_ms = 1000
health_check_enabled = false
metrics_enabled = false
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_config_is_valid_toml() {
        let config = minimal_config(12345);
        let parsed: Result<toml::Value, _> = toml::from_str(&config);
        assert!(parsed.is_ok(), "Failed to parse: {:?}", parsed.err());
    }

    #[test]
    fn test_single_proxy_config_is_valid_toml() {
        let config = single_proxy_config(12345, "http://localhost:8080");
        let parsed: Result<toml::Value, _> = toml::from_str(&config);
        assert!(parsed.is_ok(), "Failed to parse: {:?}", parsed.err());
    }

    #[test]
    fn test_multi_proxy_config_is_valid_toml() {
        let config = multi_proxy_config(12345, &["http://localhost:8080", "http://localhost:8081"]);
        let parsed: Result<toml::Value, _> = toml::from_str(&config);
        assert!(parsed.is_ok(), "Failed to parse: {:?}", parsed.err());
    }

    #[test]
    fn test_health_check_config_is_valid_toml() {
        let config = config_with_health_check(12345, "http://localhost:8080", 5, 3);
        let parsed: Result<toml::Value, _> = toml::from_str(&config);
        assert!(parsed.is_ok(), "Failed to parse: {:?}", parsed.err());
    }

    #[test]
    fn test_failover_config_is_valid_toml() {
        let config =
            config_with_failover(12345, "http://localhost:8080", "http://localhost:8081", 30);
        let parsed: Result<toml::Value, _> = toml::from_str(&config);
        assert!(parsed.is_ok(), "Failed to parse: {:?}", parsed.err());
    }

    #[test]
    fn test_load_balancing_config_is_valid_toml() {
        let config = config_with_load_balancing(
            12345,
            &[
                ("http://localhost:8080", 100),
                ("http://localhost:8081", 50),
            ],
            "weighted",
        );
        let parsed: Result<toml::Value, _> = toml::from_str(&config);
        assert!(parsed.is_ok(), "Failed to parse: {:?}", parsed.err());
    }
}

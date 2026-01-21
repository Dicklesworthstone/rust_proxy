use crate::config::{AppConfig, DegradationPolicy, ProxyConfig, Settings, TargetSpec};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Severity level for validation results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ValidationSeverity {
    Error,
    Warning,
    Info,
}

/// A single validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub severity: ValidationSeverity,
    pub category: &'static str,
    pub id: Option<String>,
    pub message: String,
    pub suggestion: Option<String>,
}

impl ValidationResult {
    pub fn error(category: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: ValidationSeverity::Error,
            category,
            id: None,
            message: message.into(),
            suggestion: None,
        }
    }

    pub fn warning(category: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: ValidationSeverity::Warning,
            category,
            id: None,
            message: message.into(),
            suggestion: None,
        }
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }
}

/// Complete validation report
#[derive(Debug, Clone)]
pub struct ValidationReport {
    #[allow(dead_code)]
    pub config_path: PathBuf,
    pub results: Vec<ValidationResult>,
}

impl ValidationReport {
    pub fn has_errors(&self) -> bool {
        self.results
            .iter()
            .any(|r| r.severity == ValidationSeverity::Error)
    }

    pub fn has_warnings(&self) -> bool {
        self.results
            .iter()
            .any(|r| r.severity == ValidationSeverity::Warning)
    }

    pub fn error_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.severity == ValidationSeverity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.severity == ValidationSeverity::Warning)
            .count()
    }
}

/// Main entry point for configuration validation
pub fn validate_config(config: &AppConfig, config_path: &Path) -> ValidationReport {
    let mut results = Vec::new();

    // Validate proxies
    results.extend(validate_proxies(&config.proxies));

    // Validate targets
    results.extend(validate_targets(&config.targets));

    // Validate settings
    results.extend(validate_settings(&config.settings));

    // Validate active proxy reference
    results.extend(validate_active_proxy(
        config.active_proxy.as_deref(),
        &config.proxies,
    ));

    ValidationReport {
        config_path: config_path.to_path_buf(),
        results,
    }
}

/// Validate proxy configurations
pub fn validate_proxies(proxies: &[ProxyConfig]) -> Vec<ValidationResult> {
    let mut results = Vec::new();
    let mut seen_ids = HashSet::new();

    for proxy in proxies {
        // Check for duplicate IDs
        if !seen_ids.insert(&proxy.id) {
            results.push(
                ValidationResult::error("proxy", format!("Duplicate proxy ID: {}", proxy.id))
                    .with_id(&proxy.id),
            );
        }

        // Validate URL format
        if let Err(e) = crate::util::parse_proxy_url(&proxy.url) {
            results.push(
                ValidationResult::error("proxy", format!("Invalid proxy URL: {}", e))
                    .with_id(&proxy.id)
                    .with_suggestion("URL must be in format http://host:port or https://host:port"),
            );
        } else {
            // Check for http/https scheme
            if !proxy.url.starts_with("http://") && !proxy.url.starts_with("https://") {
                results.push(
                    ValidationResult::warning(
                        "proxy",
                        "URL missing scheme, will default to http://",
                    )
                    .with_id(&proxy.id)
                    .with_suggestion("Consider specifying http:// or https:// explicitly"),
                );
            }
        }

        // Validate auth configuration
        let auth_results = validate_proxy_auth(&proxy.auth, &proxy.id);
        results.extend(auth_results);
    }

    // Warn if no proxies defined
    if proxies.is_empty() {
        results.push(
            ValidationResult::warning("proxy", "No proxies configured")
                .with_suggestion("Add a proxy with: rust_proxy proxy add <id> <url>"),
        );
    }

    results
}

/// Validate proxy authentication configuration
fn validate_proxy_auth(auth: &crate::config::ProxyAuth, proxy_id: &str) -> Vec<ValidationResult> {
    let mut results = Vec::new();

    // Check if using env vars
    if let Some(ref env_user) = auth.username_env {
        if std::env::var(env_user).is_err() {
            results.push(
                ValidationResult::error(
                    "proxy",
                    format!("{} environment variable not set", env_user),
                )
                .with_id(proxy_id)
                .with_suggestion(format!(
                    "Set {} or use --username flag when adding proxy",
                    env_user
                )),
            );
        } else if std::env::var(env_user).unwrap_or_default().is_empty() {
            results.push(
                ValidationResult::error(
                    "proxy",
                    format!("{} environment variable is empty", env_user),
                )
                .with_id(proxy_id),
            );
        }
    }

    if let Some(ref env_pass) = auth.password_env {
        if std::env::var(env_pass).is_err() {
            results.push(
                ValidationResult::error(
                    "proxy",
                    format!("{} environment variable not set", env_pass),
                )
                .with_id(proxy_id)
                .with_suggestion(format!(
                    "Set {} or use --password flag when adding proxy",
                    env_pass
                )),
            );
        } else if std::env::var(env_pass).unwrap_or_default().is_empty() {
            results.push(
                ValidationResult::error(
                    "proxy",
                    format!("{} environment variable is empty", env_pass),
                )
                .with_id(proxy_id),
            );
        }
    }

    // Warn about plaintext credentials
    if auth.username.is_some() || auth.password.is_some() {
        results.push(
            ValidationResult::warning("proxy", "Using plaintext credentials in config file")
                .with_id(proxy_id)
                .with_suggestion("Consider using --username-env/--password-env for security"),
        );
    }

    results
}

/// Validate target domain configurations
pub fn validate_targets(targets: &[TargetSpec]) -> Vec<ValidationResult> {
    let mut results = Vec::new();
    let mut seen_domains = HashSet::new();

    for target in targets {
        let domain = target.domain();

        // Check for duplicate domains
        if !seen_domains.insert(domain.to_lowercase()) {
            results.push(
                ValidationResult::warning("target", format!("Duplicate target domain: {}", domain))
                    .with_id(domain),
            );
        }

        // Check for protocol prefix
        if domain.starts_with("http://") || domain.starts_with("https://") {
            results.push(
                ValidationResult::error(
                    "target",
                    format!("Domain has protocol prefix: {}", domain),
                )
                .with_id(domain)
                .with_suggestion("Remove the protocol prefix (use just the domain name)"),
            );
        }

        // Check for path component
        if domain.contains('/') {
            results.push(
                ValidationResult::error("target", format!("Domain contains path: {}", domain))
                    .with_id(domain)
                    .with_suggestion("Domains should not include paths"),
            );
        }

        // Check for port in domain (not typically valid for target matching)
        if domain.contains(':') && !domain.starts_with("http") {
            results.push(
                ValidationResult::warning(
                    "target",
                    format!("Domain contains port number: {}", domain),
                )
                .with_id(domain)
                .with_suggestion("Target matching is typically done by domain name only"),
            );
        }

        // Validate hostname characters (basic check)
        if !is_valid_hostname(domain) {
            results.push(
                ValidationResult::error("target", format!("Invalid hostname format: {}", domain))
                    .with_id(domain)
                    .with_suggestion(
                        "Hostnames should contain only alphanumeric characters, dots, and hyphens",
                    ),
            );
        }

        // Validate provider hint for Detailed targets
        if let TargetSpec::Detailed { provider, .. } = target {
            // Provider is already validated by serde deserialization
            // Just check if it's the expected one based on domain
            if let Some(inferred) = crate::config::infer_provider(domain) {
                if inferred != *provider {
                    results.push(
                        ValidationResult::warning(
                            "target",
                            format!(
                                "Provider hint '{}' differs from inferred '{}'",
                                provider.as_str(),
                                inferred.as_str()
                            ),
                        )
                        .with_id(domain),
                    );
                }
            }
        }
    }

    // Warn if no targets defined
    if targets.is_empty() {
        results.push(
            ValidationResult::warning("target", "No targets configured")
                .with_suggestion("Add targets with: rust_proxy targets add <domain>"),
        );
    }

    results
}

/// Basic hostname validation
fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    // Check each label
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        // Labels should start and end with alphanumeric
        if !label.chars().next().is_some_and(|c| c.is_alphanumeric()) {
            return false;
        }
        if label.len() > 1 && !label.chars().last().is_some_and(|c| c.is_alphanumeric()) {
            return false;
        }
        // All characters should be alphanumeric or hyphen
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

/// Validate a bind address as either an IP address or hostname.
fn is_valid_bind_addr(addr: &str) -> bool {
    if addr.parse::<IpAddr>().is_ok() {
        return true;
    }
    is_valid_hostname(addr)
}

/// Validate settings
pub fn validate_settings(settings: &Settings) -> Vec<ValidationResult> {
    let mut results = Vec::new();

    // listen_port
    if settings.listen_port < 1024 {
        results.push(
            ValidationResult::warning(
                "settings",
                format!(
                    "listen_port ({}) is below 1024, requires root privileges",
                    settings.listen_port
                ),
            )
            .with_id("listen_port"),
        );
    }

    // metrics_port
    if settings.metrics_enabled && settings.metrics_port == settings.listen_port {
        results.push(
            ValidationResult::error(
                "settings",
                "metrics_port must be different from listen_port to avoid conflicts",
            )
            .with_id("metrics_port")
            .with_suggestion("Choose a different metrics_port or change listen_port"),
        );
    }
    if settings.metrics_port == 0 {
        results.push(
            ValidationResult::error("settings", "metrics_port cannot be 0")
                .with_id("metrics_port")
                .with_suggestion("Set metrics_port to a valid TCP port (e.g., 9090)"),
        );
    } else if settings.metrics_enabled && settings.metrics_port < 1024 {
        results.push(
            ValidationResult::warning(
                "settings",
                format!(
                    "metrics_port ({}) is below 1024, requires root privileges",
                    settings.metrics_port
                ),
            )
            .with_id("metrics_port"),
        );
    }

    // metrics_path
    if settings.metrics_path.trim().is_empty() {
        results.push(
            ValidationResult::error("settings", "metrics_path cannot be empty")
                .with_id("metrics_path")
                .with_suggestion("Use a path like /metrics"),
        );
    } else if !settings.metrics_path.starts_with('/') {
        results.push(
            ValidationResult::error(
                "settings",
                format!(
                    "metrics_path must start with '/': {}",
                    settings.metrics_path
                ),
            )
            .with_id("metrics_path")
            .with_suggestion("Prefix the path with '/', e.g. /metrics"),
        );
    }

    // metrics_bind
    if settings.metrics_bind.trim().is_empty() {
        results.push(
            ValidationResult::error("settings", "metrics_bind cannot be empty")
                .with_id("metrics_bind")
                .with_suggestion("Use an IP address like 0.0.0.0 or 127.0.0.1"),
        );
    } else if !is_valid_bind_addr(&settings.metrics_bind) {
        results.push(
            ValidationResult::error(
                "settings",
                format!("metrics_bind is not a valid address: {}", settings.metrics_bind),
            )
            .with_id("metrics_bind")
            .with_suggestion("Use an IP address like 0.0.0.0 or 127.0.0.1"),
        );
    }

    // dns_refresh_secs
    if settings.dns_refresh_secs == 0 {
        results.push(
            ValidationResult::error("settings", "dns_refresh_secs cannot be 0")
                .with_id("dns_refresh_secs")
                .with_suggestion("Set to at least 1 second"),
        );
    } else if settings.dns_refresh_secs < 60 {
        results.push(
            ValidationResult::warning(
                "settings",
                format!(
                    "dns_refresh_secs ({}) is very frequent, consider >= 60",
                    settings.dns_refresh_secs
                ),
            )
            .with_id("dns_refresh_secs"),
        );
    } else if settings.dns_refresh_secs > 86400 {
        results.push(
            ValidationResult::warning(
                "settings",
                format!(
                    "dns_refresh_secs ({}) exceeds 24 hours, may miss IP changes",
                    settings.dns_refresh_secs
                ),
            )
            .with_id("dns_refresh_secs"),
        );
    }

    // ping_interval_secs
    if settings.ping_interval_secs == 0 {
        results.push(
            ValidationResult::error("settings", "ping_interval_secs cannot be 0")
                .with_id("ping_interval_secs")
                .with_suggestion("Set to at least 1 second"),
        );
    } else if settings.ping_interval_secs < 10 {
        results.push(
            ValidationResult::warning(
                "settings",
                format!(
                    "ping_interval_secs ({}) is very frequent, consider >= 10",
                    settings.ping_interval_secs
                ),
            )
            .with_id("ping_interval_secs"),
        );
    } else if settings.ping_interval_secs > 3600 {
        results.push(
            ValidationResult::warning(
                "settings",
                format!(
                    "ping_interval_secs ({}) exceeds 1 hour, proxy failures may go undetected",
                    settings.ping_interval_secs
                ),
            )
            .with_id("ping_interval_secs"),
        );
    }

    // ping_timeout_ms vs ping_interval_secs
    let ping_interval_ms = settings.ping_interval_secs * 1000;
    if settings.ping_timeout_ms >= ping_interval_ms {
        results.push(
            ValidationResult::error(
                "settings",
                format!(
                    "ping_timeout_ms ({}) must be less than ping_interval_secs × 1000 ({})",
                    settings.ping_timeout_ms, ping_interval_ms
                ),
            )
            .with_id("ping_timeout_ms"),
        );
    }

    // ipset_name validation
    if settings.ipset_name.is_empty() {
        results.push(
            ValidationResult::error("settings", "ipset_name cannot be empty").with_id("ipset_name"),
        );
    } else if settings.ipset_name.len() > 31 {
        results.push(
            ValidationResult::error(
                "settings",
                format!(
                    "ipset_name ({}) exceeds 31 characters",
                    settings.ipset_name.len()
                ),
            )
            .with_id("ipset_name"),
        );
    } else if !is_valid_identifier(&settings.ipset_name) {
        results.push(
            ValidationResult::error(
                "settings",
                format!(
                    "ipset_name '{}' contains invalid characters",
                    settings.ipset_name
                ),
            )
            .with_id("ipset_name")
            .with_suggestion("Use only alphanumeric characters and underscores"),
        );
    }

    // chain_name validation
    if settings.chain_name.is_empty() {
        results.push(
            ValidationResult::error("settings", "chain_name cannot be empty").with_id("chain_name"),
        );
    } else if settings.chain_name.len() > 28 {
        results.push(
            ValidationResult::error(
                "settings",
                format!(
                    "chain_name ({}) exceeds 28 characters",
                    settings.chain_name.len()
                ),
            )
            .with_id("chain_name"),
        );
    } else if !is_valid_identifier(&settings.chain_name) {
        results.push(
            ValidationResult::error(
                "settings",
                format!(
                    "chain_name '{}' contains invalid characters",
                    settings.chain_name
                ),
            )
            .with_id("chain_name")
            .with_suggestion("Use only alphanumeric characters and underscores"),
        );
    }

    // connect_max_retries
    if settings.connect_max_retries > 100 {
        results.push(
            ValidationResult::warning(
                "settings",
                format!(
                    "connect_max_retries ({}) is very high, may cause long delays",
                    settings.connect_max_retries
                ),
            )
            .with_id("connect_max_retries"),
        );
    }

    // connect_backoff validation
    if settings.connect_initial_backoff_ms == 0 {
        results.push(
            ValidationResult::error("settings", "connect_initial_backoff_ms cannot be 0")
                .with_id("connect_initial_backoff_ms")
                .with_suggestion("Set to at least 1 millisecond"),
        );
    }

    if settings.connect_max_backoff_ms < settings.connect_initial_backoff_ms {
        results.push(
            ValidationResult::error(
                "settings",
                format!(
                    "connect_max_backoff_ms ({}) must be >= connect_initial_backoff_ms ({})",
                    settings.connect_max_backoff_ms, settings.connect_initial_backoff_ms
                ),
            )
            .with_id("connect_max_backoff_ms"),
        );
    }

    // Degradation policy validation
    if settings.degradation_policy == DegradationPolicy::Direct && !settings.allow_direct_fallback {
        results.push(
            ValidationResult::error(
                "settings",
                "degradation_policy 'direct' requires allow_direct_fallback = true",
            )
            .with_id("degradation_policy")
            .with_suggestion(
                "Set allow_direct_fallback = true in settings to enable direct connections",
            ),
        );
    }

    // Warn about degradation_delay_secs == 0
    if settings.degradation_delay_secs == 0 {
        results.push(
            ValidationResult::warning(
                "settings",
                "degradation_delay_secs = 0 means no debounce before degradation",
            )
            .with_id("degradation_delay_secs")
            .with_suggestion("Consider setting to at least 5 seconds to avoid flapping"),
        );
    }

    results
}

/// Check if a string is a valid identifier (alphanumeric + underscore)
fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Validate active proxy reference
pub fn validate_active_proxy(
    active: Option<&str>,
    proxies: &[ProxyConfig],
) -> Vec<ValidationResult> {
    let mut results = Vec::new();

    match active {
        Some(proxy_id) => {
            // Check if referenced proxy exists
            if !proxies.iter().any(|p| p.id == proxy_id) {
                results.push(
                    ValidationResult::error(
                        "active",
                        format!("Active proxy '{}' not found in proxy list", proxy_id),
                    )
                    .with_id(proxy_id)
                    .with_suggestion("Use 'rust_proxy proxy add' to add this proxy first"),
                );
            }
        }
        None => {
            results.push(
                ValidationResult::warning("active", "No active proxy configured")
                    .with_suggestion("Use 'rust_proxy activate <id>' to set an active proxy"),
            );
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyAuth;

    #[test]
    fn test_valid_hostname() {
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("api.example.com"));
        assert!(is_valid_hostname("my-api.example.com"));
        assert!(is_valid_hostname("a.b.c.d.e"));
    }

    #[test]
    fn test_invalid_hostname() {
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname(".example.com"));
        assert!(!is_valid_hostname("example..com"));
        assert!(!is_valid_hostname("-example.com"));
        assert!(!is_valid_hostname("example-.com"));
        assert!(!is_valid_hostname("exam_ple.com")); // underscore not valid in hostname
    }

    #[test]
    fn test_valid_identifier() {
        assert!(is_valid_identifier("rust_proxy"));
        assert!(is_valid_identifier("CHAIN_NAME"));
        assert!(is_valid_identifier("test123"));
    }

    #[test]
    fn test_invalid_identifier() {
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("test-name"));
        assert!(!is_valid_identifier("test.name"));
        assert!(!is_valid_identifier("test name"));
    }

    #[test]
    fn test_validate_proxies_empty() {
        let results = validate_proxies(&[]);
        assert!(results
            .iter()
            .any(|r| r.message.contains("No proxies configured")));
    }

    #[test]
    fn test_validate_proxies_duplicate_id() {
        let proxies = vec![
            ProxyConfig {
                id: "test".to_string(),
                url: "http://proxy1:8080".to_string(),
                auth: ProxyAuth::default(),
                priority: None,
                health_check_url: None,
            },
            ProxyConfig {
                id: "test".to_string(),
                url: "http://proxy2:8080".to_string(),
                auth: ProxyAuth::default(),
                priority: None,
                health_check_url: None,
            },
        ];
        let results = validate_proxies(&proxies);
        assert!(results
            .iter()
            .any(|r| r.message.contains("Duplicate proxy ID")));
    }

    #[test]
    fn test_validate_targets_protocol_prefix() {
        let targets = vec![TargetSpec::Simple("https://api.example.com".to_string())];
        let results = validate_targets(&targets);
        assert!(results
            .iter()
            .any(|r| r.message.contains("protocol prefix")));
    }

    #[test]
    fn test_validate_targets_with_path() {
        let targets = vec![TargetSpec::Simple("api.example.com/v1".to_string())];
        let results = validate_targets(&targets);
        assert!(results.iter().any(|r| r.message.contains("path")));
    }

    #[test]
    fn test_validate_settings_invalid_backoff() {
        let settings = Settings {
            connect_max_backoff_ms: 50,
            connect_initial_backoff_ms: 100,
            ..Settings::default()
        };
        let results = validate_settings(&settings);
        assert!(results
            .iter()
            .any(|r| r.message.contains("connect_max_backoff_ms")));
    }

    #[test]
    fn test_validate_settings_ping_timeout_too_high() {
        let settings = Settings {
            ping_interval_secs: 60,
            ping_timeout_ms: 65000,
            ..Settings::default()
        };
        let results = validate_settings(&settings);
        assert!(results
            .iter()
            .any(|r| r.severity == ValidationSeverity::Error
                && r.message.contains("ping_timeout_ms")));
    }

    #[test]
    fn test_validate_metrics_port_conflict() {
        let settings = Settings {
            metrics_enabled: true,
            metrics_port: 12345,
            listen_port: 12345,
            ..Settings::default()
        };
        let results = validate_settings(&settings);
        assert!(results.iter().any(|r| {
            r.severity == ValidationSeverity::Error && r.message.contains("metrics_port")
        }));
    }

    #[test]
    fn test_validate_metrics_path_requires_slash() {
        let settings = Settings {
            metrics_path: "metrics".to_string(),
            ..Settings::default()
        };
        let results = validate_settings(&settings);
        assert!(results.iter().any(|r| {
            r.severity == ValidationSeverity::Error && r.message.contains("metrics_path")
        }));
    }

    #[test]
    fn test_validate_metrics_bind_invalid() {
        let settings = Settings {
            metrics_bind: "bad addr".to_string(),
            ..Settings::default()
        };
        let results = validate_settings(&settings);
        assert!(results.iter().any(|r| {
            r.severity == ValidationSeverity::Error && r.message.contains("metrics_bind")
        }));
    }

    #[test]
    fn test_validate_active_proxy_not_found() {
        let proxies = vec![ProxyConfig {
            id: "existing".to_string(),
            url: "http://proxy:8080".to_string(),
            auth: ProxyAuth::default(),
            priority: None,
            health_check_url: None,
        }];
        let results = validate_active_proxy(Some("nonexistent"), &proxies);
        assert!(results.iter().any(|r| r.message.contains("not found")));
    }

    #[test]
    fn test_validate_active_proxy_none() {
        let results = validate_active_proxy(None, &[]);
        assert!(results
            .iter()
            .any(|r| r.message.contains("No active proxy")));
    }

    #[test]
    fn test_validation_report_counts() {
        let report = ValidationReport {
            config_path: PathBuf::from("/test"),
            results: vec![
                ValidationResult::error("test", "error1"),
                ValidationResult::error("test", "error2"),
                ValidationResult::warning("test", "warning1"),
            ],
        };
        assert_eq!(report.error_count(), 2);
        assert_eq!(report.warning_count(), 1);
        assert!(report.has_errors());
        assert!(report.has_warnings());
    }

    #[test]
    fn test_validate_degradation_policy_direct_requires_fallback() {
        let settings = Settings {
            degradation_policy: DegradationPolicy::Direct,
            allow_direct_fallback: false,
            ..Settings::default()
        };
        let results = validate_settings(&settings);
        assert!(results.iter().any(|r| {
            r.severity == ValidationSeverity::Error && r.message.contains("allow_direct_fallback")
        }));
    }

    #[test]
    fn test_validate_degradation_policy_direct_with_fallback_enabled() {
        let settings = Settings {
            degradation_policy: DegradationPolicy::Direct,
            allow_direct_fallback: true,
            ..Settings::default()
        };
        let results = validate_settings(&settings);
        assert!(!results.iter().any(|r| {
            r.severity == ValidationSeverity::Error && r.message.contains("allow_direct_fallback")
        }));
    }

    #[test]
    fn test_validate_degradation_delay_zero_warning() {
        let settings = Settings {
            degradation_delay_secs: 0,
            ..Settings::default()
        };
        let results = validate_settings(&settings);
        assert!(results.iter().any(|r| {
            r.severity == ValidationSeverity::Warning
                && r.message.contains("degradation_delay_secs")
        }));
    }

    #[test]
    fn test_validate_degradation_policy_fail_closed_default() {
        let settings = Settings::default();
        let results = validate_settings(&settings);
        // Default fail_closed should not generate degradation-related errors
        assert!(!results.iter().any(|r| {
            r.severity == ValidationSeverity::Error && r.message.contains("degradation_policy")
        }));
    }
}

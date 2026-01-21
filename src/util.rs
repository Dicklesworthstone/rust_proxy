use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use owo_colors::OwoColorize;
use std::path::Path;
use std::time::Duration;
use url::Url;

/// Helper for dry-run mode that provides consistent messaging across commands.
///
/// When dry-run is enabled, actions are printed with "Would: <action>" prefix
/// and the actual operation is skipped.
///
/// # Example
/// ```ignore
/// let dry_run = DryRun::new(args.dry_run);
/// if dry_run.would_do("remove proxy 'test'") {
///     return Ok(());
/// }
/// // Actually remove the proxy...
/// ```
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Infrastructure for future dry-run implementations
pub struct DryRun {
    enabled: bool,
}

#[allow(dead_code)] // Infrastructure for future dry-run implementations
impl DryRun {
    /// Create a new DryRun helper
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Returns true if dry-run mode is enabled
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Print what would happen and return true if dry-run is enabled (caller should skip action).
    ///
    /// # Example
    /// ```ignore
    /// let dry_run = DryRun::new(true);
    /// if dry_run.would_do("delete config file") {
    ///     return Ok(()); // Skip the actual deletion
    /// }
    /// // Actually delete the file...
    /// ```
    pub fn would_do(&self, action: &str) -> bool {
        if self.enabled {
            println!("{} {}", "Would:".yellow().bold(), action);
            true
        } else {
            false
        }
    }

    /// Print what would happen using a format string and return true if dry-run is enabled.
    ///
    /// # Example
    /// ```ignore
    /// let dry_run = DryRun::new(true);
    /// if dry_run.would_do_fmt(format_args!("remove proxy '{}'", proxy_id)) {
    ///     return Ok(());
    /// }
    /// ```
    pub fn would_do_fmt(&self, action: std::fmt::Arguments<'_>) -> bool {
        if self.enabled {
            println!("{} {}", "Would:".yellow().bold(), action);
            true
        } else {
            false
        }
    }

    /// Execute an action only if not in dry-run mode.
    /// If in dry-run mode, prints what would happen and returns Ok(default).
    ///
    /// # Example
    /// ```ignore
    /// let dry_run = DryRun::new(true);
    /// let result = dry_run.execute_or_skip(
    ///     "save configuration",
    ///     || config.save(),
    ///     || Ok(())
    /// )?;
    /// ```
    pub fn execute_or_skip<T, E, F, D>(
        &self,
        action: &str,
        op: F,
        default: D,
    ) -> std::result::Result<T, E>
    where
        F: FnOnce() -> std::result::Result<T, E>,
        D: FnOnce() -> std::result::Result<T, E>,
    {
        if self.would_do(action) {
            default()
        } else {
            op()
        }
    }
}

impl Default for DryRun {
    fn default() -> Self {
        Self::new(false)
    }
}

impl From<bool> for DryRun {
    fn from(enabled: bool) -> Self {
        Self::new(enabled)
    }
}

#[derive(Debug, Clone)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
}

pub fn parse_proxy_url(raw: &str) -> Result<ProxyEndpoint> {
    let normalized = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{}", raw)
    };
    let url = Url::parse(&normalized).with_context(|| format!("Invalid proxy URL: {raw}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Proxy URL missing host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("Proxy URL missing port"))?;
    Ok(ProxyEndpoint {
        host: host.to_string(),
        port,
    })
}

#[allow(dead_code)]
pub fn generate_service_file(
    binary_path: &Path,
    config_path: &Path,
    user: &str,
    group: &str,
    hardened: bool,
) -> String {
    let mut service = format!(
        r#"[Unit]
Description=rust_proxy - Targeted transparent proxy daemon
Documentation=https://github.com/Dicklesworthstone/rust_proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary} daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

User={user}
Group={group}

# Config file path (for reference)
Environment=RUST_PROXY_CONFIG={config}

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rust_proxy

# Resource limits
LimitNOFILE=65535
"#,
        binary = binary_path.display(),
        config = config_path.display(),
        user = user,
        group = group
    );

    if hardened {
        service.push_str(&hardening_section(config_path));
    }

    service.push_str(
        r#"
[Install]
WantedBy=multi-user.target
"#,
    );

    service
}

#[allow(dead_code)]
fn hardening_section(config_path: &Path) -> String {
    let config_dir = config_path.parent().unwrap_or(config_path);
    let mut section = String::new();
    section.push_str("\n# Security hardening (limited due to iptables requirement)\n");
    section.push_str("ProtectSystem=strict\n");
    section.push_str(&format!("ReadWritePaths={}\n", config_dir.display()));
    if let Ok(state_dir) = crate::config::state_dir() {
        section.push_str(&format!("ReadWritePaths={}\n", state_dir.display()));
    }
    section.push_str("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n");
    section.push_str("NoNewPrivileges=no\n");
    section.push_str("PrivateTmp=true\n");
    section.push_str("ProtectHome=read-only\n");
    section.push_str("ProtectKernelTunables=true\n");
    section.push_str("ProtectKernelModules=true\n");
    section.push_str("ProtectControlGroups=true\n");
    section
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let value = bytes as f64;
    if value < KB {
        format!("{} B", bytes)
    } else if value < MB {
        format!("{:.1} KB", value / KB)
    } else if value < GB {
        format!("{:.1} MB", value / MB)
    } else {
        format!("{:.2} GB", value / GB)
    }
}

pub fn format_duration_since(when: Option<DateTime<Utc>>) -> String {
    let Some(ts) = when else {
        return "-".to_string();
    };
    let now = Utc::now();
    let delta = now.signed_duration_since(ts);
    if delta.num_seconds() < 0 {
        return "0s".to_string();
    }
    format_duration(delta.to_std().unwrap_or(Duration::from_secs(0)))
}

pub fn format_duration(duration: Duration) -> String {
    let mut secs = duration.as_secs();
    let days = secs / 86400;
    secs %= 86400;
    let hours = secs / 3600;
    secs %= 3600;
    let minutes = secs / 60;
    let seconds = secs % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 || !parts.is_empty() {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 || !parts.is_empty() {
        parts.push(format!("{}m", minutes));
    }
    parts.push(format!("{}s", seconds));

    parts.join(" ")
}

pub fn format_timeout(ms: u64) -> Result<Duration> {
    if ms == 0 {
        bail!("Timeout must be greater than 0")
    }
    Ok(Duration::from_millis(ms))
}

pub fn format_since_label(when: Option<DateTime<Utc>>) -> String {
    if let Some(ts) = when {
        let now = Utc::now();
        let delta = now.signed_duration_since(ts);
        let pretty = format_duration(delta.to_std().unwrap_or(Duration::from_secs(0)));
        format!("{pretty} ago")
    } else {
        "-".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proxy_url_with_scheme() {
        let result = parse_proxy_url("http://proxy.example.com:8080").unwrap();
        assert_eq!(result.host, "proxy.example.com");
        assert_eq!(result.port, 8080);
    }

    #[test]
    fn test_parse_proxy_url_without_scheme() {
        let result = parse_proxy_url("proxy.example.com:3128").unwrap();
        assert_eq!(result.host, "proxy.example.com");
        assert_eq!(result.port, 3128);
    }

    #[test]
    fn test_parse_proxy_url_default_http_port() {
        let result = parse_proxy_url("http://proxy.example.com").unwrap();
        assert_eq!(result.host, "proxy.example.com");
        assert_eq!(result.port, 80);
    }

    #[test]
    fn test_parse_proxy_url_https_default_port() {
        let result = parse_proxy_url("https://proxy.example.com").unwrap();
        assert_eq!(result.host, "proxy.example.com");
        assert_eq!(result.port, 443);
    }

    #[test]
    fn test_parse_proxy_url_invalid() {
        let result = parse_proxy_url("not a valid url ::::");
        assert!(result.is_err());
    }

    #[test]
    fn test_format_bytes_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn test_format_bytes_kb() {
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(10240), "10.0 KB");
    }

    #[test]
    fn test_format_bytes_mb() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 5), "5.0 MB");
    }

    #[test]
    fn test_format_bytes_gb() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_bytes(1024 * 1024 * 1024 * 2), "2.00 GB");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(Duration::from_secs(60)), "1m 0s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3599)), "59m 59s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h 0m 0s");
        assert_eq!(format_duration(Duration::from_secs(7200)), "2h 0m 0s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
    }

    #[test]
    fn test_format_duration_days() {
        assert_eq!(format_duration(Duration::from_secs(86400)), "1d 0h 0m 0s");
        assert_eq!(format_duration(Duration::from_secs(90061)), "1d 1h 1m 1s");
    }

    #[test]
    fn test_format_timeout_valid() {
        let result = format_timeout(1000).unwrap();
        assert_eq!(result, Duration::from_millis(1000));
    }

    #[test]
    fn test_format_timeout_zero() {
        let result = format_timeout(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_duration_since_none() {
        assert_eq!(format_duration_since(None), "-");
    }

    #[test]
    fn test_format_since_label_none() {
        assert_eq!(format_since_label(None), "-");
    }

    #[test]
    fn test_dry_run_new() {
        let dry_run = DryRun::new(true);
        assert!(dry_run.is_enabled());

        let dry_run = DryRun::new(false);
        assert!(!dry_run.is_enabled());
    }

    #[test]
    fn test_dry_run_default() {
        let dry_run = DryRun::default();
        assert!(!dry_run.is_enabled());
    }

    #[test]
    fn test_dry_run_from_bool() {
        let dry_run: DryRun = true.into();
        assert!(dry_run.is_enabled());

        let dry_run: DryRun = false.into();
        assert!(!dry_run.is_enabled());
    }

    #[test]
    fn test_dry_run_would_do_enabled() {
        let dry_run = DryRun::new(true);
        // When enabled, would_do returns true (skip action)
        assert!(dry_run.would_do("test action"));
    }

    #[test]
    fn test_dry_run_would_do_disabled() {
        let dry_run = DryRun::new(false);
        // When disabled, would_do returns false (execute action)
        assert!(!dry_run.would_do("test action"));
    }

    #[test]
    fn test_dry_run_would_do_fmt_enabled() {
        let dry_run = DryRun::new(true);
        let proxy_id = "test-proxy";
        // When enabled, would_do_fmt returns true (skip action)
        assert!(dry_run.would_do_fmt(format_args!("remove proxy '{}'", proxy_id)));
    }

    #[test]
    fn test_dry_run_would_do_fmt_disabled() {
        let dry_run = DryRun::new(false);
        let proxy_id = "test-proxy";
        // When disabled, would_do_fmt returns false (execute action)
        assert!(!dry_run.would_do_fmt(format_args!("remove proxy '{}'", proxy_id)));
    }

    #[test]
    fn test_dry_run_execute_or_skip_enabled() {
        let dry_run = DryRun::new(true);
        let mut executed = false;
        let result: std::result::Result<i32, &str> = dry_run.execute_or_skip(
            "test action",
            || {
                executed = true;
                Ok(42)
            },
            || Ok(0),
        );
        assert!(!executed);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_dry_run_execute_or_skip_disabled() {
        let dry_run = DryRun::new(false);
        let mut executed = false;
        let result: std::result::Result<i32, &str> = dry_run.execute_or_skip(
            "test action",
            || {
                executed = true;
                Ok(42)
            },
            || Ok(0),
        );
        assert!(executed);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_generate_service_file_basic() {
        let binary = std::path::Path::new("/usr/local/bin/rust_proxy");
        let config = std::path::Path::new("/etc/rust_proxy/config.toml");
        let service = generate_service_file(binary, config, "root", "root", false);
        assert!(service.contains("ExecStart=/usr/local/bin/rust_proxy daemon"));
        assert!(service.contains("Environment=RUST_PROXY_CONFIG=/etc/rust_proxy/config.toml"));
        assert!(service.contains("User=root"));
        assert!(service.contains("Group=root"));
        assert!(!service.contains("ProtectSystem=strict"));
    }

    #[test]
    fn test_generate_service_file_hardened() {
        let binary = std::path::Path::new("/usr/local/bin/rust_proxy");
        let config = std::path::Path::new("/etc/rust_proxy/config.toml");
        let service = generate_service_file(binary, config, "root", "root", true);
        assert!(service.contains("ProtectSystem=strict"));
        assert!(service.contains("ReadWritePaths=/etc/rust_proxy"));
    }
}

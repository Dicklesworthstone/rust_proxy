use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use owo_colors::OwoColorize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tabled::settings::Style;
use tabled::{Table, Tabled};
use tokio::net::TcpStream;
use tokio::time::Instant;

mod config;
mod dns;
mod health;
mod ip_ranges;
mod iptables;
mod proxy;
mod state;
mod util;
mod validation;

use config::{infer_provider, AppConfig, Provider, ProxyAuth, ProxyConfig, TargetSpec};
use proxy::{RetryConfig, UpstreamProxy};
use state::{HealthStatus, RuntimeState, State, StateStore};

#[derive(Parser)]
#[command(
    name = "rust_proxy",
    version,
    about = "Machine-wide proxy selector for targeted domains"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a default config if missing
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Manage proxy entries
    Proxy {
        #[command(subcommand)]
        command: ProxyCmd,
    },
    /// Manage target domains
    Targets {
        #[command(subcommand)]
        command: TargetCmd,
    },
    /// Show proxy list with stats
    List(OutputArgs),
    /// Activate a proxy and optionally run the daemon
    Activate {
        id: Option<String>,
        #[arg(long)]
        select: bool,
        #[arg(long)]
        run: bool,
    },
    /// Deactivate proxy routing (clears iptables/ipset if root)
    Deactivate {
        #[arg(long)]
        keep_rules: bool,
    },
    /// Run transparent proxy daemon (requires sudo)
    Daemon,
    /// Show current status
    Status(OutputArgs),
    /// Check system dependencies
    Diagnose,
    /// Validate configuration without side effects
    Check {
        /// Treat warnings as errors (exit code 2)
        #[arg(long)]
        strict: bool,
        /// Output validation results as JSON
        #[arg(long)]
        json: bool,
        /// Only output errors (no success messages)
        #[arg(long)]
        quiet: bool,
        /// Test actual network connectivity to proxies
        #[arg(long)]
        test_connectivity: bool,
    },
    /// Test how a URL would be routed (proxied or direct)
    Test {
        /// URL or domain to test (e.g., https://api.openai.com/v1/chat, api.openai.com)
        url: String,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
        /// Show detailed routing decision process
        #[arg(short, long)]
        verbose: bool,
        /// Skip DNS resolution (only check config)
        #[arg(long)]
        no_dns: bool,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Args)]
struct OutputArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum ProxyCmd {
    /// Add a proxy
    Add {
        id: String,
        url: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        username_env: Option<String>,
        #[arg(long)]
        password_env: Option<String>,
    },
    /// Remove a proxy
    Remove { id: String },
    /// List proxies (no stats)
    List,
}

#[derive(Subcommand)]
enum TargetCmd {
    /// Add target domain
    Add {
        domain: String,
        #[arg(long)]
        provider: Option<ProviderArg>,
    },
    /// Remove target domain
    Remove { domain: String },
    /// List target domains
    List,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum ProviderArg {
    Anthropic,
    Openai,
    Google,
    Amazon,
    Cloudflare,
    Vercel,
    Supabase,
}

impl From<ProviderArg> for Provider {
    fn from(value: ProviderArg) -> Self {
        match value {
            ProviderArg::Anthropic => Provider::Anthropic,
            ProviderArg::Openai => Provider::Openai,
            ProviderArg::Google => Provider::Google,
            ProviderArg::Amazon => Provider::Amazon,
            ProviderArg::Cloudflare => Provider::Cloudflare,
            ProviderArg::Vercel => Provider::Vercel,
            ProviderArg::Supabase => Provider::Supabase,
        }
    }
}

#[derive(Tabled)]
struct TargetRow {
    domain: String,
    provider: String,
}

#[derive(Tabled)]
struct ProxyRow {
    id: String,
    url: String,
    active: String,
    since: String,
    sent: String,
    received: String,
    ping: String,
    last_active: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { force } => init_config(force)?,
        Commands::Proxy { command } => proxy_cmd(command)?,
        Commands::Targets { command } => targets_cmd(command)?,
        Commands::List(args) => list_cmd(args.json)?,
        Commands::Activate { id, select, run } => activate_cmd(id, select, run).await?,
        Commands::Deactivate { keep_rules } => deactivate_cmd(keep_rules)?,
        Commands::Daemon => run_daemon().await?,
        Commands::Status(args) => status_cmd(args.json)?,
        Commands::Diagnose => diagnose_cmd()?,
        Commands::Check {
            strict,
            json,
            quiet,
            test_connectivity,
        } => check_cmd(strict, json, quiet, test_connectivity).await?,
        Commands::Test {
            url,
            json,
            verbose,
            no_dns,
        } => test_cmd(&url, json, verbose, no_dns).await?,
        Commands::Completions { shell } => completions_cmd(shell),
    }

    Ok(())
}

fn init_config(force: bool) -> Result<()> {
    let path = config::config_path()?;
    if path.exists() && !force {
        println!("Config already exists at {}", path.display());
        return Ok(());
    }
    let config = AppConfig::default();
    config.save()?;
    println!("Wrote config to {}", path.display());
    Ok(())
}

fn proxy_cmd(cmd: ProxyCmd) -> Result<()> {
    let mut config = AppConfig::load()?;
    match cmd {
        ProxyCmd::Add {
            id,
            url,
            username,
            password,
            username_env,
            password_env,
        } => {
            if config.proxies.iter().any(|p| p.id == id) {
                bail!("Proxy ID already exists: {}", id);
            }
            let auth = ProxyAuth {
                username,
                password,
                username_env,
                password_env,
            };
            config.proxies.push(ProxyConfig {
                id,
                url,
                auth,
                priority: None,
                health_check_url: None,
            });
            config.save()?;
            println!("Proxy added.");
        }
        ProxyCmd::Remove { id } => {
            let before = config.proxies.len();
            config.proxies.retain(|p| p.id != id);
            if config.proxies.len() == before {
                bail!("Proxy not found: {}", id);
            }
            if config.active_proxy.as_deref() == Some(&id) {
                config.active_proxy = None;
            }
            config.save()?;
            println!("Proxy removed.");
        }
        ProxyCmd::List => {
            for proxy in &config.proxies {
                println!("{} -> {}", proxy.id, proxy.url);
            }
        }
    }
    Ok(())
}

fn targets_cmd(cmd: TargetCmd) -> Result<()> {
    let mut config = AppConfig::load()?;
    match cmd {
        TargetCmd::Add { domain, provider } => {
            if config.targets.iter().any(|d| d.domain() == domain.as_str()) {
                bail!("Target already exists: {}", domain);
            }
            let provider = match provider {
                Some(value) => Provider::from(value),
                None => infer_provider(&domain).ok_or_else(|| {
                    anyhow::anyhow!("Provider is required for nonstandard domain. Use --provider.")
                })?,
            };
            config
                .targets
                .push(TargetSpec::Detailed { domain, provider });
            config.save()?;
            println!("Target added.");
        }
        TargetCmd::Remove { domain } => {
            let before = config.targets.len();
            config.targets.retain(|d| d.domain() != domain.as_str());
            if config.targets.len() == before {
                bail!("Target not found: {}", domain);
            }
            config.save()?;
            println!("Target removed.");
        }
        TargetCmd::List => {
            let mut rows = Vec::new();
            for target in &config.targets {
                rows.push(TargetRow {
                    domain: target.domain().to_string(),
                    provider: target.provider().as_str().to_string(),
                });
            }
            let mut table = Table::new(rows);
            table.with(Style::ascii());
            println!("{table}");
        }
    }
    Ok(())
}

fn list_cmd(json: bool) -> Result<()> {
    let config = AppConfig::load()?;
    let state_path = state::state_path()?;
    let state = State::load(&state_path)?;

    if json {
        let payload = serde_json::json!({
            "active_proxy": config.active_proxy,
            "proxies": config.proxies,
            "stats": state,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    let rows = build_proxy_rows(&config, &state);
    let mut table = Table::new(rows);
    table.with(Style::ascii());
    println!("{}", table);
    Ok(())
}

fn status_cmd(json: bool) -> Result<()> {
    let config = AppConfig::load()?;
    let state_path = state::state_path()?;
    let state = State::load(&state_path)?;
    let rules_active = iptables::chain_present(&config.settings.chain_name);

    if json {
        // Build health info for JSON output
        let proxy_health: Vec<_> = config
            .proxies
            .iter()
            .map(|p| {
                let stats = state.proxies.get(&p.id);
                serde_json::json!({
                    "id": p.id,
                    "status": stats.map(|s| s.health_status.to_string()).unwrap_or_else(|| "unknown".to_string()),
                    "priority": p.priority,
                    "latency_ms": stats.and_then(|s| s.ping_avg_ms),
                    "last_check": stats.and_then(|s| s.last_health_check),
                    "consecutive_failures": stats.map(|s| s.consecutive_failures).unwrap_or(0),
                    "last_healthy": stats.and_then(|s| s.last_healthy),
                    "last_failure_reason": stats.and_then(|s| s.last_failure_reason.clone()),
                })
            })
            .collect();

        let active_health = config.active_proxy.as_ref().and_then(|id| {
            state.proxies.get(id).map(|stats| {
                serde_json::json!({
                    "status": stats.health_status.to_string(),
                    "last_check": stats.last_health_check,
                    "latency_ms": stats.ping_avg_ms,
                    "consecutive_failures": stats.consecutive_failures,
                })
            })
        });

        let payload = serde_json::json!({
            "active_proxy": config.active_proxy,
            "active_proxy_health": active_health,
            "rules_active": rules_active,
            "health_check_enabled": config.settings.health_check_enabled,
            "auto_failover": config.settings.auto_failover,
            "auto_failback": config.settings.auto_failback,
            "targets": config.targets.len(),
            "proxy_health": proxy_health,
            "stats": state,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    // Human-readable output
    let active = config
        .active_proxy
        .clone()
        .unwrap_or_else(|| "-".to_string());
    println!("Active proxy: {}", active);

    // Show active proxy health if available
    if let Some(ref active_id) = config.active_proxy {
        if let Some(stats) = state.proxies.get(active_id) {
            let health_str = format_health_status(stats.health_status);
            let last_check = format_time_ago(stats.last_health_check);
            let latency = stats
                .ping_avg_ms
                .map(|ms| format!("{:.0}ms", ms))
                .unwrap_or_else(|| "-".to_string());
            println!(
                "Health: {} (last check: {}, latency: {})",
                health_str, last_check, latency
            );
        }
    }

    println!("Rules active: {}", if rules_active { "yes" } else { "no" });
    println!("Targets: {}", config.targets.len());

    // Show health summary if health checks are enabled and there are proxies
    if config.settings.health_check_enabled && !config.proxies.is_empty() {
        println!();
        println!("Proxy Health Summary:");
        println!(
            "  {:<12} {:<12} {:<10} {:<10} {:<12} Failures",
            "ID", "Status", "Priority", "Latency", "Last Check"
        );
        for proxy in &config.proxies {
            let stats = state.proxies.get(&proxy.id);
            let status = stats
                .map(|s| format_health_status(s.health_status))
                .unwrap_or_else(|| "? Unknown".dimmed().to_string());
            let priority = proxy
                .priority
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());
            let latency = stats
                .and_then(|s| s.ping_avg_ms)
                .map(|ms| format!("{:.0}ms", ms))
                .unwrap_or_else(|| "-".to_string());
            let last_check = stats
                .and_then(|s| s.last_health_check)
                .map(|t| format_time_ago(Some(t)))
                .unwrap_or_else(|| "never".to_string());
            let failures = stats.map(|s| s.consecutive_failures).unwrap_or(0);

            println!(
                "  {:<12} {:<12} {:<10} {:<10} {:<12} {}",
                proxy.id, status, priority, latency, last_check, failures
            );
        }
    } else if !config.settings.health_check_enabled {
        println!();
        println!("Health checks: {}", "disabled".dimmed());
    }

    Ok(())
}

/// Format health status with color
fn format_health_status(status: HealthStatus) -> String {
    match status {
        HealthStatus::Healthy => "✓ Healthy".green().to_string(),
        HealthStatus::Degraded => "⚠ Degraded".yellow().to_string(),
        HealthStatus::Unhealthy => "✗ Unhealthy".red().to_string(),
        HealthStatus::Unknown => "? Unknown".dimmed().to_string(),
    }
}

/// Format a timestamp as relative time (e.g., "5s ago")
fn format_time_ago(dt: Option<chrono::DateTime<chrono::Utc>>) -> String {
    dt.map(|t| {
        let ago = chrono::Utc::now().signed_duration_since(t);
        if ago.num_seconds() < 60 {
            format!("{}s ago", ago.num_seconds())
        } else if ago.num_minutes() < 60 {
            format!("{}m ago", ago.num_minutes())
        } else if ago.num_hours() < 24 {
            format!("{}h ago", ago.num_hours())
        } else {
            format!("{}d ago", ago.num_days())
        }
    })
    .unwrap_or_else(|| "never".to_string())
}

async fn activate_cmd(id: Option<String>, select: bool, run: bool) -> Result<()> {
    let mut config = AppConfig::load()?;
    if config.proxies.is_empty() {
        bail!("No proxies configured. Add one first.");
    }

    let target_id = match id {
        Some(id) => id,
        None => {
            if !select {
                bail!("Missing proxy id. Use --select for interactive mode.");
            }
            let choices: Vec<String> = config.proxies.iter().map(|p| p.id.clone()).collect();
            let selection = inquire::Select::new("Select proxy", choices).prompt()?;
            selection
        }
    };

    if !config.proxies.iter().any(|p| p.id == target_id) {
        bail!("Proxy not found: {}", target_id);
    }

    config.active_proxy = Some(target_id.clone());
    config.save()?;

    let state_path = state::state_path()?;
    let mut state = State::load(&state_path)?;
    let stats = state.proxies.entry(target_id.clone()).or_default();
    let now = chrono::Utc::now();
    stats.activated_at = Some(now);
    stats.last_active = Some(now);
    state.save(&state_path)?;

    println!("Activated proxy {}", target_id.green());

    if run {
        run_daemon().await?;
    } else {
        println!("Run `sudo rust_proxy daemon` to apply machine-wide routing.");
    }

    Ok(())
}

fn deactivate_cmd(keep_rules: bool) -> Result<()> {
    let mut config = AppConfig::load()?;
    config.active_proxy = None;
    config.save()?;

    if !keep_rules {
        match iptables::require_root() {
            Ok(_) => {
                iptables::clear_rules(&config.settings.chain_name, &config.settings.ipset_name)?;
            }
            Err(err) => {
                println!("Note: {}", err);
            }
        }
    }

    println!("Proxy routing deactivated.");
    Ok(())
}

fn diagnose_cmd() -> Result<()> {
    let iptables_ok = std::process::Command::new("iptables")
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let ipset_ok = std::process::Command::new("ipset")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    println!("iptables: {}", if iptables_ok { "ok" } else { "missing" });
    println!("ipset:    {}", if ipset_ok { "ok" } else { "missing" });
    Ok(())
}

/// Result of testing connectivity to a proxy
#[derive(Debug, Clone, serde::Serialize)]
struct ConnectivityResult {
    proxy_id: String,
    status: String, // "success", "dns_failure", "connect_failure", "timeout", "auth_required"
    latency_ms: Option<u64>,
    error: Option<String>,
}

/// Test connectivity to a single proxy
async fn test_proxy_connectivity(
    proxy: &config::ProxyConfig,
    timeout_ms: u64,
) -> ConnectivityResult {
    use health::check_proxy_health;

    let result = check_proxy_health(proxy, timeout_ms).await;

    ConnectivityResult {
        proxy_id: proxy.id.clone(),
        status: if result.success {
            "success".to_string()
        } else if result
            .failure_reason
            .as_ref()
            .is_some_and(|r| r.contains("timeout"))
        {
            "timeout".to_string()
        } else if result
            .failure_reason
            .as_ref()
            .is_some_and(|r| r.contains("407"))
        {
            "auth_required".to_string()
        } else {
            "connect_failure".to_string()
        },
        latency_ms: if result.success {
            Some(result.latency_ms as u64)
        } else {
            None
        },
        error: result.failure_reason,
    }
}

async fn check_cmd(strict: bool, json: bool, quiet: bool, test_connectivity: bool) -> Result<()> {
    use validation::{validate_config, ValidationSeverity};

    let config_path = config::config_path()?;

    // Try to load config
    let config = match AppConfig::load() {
        Ok(config) => config,
        Err(err) => {
            if json {
                let output = serde_json::json!({
                    "valid": false,
                    "config_path": config_path.display().to_string(),
                    "errors": [{
                        "category": "file",
                        "message": format!("Failed to load configuration: {}", err),
                    }],
                    "warnings": [],
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                eprintln!("{} Failed to load configuration: {}", "✗".red(), err);
            }
            std::process::exit(3);
        }
    };

    let report = validate_config(&config, &config_path);

    // Run connectivity tests if requested (in parallel)
    let connectivity_results: Vec<ConnectivityResult> =
        if test_connectivity && !config.proxies.is_empty() {
            let timeout_ms = config.settings.health_check_timeout_ms;
            let futures: Vec<_> = config
                .proxies
                .iter()
                .map(|proxy| test_proxy_connectivity(proxy, timeout_ms))
                .collect();
            futures::future::join_all(futures).await
        } else {
            Vec::new()
        };

    if json {
        let errors: Vec<serde_json::Value> = report
            .results
            .iter()
            .filter(|r| r.severity == ValidationSeverity::Error)
            .map(|r| {
                let mut obj = serde_json::json!({
                    "category": r.category,
                    "message": r.message,
                });
                if let Some(ref id) = r.id {
                    obj["id"] = serde_json::Value::String(id.clone());
                }
                if let Some(ref suggestion) = r.suggestion {
                    obj["suggestion"] = serde_json::Value::String(suggestion.clone());
                }
                obj
            })
            .collect();

        let warnings: Vec<serde_json::Value> = report
            .results
            .iter()
            .filter(|r| r.severity == ValidationSeverity::Warning)
            .map(|r| {
                let mut obj = serde_json::json!({
                    "category": r.category,
                    "message": r.message,
                });
                if let Some(ref id) = r.id {
                    obj["id"] = serde_json::Value::String(id.clone());
                }
                if let Some(ref suggestion) = r.suggestion {
                    obj["suggestion"] = serde_json::Value::String(suggestion.clone());
                }
                obj
            })
            .collect();

        let mut output = serde_json::json!({
            "valid": !report.has_errors(),
            "config_path": config_path.display().to_string(),
            "errors": errors,
            "warnings": warnings,
            "summary": {
                "error_count": report.error_count(),
                "warning_count": report.warning_count(),
            }
        });

        // Add connectivity results if tested
        if test_connectivity {
            output["connectivity"] = serde_json::json!(connectivity_results);
        }

        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if !quiet || report.has_errors() || (strict && report.has_warnings()) {
        println!("Configuration: {}", config_path.display());
        println!();

        // Group results by category
        let mut by_category: std::collections::HashMap<&str, Vec<_>> =
            std::collections::HashMap::new();
        for result in &report.results {
            by_category.entry(result.category).or_default().push(result);
        }

        // Display by category
        for category in ["file", "proxy", "target", "settings", "active"] {
            if let Some(results) = by_category.get(category) {
                let category_name = match category {
                    "file" => "File Access",
                    "proxy" => "Proxies",
                    "target" => "Targets",
                    "settings" => "Settings",
                    "active" => "Active Proxy",
                    _ => category,
                };

                let has_errors = results
                    .iter()
                    .any(|r| r.severity == ValidationSeverity::Error);
                let has_warnings = results
                    .iter()
                    .any(|r| r.severity == ValidationSeverity::Warning);

                if has_errors || has_warnings {
                    println!("{}:", category_name);
                    for result in results {
                        let prefix = match result.severity {
                            ValidationSeverity::Error => "✗".red().to_string(),
                            ValidationSeverity::Warning => "⚠".yellow().to_string(),
                            ValidationSeverity::Info => "ℹ".blue().to_string(),
                        };
                        let id_str = result
                            .id
                            .as_deref()
                            .map(|id| format!(" [{}]", id))
                            .unwrap_or_default();
                        println!("  {}{} {}", prefix, id_str, result.message);
                        if let Some(ref suggestion) = result.suggestion {
                            println!("    → {}", suggestion);
                        }
                    }
                    println!();
                }
            }
        }

        // Display connectivity results if tested
        if test_connectivity && !connectivity_results.is_empty() {
            println!("Connectivity Tests:");
            for result in &connectivity_results {
                let (prefix, status_text) = match result.status.as_str() {
                    "success" => (
                        "✓".green().to_string(),
                        format!("reachable ({}ms)", result.latency_ms.unwrap_or(0)),
                    ),
                    "auth_required" => (
                        "⚠".yellow().to_string(),
                        "reachable (auth required)".to_string(),
                    ),
                    "timeout" => ("✗".red().to_string(), "timeout".to_string()),
                    _ => (
                        "✗".red().to_string(),
                        result
                            .error
                            .clone()
                            .unwrap_or_else(|| "connection failed".to_string()),
                    ),
                };
                println!("  {} [{}] {}", prefix, result.proxy_id, status_text);
            }
            println!();
        }

        // Summary
        if report.has_errors() {
            println!(
                "Configuration {}: {} error(s), {} warning(s)",
                "invalid".red(),
                report.error_count(),
                report.warning_count()
            );
        } else if report.has_warnings() {
            println!(
                "Configuration {}: {} warning(s)",
                "valid".green(),
                report.warning_count()
            );
        } else {
            println!("Configuration {}.", "valid".green());
        }
    }

    // Exit codes
    if report.has_errors() {
        std::process::exit(1);
    } else if strict && report.has_warnings() {
        std::process::exit(2);
    }

    Ok(())
}

/// Routing decision result for a URL/domain
#[derive(Debug)]
struct RoutingDecision {
    input: String,
    domain: String,
    resolved_ips: Vec<String>,
    dns_error: Option<String>,
    would_proxy: bool,
    domain_in_targets: bool,
    target_provider: Option<String>,
    provider_range_matches: Vec<ProviderMatch>,
    daemon_running: bool,
    active_proxy: Option<(String, String)>, // (id, url)
}

#[derive(Debug)]
struct ProviderMatch {
    ip: String,
    provider: String,
    cidr: String,
}

/// Parse a URL or domain input and extract the domain
fn extract_domain(input: &str) -> String {
    let input = input.trim();

    // If it looks like a URL, parse it
    if input.starts_with("http://") || input.starts_with("https://") {
        if let Ok(url) = url::Url::parse(input) {
            if let Some(host) = url.host_str() {
                return host.to_string();
            }
        }
    }

    // Try adding https:// and parsing
    if let Ok(url) = url::Url::parse(&format!("https://{}", input)) {
        if let Some(host) = url.host_str() {
            return host.to_string();
        }
    }

    // Fall back to treating as domain (strip path if present)
    input.split('/').next().unwrap_or(input).to_string()
}

/// Check if an IP address is within a CIDR range
fn ip_in_cidr(ip_str: &str, cidr: &str) -> bool {
    use std::net::Ipv4Addr;

    let ip: Ipv4Addr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let network: Ipv4Addr = match parts[0].parse() {
        Ok(n) => n,
        Err(_) => return false,
    };

    let prefix_len: u32 = match parts[1].parse() {
        Ok(p) if p <= 32 => p,
        _ => return false,
    };

    if prefix_len == 0 {
        return true;
    }

    let mask = !0u32 << (32 - prefix_len);
    let ip_bits = u32::from(ip);
    let net_bits = u32::from(network);

    (ip_bits & mask) == (net_bits & mask)
}

/// Find which provider range (if any) contains an IP
async fn find_provider_match(
    ip: &str,
    include_aws: bool,
    include_cloudflare: bool,
    include_google: bool,
) -> Option<ProviderMatch> {
    // Check Cloudflare first (most common for API providers)
    if include_cloudflare {
        if let Ok(ranges) = ip_ranges::fetch_cloudflare_ipv4().await {
            for cidr in &ranges {
                if ip_in_cidr(ip, cidr) {
                    return Some(ProviderMatch {
                        ip: ip.to_string(),
                        provider: "cloudflare".to_string(),
                        cidr: cidr.clone(),
                    });
                }
            }
        }
    }

    // Check Google
    if include_google {
        if let Ok(ranges) = ip_ranges::fetch_google_ipv4().await {
            for cidr in &ranges {
                if ip_in_cidr(ip, cidr) {
                    return Some(ProviderMatch {
                        ip: ip.to_string(),
                        provider: "google".to_string(),
                        cidr: cidr.clone(),
                    });
                }
            }
        }
    }

    // Check AWS
    if include_aws {
        if let Ok(ranges) = ip_ranges::fetch_aws_ipv4().await {
            for cidr in &ranges {
                if ip_in_cidr(ip, cidr) {
                    return Some(ProviderMatch {
                        ip: ip.to_string(),
                        provider: "aws".to_string(),
                        cidr: cidr.clone(),
                    });
                }
            }
        }
    }

    None
}

/// Check if daemon is running by attempting to connect to the listen port
fn is_daemon_running(port: u16) -> bool {
    std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
}

async fn test_cmd(url: &str, json: bool, verbose: bool, no_dns: bool) -> Result<()> {
    let config = AppConfig::load()?;

    let domain = extract_domain(url);

    if verbose {
        println!("[1/5] Parsing URL...");
        println!("      Input: {}", url);
        println!("      Extracted domain: {}", domain);
        println!();
    }

    // Check if domain is in targets
    let (domain_in_targets, target_provider) = {
        let mut found = false;
        let mut provider: Option<String> = None;
        for target in &config.targets {
            if target.domain().eq_ignore_ascii_case(&domain) {
                found = true;
                provider = Some(target.provider().as_str().to_string());
                break;
            }
        }
        (found, provider)
    };

    if verbose {
        println!("[2/5] Checking targets list...");
        println!(
            "      Searching {} configured targets",
            config.targets.len()
        );
        if domain_in_targets {
            println!(
                "      {} Found: {} (provider: {})",
                "✓".green(),
                domain,
                target_provider.as_deref().unwrap_or("unknown")
            );
        } else {
            println!("      {} Not found: {}", "✗".red(), domain);
        }
        println!();
    }

    // Resolve DNS
    let (resolved_ips, dns_error) = if no_dns {
        if verbose {
            println!("[3/5] Resolving DNS...");
            println!("      Skipped (--no-dns flag)");
            println!();
        }
        (Vec::new(), None)
    } else {
        if verbose {
            println!("[3/5] Resolving DNS...");
            println!("      Query: {} A", domain);
        }
        let start = std::time::Instant::now();
        match dns::resolve_ipv4(std::slice::from_ref(&domain)).await {
            Ok(ips) => {
                let ips: Vec<String> = ips.into_iter().collect();
                if verbose {
                    println!(
                        "      Response: {} ({:.0}ms)",
                        if ips.is_empty() {
                            "no results".to_string()
                        } else {
                            ips.join(", ")
                        },
                        start.elapsed().as_millis()
                    );
                    println!();
                }
                (ips, None)
            }
            Err(err) => {
                if verbose {
                    println!("      {} Error: {}", "✗".red(), err);
                    println!();
                }
                (Vec::new(), Some(err.to_string()))
            }
        }
    };

    // Check daemon status
    let daemon_running = is_daemon_running(config.settings.listen_port);

    if verbose {
        println!("[4/5] Checking daemon status...");
        if daemon_running {
            println!("      {} Daemon is running", "✓".green());
        } else {
            println!("      Daemon is not running");
            println!("      (ipset rules not active until daemon runs)");
        }
        println!();
    }

    // Check provider IP ranges
    let mut provider_range_matches = Vec::new();
    if !no_dns && !resolved_ips.is_empty() {
        if verbose {
            println!("[5/5] Checking provider IP ranges...");
        }
        for ip in &resolved_ips {
            if let Some(m) = find_provider_match(
                ip,
                config.settings.include_aws_ip_ranges,
                config.settings.include_cloudflare_ip_ranges,
                config.settings.include_google_ip_ranges,
            )
            .await
            {
                if verbose {
                    println!(
                        "      IP {}: {} matches {} range {}",
                        ip,
                        "✓".green(),
                        m.provider,
                        m.cidr
                    );
                }
                provider_range_matches.push(m);
            } else if verbose {
                println!("      IP {}: {} no provider range match", ip, "✗".red());
            }
        }
        if verbose {
            println!();
        }
    } else if verbose && !no_dns {
        println!("[5/5] Checking provider IP ranges...");
        println!("      Skipped (no resolved IPs)");
        println!();
    } else if verbose {
        println!("[5/5] Checking provider IP ranges...");
        println!("      Skipped (--no-dns flag)");
        println!();
    }

    // Get active proxy info
    let active_proxy = config.active_proxy.as_ref().and_then(|id| {
        config
            .proxies
            .iter()
            .find(|p| &p.id == id)
            .map(|p| (p.id.clone(), p.url.clone()))
    });

    // Determine final routing decision
    let would_proxy = domain_in_targets || !provider_range_matches.is_empty();

    let decision = RoutingDecision {
        input: url.to_string(),
        domain: domain.clone(),
        resolved_ips: resolved_ips.clone(),
        dns_error,
        would_proxy,
        domain_in_targets,
        target_provider,
        provider_range_matches,
        daemon_running,
        active_proxy,
    };

    // Output
    if json {
        output_test_json(&decision)?;
    } else {
        output_test_standard(&decision, verbose);
    }

    Ok(())
}

fn output_test_json(decision: &RoutingDecision) -> Result<()> {
    let output = serde_json::json!({
        "input": decision.input,
        "domain": decision.domain,
        "resolved_ips": decision.resolved_ips,
        "dns_error": decision.dns_error,
        "would_proxy": decision.would_proxy,
        "active_proxy": decision.active_proxy.as_ref().map(|(id, url)| {
            serde_json::json!({
                "id": id,
                "url": url
            })
        }),
        "routing_decision": {
            "domain_in_targets": decision.domain_in_targets,
            "target_provider": decision.target_provider,
            "provider_range_matches": decision.provider_range_matches.iter().map(|m| {
                serde_json::json!({
                    "ip": m.ip,
                    "provider": m.provider,
                    "cidr": m.cidr
                })
            }).collect::<Vec<_>>()
        },
        "daemon_running": decision.daemon_running,
        "suggestions": build_suggestions(decision)
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn output_test_standard(decision: &RoutingDecision, verbose: bool) {
    if verbose {
        println!("─────────────────────────────────────────────────");
    }

    println!("URL: {}", decision.input);
    println!("Domain: {}", decision.domain);

    if !decision.resolved_ips.is_empty() {
        println!("Resolved IPs: {}", decision.resolved_ips.join(", "));
    } else if let Some(ref err) = decision.dns_error {
        println!("DNS Error: {}", err.red());
    }
    println!();

    // Main result
    match (&decision.active_proxy, decision.would_proxy) {
        (None, true) => {
            println!("{} NO ACTIVE PROXY CONFIGURED", "⚠".yellow());
            println!();
            println!("The domain matches routing rules, but no proxy is activated.");
            println!(
                "Run '{}' to choose a proxy.",
                "rust_proxy activate --select".cyan()
            );
        }
        (Some((id, _url)), true) => {
            if decision.daemon_running {
                println!("{} WOULD BE PROXIED via '{}'", "✓".green(), id.green());
            } else {
                println!(
                    "{} WOULD BE PROXIED via '{}' (when daemon is running)",
                    "✓".green(),
                    id.green()
                );
            }
        }
        (_, false) => {
            println!("{} WOULD NOT BE PROXIED (direct connection)", "✗".red());
        }
    }

    println!();
    println!("Routing Decision:");

    // Domain in targets
    if decision.domain_in_targets {
        println!(
            "  {} Domain '{}' is in targets list",
            "✓".green(),
            decision.domain
        );
        if let Some(ref provider) = decision.target_provider {
            println!("    └─ Provider hint: {}", provider);
        }
    } else {
        println!(
            "  {} Domain '{}' is not in targets list",
            "✗".red(),
            decision.domain
        );
    }

    // Provider range matches
    if !decision.provider_range_matches.is_empty() {
        for m in &decision.provider_range_matches {
            println!("  {} IP {} matches {} range", "✓".green(), m.ip, m.provider);
            println!("    └─ Matched range: {}", m.cidr);
        }
    } else if !decision.resolved_ips.is_empty() {
        println!("  {} IPs do not match any provider range", "✗".red());
    }

    // Suggestions
    let suggestions = build_suggestions(decision);
    if !suggestions.is_empty() {
        println!();
        println!("Suggestions:");
        for suggestion in suggestions {
            println!("  • {}", suggestion);
        }
    }

    // Notes
    if !decision.daemon_running && decision.would_proxy {
        println!();
        println!(
            "Note: Daemon is not running. Run '{}' to activate routing.",
            "sudo rust_proxy daemon".cyan()
        );
    }
}

fn build_suggestions(decision: &RoutingDecision) -> Vec<String> {
    let mut suggestions = Vec::new();

    if !decision.would_proxy {
        suggestions.push(format!(
            "Add domain to targets: {}",
            format!("rust_proxy targets add {}", decision.domain).cyan()
        ));
    }

    if decision.active_proxy.is_none() && (decision.domain_in_targets || decision.would_proxy) {
        suggestions.push(format!(
            "Activate a proxy: {}",
            "rust_proxy activate --select".cyan()
        ));
    }

    suggestions
}

fn completions_cmd(shell: Shell) {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "rust_proxy", &mut std::io::stdout());
}

async fn run_daemon() -> Result<()> {
    iptables::require_root()?;
    let config = AppConfig::load()?;
    let active_id = config
        .active_proxy
        .clone()
        .context("No active proxy configured")?;

    let proxy_cfg = config
        .proxies
        .iter()
        .find(|p| p.id == active_id)
        .context("Active proxy not found in config")?;

    if config.targets.is_empty() {
        bail!("No targets configured. Add domains with `rust_proxy targets add`.");
    }

    let upstream = UpstreamProxy::from_config(proxy_cfg)?;
    let upstream_host = upstream.host.clone();
    let upstream_hosts = vec![upstream_host.clone()];
    let upstream_excludes = dns::resolve_ipv4(&upstream_hosts).await?;
    if upstream_excludes.is_empty() {
        tracing::warn!(
            "No IPv4 addresses found for upstream {}. Upstream traffic may be redirected.",
            upstream_host
        );
    }

    let state = Arc::new(StateStore::load().await?);
    state.record_activated(&active_id, chrono::Utc::now()).await;
    state.clone().start_flush_loop(Duration::from_secs(5));

    // Create runtime state for dynamic proxy management
    let runtime_state = RuntimeState::new(config.active_proxy.clone());

    iptables::ensure_ipset(&config.settings.ipset_name)?;

    let initial_targets = build_target_entries(&config).await?;
    iptables::sync_ipset(&config.settings.ipset_name, &initial_targets)?;
    iptables::apply_rules(
        &config.settings.chain_name,
        &config.settings.ipset_name,
        config.settings.listen_port,
        None,
        &upstream_excludes,
    )?;

    let refresh_targets = config.targets.clone();
    let include_aws = config.settings.include_aws_ip_ranges;
    let include_cloudflare = config.settings.include_cloudflare_ip_ranges;
    let include_google = config.settings.include_google_ip_ranges;
    let ipset_name = config.settings.ipset_name.clone();
    let refresh_secs = config.settings.dns_refresh_secs;
    let refresh_task = tokio::spawn(async move {
        let mut seen: HashSet<String> = HashSet::new();
        loop {
            tokio::time::sleep(Duration::from_secs(refresh_secs)).await;
            match refresh_target_entries(
                &refresh_targets,
                include_aws,
                include_cloudflare,
                include_google,
            )
            .await
            {
                Ok(entries) => {
                    if let Err(err) = iptables::sync_ipset(&ipset_name, &entries) {
                        tracing::warn!("ipset sync failed: {err}");
                    } else if seen != entries {
                        tracing::info!("ipset refreshed: {} targets", entries.len());
                        seen = entries;
                    }
                }
                Err(err) => tracing::warn!("target refresh failed: {err}"),
            }
        }
    });

    let ping_proxies = config.proxies.clone();
    let ping_interval = config.settings.ping_interval_secs;
    let ping_timeout = config.settings.ping_timeout_ms;
    let state_clone = state.clone();
    let ping_task = tokio::spawn(async move {
        loop {
            for proxy in &ping_proxies {
                if let Ok(endpoint) = util::parse_proxy_url(&proxy.url) {
                    match ping_proxy(&endpoint.host, endpoint.port, ping_timeout).await {
                        Ok(ms) => state_clone.record_ping(&proxy.id, ms).await,
                        Err(err) => tracing::warn!("ping failed for {}: {err}", proxy.id),
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(ping_interval)).await;
        }
    });

    // Health check task (only if enabled)
    let health_task = if config.settings.health_check_enabled {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let health_config = config.clone();
        let health_state = state.clone();
        let health_runtime = runtime_state.clone();
        Some((
            tokio::spawn(health::health_check_loop(
                health_config,
                health_state,
                health_runtime,
                shutdown_rx,
            )),
            shutdown_tx,
        ))
    } else {
        None
    };

    let retry_config = RetryConfig {
        max_retries: config.settings.connect_max_retries,
        initial_backoff_ms: config.settings.connect_initial_backoff_ms,
        max_backoff_ms: config.settings.connect_max_backoff_ms,
    };
    let proxy_task = tokio::spawn(proxy::run_proxy(
        config.settings.listen_port,
        upstream,
        state.clone(),
        retry_config,
    ));

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutdown signal received");
        }
        res = proxy_task => {
            match res {
                Ok(Ok(())) => tracing::info!("Proxy task completed"),
                Ok(Err(err)) => tracing::error!("Proxy error: {err}"),
                Err(err) => tracing::error!("Proxy task panicked: {err}"),
            }
        }
    }

    refresh_task.abort();
    ping_task.abort();
    if let Some((task, shutdown_tx)) = health_task {
        let _ = shutdown_tx.send(true);
        task.abort();
    }
    iptables::clear_rules(&config.settings.chain_name, &config.settings.ipset_name)?;
    state.flush().await?;

    Ok(())
}

async fn ping_proxy(host: &str, port: u16, timeout_ms: u64) -> Result<f64> {
    let timeout = util::format_timeout(timeout_ms)?;
    let start = Instant::now();
    let connect = TcpStream::connect((host, port));
    let stream = tokio::time::timeout(timeout, connect)
        .await
        .context("Ping timed out")??;
    drop(stream);
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

fn build_proxy_rows(config: &AppConfig, state: &State) -> Vec<ProxyRow> {
    let mut rows = Vec::new();
    for proxy in &config.proxies {
        let stats = state.proxies.get(&proxy.id).cloned().unwrap_or_default();
        let active = if config.active_proxy.as_deref() == Some(proxy.id.as_str()) {
            "ACTIVE".green().to_string()
        } else {
            "-".to_string()
        };
        let since = util::format_duration_since(stats.activated_at);
        let sent = util::format_bytes(stats.bytes_sent);
        let received = util::format_bytes(stats.bytes_received);
        let ping = stats
            .ping_avg_ms
            .map(|ms| format!("{:.0}ms", ms))
            .unwrap_or_else(|| "-".to_string());
        let last_active = util::format_since_label(stats.last_active);

        rows.push(ProxyRow {
            id: proxy.id.clone(),
            url: proxy.url.clone(),
            active,
            since,
            sent,
            received,
            ping,
            last_active,
        });
    }
    rows
}

async fn build_target_entries(config: &AppConfig) -> Result<HashSet<String>> {
    refresh_target_entries(
        &config.targets,
        config.settings.include_aws_ip_ranges,
        config.settings.include_cloudflare_ip_ranges,
        config.settings.include_google_ip_ranges,
    )
    .await
}

async fn refresh_target_entries(
    domains: &[TargetSpec],
    include_aws: bool,
    include_cloudflare: bool,
    include_google: bool,
) -> Result<HashSet<String>> {
    let domains: Vec<String> = domains.iter().map(|d| d.domain().to_string()).collect();
    let mut entries = dns::resolve_ipv4(&domains).await?;
    if include_aws {
        match ip_ranges::fetch_aws_ipv4().await {
            Ok(prefixes) => entries.extend(prefixes),
            Err(err) => tracing::warn!("AWS IP ranges fetch failed: {err}"),
        }
    }
    if include_cloudflare {
        match ip_ranges::fetch_cloudflare_ipv4().await {
            Ok(prefixes) => entries.extend(prefixes),
            Err(err) => tracing::warn!("Cloudflare IP ranges fetch failed: {err}"),
        }
    }
    if include_google {
        match ip_ranges::fetch_google_ipv4().await {
            Ok(prefixes) => entries.extend(prefixes),
            Err(err) => tracing::warn!("Google IP ranges fetch failed: {err}"),
        }
    }
    Ok(entries)
}

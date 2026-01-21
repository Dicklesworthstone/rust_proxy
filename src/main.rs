use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use owo_colors::OwoColorize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tabled::settings::Style;
use tabled::{Table, Tabled};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

mod config;
mod dns;
mod error;
mod health;
mod ip_ranges;
mod iptables;
mod load_balancer;
mod metrics;
mod metrics_server;
mod output;
mod proxy;
mod state;
mod util;
mod validation;
mod watcher;

use config::{infer_provider, AppConfig, Provider, ProxyAuth, ProxyConfig, TargetSpec};
use load_balancer::LoadBalancer;
use output::OutputDispatcher;
use proxy::RetryConfig;
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
    /// Check system dependencies (deprecated, use doctor)
    Diagnose,
    /// Comprehensive health check for rust_proxy
    Doctor {
        /// Output results as JSON
        #[arg(long)]
        json: bool,
        /// Only output errors (no success messages)
        #[arg(long)]
        quiet: bool,
        /// Skip network connectivity tests
        #[arg(long)]
        offline: bool,
    },
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
        /// Validate health check target is reachable through proxies
        #[arg(long)]
        validate_health_target: bool,
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
    /// Trace full connection flow to a target through the proxy
    Trace {
        /// URL or domain to trace (e.g., https://api.openai.com, api.openai.com:443)
        target: String,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
        /// Attempt TLS handshake after CONNECT
        #[arg(long)]
        tls: bool,
    },
    /// Ping a proxy and report latency statistics
    Ping {
        /// Proxy ID to ping (defaults to active proxy)
        proxy_id: Option<String>,
        /// Output results as JSON
        #[arg(long)]
        json: bool,
        /// Number of pings to send
        #[arg(long, default_value = "3")]
        count: u32,
        /// Interval between pings in milliseconds
        #[arg(long = "interval", default_value = "1000")]
        interval_ms: u64,
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
        Commands::Init { force } => {
            let output = OutputDispatcher::from_flags(false, false);
            init_config(force, &output)?
        }
        Commands::Proxy { command } => {
            let output = OutputDispatcher::from_flags(false, false);
            proxy_cmd(command, &output)?
        }
        Commands::Targets { command } => {
            let output = OutputDispatcher::from_flags(false, false);
            targets_cmd(command, &output)?
        }
        Commands::List(args) => {
            let output = OutputDispatcher::from_flags(args.json, false);
            list_cmd(&output)?
        }
        Commands::Activate { id, select, run } => {
            let output = OutputDispatcher::from_flags(false, false);
            activate_cmd(id, select, run, &output).await?
        }
        Commands::Deactivate { keep_rules } => {
            let output = OutputDispatcher::from_flags(false, false);
            deactivate_cmd(keep_rules, &output)?
        }
        Commands::Daemon => run_daemon().await?,
        Commands::Status(args) => {
            let output = OutputDispatcher::from_flags(args.json, false);
            status_cmd(&output)?
        }
        Commands::Diagnose => {
            let output = OutputDispatcher::from_flags(false, false);
            diagnose_cmd(&output)?
        }
        Commands::Doctor {
            json,
            quiet,
            offline,
        } => {
            let output = OutputDispatcher::from_flags(json, quiet);
            doctor_cmd(&output, offline).await?
        }
        Commands::Check {
            strict,
            json,
            quiet,
            test_connectivity,
        } => {
            let output = OutputDispatcher::from_flags(json, quiet);
            check_cmd(strict, test_connectivity, &output).await?
        }
        Commands::Test {
            url,
            json,
            verbose,
            no_dns,
        } => {
            let output = OutputDispatcher::from_flags(json, false);
            test_cmd(&url, verbose, no_dns, &output).await?
        }
        Commands::Trace { target, json, tls } => {
            let output = OutputDispatcher::from_flags(json, false);
            trace_cmd(&target, tls, &output).await?
        }
        Commands::Ping {
            proxy_id,
            json,
            count,
            interval_ms,
        } => {
            let output = OutputDispatcher::from_flags(json, false);
            ping_cmd(proxy_id, count, interval_ms, &output).await?
        }
        Commands::Completions { shell } => completions_cmd(shell),
    }

    Ok(())
}

fn init_config(force: bool, output: &OutputDispatcher) -> Result<()> {
    let config_path = config::config_path()?;
    let state_path = state::state_path()?;

    // Check if config already exists
    let already_exists = config_path.exists() && !force;

    if already_exists {
        // Config exists and --force not used
        if output.mode().is_json() {
            output.print_json(&serde_json::json!({
                "config_path": config_path.display().to_string(),
                "state_path": state_path.display().to_string(),
                "created": false,
                "message": "Config already exists"
            }));
        } else if output.mode().is_rich() {
            let content = format!(
                "[bold cyan]rust_proxy[/] is already initialized.\n\n\
                 [bold]Config:[/]  {}\n\
                 [bold]State:[/]   {}\n\n\
                 Use [dim]--force[/] to overwrite the existing configuration.",
                config_path.display(),
                state_path.display()
            );
            let panel = output::widgets::info_panel(&content, "Already Initialized");
            output.print_renderable(&panel);
        } else {
            output.print_plain(&format!(
                "Config already exists at {}",
                config_path.display()
            ));
        }
        return Ok(());
    }

    // Create the config
    config::write_config_template(&config_path)?;

    if output.mode().is_json() {
        output.print_json(&serde_json::json!({
            "config_path": config_path.display().to_string(),
            "state_path": state_path.display().to_string(),
            "created": true,
            "message": "Configuration initialized successfully"
        }));
    } else if output.mode().is_rich() {
        let content = format!(
            "[bold cyan]rust_proxy[/] initialized successfully!\n\n\
             [bold]Config:[/]  {}\n\
             [bold]State:[/]   {}\n\n\
             [bold]Next steps:[/]\n\
             1. Add a proxy:    [dim]rust_proxy proxy add <id> <host:port>[/]\n\
             2. Add targets:    [dim]rust_proxy targets add <domain>[/]\n\
             3. Activate:       [dim]rust_proxy activate --select[/]\n\
             4. Start daemon:   [dim]sudo rust_proxy daemon[/]",
            config_path.display(),
            state_path.display()
        );
        let panel = output::widgets::success_panel(&content);
        output.print_renderable(&panel);
    } else {
        output.print_plain(&format!("Wrote config to {}", config_path.display()));
    }

    Ok(())
}

fn proxy_cmd(cmd: ProxyCmd, _output: &OutputDispatcher) -> Result<()> {
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
                weight: 100,
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

fn targets_cmd(cmd: TargetCmd, _output: &OutputDispatcher) -> Result<()> {
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

fn list_cmd(output: &OutputDispatcher) -> Result<()> {
    let config = AppConfig::load()?;
    let state_path = state::state_path()?;
    let state = State::load(&state_path)?;

    if output.mode().is_json() {
        let payload = serde_json::json!({
            "active_proxy": config.active_proxy,
            "proxies": config.proxies,
            "stats": state,
        });
        output.print_json(&payload);
        return Ok(());
    }

    let rows = build_proxy_rows(&config, &state);
    let mut table = Table::new(rows);
    table.with(Style::ascii());
    println!("{}", table);
    Ok(())
}

fn status_cmd(output: &OutputDispatcher) -> Result<()> {
    let config = AppConfig::load()?;
    let state_path = state::state_path()?;
    let state = State::load(&state_path)?;
    let rules_active = iptables::chain_present(&config.settings.chain_name);

    if output.mode().is_json() {
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
                    "weight": p.weight,
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

        // Build load balancing info
        let load_balancing = serde_json::json!({
            "strategy": format!("{:?}", config.settings.load_balance_strategy).to_lowercase(),
            "note": "Selection stats only available when daemon is running"
        });

        let payload = serde_json::json!({
            "active_proxy": config.active_proxy,
            "active_proxy_health": active_health,
            "rules_active": rules_active,
            "health_check_enabled": config.settings.health_check_enabled,
            "auto_failover": config.settings.auto_failover,
            "auto_failback": config.settings.auto_failback,
            "targets": config.targets.len(),
            "load_balancing": load_balancing,
            "proxy_health": proxy_health,
            "stats": state,
        });
        output.print_json(&payload);
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

    // Show load balancing configuration
    let strategy_str = match config.settings.load_balance_strategy {
        config::LoadBalanceStrategy::Single => "single".to_string(),
        config::LoadBalanceStrategy::RoundRobin => "round_robin".cyan().to_string(),
        config::LoadBalanceStrategy::LeastLatency => "least_latency".cyan().to_string(),
        config::LoadBalanceStrategy::Weighted => "weighted".cyan().to_string(),
    };
    println!("Load balancing: {}", strategy_str);

    // Show health summary if health checks are enabled and there are proxies
    let show_weight =
        config.settings.load_balance_strategy == config::LoadBalanceStrategy::Weighted;
    if config.settings.health_check_enabled && !config.proxies.is_empty() {
        println!();
        println!("Proxy Health Summary:");
        if show_weight {
            println!(
                "  {:<12} {:<12} {:<10} {:<8} {:<10} {:<12} Failures",
                "ID", "Status", "Priority", "Weight", "Latency", "Last Check"
            );
        } else {
            println!(
                "  {:<12} {:<12} {:<10} {:<10} {:<12} Failures",
                "ID", "Status", "Priority", "Latency", "Last Check"
            );
        }
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

            if show_weight {
                println!(
                    "  {:<12} {:<12} {:<10} {:<8} {:<10} {:<12} {}",
                    proxy.id, status, priority, proxy.weight, latency, last_check, failures
                );
            } else {
                println!(
                    "  {:<12} {:<12} {:<10} {:<10} {:<12} {}",
                    proxy.id, status, priority, latency, last_check, failures
                );
            }
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

async fn activate_cmd(
    id: Option<String>,
    select: bool,
    run: bool,
    _output: &OutputDispatcher,
) -> Result<()> {
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

fn deactivate_cmd(keep_rules: bool, _output: &OutputDispatcher) -> Result<()> {
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

fn diagnose_cmd(_output: &OutputDispatcher) -> Result<()> {
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

// ============================================================================
// Doctor Command - Comprehensive Health Check
// ============================================================================

/// Individual check result for doctor command
#[derive(Debug, Clone, serde::Serialize)]
struct DoctorCheck {
    name: String,
    status: DoctorStatus,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    suggestion: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Ok,
    Warning,
    Error,
}

/// Overall doctor report
#[derive(Debug, Clone, serde::Serialize)]
struct DoctorReport {
    healthy: bool,
    checks: Vec<DoctorCheck>,
    summary: DoctorSummary,
}

#[derive(Debug, Clone, serde::Serialize)]
struct DoctorSummary {
    total: usize,
    passed: usize,
    warnings: usize,
    errors: usize,
}

impl DoctorCheck {
    fn ok(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: DoctorStatus::Ok,
            message: message.into(),
            suggestion: None,
        }
    }

    fn warning(
        name: impl Into<String>,
        message: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: DoctorStatus::Warning,
            message: message.into(),
            suggestion: Some(suggestion.into()),
        }
    }

    fn error(
        name: impl Into<String>,
        message: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: DoctorStatus::Error,
            message: message.into(),
            suggestion: Some(suggestion.into()),
        }
    }
}

/// Comprehensive health check command
async fn doctor_cmd(output: &OutputDispatcher, offline: bool) -> Result<()> {
    let mut checks = Vec::new();

    // 1. Check config file
    checks.push(check_config_file().await);

    // 2. Check config validity (if file exists)
    let config = check_config_validity(&mut checks).await;

    // 3. Check state directory
    checks.push(check_state_directory().await);

    // 4. Check system dependencies (iptables, ipset)
    checks.extend(check_system_dependencies().await);

    // 5. Check listen port availability (if config loaded)
    if let Some(ref cfg) = config {
        checks.push(check_listen_port(cfg.settings.listen_port).await);
    }

    // 6. Network checks (unless offline)
    if !offline {
        if let Some(ref cfg) = config {
            // Check proxy connectivity
            checks.extend(check_proxy_connectivity(cfg).await);

            // Check DNS resolution for a sample domain
            checks.push(check_dns_resolution().await);
        }
    } else {
        checks.push(DoctorCheck::ok("Network Tests", "Skipped (--offline mode)"));
    }

    // Build report
    let passed = checks
        .iter()
        .filter(|c| c.status == DoctorStatus::Ok)
        .count();
    let warnings = checks
        .iter()
        .filter(|c| c.status == DoctorStatus::Warning)
        .count();
    let errors = checks
        .iter()
        .filter(|c| c.status == DoctorStatus::Error)
        .count();

    let report = DoctorReport {
        healthy: errors == 0,
        checks: checks.clone(),
        summary: DoctorSummary {
            total: checks.len(),
            passed,
            warnings,
            errors,
        },
    };

    // Output based on mode
    if output.mode().is_json() {
        output.print_json(&report);
    } else {
        print_doctor_report(output, &report);
    }

    // Exit with error code if unhealthy
    if !report.healthy {
        std::process::exit(1);
    }

    Ok(())
}

fn print_doctor_report(output: &OutputDispatcher, report: &DoctorReport) {
    output.print_rich("\n[bold]rust_proxy doctor[/]\n");

    for check in &report.checks {
        let (icon, color) = match check.status {
            DoctorStatus::Ok => ("✓", "green"),
            DoctorStatus::Warning => ("!", "yellow"),
            DoctorStatus::Error => ("✗", "red"),
        };

        output.print_rich(&format!(
            "[{color}]{icon}[/] [bold]{}[/]: {}",
            check.name, check.message
        ));

        if let Some(ref suggestion) = check.suggestion {
            output.print_rich(&format!("  [dim]→ {}[/]", suggestion));
        }
    }

    output.newline();

    // Summary line
    let summary = &report.summary;
    let status_text = if report.healthy {
        "[bold green]All checks passed[/]"
    } else {
        "[bold red]Issues detected[/]"
    };

    output.print_rich(&format!(
        "{} ({} passed, {} warnings, {} errors)",
        status_text, summary.passed, summary.warnings, summary.errors
    ));
    output.newline();
}

async fn check_config_file() -> DoctorCheck {
    match config::config_path() {
        Ok(path) => {
            if path.exists() {
                DoctorCheck::ok("Config File", format!("Found at {}", path.display()))
            } else {
                DoctorCheck::error(
                    "Config File",
                    format!("Not found at {}", path.display()),
                    "Run 'rp init' to create a default configuration",
                )
            }
        }
        Err(e) => DoctorCheck::error(
            "Config File",
            format!("Cannot determine path: {}", e),
            "Check your home directory permissions",
        ),
    }
}

async fn check_config_validity(checks: &mut Vec<DoctorCheck>) -> Option<AppConfig> {
    match AppConfig::load() {
        Ok(config) => {
            // Basic validation
            if config.proxies.is_empty() {
                checks.push(DoctorCheck::warning(
                    "Config Validation",
                    "No proxies configured",
                    "Add a proxy with 'rp proxy add <id> <url>'",
                ));
            } else {
                checks.push(DoctorCheck::ok(
                    "Config Validation",
                    format!(
                        "{} proxies, {} targets configured",
                        config.proxies.len(),
                        config.targets.len()
                    ),
                ));
            }

            if config.active_proxy.is_none() && !config.proxies.is_empty() {
                checks.push(DoctorCheck::warning(
                    "Active Proxy",
                    "No proxy is currently active",
                    "Run 'rp activate <proxy-id>' to activate a proxy",
                ));
            } else if let Some(ref active) = config.active_proxy {
                let exists = config.proxies.iter().any(|p| &p.id == active);
                if exists {
                    checks.push(DoctorCheck::ok(
                        "Active Proxy",
                        format!("'{}' is active", active),
                    ));
                } else {
                    checks.push(DoctorCheck::error(
                        "Active Proxy",
                        format!("'{}' is set but not found in proxies", active),
                        "Update active_proxy in config or run 'rp activate <valid-id>'",
                    ));
                }
            }

            Some(config)
        }
        Err(e) => {
            checks.push(DoctorCheck::error(
                "Config Validation",
                format!("Failed to load: {}", e),
                "Check config syntax with 'rp check'",
            ));
            None
        }
    }
}

async fn check_state_directory() -> DoctorCheck {
    match config::state_dir() {
        Ok(dir) => {
            // Check if directory exists
            if !dir.exists() {
                // Try to create it
                if std::fs::create_dir_all(&dir).is_ok() {
                    return DoctorCheck::ok(
                        "State Directory",
                        format!("Created at {}", dir.display()),
                    );
                } else {
                    return DoctorCheck::error(
                        "State Directory",
                        format!("Cannot create {}", dir.display()),
                        "Check parent directory permissions",
                    );
                }
            }

            // Check if writable by creating a temp file
            let test_file = dir.join(".doctor_test");
            match std::fs::write(&test_file, "test") {
                Ok(()) => {
                    let _ = std::fs::remove_file(&test_file);
                    DoctorCheck::ok("State Directory", format!("Writable at {}", dir.display()))
                }
                Err(e) => DoctorCheck::error(
                    "State Directory",
                    format!("Not writable: {}", e),
                    "Check directory permissions",
                ),
            }
        }
        Err(e) => DoctorCheck::error(
            "State Directory",
            format!("Cannot determine path: {}", e),
            "Check your home directory permissions",
        ),
    }
}

async fn check_system_dependencies() -> Vec<DoctorCheck> {
    let mut checks = Vec::new();

    // Check iptables
    let iptables_ok = std::process::Command::new("iptables")
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if iptables_ok {
        checks.push(DoctorCheck::ok("iptables", "Available"));
    } else {
        checks.push(DoctorCheck::error(
            "iptables",
            "Not found or not executable",
            "Install iptables (apt install iptables / dnf install iptables)",
        ));
    }

    // Check ipset
    let ipset_ok = std::process::Command::new("ipset")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if ipset_ok {
        checks.push(DoctorCheck::ok("ipset", "Available"));
    } else {
        checks.push(DoctorCheck::error(
            "ipset",
            "Not found or not executable",
            "Install ipset (apt install ipset / dnf install ipset)",
        ));
    }

    checks
}

async fn check_listen_port(port: u16) -> DoctorCheck {
    use tokio::net::TcpListener;

    match TcpListener::bind(format!("127.0.0.1:{}", port)).await {
        Ok(_) => DoctorCheck::ok("Listen Port", format!("Port {} is available", port)),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::AddrInUse {
                // Check if it's our daemon
                DoctorCheck::warning(
                    "Listen Port",
                    format!("Port {} is in use", port),
                    "This may be the rust_proxy daemon or another process",
                )
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                DoctorCheck::warning(
                    "Listen Port",
                    format!("Port {} requires elevated privileges", port),
                    "Run with sudo or use a port >= 1024",
                )
            } else {
                DoctorCheck::error(
                    "Listen Port",
                    format!("Cannot bind to port {}: {}", port, e),
                    "Check if port is in use or try a different port",
                )
            }
        }
    }
}

async fn check_proxy_connectivity(config: &AppConfig) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();

    if config.proxies.is_empty() {
        return checks;
    }

    let timeout_ms = config.settings.health_check_timeout_ms;

    for proxy in &config.proxies {
        let result =
            health::check_proxy_health(proxy, timeout_ms, &config.settings.health_check_target)
                .await;

        if result.success {
            checks.push(DoctorCheck::ok(
                format!("Proxy '{}'", proxy.id),
                format!("Reachable ({}ms)", result.latency_ms as u64),
            ));
        } else {
            let reason = result
                .failure_reason
                .unwrap_or_else(|| "Unknown".to_string());
            if reason.contains("timeout") {
                checks.push(DoctorCheck::warning(
                    format!("Proxy '{}'", proxy.id),
                    format!("Timeout after {}ms", timeout_ms),
                    "Check proxy URL and network connectivity",
                ));
            } else if reason.contains("407") {
                checks.push(DoctorCheck::warning(
                    format!("Proxy '{}'", proxy.id),
                    "Authentication required (407)",
                    "Configure proxy credentials with --username/--password",
                ));
            } else {
                checks.push(DoctorCheck::error(
                    format!("Proxy '{}'", proxy.id),
                    format!("Connection failed: {}", reason),
                    "Verify proxy URL and that the proxy is running",
                ));
            }
        }
    }

    checks
}

async fn check_dns_resolution() -> DoctorCheck {
    // Test DNS resolution with a reliable domain
    let test_domain = "www.google.com";

    match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((test_domain, 80)),
    )
    .await
    {
        Ok(Ok(addrs)) => {
            let count = addrs.count();
            if count > 0 {
                DoctorCheck::ok(
                    "DNS Resolution",
                    format!("{} resolved ({} addresses)", test_domain, count),
                )
            } else {
                DoctorCheck::warning(
                    "DNS Resolution",
                    format!("{} returned no addresses", test_domain),
                    "Check your DNS configuration",
                )
            }
        }
        Ok(Err(e)) => DoctorCheck::error(
            "DNS Resolution",
            format!("Failed to resolve {}: {}", test_domain, e),
            "Check your network and DNS settings",
        ),
        Err(_) => DoctorCheck::error(
            "DNS Resolution",
            "DNS lookup timed out after 5 seconds",
            "Check your network connectivity and DNS settings",
        ),
    }
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
    target: &config::HealthCheckTarget,
) -> ConnectivityResult {
    use health::check_proxy_health;

    let result = check_proxy_health(proxy, timeout_ms, target).await;

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

async fn check_cmd(strict: bool, test_connectivity: bool, output: &OutputDispatcher) -> Result<()> {
    use validation::{validate_config, ValidationSeverity};

    let config_path = config::config_path()?;

    // Try to load config
    let config = match AppConfig::load() {
        Ok(config) => config,
        Err(err) => {
            if output.mode().is_json() {
                let json_output = serde_json::json!({
                    "valid": false,
                    "config_path": config_path.display().to_string(),
                    "errors": [{
                        "category": "file",
                        "message": format!("Failed to load configuration: {}", err),
                    }],
                    "warnings": [],
                });
                output.print_json(&json_output);
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
            let target = &config.settings.health_check_target;
            let futures: Vec<_> = config
                .proxies
                .iter()
                .map(|proxy| test_proxy_connectivity(proxy, timeout_ms, target))
                .collect();
            futures::future::join_all(futures).await
        } else {
            Vec::new()
        };

    if output.mode().is_json() {
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

        let mut json_output = serde_json::json!({
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
            json_output["connectivity"] = serde_json::json!(connectivity_results);
        }

        output.print_json(&json_output);
    } else if !output.mode().is_quiet() || report.has_errors() || (strict && report.has_warnings())
    {
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

#[derive(Debug)]
struct TraceTarget {
    input: String,
    host: String,
    port: u16,
    scheme: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct TraceTargetInfo {
    host: String,
    port: u16,
    scheme: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct TraceProxyInfo {
    id: String,
    url: String,
    host: String,
    port: u16,
}

#[derive(Debug, serde::Serialize)]
struct TraceReport {
    input: String,
    target: TraceTargetInfo,
    resolved_ips: Vec<String>,
    dns_error: Option<String>,
    proxy: Option<TraceProxyInfo>,
    steps: Vec<TraceStep>,
    total_ms: u64,
}

#[derive(Debug, serde::Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum TraceStatus {
    Ok,
    Failed,
    Skipped,
}

#[derive(Debug, serde::Serialize)]
struct TraceStep {
    name: String,
    status: TraceStatus,
    duration_ms: Option<u64>,
    detail: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct PingAttempt {
    seq: u32,
    success: bool,
    latency_ms: Option<f64>,
    error: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct PingSummary {
    sent: u32,
    received: u32,
    loss_pct: f64,
    min_ms: Option<f64>,
    avg_ms: Option<f64>,
    max_ms: Option<f64>,
}

#[derive(Debug, serde::Serialize)]
struct PingReport {
    proxy_id: String,
    proxy_url: String,
    proxy_host: String,
    proxy_port: u16,
    count: u32,
    interval_ms: u64,
    results: Vec<PingAttempt>,
    summary: PingSummary,
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

/// Parse a trace target into host/port with sensible defaults.
fn parse_trace_target(input: &str) -> Result<TraceTarget> {
    let trimmed = input.trim();
    let url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        url::Url::parse(trimmed)
    } else {
        url::Url::parse(&format!("https://{}", trimmed))
    }
    .with_context(|| format!("Invalid target: {trimmed}"))?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Target missing host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("Target missing port"))?;

    Ok(TraceTarget {
        input: input.to_string(),
        host: host.to_string(),
        port,
        scheme: Some(url.scheme().to_string()),
    })
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

async fn test_cmd(url: &str, verbose: bool, no_dns: bool, output: &OutputDispatcher) -> Result<()> {
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
    if output.mode().is_json() {
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

fn push_trace_step(
    steps: &mut Vec<TraceStep>,
    name: &str,
    status: TraceStatus,
    duration: Option<Duration>,
    detail: Option<String>,
) {
    steps.push(TraceStep {
        name: name.to_string(),
        status,
        duration_ms: duration.map(|elapsed| elapsed.as_millis() as u64),
        detail,
    });
}

fn push_trace_skip(steps: &mut Vec<TraceStep>, name: &str, reason: &str) {
    push_trace_step(
        steps,
        name,
        TraceStatus::Skipped,
        None,
        Some(reason.to_string()),
    );
}

async fn trace_cmd(target: &str, tls: bool, output: &OutputDispatcher) -> Result<()> {
    let config = AppConfig::load()?;
    let target = parse_trace_target(target)?;

    let mut steps = Vec::new();
    let overall_start = Instant::now();

    // Step 1: DNS resolution
    let dns_start = Instant::now();
    let dns_result = dns::resolve_ipv4(std::slice::from_ref(&target.host)).await;
    let dns_duration = dns_start.elapsed();
    let (resolved_ips, dns_error) = match dns_result {
        Ok(ips) => {
            let mut list: Vec<String> = ips.into_iter().collect();
            list.sort();
            push_trace_step(
                &mut steps,
                "DNS resolution",
                TraceStatus::Ok,
                Some(dns_duration),
                Some(format!(
                    "Resolved {} IP(s): {}",
                    list.len(),
                    if list.is_empty() {
                        "none".to_string()
                    } else {
                        list.join(", ")
                    }
                )),
            );
            (list, None)
        }
        Err(err) => {
            let msg = err.to_string();
            push_trace_step(
                &mut steps,
                "DNS resolution",
                TraceStatus::Failed,
                Some(dns_duration),
                Some(msg.clone()),
            );
            (Vec::new(), Some(msg))
        }
    };

    // Step 2: Proxy selection
    let selection_start = Instant::now();
    let state = StateStore::load().await?;
    let load_balancer = LoadBalancer::new();
    let selected_proxy = load_balancer
        .select_proxy(
            config.settings.load_balance_strategy,
            &config.proxies,
            &state,
        )
        .await;
    let selection_duration = selection_start.elapsed();

    let proxy_id = match selected_proxy {
        Some(id) => {
            push_trace_step(
                &mut steps,
                "Proxy selection",
                TraceStatus::Ok,
                Some(selection_duration),
                Some(format!(
                    "Selected {id} (strategy: {:?})",
                    config.settings.load_balance_strategy
                )),
            );
            id
        }
        None => {
            push_trace_step(
                &mut steps,
                "Proxy selection",
                TraceStatus::Failed,
                Some(selection_duration),
                Some("No healthy proxy available".to_string()),
            );
            push_trace_skip(
                &mut steps,
                "Proxy connect",
                "Skipped due to proxy selection failure",
            );
            push_trace_skip(
                &mut steps,
                "CONNECT request",
                "Skipped due to proxy selection failure",
            );
            push_trace_skip(
                &mut steps,
                "Proxy response",
                "Skipped due to proxy selection failure",
            );
            push_trace_skip(
                &mut steps,
                "TLS handshake",
                "Skipped due to proxy selection failure",
            );

            let report = TraceReport {
                input: target.input.clone(),
                target: TraceTargetInfo {
                    host: target.host.clone(),
                    port: target.port,
                    scheme: target.scheme.clone(),
                },
                resolved_ips,
                dns_error,
                proxy: None,
                steps,
                total_ms: overall_start.elapsed().as_millis() as u64,
            };
            output_trace_report(&report, output);
            return Ok(());
        }
    };

    let proxy_cfg = match config.proxies.iter().find(|p| p.id == proxy_id) {
        Some(proxy) => proxy,
        None => {
            push_trace_step(
                &mut steps,
                "Proxy selection",
                TraceStatus::Failed,
                Some(Duration::from_millis(0)),
                Some(format!("Proxy '{proxy_id}' not found in config")),
            );
            push_trace_skip(
                &mut steps,
                "Proxy connect",
                "Skipped due to proxy selection failure",
            );
            push_trace_skip(
                &mut steps,
                "CONNECT request",
                "Skipped due to proxy selection failure",
            );
            push_trace_skip(
                &mut steps,
                "Proxy response",
                "Skipped due to proxy selection failure",
            );
            push_trace_skip(
                &mut steps,
                "TLS handshake",
                "Skipped due to proxy selection failure",
            );

            let report = TraceReport {
                input: target.input.clone(),
                target: TraceTargetInfo {
                    host: target.host.clone(),
                    port: target.port,
                    scheme: target.scheme.clone(),
                },
                resolved_ips,
                dns_error,
                proxy: None,
                steps,
                total_ms: overall_start.elapsed().as_millis() as u64,
            };
            output_trace_report(&report, output);
            return Ok(());
        }
    };

    let upstream = proxy::UpstreamProxy::from_config(proxy_cfg)?;
    let proxy_info = TraceProxyInfo {
        id: upstream.id.clone(),
        url: proxy_cfg.url.clone(),
        host: upstream.host.clone(),
        port: upstream.port,
    };

    let timeout = util::format_timeout(config.settings.health_check_timeout_ms)?;

    // Step 3: Proxy TCP connect
    let connect_start = Instant::now();
    let connect_result = tokio::time::timeout(
        timeout,
        TcpStream::connect((upstream.host.as_str(), upstream.port)),
    )
    .await;
    let connect_duration = connect_start.elapsed();

    let mut upstream_socket = match connect_result {
        Ok(Ok(socket)) => {
            push_trace_step(
                &mut steps,
                "Proxy connect",
                TraceStatus::Ok,
                Some(connect_duration),
                Some(format!("Connected to {}:{}", upstream.host, upstream.port)),
            );
            socket
        }
        Ok(Err(err)) => {
            push_trace_step(
                &mut steps,
                "Proxy connect",
                TraceStatus::Failed,
                Some(connect_duration),
                Some(err.to_string()),
            );
            push_trace_skip(
                &mut steps,
                "CONNECT request",
                "Skipped due to connect failure",
            );
            push_trace_skip(
                &mut steps,
                "Proxy response",
                "Skipped due to connect failure",
            );
            push_trace_skip(
                &mut steps,
                "TLS handshake",
                "Skipped due to connect failure",
            );

            let report = TraceReport {
                input: target.input.clone(),
                target: TraceTargetInfo {
                    host: target.host.clone(),
                    port: target.port,
                    scheme: target.scheme.clone(),
                },
                resolved_ips,
                dns_error,
                proxy: Some(proxy_info),
                steps,
                total_ms: overall_start.elapsed().as_millis() as u64,
            };
            output_trace_report(&report, output);
            return Ok(());
        }
        Err(_) => {
            push_trace_step(
                &mut steps,
                "Proxy connect",
                TraceStatus::Failed,
                Some(connect_duration),
                Some("Connection timed out".to_string()),
            );
            push_trace_skip(
                &mut steps,
                "CONNECT request",
                "Skipped due to connect failure",
            );
            push_trace_skip(
                &mut steps,
                "Proxy response",
                "Skipped due to connect failure",
            );
            push_trace_skip(
                &mut steps,
                "TLS handshake",
                "Skipped due to connect failure",
            );

            let report = TraceReport {
                input: target.input.clone(),
                target: TraceTargetInfo {
                    host: target.host.clone(),
                    port: target.port,
                    scheme: target.scheme.clone(),
                },
                resolved_ips,
                dns_error,
                proxy: Some(proxy_info),
                steps,
                total_ms: overall_start.elapsed().as_millis() as u64,
            };
            output_trace_report(&report, output);
            return Ok(());
        }
    };

    // Step 4: CONNECT request
    let auth_header = if let (Some(user), Some(pass)) =
        (upstream.username.as_ref(), upstream.password.as_ref())
    {
        let token = Base64.encode(format!("{user}:{pass}"));
        format!("Proxy-Authorization: Basic {}\r\n", token)
    } else {
        String::new()
    };

    let connect_req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n{}\r\n",
        target.host, target.port, target.host, target.port, auth_header
    );

    let request_start = Instant::now();
    let write_result = upstream_socket.write_all(connect_req.as_bytes()).await;
    let request_result = match write_result {
        Ok(()) => upstream_socket.flush().await,
        Err(err) => Err(err),
    };
    let request_duration = request_start.elapsed();

    if let Err(err) = request_result {
        push_trace_step(
            &mut steps,
            "CONNECT request",
            TraceStatus::Failed,
            Some(request_duration),
            Some(err.to_string()),
        );
        push_trace_skip(
            &mut steps,
            "Proxy response",
            "Skipped due to CONNECT failure",
        );
        push_trace_skip(
            &mut steps,
            "TLS handshake",
            "Skipped due to CONNECT failure",
        );

        let report = TraceReport {
            input: target.input.clone(),
            target: TraceTargetInfo {
                host: target.host.clone(),
                port: target.port,
                scheme: target.scheme.clone(),
            },
            resolved_ips,
            dns_error,
            proxy: Some(proxy_info),
            steps,
            total_ms: overall_start.elapsed().as_millis() as u64,
        };
        output_trace_report(&report, output);
        return Ok(());
    }

    push_trace_step(
        &mut steps,
        "CONNECT request",
        TraceStatus::Ok,
        Some(request_duration),
        Some(format!(
            "Sent CONNECT for {}:{}{}",
            target.host,
            target.port,
            if auth_header.is_empty() {
                ""
            } else {
                " (with auth)"
            }
        )),
    );

    // Step 5: Proxy response
    let response_start = Instant::now();
    let mut buffer = [0u8; 1024];
    let response_result = tokio::time::timeout(timeout, upstream_socket.read(&mut buffer)).await;
    let response_duration = response_start.elapsed();

    let mut connect_ok = false;
    match response_result {
        Ok(Ok(0)) => {
            push_trace_step(
                &mut steps,
                "Proxy response",
                TraceStatus::Failed,
                Some(response_duration),
                Some("Proxy closed connection without response".to_string()),
            );
        }
        Ok(Ok(n)) => {
            let response = String::from_utf8_lossy(&buffer[..n]);
            let first_line = response.lines().next().unwrap_or("");
            if first_line.contains("200") {
                connect_ok = true;
                push_trace_step(
                    &mut steps,
                    "Proxy response",
                    TraceStatus::Ok,
                    Some(response_duration),
                    Some(first_line.to_string()),
                );
            } else {
                push_trace_step(
                    &mut steps,
                    "Proxy response",
                    TraceStatus::Failed,
                    Some(response_duration),
                    Some(first_line.to_string()),
                );
            }
        }
        Ok(Err(err)) => {
            push_trace_step(
                &mut steps,
                "Proxy response",
                TraceStatus::Failed,
                Some(response_duration),
                Some(err.to_string()),
            );
        }
        Err(_) => {
            push_trace_step(
                &mut steps,
                "Proxy response",
                TraceStatus::Failed,
                Some(response_duration),
                Some("Response timed out".to_string()),
            );
        }
    }

    // Step 6: Optional TLS handshake
    if !connect_ok {
        push_trace_step(
            &mut steps,
            "TLS handshake",
            TraceStatus::Skipped,
            None,
            Some("CONNECT failed".to_string()),
        );
    } else if !tls {
        push_trace_step(
            &mut steps,
            "TLS handshake",
            TraceStatus::Skipped,
            None,
            Some("Use --tls to enable".to_string()),
        );
    } else {
        let tls_start = Instant::now();
        let tls_result = tokio::time::timeout(
            timeout,
            perform_tls_handshake(upstream_socket, &target.host),
        )
        .await;
        let tls_duration = tls_start.elapsed();
        match tls_result {
            Ok(Ok(())) => {
                push_trace_step(
                    &mut steps,
                    "TLS handshake",
                    TraceStatus::Ok,
                    Some(tls_duration),
                    Some("Handshake completed".to_string()),
                );
            }
            Ok(Err(err)) => {
                push_trace_step(
                    &mut steps,
                    "TLS handshake",
                    TraceStatus::Failed,
                    Some(tls_duration),
                    Some(err.to_string()),
                );
            }
            Err(_) => {
                push_trace_step(
                    &mut steps,
                    "TLS handshake",
                    TraceStatus::Failed,
                    Some(tls_duration),
                    Some("TLS handshake timed out".to_string()),
                );
            }
        }
    }

    let report = TraceReport {
        input: target.input.clone(),
        target: TraceTargetInfo {
            host: target.host.clone(),
            port: target.port,
            scheme: target.scheme.clone(),
        },
        resolved_ips,
        dns_error,
        proxy: Some(proxy_info),
        steps,
        total_ms: overall_start.elapsed().as_millis() as u64,
    };

    output_trace_report(&report, output);
    Ok(())
}

fn output_trace_report(report: &TraceReport, output: &OutputDispatcher) {
    if output.mode().is_json() {
        output.print_json(report);
        return;
    }

    println!(
        "Trace target: {} ({}:{})",
        report.input, report.target.host, report.target.port
    );
    if let Some(proxy) = &report.proxy {
        println!("Proxy: {} ({})", proxy.id, proxy.url);
    } else {
        println!("Proxy: -");
    }
    println!();

    let total_steps = report.steps.len();
    for (idx, step) in report.steps.iter().enumerate() {
        let status = match step.status {
            TraceStatus::Ok => "OK".green().to_string(),
            TraceStatus::Failed => "FAIL".red().to_string(),
            TraceStatus::Skipped => "SKIP".yellow().to_string(),
        };
        let duration = step
            .duration_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "[{}/{}] {:<16} {} ({})",
            idx + 1,
            total_steps,
            step.name,
            status,
            duration
        );
        if let Some(detail) = &step.detail {
            println!("         {}", detail);
        }
    }

    println!();
    println!("Total: {}ms", report.total_ms);
}

async fn perform_tls_handshake(stream: TcpStream, host: &str) -> Result<()> {
    let native = rustls_native_certs::load_native_certs();
    if native.certs.is_empty() {
        anyhow::bail!("No native TLS certificates available");
    }

    let mut roots = RootCertStore::empty();
    for cert in native.certs {
        roots
            .add(cert)
            .context("Failed to add TLS root certificate")?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host)
        .map_err(|_| anyhow::anyhow!("Invalid server name for TLS: {host}"))?
        .to_owned();

    connector
        .connect(server_name, stream)
        .await
        .context("TLS handshake failed")?;
    Ok(())
}

async fn ping_cmd(
    proxy_id: Option<String>,
    count: u32,
    interval_ms: u64,
    output: &OutputDispatcher,
) -> Result<()> {
    if count == 0 {
        bail!("count must be greater than 0");
    }

    let config = AppConfig::load()?;
    let selected_id = match proxy_id {
        Some(id) => id,
        None => config
            .active_proxy
            .clone()
            .context("No proxy ID provided and no active proxy configured")?,
    };

    let proxy_cfg = config
        .proxies
        .iter()
        .find(|p| p.id == selected_id)
        .context("Proxy ID not found in config")?;
    let upstream = proxy::UpstreamProxy::from_config(proxy_cfg)?;

    let timeout_ms = config.settings.health_check_timeout_ms;
    let mut results = Vec::with_capacity(count as usize);
    let mut latencies = Vec::new();

    if !output.mode().is_json() {
        println!(
            "PING {} ({}:{})",
            proxy_cfg.id, upstream.host, upstream.port
        );
    }

    for seq in 1..=count {
        let result =
            health::check_proxy_health(proxy_cfg, timeout_ms, &config.settings.health_check_target)
                .await;
        if result.success {
            latencies.push(result.latency_ms);
            results.push(PingAttempt {
                seq,
                success: true,
                latency_ms: Some(result.latency_ms),
                error: None,
            });
            if !output.mode().is_json() {
                println!("Response {}: time={:.0}ms", seq, result.latency_ms);
            }
        } else {
            let error = result
                .failure_reason
                .clone()
                .unwrap_or_else(|| "failed".to_string());
            results.push(PingAttempt {
                seq,
                success: false,
                latency_ms: None,
                error: Some(error.clone()),
            });
            if !output.mode().is_json() {
                println!("Response {}: FAIL ({})", seq, error);
            }
        }

        if seq < count {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }

    let sent = count;
    let received = latencies.len() as u32;
    let loss_pct = if sent == 0 {
        0.0
    } else {
        ((sent - received) as f64 / sent as f64) * 100.0
    };
    let (min_ms, max_ms, avg_ms) = if latencies.is_empty() {
        (None, None, None)
    } else {
        let min = latencies.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = latencies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
        (Some(min), Some(max), Some(avg))
    };

    let summary = PingSummary {
        sent,
        received,
        loss_pct,
        min_ms,
        avg_ms,
        max_ms,
    };

    let report = PingReport {
        proxy_id: proxy_cfg.id.clone(),
        proxy_url: proxy_cfg.url.clone(),
        proxy_host: upstream.host,
        proxy_port: upstream.port,
        count,
        interval_ms,
        results,
        summary,
    };

    if output.mode().is_json() {
        output.print_json(&report);
        return Ok(());
    }

    println!("--- {} statistics ---", report.proxy_id);
    println!(
        "{} requests, {} responses, {:.0}% loss",
        report.summary.sent, report.summary.received, report.summary.loss_pct
    );
    if let (Some(min), Some(avg), Some(max)) = (
        report.summary.min_ms,
        report.summary.avg_ms,
        report.summary.max_ms,
    ) {
        println!("min/avg/max = {:.0}/{:.1}/{:.0} ms", min, avg, max);
    } else {
        println!("No successful responses");
    }

    Ok(())
}

fn completions_cmd(shell: Shell) {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "rust_proxy", &mut std::io::stdout());
}

async fn run_daemon() -> Result<()> {
    iptables::require_root()?;
    let config = AppConfig::load()?;

    // Initialize metrics registry (safe to call even if already initialized)
    if let Err(e) = metrics::init_metrics() {
        tracing::warn!(error = %e, "Failed to initialize metrics (continuing without metrics)");
    }

    // For Single strategy, require active_proxy; for load-balanced strategies, just need proxies
    let active_id = match config.settings.load_balance_strategy {
        config::LoadBalanceStrategy::Single => {
            let id = config
                .active_proxy
                .clone()
                .context("No active proxy configured (required for Single strategy)")?;
            // Verify active proxy exists
            if !config.proxies.iter().any(|p| p.id == id) {
                bail!("Active proxy '{}' not found in config", id);
            }
            Some(id)
        }
        _ => {
            // For load-balanced strategies, active_proxy is optional
            // (load balancer will select from healthy proxies)
            if config.proxies.is_empty() {
                bail!("No proxies configured");
            }
            config.active_proxy.clone()
        }
    };

    if config.targets.is_empty() {
        bail!("No targets configured. Add domains with `rust_proxy targets add`.");
    }

    metrics::set_target_proxy_counts(config.targets.len(), config.proxies.len());
    metrics::set_effective_proxy(
        config.proxies.iter().map(|p| p.id.as_str()),
        active_id.as_deref(),
    );

    // Collect all proxy hosts to exclude from iptables (prevents redirect loops)
    let mut upstream_hosts = Vec::new();
    for proxy in &config.proxies {
        if let Ok(endpoint) = util::parse_proxy_url(&proxy.url) {
            upstream_hosts.push(endpoint.host);
        }
    }
    upstream_hosts.sort();
    upstream_hosts.dedup();

    let upstream_excludes = dns::resolve_ipv4(&upstream_hosts).await?;
    if upstream_excludes.is_empty() {
        tracing::warn!(
            "No IPv4 addresses found for upstream proxies. Upstream traffic may be redirected."
        );
    }

    let state = Arc::new(StateStore::load().await?);
    if let Some(ref id) = active_id {
        state.record_activated(id, chrono::Utc::now()).await;
    }
    state.clone().start_flush_loop(Duration::from_secs(5));

    // Create load balancer
    let load_balancer = Arc::new(LoadBalancer::new());

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

    // Wrap config in Arc for sharing with proxy task
    let config_arc = Arc::new(config.clone());

    let proxy_task = tokio::spawn(proxy::run_proxy_with_load_balancing(
        config.settings.listen_port,
        config_arc,
        state.clone(),
        load_balancer,
        retry_config,
    ));

    // Metrics server task (only if enabled)
    let metrics_task = if config.settings.metrics_enabled {
        let metrics_bind = format!(
            "{}:{}",
            config.settings.metrics_bind, config.settings.metrics_port
        );
        let metrics_addr = match metrics_bind.parse() {
            Ok(addr) => addr,
            Err(e) => {
                tracing::warn!(
                    bind = %metrics_bind,
                    error = %e,
                    "Invalid metrics bind address (continuing without metrics)"
                );
                // Use a dummy address - server will fail gracefully
                "0.0.0.0:0".parse().unwrap()
            }
        };
        let metrics_path = config.settings.metrics_path.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        Some((
            tokio::spawn(metrics_server::run_metrics_server(
                metrics_addr,
                metrics_path,
                shutdown_rx,
            )),
            shutdown_tx,
        ))
    } else {
        None
    };

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
    if let Some((task, shutdown_tx)) = metrics_task {
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

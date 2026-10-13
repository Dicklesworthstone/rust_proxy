use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine as _;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, Shell};
use owo_colors::OwoColorize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tabled::settings::Style;
use tabled::{Table, Tabled};
use tokio::io::AsyncWriteExt;
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

use config::{infer_provider, AppConfig, Provider, ProxyAuth, ProxyConfig, Settings, TargetSpec};
use load_balancer::LoadBalancer;
use output::{OutputDispatcher, OutputFormat};
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
    /// Clear stale firewall/pid state left by a crashed daemon
    CleanupStale,
    /// Manage systemd service files
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Reload configuration of the running daemon (sends SIGHUP)
    Reload,
    /// Run transparent proxy daemon (requires sudo)
    Daemon,
    /// Show current status
    Status(OutputArgs),
    /// Check system dependencies (deprecated, use doctor)
    Diagnose,
    /// Comprehensive health check for rust_proxy
    Doctor {
        /// Output results in machine format (JSON/TOON)
        #[arg(long)]
        json: bool,
        /// Machine output format (json or toon)
        #[arg(long, value_enum)]
        format: Option<OutputFormatArg>,
        /// Only print failing checks; silence on success
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
        /// Output validation results in machine format (JSON/TOON)
        #[arg(long)]
        json: bool,
        /// Machine output format (json or toon)
        #[arg(long, value_enum)]
        format: Option<OutputFormatArg>,
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
        /// Output results in machine format (JSON/TOON)
        #[arg(long)]
        json: bool,
        /// Machine output format (json or toon)
        #[arg(long, value_enum)]
        format: Option<OutputFormatArg>,
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
        /// Output results in machine format (JSON/TOON)
        #[arg(long)]
        json: bool,
        /// Machine output format (json or toon)
        #[arg(long, value_enum)]
        format: Option<OutputFormatArg>,
        /// Attempt TLS handshake after CONNECT
        #[arg(long)]
        tls: bool,
    },
    /// Ping a proxy and report latency statistics
    Ping {
        /// Proxy ID to ping (defaults to active proxy)
        proxy_id: Option<String>,
        /// Output results in machine format (JSON/TOON)
        #[arg(long)]
        json: bool,
        /// Machine output format (json or toon)
        #[arg(long, value_enum)]
        format: Option<OutputFormatArg>,
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
    /// Machine output format (json or toon)
    #[arg(long, value_enum)]
    format: Option<OutputFormatArg>,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormatArg {
    Json,
    Toon,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(value: OutputFormatArg) -> Self {
        match value {
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Toon => OutputFormat::Toon,
        }
    }
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
    List(OutputArgs),
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Generate systemd service file
    Generate {
        /// Output path (default: /tmp/rust_proxy.service)
        #[arg(long, default_value = "/tmp/rust_proxy.service")]
        output: PathBuf,
        /// User to run service as
        #[arg(long, default_value = "root")]
        user: String,
        /// Group to run service as
        #[arg(long, default_value = "root")]
        group: String,
        /// Path to config file (defaults to standard config path)
        #[arg(long)]
        config: Option<PathBuf>,
        /// Apply security hardening in the generated service
        #[arg(long)]
        hardened: bool,
    },
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

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async_main());
    // Native DNS resolution uses Tokio's blocking pool. Its OS call can
    // outlive an async lookup timeout; it must not hold process exit forever.
    runtime.shutdown_timeout(Duration::from_secs(3));
    result
}

async fn async_main() -> Result<()> {
    // Logs go to stderr: stdout stays clean for command output/piping, and
    // journald (the daemon's normal log sink) captures both streams.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { force } => {
            let output = OutputDispatcher::from_flags(false, false, None);
            init_config(force, &output)?
        }
        Commands::Proxy { command } => {
            let output = OutputDispatcher::from_flags(false, false, None);
            proxy_cmd(command, &output)?
        }
        Commands::Targets { command } => {
            let output = match &command {
                TargetCmd::List(args) => {
                    OutputDispatcher::from_flags(args.json, false, args.format.map(Into::into))
                }
                _ => OutputDispatcher::from_flags(false, false, None),
            };
            targets_cmd(command, &output)?
        }
        Commands::List(args) => {
            let output =
                OutputDispatcher::from_flags(args.json, false, args.format.map(Into::into));
            list_cmd(&output)?
        }
        Commands::Activate { id, select, run } => {
            let output = OutputDispatcher::from_flags(false, false, None);
            activate_cmd(id, select, run, &output).await?
        }
        Commands::Deactivate { keep_rules } => {
            let output = OutputDispatcher::from_flags(false, false, None);
            deactivate_cmd(keep_rules, &output)?
        }
        Commands::CleanupStale => {
            let output = OutputDispatcher::from_flags(false, false, None);
            cleanup_stale_cmd(&output)?
        }
        Commands::Service { action } => {
            let output = OutputDispatcher::from_flags(false, false, None);
            service_cmd(action, &output)?
        }
        Commands::Daemon => run_daemon().await?,
        Commands::Reload => {
            let output = OutputDispatcher::from_flags(false, false, None);
            reload_cmd(&output)?
        }
        Commands::Status(args) => {
            let output =
                OutputDispatcher::from_flags(args.json, false, args.format.map(Into::into));
            status_cmd(&output)?
        }
        Commands::Diagnose => {
            let output = OutputDispatcher::from_flags(false, false, None);
            diagnose_cmd(&output)?
        }
        Commands::Doctor {
            json,
            format,
            quiet,
            offline,
        } => {
            let output = OutputDispatcher::from_flags(json, quiet, format.map(Into::into));
            doctor_cmd(&output, offline).await?
        }
        Commands::Check {
            strict,
            json,
            format,
            quiet,
            test_connectivity,
            validate_health_target,
        } => {
            let output = OutputDispatcher::from_flags(json, quiet, format.map(Into::into));
            check_cmd(strict, test_connectivity, validate_health_target, &output).await?
        }
        Commands::Test {
            url,
            json,
            format,
            verbose,
            no_dns,
        } => {
            let output = OutputDispatcher::from_flags(json, false, format.map(Into::into));
            test_cmd(&url, verbose, no_dns, &output).await?
        }
        Commands::Trace {
            target,
            json,
            format,
            tls,
        } => {
            let output = OutputDispatcher::from_flags(json, false, format.map(Into::into));
            trace_cmd(&target, tls, &output).await?
        }
        Commands::Ping {
            proxy_id,
            json,
            format,
            count,
            interval_ms,
        } => {
            let output = OutputDispatcher::from_flags(json, false, format.map(Into::into));
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
                println!("{} -> {}", proxy.id, util::redact_proxy_url(&proxy.url));
            }
        }
    }
    Ok(())
}

fn targets_cmd(cmd: TargetCmd, output: &OutputDispatcher) -> Result<()> {
    let mut config = AppConfig::load()?;
    match cmd {
        TargetCmd::Add { domain, provider } => {
            let domain = config::canonical_target_domain(&domain)?;
            if config.targets.iter().any(|d| {
                config::canonical_target_domain(d.domain()).ok().as_deref() == Some(domain.as_str())
            }) {
                bail!("Target already exists: {}", domain);
            }
            let provider = provider
                .map(Provider::from)
                .or_else(|| infer_provider(&domain));
            let target = match provider {
                Some(provider) => TargetSpec::Detailed {
                    domain: domain.clone(),
                    provider,
                },
                None => TargetSpec::Simple(domain.clone()),
            };
            config.targets.push(target);
            config.save()?;
            if output.mode().is_json() {
                output.print_json(&serde_json::json!({"added": true, "domain": domain, "provider": provider.map(|p| p.as_str())}));
            } else {
                output.print_rich("[green]Target added.[/]");
            }
        }
        TargetCmd::Remove { domain } => {
            let domain = config::canonical_target_domain(&domain)?;
            let before = config.targets.len();
            config.targets.retain(|d| {
                config::canonical_target_domain(d.domain()).ok().as_deref() != Some(domain.as_str())
            });
            if config.targets.len() == before {
                bail!("Target not found: {}", domain);
            }
            config.save()?;
            if output.mode().is_json() {
                output.print_json(&serde_json::json!({"removed": true, "domain": domain}));
            } else {
                output.print_rich("[green]Target removed.[/]");
            }
        }
        TargetCmd::List(_) => {
            if output.mode().is_json() {
                let targets: Vec<_> = config
                    .targets
                    .iter()
                    .map(|target| {
                        serde_json::json!({
                            "domain": target.domain(),
                            "provider": target.provider().map(|p| p.as_str()),
                        })
                    })
                    .collect();
                output.print_json(&targets);
                return Ok(());
            }
            let mut rows = Vec::new();
            for target in &config.targets {
                rows.push(TargetRow {
                    domain: target.domain().to_string(),
                    provider: target
                        .provider()
                        .map_or("custom", |p| p.as_str())
                        .to_string(),
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
            "proxies": config.proxies.iter().map(ProxyConfig::redacted).collect::<Vec<_>>(),
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

        // Build degradation policy info
        let degradation = serde_json::json!({
            "policy": format!("{:?}", config.settings.degradation_policy).to_lowercase(),
            "delay_secs": config.settings.degradation_delay_secs,
            "allow_direct_fallback": config.settings.allow_direct_fallback,
            "note": "Live degradation status only available when daemon is running"
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
            "degradation": degradation,
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

    // Show degradation policy configuration
    let degradation_str = match config.settings.degradation_policy {
        config::DegradationPolicy::FailClosed => "fail_closed".to_string(),
        config::DegradationPolicy::TryAll => "try_all".cyan().to_string(),
        config::DegradationPolicy::UseLast => "use_last".cyan().to_string(),
        config::DegradationPolicy::Direct => {
            if config.settings.allow_direct_fallback {
                "direct".yellow().to_string()
            } else {
                "direct (disabled)".red().to_string()
            }
        }
    };
    println!(
        "Degradation: {} (delay: {}s)",
        degradation_str, config.settings.degradation_delay_secs
    );

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
    let rules_present = if keep_rules {
        false
    } else {
        let chain = iptables::chain_snapshot(&config.settings.chain_name)?.present;
        let set = iptables::ipset_present(&config.settings.ipset_name)?;
        chain || set
    };

    match deactivate_action(rules_present, iptables::require_root().is_ok(), keep_rules) {
        DeactivateAction::ProceedClear => {
            if rules_present {
                iptables::clear_rules(&config.settings.chain_name, &config.settings.ipset_name)?;
            }
            config.active_proxy = None;
            config.save()?;
            println!("Proxy routing deactivated.");
        }
        DeactivateAction::WarnRemains => {
            eprintln!(
                "Warning: not running as root; routing rules were NOT removed and remain active."
            );
            eprintln!(
                "Remaining: iptables chain '{}' and ipset '{}'.",
                config.settings.chain_name, config.settings.ipset_name
            );
            eprintln!("Re-run with sudo to remove them: sudo rust_proxy deactivate");
            std::process::exit(1);
        }
        DeactivateAction::NoteKept => {
            config.active_proxy = None;
            config.save()?;
            println!("Proxy routing deactivated (rules intentionally kept).");
        }
    }

    Ok(())
}

/// Pure decision helper for `deactivate`: what should the command do about rules?
fn deactivate_action(rules_present: bool, is_root: bool, keep_rules: bool) -> DeactivateAction {
    if keep_rules {
        return DeactivateAction::NoteKept;
    }
    if !rules_present || is_root {
        return DeactivateAction::ProceedClear;
    }
    DeactivateAction::WarnRemains
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeactivateAction {
    /// Rules absent or root available: clear them and report success.
    ProceedClear,
    /// Rules present but cannot be removed (not root): warn and exit non-zero.
    WarnRemains,
    /// --keep-rules: no removal attempted; success with an explicit note.
    NoteKept,
}

/// What `cleanup-stale` should do given what it found. Pure for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupAction {
    /// A live daemon owns the rules: refuse to touch anything.
    RefuseLive(u32),
    /// No chain remnants and no (dead) pidfile owner: nothing to do.
    NothingStale,
    /// Crash leftovers present: clear rules and/or remove the stale pidfile.
    ClearStale {
        had_chain: bool,
        stale_pid: Option<u32>,
    },
}

fn cleanup_action(
    pidfile_pid: Option<u32>,
    is_alive: impl Fn(u32) -> bool,
    chain_present: bool,
) -> CleanupAction {
    if let Some(pid) = pidfile_pid {
        if is_alive(pid) {
            return CleanupAction::RefuseLive(pid);
        }
    }
    let stale_pid = pidfile_pid.filter(|pid| !is_alive(*pid));
    if chain_present || stale_pid.is_some() {
        CleanupAction::ClearStale {
            had_chain: chain_present,
            stale_pid,
        }
    } else {
        CleanupAction::NothingStale
    }
}

/// What `reload` should do given the pidfile contents. Pure for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReloadAction {
    /// No pidfile: no daemon was started (or state was cleaned up).
    NoDaemon,
    /// Pidfile holds a dead pid: stale leftover, nothing to signal.
    Stale(u32),
    /// Pidfile holds a live pid: signal it.
    Signal(u32),
}

fn reload_action(pidfile_pid: Option<u32>, is_alive: impl Fn(u32) -> bool) -> ReloadAction {
    match pidfile_pid {
        None => ReloadAction::NoDaemon,
        Some(pid) if is_alive(pid) => ReloadAction::Signal(pid),
        Some(pid) => ReloadAction::Stale(pid),
    }
}

fn reload_cmd(output: &OutputDispatcher) -> Result<()> {
    let pid_path = std::path::PathBuf::from(state::DEFAULT_PID_PATH);
    let action = reload_action(state::read_pidfile(&pid_path), state::process_alive);
    match action {
        ReloadAction::NoDaemon => {
            output.print_json(&serde_json::json!({"reloaded": false, "reason": "no daemon"}));
            bail!(
                "No running daemon found (no pidfile at {}). Start it with \
                 `sudo rust_proxy daemon`.",
                pid_path.display()
            );
        }
        ReloadAction::Stale(pid) => {
            output.print_json(&serde_json::json!({
                "reloaded": false,
                "reason": "stale pidfile",
                "stale_pid": pid,
            }));
            bail!(
                "Pidfile {} points at dead pid {pid}; run \
                 `sudo rust_proxy cleanup-stale`.",
                pid_path.display()
            );
        }
        ReloadAction::Signal(pid) => {
            // SAFETY: SIGHUP to a valid pid triggers the daemon's reload
            // path; no data is mutated by the signal itself.
            let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGHUP) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                output.print_json(&serde_json::json!({
                    "reloaded": false,
                    "reason": format!("signal failed: {err}"),
                    "pid": pid,
                }));
                bail!("Failed to send SIGHUP to pid {pid}: {err}");
            }
            output.print_json(&serde_json::json!({"reloaded": true, "pid": pid}));
            Ok(())
        }
    }
}

fn cleanup_stale_cmd(output: &OutputDispatcher) -> Result<()> {
    let config = AppConfig::load()?;
    let pid_path = std::path::PathBuf::from(state::DEFAULT_PID_PATH);
    let pidfile_pid = state::read_pidfile(&pid_path);
    let snapshot = iptables::chain_snapshot(&config.settings.chain_name)?;

    match cleanup_action(pidfile_pid, state::process_alive, snapshot.present) {
        CleanupAction::RefuseLive(pid) => {
            output.print_json(&serde_json::json!({
                "cleared": false,
                "live_daemon_pid": pid,
                "had_chain": snapshot.present,
                "stale_pid_removed": null,
            }));
            bail!("Daemon is alive (pid {pid}); refusing to clear state it owns.");
        }
        CleanupAction::NothingStale => {
            output.print_json(&serde_json::json!({
                "cleared": false,
                "live_daemon_pid": null,
                "had_chain": false,
                "stale_pid_removed": null,
            }));
            Ok(())
        }
        CleanupAction::ClearStale {
            had_chain,
            stale_pid,
        } => {
            // Removal mutates firewall state; mirror deactivate's rule of
            // only attempting as root.
            if !iptables::require_root().is_ok() {
                bail!(
                    "Found stale state (chain: {had_chain}, stale pidfile: {}) \
                     but root is required to remove it. Re-run with sudo.",
                    stale_pid
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                );
            }
            if had_chain {
                iptables::clear_rules(&config.settings.chain_name, &config.settings.ipset_name)?;
            }
            if stale_pid.is_some() {
                state::remove_pidfile(&pid_path);
            }
            output.print_json(&serde_json::json!({
                "cleared": true,
                "live_daemon_pid": null,
                "had_chain": had_chain,
                "stale_pid_removed": stale_pid,
            }));
            Ok(())
        }
    }
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
    if output.mode().is_quiet() {
        // Quiet contract: only failing checks, plain text on stdout, one per line,
        // no ANSI; a fully healthy report prints nothing. `print_plain` is a no-op
        // in Quiet mode, so write straight to stdout here.
        for line in doctor_quiet_lines(report) {
            println!("{line}");
        }
        return;
    }

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

/// Pure helper: lines to emit for `doctor --quiet` (non-Ok checks, plain text).
fn doctor_quiet_lines(report: &DoctorReport) -> Vec<String> {
    report
        .checks
        .iter()
        .filter(|check| check.status != DoctorStatus::Ok)
        .map(|check| match check.suggestion.as_deref() {
            Some(suggestion) => format!("{}: {} (fix: {})", check.name, check.message, suggestion),
            None => format!("{}: {}", check.name, check.message),
        })
        .collect()
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

async fn check_cmd(
    strict: bool,
    test_connectivity: bool,
    validate_health_target: bool,
    output: &OutputDispatcher,
) -> Result<()> {
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

    // --validate-health-target: probe the configured target directly so we
    // can tell "target down" apart from "proxies broken". If this probe
    // fails, every proxy health check against it fails for that reason alone.
    let target_probe = if validate_health_target {
        Some(
            health::check_target_reachable(
                config.settings.health_check_timeout_ms,
                &config.settings.health_check_target,
            )
            .await,
        )
    } else {
        None
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

        // Add direct-target probe results when requested
        if let Some(probe) = &target_probe {
            json_output["health_target"] = serde_json::json!({
                "directly_reachable": probe.success,
                "latency_ms": probe.latency_ms,
                "error": probe.failure_reason,
            });
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
                        "unusable (authentication failed, 407)".to_string(),
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

        // Display direct-target verdict when probed
        if let Some(probe) = &target_probe {
            println!("Health Check Target:");
            if probe.success {
                println!(
                    "  {} directly reachable ({}ms)",
                    "✓".green(),
                    probe.latency_ms as u64
                );
            } else {
                println!(
                    "  {} NOT directly reachable from this machine ({}) — \
                     every proxy check against it will fail for that reason",
                    "⚠".yellow(),
                    probe.failure_reason.clone().unwrap_or_default()
                );
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

    let domain = config::canonical_target_domain(&extract_domain(url))?;
    let verbose = verbose && !output.mode().is_json();

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
            if config::canonical_target_domain(target.domain())
                .ok()
                .as_deref()
                == Some(domain.as_str())
            {
                found = true;
                provider = target.provider().map(|p| p.as_str().to_string());
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
            .map(|p| (p.id.clone(), util::redact_proxy_url(&p.url)))
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
        output_test_json(&decision, output)?;
    } else {
        output_test_standard(&decision, verbose);
    }

    Ok(())
}

fn test_decision_payload(decision: &RoutingDecision) -> serde_json::Value {
    serde_json::json!({
        "input": decision.input.clone(),
        "domain": decision.domain.clone(),
        "resolved_ips": decision.resolved_ips.clone(),
        "dns_error": decision.dns_error.clone(),
        "would_proxy": decision.would_proxy,
        "active_proxy": decision.active_proxy.as_ref().map(|(id, url)| {
            serde_json::json!({
                "id": id,
                "url": url
            })
        }),
        "routing_decision": {
            "domain_in_targets": decision.domain_in_targets,
            "target_provider": decision.target_provider.clone(),
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
    })
}

fn output_test_json(decision: &RoutingDecision, output: &OutputDispatcher) -> Result<()> {
    let payload = test_decision_payload(decision);
    output.print_json(&payload);
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
        for suggestion in suggestions {
            match suggestion.split_once(": ") {
                Some((label, command)) => println!("  • {}: {}", label, command.cyan()),
                None => println!("  • {}", suggestion),
            }
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
            "Add domain to targets: rust_proxy targets add {}",
            decision.domain
        ));
    }

    if decision.active_proxy.is_none() && (decision.domain_in_targets || decision.would_proxy) {
        suggestions.push("Activate a proxy: rust_proxy activate --select".to_string());
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
    // trace runs outside the daemon, so there is no live RuntimeState with
    // health-loop failover history; seed one from config so the configured
    // active proxy steers Single-strategy selection like daemon startup does.
    let runtime = RuntimeState::new(config.active_proxy.clone());
    let selected_proxy = load_balancer
        .select_proxy(
            config.settings.load_balance_strategy,
            &config.proxies,
            &state,
            runtime.get_effective_proxy().await.as_deref(),
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
        url: util::redact_proxy_url(&proxy_cfg.url),
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
        let mut creds = Vec::with_capacity(user.len() + 1 + pass.len());
        creds.extend_from_slice(user.as_bytes());
        creds.push(b':');
        creds.extend_from_slice(pass.as_bytes());
        let auth_b64 = Base64.encode(creds);
        format!("Proxy-Authorization: Basic {}\r\n", auth_b64)
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
    let response_result =
        tokio::time::timeout(timeout, proxy::read_response_head(&mut upstream_socket)).await;
    let response_duration = response_start.elapsed();

    let mut connect_ok = false;
    match response_result {
        Ok(Ok((status, _))) => {
            if (200..300).contains(&status) {
                connect_ok = true;
                push_trace_step(
                    &mut steps,
                    "Proxy response",
                    TraceStatus::Ok,
                    Some(response_duration),
                    Some(format!("HTTP status {status}")),
                );
            } else {
                push_trace_step(
                    &mut steps,
                    "Proxy response",
                    TraceStatus::Failed,
                    Some(response_duration),
                    Some(format!("HTTP status {status}")),
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
        proxy_url: util::redact_proxy_url(&proxy_cfg.url),
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

fn service_cmd(action: ServiceAction, output: &OutputDispatcher) -> Result<()> {
    match action {
        ServiceAction::Generate {
            output: output_path,
            user,
            group,
            config,
            hardened,
        } => service_generate(output_path, user, group, config, hardened, output),
    }
}

fn service_generate(
    output_path: PathBuf,
    user: String,
    group: String,
    config: Option<PathBuf>,
    hardened: bool,
    output: &OutputDispatcher,
) -> Result<()> {
    let binary_path =
        std::env::current_exe().context("Failed to resolve current executable path")?;
    let config_path = match config {
        Some(path) => path,
        None => config::config_path()?,
    };

    let service_content =
        util::generate_service_file(&binary_path, &config_path, &user, &group, hardened);
    std::fs::write(&output_path, service_content)
        .with_context(|| format!("Failed to write {}", output_path.display()))?;

    output.print_plain(&format!(
        "Generated systemd service file: {}",
        output_path.display()
    ));
    output.print_plain("");
    output.print_plain("To install:");
    output.print_plain(&format!(
        "  sudo cp {} /etc/systemd/system/rust_proxy.service",
        output_path.display()
    ));
    output.print_plain("  sudo systemctl daemon-reload");
    output.print_plain("  sudo systemctl enable --now rust_proxy");

    Ok(())
}

// ============================================================================
// Config Hot-Reload
// ============================================================================

/// Settings that only take effect at daemon start: the listen socket, firewall
/// chain/ipset names, and metrics bind coordinates are captured once by their
/// long-lived tasks and cannot be swapped live.
const RESTART_REQUIRED_SETTINGS: &[&str] = &[
    "listen_port",
    "chain_name",
    "ipset_name",
    "metrics_bind",
    "metrics_port",
];

/// Pure helper: which restart-required settings differ between two snapshots,
/// in [`RESTART_REQUIRED_SETTINGS`] order.
fn changed_restart_required_settings(old: &Settings, new: &Settings) -> Vec<&'static str> {
    RESTART_REQUIRED_SETTINGS
        .iter()
        .copied()
        .filter(|&name| match name {
            "listen_port" => old.listen_port != new.listen_port,
            "chain_name" => old.chain_name != new.chain_name,
            "ipset_name" => old.ipset_name != new.ipset_name,
            "metrics_bind" => old.metrics_bind != new.metrics_bind,
            "metrics_port" => old.metrics_port != new.metrics_port,
            _ => false,
        })
        .collect()
}

/// Load the config from an explicit path for a hot-reload attempt.
fn load_config_for_reload(path: &std::path::Path) -> Result<AppConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed reading config {}", path.display()))?;
    let config: AppConfig = toml::from_str(&content)
        .with_context(|| format!("Failed parsing config {}", path.display()))?;
    Ok(config)
}

/// Run one hot-reload cycle: load from disk, gate on the same validation as
/// `rust_proxy check`, warn about restart-required fields, and swap the new
/// snapshot into the config bus. Returns true when the bus was updated.
///
/// Invalid configs are rejected with a warning and the last-known-good
/// snapshot stays live.
async fn reload_config_once(
    config_tx: &tokio::sync::watch::Sender<Arc<AppConfig>>,
    path: &std::path::Path,
) -> bool {
    let mut new_config = match load_config_for_reload(path) {
        Ok(config) => config,
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                "Config reload could not read/parse file; keeping last-known-good configuration"
            );
            return false;
        }
    };

    let report = validation::validate_config(&new_config, path);
    if report.has_errors() {
        tracing::warn!(
            errors = report.error_count(),
            warnings = report.warning_count(),
            "Rejected invalid config on hot-reload; keeping last-known-good configuration"
        );
        return false;
    }

    let old = config_tx.borrow().clone();
    for field in changed_restart_required_settings(&old.settings, &new_config.settings) {
        tracing::warn!(
            setting = field,
            "setting '{field}' requires daemon restart to take effect"
        );
    }
    // Keep the published snapshot consistent with the sockets and firewall
    // objects this process actually owns. Requested restart values remain on
    // disk and are picked up by the next daemon; refresh must not use them now.
    new_config.settings.listen_port = old.settings.listen_port;
    new_config
        .settings
        .chain_name
        .clone_from(&old.settings.chain_name);
    new_config
        .settings
        .ipset_name
        .clone_from(&old.settings.ipset_name);
    new_config
        .settings
        .metrics_bind
        .clone_from(&old.settings.metrics_bind);
    new_config.settings.metrics_port = old.settings.metrics_port;
    if old.active_proxy != new_config.active_proxy {
        // RuntimeState has no reset API for the failback origin, so the new
        // active proxy is picked up by consumers but not written back into
        // runtime failover bookkeeping.
        tracing::info!("active_proxy change applies to failback origin on next restart");
    }

    match config_tx.send(Arc::new(new_config)) {
        Ok(()) => {
            tracing::info!(path = %path.display(), "Configuration hot-reloaded");
            true
        }
        Err(_) => false,
    }
}

/// Resources acquired by this daemon only. Kept outside spawned tasks so an
/// early startup error also rolls back while the exclusive owner lock is held.
struct DaemonResources {
    _ownership: Option<state::DaemonOwnership>,
    chain_name: String,
    ipset_name: String,
    firewall_started: bool,
    pid_written: bool,
}

impl DaemonResources {
    fn cleanup(&mut self) -> Result<()> {
        let result = if self.firewall_started {
            self.firewall_started = false;
            iptables::clear_rules(&self.chain_name, &self.ipset_name)
        } else {
            Ok(())
        };
        if self.pid_written {
            self.pid_written = false;
            let path = std::path::Path::new(state::DEFAULT_PID_PATH);
            if state::read_pidfile(path) == Some(std::process::id()) {
                state::remove_pidfile(path);
            }
        }
        result
    }
}

impl Drop for DaemonResources {
    fn drop(&mut self) {
        if let Err(err) = self.cleanup() {
            tracing::error!(error = %err, "Failed to roll back owned daemon resources");
        }
    }
}

async fn run_daemon() -> Result<()> {
    // Runtime-gated test mode: the production binary behaves identically unless
    // the operator explicitly opts in via RUST_PROXY_TEST_MODE=1.
    let test_mode = std::env::var("RUST_PROXY_TEST_MODE").as_deref() == Ok("1");
    if !test_mode {
        iptables::require_root()?;
    } else {
        tracing::info!("test mode: skipping root privilege requirement");
    }
    let watch_config_path = config::config_path()?;
    // Subscribe before reading the startup snapshot or advertising a listener.
    // Otherwise an edit after that read but before the spawned watcher starts
    // can be lost for the lifetime of the daemon.
    let mut config_watcher =
        watcher::ConfigWatcher::new(&watch_config_path).with_context(|| {
            format!(
                "Failed watching configuration before startup: {}",
                watch_config_path.display()
            )
        })?;
    let config = AppConfig::load()?;
    let report = validation::validate_config(&config, &watch_config_path);
    if report.has_errors() {
        bail!(
            "Invalid daemon configuration ({} errors); run `rust_proxy check` for details",
            report.error_count()
        );
    }
    // Register all stop/reload handlers before publishing any owned state.
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut resources = DaemonResources {
        _ownership: if test_mode {
            None
        } else {
            Some(state::DaemonOwnership::acquire(std::path::Path::new(
                state::DEFAULT_LOCK_PATH,
            ))?)
        },
        chain_name: config.settings.chain_name.clone(),
        ipset_name: config.settings.ipset_name.clone(),
        firewall_started: false,
        pid_written: false,
    };
    if !test_mode {
        // Single-daemon guarantee + crash detection: a pidfile holding a
        // live pid means another daemon owns the firewall rules; a dead one
        // means a predecessor crashed and likely left stale state behind.
        let pid_path = std::path::PathBuf::from(state::DEFAULT_PID_PATH);
        match state::decide_pidfile_action(state::read_pidfile(&pid_path), state::process_alive) {
            state::PidfileDecision::Refuse(pid) => bail!(
                "Another rust_proxy daemon appears to be running (pid {pid}, \
                 per {}). If that process is really gone, run \
                 `sudo rust_proxy cleanup-stale` and retry.",
                pid_path.display()
            ),
            state::PidfileDecision::TakeOver(pid) => tracing::warn!(
                stale_pid = pid,
                "Previous daemon exited ungracefully (stale pidfile); \
                 taking over and rebuilding firewall state"
            ),
            state::PidfileDecision::Start => {}
        }
    }

    // Initialize metrics registry (safe to call even if already initialized)
    if let Err(e) = metrics::init_metrics() {
        tracing::warn!(error = %e, "Failed to initialize metrics (continuing without metrics)");
    }

    // Config hot-reload bus. Consumers hold a receiver and borrow+clone the
    // latest validated snapshot per tick / per accept instead of pinning a
    // static Arc<AppConfig>.
    let (config_tx, config_rx) = tokio::sync::watch::channel(Arc::new(config.clone()));
    tracing::info!(
        path = %watch_config_path.display(),
        "config hot-reload enabled: watching configuration file for changes (SIGHUP forces a reload)"
    );

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

    // Fail closed on total upstream DNS failure. resolve_ipv4 is an Ok-only
    // wrapper, so the old code could never propagate a resolution failure: a
    // total outage degraded into an empty exclude set plus a warning, and the
    // daemon started with NO upstream excludes -- every upstream connection
    // was then redirected back into this proxy (self-redirect loop).
    let upstream_report = tokio::select! {
        report = dns::resolve_parallel(&upstream_hosts) => report,
        _ = sigint.recv() => return Ok(()),
        _ = sigterm.recv() => return Ok(()),
    };
    if upstream_report.total_failure() {
        bail!(
            "DNS resolution failed for ALL {} upstream proxy host(s): {}. \
             Refusing to start: iptables would get no upstream excludes and \
             upstream traffic would be redirected back into this proxy \
             (self-redirect loop). Fix name resolution, then retry.",
            upstream_report.failed.len(),
            upstream_report
                .failed
                .iter()
                .map(|(h, _)| h.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !upstream_report.failed.is_empty() {
        tracing::warn!(
            success_ratio = format!("{:.2}", upstream_report.success_ratio()),
            "Partial DNS failure resolving upstream proxy host(s)"
        );
        for (host, err) in &upstream_report.failed {
            tracing::warn!(
                host = %host,
                error = %err,
                "Upstream host unresolved; its traffic may be redirected"
            );
        }
    }
    let upstream_excludes = upstream_report.ipv4_addresses();
    if upstream_excludes.is_empty() {
        tracing::warn!(
            "No IPv4 addresses found for upstream proxies. Upstream traffic may be redirected."
        );
    }

    let state = Arc::new(StateStore::load().await?);
    if let Some(ref id) = active_id {
        state.record_activated(id, chrono::Utc::now()).await;
    }

    // Create load balancer
    let load_balancer = Arc::new(LoadBalancer::new());

    // Create runtime state for dynamic proxy management
    let runtime_state = RuntimeState::new(config.active_proxy.clone());

    // Validate the same endpoint/auth contract used by forwarding and health.
    // Failure remains before listener and firewall admission.
    for proxy_cfg in &config.proxies {
        proxy::UpstreamProxy::from_config(proxy_cfg)?;
    }
    // Binding is an awaited startup step: a live REDIRECT can never precede a
    // successfully bound local listener. OUTPUT interception needs loopback only.
    let listen_addr = std::net::SocketAddr::from(([127, 0, 0, 1], config.settings.listen_port));
    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("Failed to bind to {listen_addr}"))?;
    let metrics_addr = if config.settings.metrics_enabled && !test_mode {
        Some(
            tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((
                    config.settings.metrics_bind.as_str(),
                    config.settings.metrics_port,
                )),
            )
            .await
            .context("Metrics bind resolution timed out")??
            .next()
            .context("Metrics bind resolved to no addresses")?,
        )
    } else {
        None
    };
    let mut target_inventory = RouteInventory::default();
    if test_mode {
        tracing::info!("test mode: skipping firewall mutations (ipset/iptables)");
    } else {
        state::write_pidfile(
            std::path::Path::new(state::DEFAULT_PID_PATH),
            std::process::id(),
        )?;
        resources.pid_written = true;
        resources.firewall_started = true;
        iptables::ensure_ipset(&config.settings.ipset_name)?;

        let outcomes = tokio::select! {
            outcomes = target_source_outcomes(&config) => outcomes,
            _ = sigint.recv() => return resources.cleanup(),
            _ = sigterm.recv() => return resources.cleanup(),
        };
        commit_target_outcomes(&config, &mut target_inventory, outcomes)?;

        // Staleness surfacing: rules surviving from a previous run mean the
        // last exit was ungraceful (the pidfile guard above has already told
        // us whether a live daemon could own them). apply_rules flushes and
        // rebuilds the chain regardless; this log explains any pre-start
        // blackholing operators observed.
        let stale_snapshot = iptables::chain_snapshot(&config.settings.chain_name)?;
        if stale_snapshot.present {
            tracing::warn!(
                redirect_ports = ?stale_snapshot.redirect_ports,
                "Found existing chain from a previous run (crash leftover \
                 unless another daemon is live); flushing and rebuilding"
            );
        }

        // Self-exemption: without it the daemon's own direct connections
        // (Direct degradation policy) are REDIRECTed back into this listener
        // and loop until fds run out. SO_MARK is precise — only sockets we
        // marked ourselves are exempt; a uid exemption as root would exempt
        // every root process on the machine, so it is deliberately not used
        // for the root-run daemon.
        let direct_enabled = matches!(
            config.settings.degradation_policy,
            config::DegradationPolicy::Direct
        ) && config.settings.allow_direct_fallback;
        let (self_exempt, bypass_mark) = if proxy::can_set_so_mark() {
            tracing::info!(
                mark = format_args!("{:#x}", iptables::DIRECT_BYPASS_MARK),
                "SO_MARK self-exemption installed: daemon direct-connect \
                 sockets bypass the REDIRECT rule"
            );
            (
                Some(iptables::SelfExemption::Mark(iptables::DIRECT_BYPASS_MARK)),
                Some(iptables::DIRECT_BYPASS_MARK),
            )
        } else if direct_enabled {
            bail!(
                "Direct degradation policy requires the SO_MARK capability \
                 (CAP_NET_ADMIN) to exempt the daemon's own connections from \
                 the REDIRECT rule. Without it, direct fallback would be \
                 re-redirected into this proxy in an unbounded loop. Refusing \
                 to install live firewall rules."
            );
        } else {
            tracing::warn!(
                "SO_MARK unavailable: no self-exemption installed; the Direct \
                 degradation policy will be refused if it is ever triggered"
            );
            (None, None)
        };

        iptables::apply_rules(
            &config.settings.chain_name,
            &config.settings.ipset_name,
            config.settings.listen_port,
            self_exempt,
            &upstream_excludes,
        )?;
        runtime_state.set_firewall_context(true, bypass_mark).await;
    }
    let flush_task = state.clone().start_flush_loop(Duration::from_secs(5));
    let mut refresh_rx = config_rx.clone();
    let refresh_task = if test_mode {
        tracing::info!("test mode: skipping DNS/ipset refresh task");
        None
    } else {
        Some(tokio::spawn(async move {
            loop {
                let delay = Duration::from_secs(refresh_rx.borrow().settings.dns_refresh_secs);
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    changed = refresh_rx.changed() => {
                        if changed.is_err() { break; }
                    }
                }
                let cfg = refresh_rx.borrow_and_update().clone();
                let outcomes = target_source_outcomes(&cfg).await;
                // A change arriving during DNS/feed IO supersedes this generation.
                if !Arc::ptr_eq(&cfg, &refresh_rx.borrow()) {
                    continue;
                }
                match commit_target_outcomes(&cfg, &mut target_inventory, outcomes) {
                    Ok(count) => tracing::info!(entries = count, "Target routes refreshed"),
                    Err(err) => {
                        tracing::warn!(error = %err, "Target refresh failed; keeping live ipset")
                    }
                }
            }
        }))
    };

    let ping_rx = config_rx.clone();
    let state_clone = state.clone();
    let ping_task = if test_mode {
        tracing::info!("test mode: skipping proxy ping task");
        None
    } else {
        Some(tokio::spawn(async move {
            loop {
                // Per-tick pickup: borrow the latest validated snapshot so
                // the proxy list and ping cadence follow hot-reloads.
                let cfg = ping_rx.borrow().clone();
                for proxy in &cfg.proxies {
                    if let Ok(endpoint) = util::parse_proxy_url(&proxy.url) {
                        match ping_proxy(
                            &endpoint.host,
                            endpoint.port,
                            cfg.settings.ping_timeout_ms,
                        )
                        .await
                        {
                            Ok(ms) => state_clone.record_ping(&proxy.id, ms).await,
                            Err(err) => tracing::warn!("ping failed for {}: {err}", proxy.id),
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(cfg.settings.ping_interval_secs)).await;
            }
        }))
    };

    // Health check task (only if enabled). Consumes the config bus so
    // health_check_* settings and the proxy set update live on reload.
    let mut health_task = if config.settings.health_check_enabled {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let health_config_rx = config_rx.clone();
        let health_state = state.clone();
        let health_runtime = runtime_state.clone();
        Some((
            tokio::spawn(health::health_check_loop(
                health_config_rx,
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

    // Proxy task: consumes the config bus; each accepted connection
    // snapshots the latest validated config (hot-reload pickup).
    let runtime_arc = Arc::new(runtime_state.clone());
    let (proxy_shutdown_tx, proxy_shutdown_rx) = tokio::sync::watch::channel(false);
    let mut proxy_task = tokio::spawn(proxy::run_proxy_with_load_balancing(
        listener,
        config_rx.clone(),
        state.clone(),
        runtime_arc,
        load_balancer,
        retry_config,
        proxy_shutdown_rx,
    ));

    // Metrics server task (only if enabled)
    let mut metrics_task = if let Some(metrics_addr) = metrics_addr {
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

    // Reload source: fs-event watcher drives the same validated reload path
    // as SIGHUP. Poll cadence bounds worst-case reload latency; debounce is
    // handled inside ConfigWatcher::poll.
    let watcher_tx = config_tx.clone();
    let watcher_path = watch_config_path.clone();
    let watcher_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if config_watcher.poll() {
                reload_config_once(&watcher_tx, &watcher_path).await;
            }
        }
    });

    let mut proxy_finished = false;
    let mut health_finished = false;
    let mut metrics_finished = false;
    let outcome = loop {
        tokio::select! {
            _ = sigint.recv() => {
                tracing::info!("SIGINT received: shutting down");
                break Ok(());
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received: shutting down");
                break Ok(());
            }
            _ = sighup.recv() => {
                tracing::info!("SIGHUP received: reloading configuration");
                reload_config_once(&config_tx, &watch_config_path).await;
            }
            result = &mut proxy_task => {
                proxy_finished = true;
                break match result {
                    Ok(Ok(())) => Err(anyhow::anyhow!("Proxy listener stopped unexpectedly")),
                    Ok(Err(err)) => Err(err.context("Proxy listener failed")),
                    Err(err) => Err(anyhow::anyhow!("Proxy task failed: {err}")),
                };
            }
            result = async {
                if let Some((task, _)) = &mut health_task { task.await }
                else { std::future::pending().await }
            } => {
                health_finished = true;
                break Err(anyhow::anyhow!("Health task stopped unexpectedly: {result:?}"));
            }
            result = async {
                if let Some((task, _)) = &mut metrics_task { task.await }
                else { std::future::pending().await }
            } => {
                metrics_finished = true;
                break Err(anyhow::anyhow!("Metrics task stopped unexpectedly: {result:?}"));
            }
        }
    };
    let _ = proxy_shutdown_tx.send(true);
    watcher_task.abort();
    let _ = watcher_task.await;
    if let Some(refresh_task) = refresh_task {
        refresh_task.abort();
        let _ = refresh_task.await;
    }
    if let Some(ping_task) = ping_task {
        ping_task.abort();
        let _ = ping_task.await;
    }
    if let Some((task, shutdown_tx)) = health_task {
        let _ = shutdown_tx.send(true);
        if !health_finished {
            task.abort();
            let _ = task.await;
        }
    }
    if let Some((task, shutdown_tx)) = metrics_task {
        let _ = shutdown_tx.send(true);
        if !metrics_finished {
            task.abort();
            let _ = task.await;
        }
    }
    let proxy_stop = if proxy_finished {
        Ok(())
    } else {
        match tokio::time::timeout(Duration::from_secs(3), &mut proxy_task).await {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => Err(anyhow::anyhow!("Proxy task failed during shutdown: {err}")),
            Err(_) => {
                proxy_task.abort();
                let _ = proxy_task.await;
                Err(anyhow::anyhow!(
                    "Proxy shutdown exceeded its three-second budget"
                ))
            }
        }
    };
    flush_task.abort();
    let _ = flush_task.await;
    let cleanup_result = resources.cleanup();
    if !test_mode && cleanup_result.is_ok() {
        tracing::info!("Owned firewall and pidfile cleanup completed");
    } else if test_mode {
        tracing::info!("test mode: skipping iptables cleanup");
    }
    let flush_result = state.flush().await;
    outcome
        .and(proxy_stop)
        .and(cleanup_result)
        .and(flush_result)
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
            url: util::redact_proxy_url(&proxy.url),
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum RouteSource {
    Domain(String),
    Provider(&'static str),
}

impl RouteSource {
    fn label(&self) -> String {
        match self {
            Self::Domain(domain) => format!("dns:{domain}"),
            Self::Provider(provider) => format!("provider:{provider}"),
        }
    }
}

#[derive(Clone, Default)]
struct SourceRoutes {
    entries: HashSet<String>,
    last_success_at: Option<chrono::DateTime<chrono::Utc>>,
    last_error: Option<String>,
}

#[derive(Clone, Default)]
struct RouteInventory {
    sources: HashMap<RouteSource, SourceRoutes>,
}

type SourceOutcome = (RouteSource, Result<HashSet<String>>);

impl RouteInventory {
    fn apply(&mut self, outcomes: Vec<SourceOutcome>) -> HashSet<String> {
        let enabled: HashSet<_> = outcomes.iter().map(|(source, _)| source.clone()).collect();
        self.sources.retain(|source, _| enabled.contains(source));
        for (source, outcome) in outcomes {
            let label = source.label();
            let cached = self.sources.entry(source).or_default();
            match outcome {
                Ok(entries) if !entries.is_empty() => {
                    cached.entries = entries;
                    cached.last_success_at = Some(chrono::Utc::now());
                    cached.last_error = None;
                }
                outcome => {
                    let error = outcome.err().map_or_else(
                        || "No usable IPv4 addresses".to_string(),
                        |err| err.to_string(),
                    );
                    tracing::warn!(source = %label, error = %error, kept = cached.entries.len(), last_success_at = ?cached.last_success_at, "Routing source failed; retaining its last-good entries");
                    cached.last_error = Some(error);
                }
            }
        }
        self.sources
            .values()
            .flat_map(|source| source.entries.iter().cloned())
            .collect()
    }

    /// Publish freshness only after the corresponding routing generation is
    /// installed. A failed ipset swap must not advertise an unapplied recovery
    /// or remove the metrics for sources still present in the live inventory.
    fn publish_metrics(&self, previous: &Self) {
        for source in previous.sources.keys() {
            if !self.sources.contains_key(source) {
                let _ = metrics::ROUTE_SOURCE_STALE.remove_label_values(&[&source.label()]);
            }
        }
        for (source, routes) in &self.sources {
            metrics::ROUTE_SOURCE_STALE
                .with_label_values(&[&source.label()])
                .set(if routes.last_error.is_some() {
                    1.0
                } else {
                    0.0
                });
        }
    }
}

/// All source outcomes belong to one generation; a nonempty feed cannot hide
/// a target lookup failure, and a second DNS lookup cannot change its meaning.
async fn target_source_outcomes(config: &AppConfig) -> Vec<SourceOutcome> {
    target_source_outcomes_with_resolver(config, |domains| async move {
        dns::resolve_parallel(&domains).await
    })
    .await
}

async fn target_source_outcomes_with_resolver<F, R>(
    config: &AppConfig,
    resolver: R,
) -> Vec<SourceOutcome>
where
    R: FnOnce(Vec<String>) -> F,
    F: std::future::Future<Output = dns::DnsResolutionReport>,
{
    let domains: Vec<_> = config
        .targets
        .iter()
        .map(|target| {
            config::canonical_target_domain(target.domain())
                .unwrap_or_else(|_| target.domain().to_string())
        })
        .collect();
    let (report, aws, cloudflare, google) = tokio::join!(
        resolver(domains.clone()),
        async {
            if config.settings.include_aws_ip_ranges {
                Some(ip_ranges::fetch_aws_ipv4().await)
            } else {
                None
            }
        },
        async {
            if config.settings.include_cloudflare_ip_ranges {
                Some(ip_ranges::fetch_cloudflare_ipv4().await)
            } else {
                None
            }
        },
        async {
            if config.settings.include_google_ip_ranges {
                Some(ip_ranges::fetch_google_ipv4().await)
            } else {
                None
            }
        },
    );
    let mut outcomes = Vec::new();
    for domain in domains {
        let outcome = report
            .resolved
            .iter()
            .find(|(host, _)| host == &domain)
            .map(|(_, ips)| {
                ips.iter()
                    .filter_map(|ip| match ip {
                        std::net::IpAddr::V4(ip) => Some(ip.to_string()),
                        std::net::IpAddr::V6(_) => None,
                    })
                    .collect()
            })
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "DNS lookup failed for {domain}: {}",
                    report
                        .failed
                        .iter()
                        .find(|(host, _)| host == &domain)
                        .map_or("missing resolution outcome", |(_, error)| error.as_str())
                )
            });
        outcomes.push((RouteSource::Domain(domain), outcome));
    }
    for (name, result) in [("aws", aws), ("cloudflare", cloudflare), ("google", google)] {
        if let Some(result) = result {
            outcomes.push((RouteSource::Provider(name), result));
        }
    }
    outcomes
}

fn commit_target_outcomes(
    config: &AppConfig,
    inventory: &mut RouteInventory,
    outcomes: Vec<SourceOutcome>,
) -> Result<usize> {
    let mut candidate = inventory.clone();
    let entries = candidate.apply(outcomes);
    if !config.targets.is_empty()
        && !candidate.sources.iter().any(|(source, routes)| {
            matches!(source, RouteSource::Domain(_)) && !routes.entries.is_empty()
        })
    {
        bail!("No configured target has usable IPv4 coverage; refusing to publish provider-only routing");
    }
    iptables::sync_ipset(&config.settings.ipset_name, &entries)?;
    candidate.publish_metrics(inventory);
    metrics::IPSET_SIZE.set(entries.len() as f64);
    *inventory = candidate;
    Ok(entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static ROUTE_RESTORES: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    fn capture_route_commands(program: &str, args: &[&str], stdin: Option<&str>) -> Result<String> {
        assert_eq!(program, "ipset");
        match args[0] {
            "list" => Ok("Name: controlled_routes\nMembers:\n".to_string()),
            "restore" => {
                ROUTE_RESTORES
                    .with(|records| records.borrow_mut().push(stdin.unwrap().to_string()));
                Ok(String::new())
            }
            // ubs:ignore[rust.ownership.panic-macro] — test backend rejects an unexpected production command rather than fabricating success.
            command => panic!("unexpected ipset command: {command}"),
        }
    }

    fn route_set(entries: &[&str]) -> HashSet<String> {
        entries.iter().map(|entry| entry.to_string()).collect()
    }

    struct RouteLogWriter(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for RouteLogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn controlled_total_dns_failure_retains_ipset_entries_warning_and_metric() {
        let config = AppConfig {
            targets: vec![TargetSpec::Simple("controlled-refresh.invalid".into())],
            settings: Settings {
                ipset_name: "controlled_routes".into(),
                include_aws_ip_ranges: false,
                include_cloudflare_ip_ranges: false,
                include_google_ip_ranges: false,
                ..Settings::default()
            },
            ..AppConfig::default()
        };
        let mut inventory = RouteInventory::default();
        ROUTE_RESTORES.with(|records| records.borrow_mut().clear());
        let first = target_source_outcomes_with_resolver(&config, |domains| async move {
            dns::DnsResolutionReport {
                resolved: vec![(domains[0].clone(), vec!["198.51.100.7".parse().unwrap()])],
                failed: vec![],
                total_domains: 1,
                elapsed: Duration::ZERO,
            }
        })
        .await;
        iptables::with_test_spawn(capture_route_commands, || {
            commit_target_outcomes(&config, &mut inventory, first)
        })
        .unwrap();
        let failed = target_source_outcomes_with_resolver(&config, |domains| async move {
            dns::DnsResolutionReport {
                resolved: vec![],
                failed: vec![(domains[0].clone(), "controlled resolver outage".into())],
                total_domains: 1,
                elapsed: Duration::ZERO,
            }
        })
        .await;
        let logs = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || RouteLogWriter(writer.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            iptables::with_test_spawn(capture_route_commands, || {
                commit_target_outcomes(&config, &mut inventory, failed)
            })
            .unwrap();
        });
        ROUTE_RESTORES.with(|records| {
            let records = records.borrow();
            assert_eq!(records.len(), 2);
            assert_eq!(
                records[0], records[1],
                "failed DNS must not empty the live set"
            );
            assert!(records[1].contains("add controlled_routes_tmp 198.51.100.7 -exist"));
        });
        let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("Routing source failed; retaining its last-good entries"),
            "{logs}"
        );
        assert!(logs.contains("controlled resolver outage"), "{logs}");
        assert_eq!(
            metrics::ROUTE_SOURCE_STALE
                .with_label_values(&["dns:controlled-refresh.invalid"])
                .get(),
            1.0
        );
    }

    #[test]
    fn per_source_failures_keep_coverage_and_explicit_removal_drops_only_that_source() {
        let a = RouteSource::Domain("a.invalid".into());
        let b = RouteSource::Domain("b.invalid".into());
        let aws = RouteSource::Provider("aws");
        let cf = RouteSource::Provider("cloudflare");
        let mut inventory = RouteInventory::default();
        inventory.apply(vec![
            (a.clone(), Ok(route_set(&["198.51.100.1"]))),
            (b.clone(), Ok(route_set(&["198.51.100.2"]))),
            (aws.clone(), Ok(route_set(&["203.0.113.0/24"]))),
            (cf.clone(), Ok(route_set(&["192.0.2.0/24"]))),
        ]);
        let entries = inventory.apply(vec![
            (a.clone(), Ok(HashSet::new())),
            (b.clone(), Ok(route_set(&["198.51.100.3"]))),
            (aws.clone(), Err(anyhow::anyhow!("feed outage"))),
            (cf, Ok(route_set(&["192.0.2.0/24"]))),
        ]);
        assert_eq!(
            entries,
            route_set(&[
                "198.51.100.1",
                "198.51.100.3",
                "203.0.113.0/24",
                "192.0.2.0/24"
            ])
        );
        assert!(inventory.sources[&a].last_error.is_some());
        assert!(inventory.sources[&aws].last_error.is_some());
        assert!(inventory.sources[&b].last_error.is_none());
        let entries = inventory.apply(vec![(a.clone(), Err(anyhow::anyhow!("DNS outage")))]);
        assert_eq!(entries, route_set(&["198.51.100.1"]));
        assert_eq!(inventory.sources.len(), 1);
        let entries = inventory.apply(vec![(b, Ok(route_set(&["198.51.100.9"])))]);
        assert_eq!(entries, route_set(&["198.51.100.9"]));
        assert!(!inventory.sources.contains_key(&a));
    }

    #[test]
    fn provider_success_cannot_make_unresolved_startup_target_routing_ready() {
        let config = AppConfig {
            targets: vec![TargetSpec::Simple("unresolved-startup.invalid".into())],
            ..AppConfig::default()
        };
        let mut inventory = RouteInventory::default();
        let result = commit_target_outcomes(
            &config,
            &mut inventory,
            vec![
                (
                    RouteSource::Domain("unresolved-startup.invalid".into()),
                    Err(anyhow::anyhow!("DNS outage")),
                ),
                (
                    RouteSource::Provider("aws"),
                    Ok(route_set(&["203.0.113.0/24"])),
                ),
            ],
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No configured target has usable IPv4 coverage"));
        assert!(inventory.sources.is_empty());
    }

    #[test]
    fn failed_ipset_update_keeps_committed_inventory_and_freshness_metric() {
        fn reject_restore(program: &str, args: &[&str], _: Option<&str>) -> Result<String> {
            assert_eq!(program, "ipset");
            assert!(matches!(args[0], "list" | "restore"));
            bail!("controlled ipset publication failure");
        }
        let domain = "failed-publication.invalid";
        let source = RouteSource::Domain(domain.into());
        let config = AppConfig {
            targets: vec![TargetSpec::Simple(domain.into())],
            settings: Settings {
                ipset_name: "controlled_routes".into(),
                ..Settings::default()
            },
            ..AppConfig::default()
        };
        let mut inventory = RouteInventory::default();
        for outcome in [
            Ok(route_set(&["198.51.100.17"])),
            Err(anyhow::anyhow!("controlled DNS outage")),
        ] {
            iptables::with_test_spawn(capture_route_commands, || {
                commit_target_outcomes(&config, &mut inventory, vec![(source.clone(), outcome)])
            })
            .unwrap();
        }
        let stale = metrics::ROUTE_SOURCE_STALE.with_label_values(&[&source.label()]);
        assert_eq!(stale.get(), 1.0);
        let result = iptables::with_test_spawn(reject_restore, || {
            commit_target_outcomes(
                &config,
                &mut inventory,
                vec![(source.clone(), Ok(route_set(&["198.51.100.18"])))],
            )
        });
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("controlled ipset publication failure"));
        assert_eq!(
            inventory.sources[&source].entries,
            route_set(&["198.51.100.17"])
        );
        assert!(inventory.sources[&source].last_error.is_some());
        assert_eq!(stale.get(), 1.0, "unapplied recovery must remain stale");
    }

    // =========================================================================
    // Scope A: machine-mode payloads must be free of ANSI escapes
    // =========================================================================

    fn fixture_decision() -> RoutingDecision {
        RoutingDecision {
            input: "https://api.anthropic.com/v1/messages".to_string(),
            domain: "api.anthropic.com".to_string(),
            resolved_ips: vec!["104.18.32.47".to_string()],
            dns_error: None,
            would_proxy: false,
            domain_in_targets: true,
            target_provider: None,
            provider_range_matches: vec![ProviderMatch {
                ip: "104.18.32.47".to_string(),
                provider: "anthropic".to_string(),
                cidr: "104.18.32.0/19".to_string(),
            }],
            daemon_running: false,
            active_proxy: None,
        }
    }

    fn assert_no_ansi(value: &serde_json::Value) {
        match value {
            serde_json::Value::String(s) => assert!(
                !s.contains('\u{1b}'),
                "ANSI escape leaked into serialized payload string: {s:?}"
            ),
            serde_json::Value::Array(items) => items.iter().for_each(assert_no_ansi),
            serde_json::Value::Object(map) => map.values().for_each(assert_no_ansi),
            _ => {}
        }
    }

    #[test]
    fn test_json_payload_is_ansi_free_and_suggestions_plain() {
        // Fixture hits both suggestion branches: would_proxy=true + no active
        // proxy + domain not in targets.
        let decision = fixture_decision();
        let payload = test_decision_payload(&decision);

        assert_no_ansi(&payload);

        let suggestions = payload["suggestions"]
            .as_array()
            .expect("suggestions array");
        assert!(
            suggestions.iter().any(|s| s
                .as_str()
                .unwrap_or("")
                .starts_with("Activate a proxy: rust_proxy activate --select")),
            "expected plain 'Activate a proxy' suggestion, got {suggestions:?}"
        );
        assert!(
            suggestions.iter().any(|s| s.as_str().unwrap_or("")
                == "Add domain to targets: rust_proxy targets add api.anthropic.com"),
            "expected plain 'Add domain to targets' suggestion, got {suggestions:?}"
        );
    }

    // =========================================================================
    // Scope B: doctor --quiet prints failing checks only, plain, on stdout
    // =========================================================================

    fn healthy_report() -> DoctorReport {
        DoctorReport {
            healthy: true,
            checks: vec![
                DoctorCheck::ok("Config File", "Found at /tmp/config.toml"),
                DoctorCheck::ok("Network Tests", "Skipped (--offline mode)"),
            ],
            summary: DoctorSummary {
                total: 2,
                passed: 2,
                warnings: 0,
                errors: 0,
            },
        }
    }

    fn failing_report() -> DoctorReport {
        DoctorReport {
            healthy: false,
            checks: vec![
                DoctorCheck::ok("State Directory", "Found"),
                DoctorCheck::error(
                    "Config File",
                    "Not found at /tmp/config.toml",
                    "Run 'rp init' to create a default configuration",
                ),
            ],
            summary: DoctorSummary {
                total: 2,
                passed: 1,
                warnings: 0,
                errors: 1,
            },
        }
    }

    fn mixed_report() -> DoctorReport {
        DoctorReport {
            healthy: false,
            checks: vec![
                DoctorCheck::warning(
                    "Active Proxy",
                    "No proxy is currently active",
                    "Run 'rp activate --select'",
                ),
                DoctorCheck::ok("DNS Resolution", "Resolved api.anthropic.com"),
                DoctorCheck::error("Listen Port", "Port 8080 in use", "Free the port"),
            ],
            summary: DoctorSummary {
                total: 3,
                passed: 1,
                warnings: 1,
                errors: 1,
            },
        }
    }

    #[test]
    fn doctor_quiet_lines_healthy_report_is_empty() {
        assert!(doctor_quiet_lines(&healthy_report()).is_empty());
    }

    #[test]
    fn doctor_quiet_lines_failing_report_lists_only_failures_with_fix() {
        let lines = doctor_quiet_lines(&failing_report());
        assert_eq!(lines.len(), 1);
        assert!(!lines[0].contains('\u{1b}'));
        assert_eq!(
            lines[0],
            "Config File: Not found at /tmp/config.toml (fix: Run 'rp init' to create a default configuration)"
        );
    }

    #[test]
    fn doctor_quiet_lines_mixed_report_skips_ok_checks_and_is_ansi_free() {
        let lines = doctor_quiet_lines(&mixed_report());
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|l| !l.contains('\u{1b}')));
        assert!(lines[0].starts_with("Active Proxy: No proxy is currently active"));
        assert!(lines[1].starts_with("Listen Port: Port 8080 in use"));
        assert!(
            !lines.iter().any(|l| l.contains("DNS Resolution")),
            "Ok checks must be silent in quiet mode"
        );
    }

    // =========================================================================
    // Scope C: deactivate decision matrix without root
    // =========================================================================

    #[test]
    fn deactivate_action_keep_rules_always_notes_kept() {
        assert_eq!(
            deactivate_action(true, false, true),
            DeactivateAction::NoteKept
        );
    }

    #[test]
    fn deactivate_action_rules_present_but_not_root_warns() {
        assert_eq!(
            deactivate_action(true, false, false),
            DeactivateAction::WarnRemains
        );
    }

    #[test]
    fn deactivate_action_rules_present_and_root_proceeds_to_clear() {
        assert_eq!(
            deactivate_action(true, true, false),
            DeactivateAction::ProceedClear
        );
    }

    #[test]
    fn deactivate_action_rules_absent_proceeds_even_without_root() {
        assert_eq!(
            deactivate_action(false, false, false),
            DeactivateAction::ProceedClear
        );
    }
    #[test]
    fn changed_restart_required_settings_detects_each_field() {
        let base = Settings::default();
        for expected in RESTART_REQUIRED_SETTINGS {
            let mut modified = base.clone();
            match *expected {
                "listen_port" => modified.listen_port += 1,
                "chain_name" => modified.chain_name = format!("{}_x", modified.chain_name),
                "ipset_name" => modified.ipset_name = format!("{}_x", modified.ipset_name),
                "metrics_bind" => modified.metrics_bind = "0.0.0.0".to_string(),
                "metrics_port" => modified.metrics_port += 1,
                // ubs:ignore[rust.ownership.panic-macro] — unit test must fail if a restart-required field lacks a case.
                other => panic!("unhandled restart-required setting: {other}"),
            }
            assert_eq!(
                changed_restart_required_settings(&base, &modified),
                vec![*expected],
                "changing {expected} must be classified restart-required"
            );
        }
    }

    #[tokio::test]
    async fn reload_pins_owned_socket_and_firewall_identity_but_applies_live_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = AppConfig::default();
        let mut requested = original.clone();
        requested.settings.listen_port += 1;
        requested.settings.chain_name = "NEXT_CHAIN".into();
        requested.settings.ipset_name = "next_targets".into();
        requested.settings.metrics_bind = "127.0.0.2".into();
        requested.settings.metrics_port += 1;
        requested.settings.dns_refresh_secs = 900;
        std::fs::write(&path, toml::to_string(&requested).unwrap()).unwrap();
        let (sender, receiver) = tokio::sync::watch::channel(Arc::new(original.clone()));
        assert!(reload_config_once(&sender, &path).await);
        let applied = receiver.borrow().clone();
        assert_eq!(applied.settings.listen_port, original.settings.listen_port);
        assert_eq!(applied.settings.chain_name, original.settings.chain_name);
        assert_eq!(applied.settings.ipset_name, original.settings.ipset_name);
        assert_eq!(
            applied.settings.metrics_bind,
            original.settings.metrics_bind
        );
        assert_eq!(
            applied.settings.metrics_port,
            original.settings.metrics_port
        );
        assert_eq!(applied.settings.dns_refresh_secs, 900);
        assert_eq!(
            load_config_for_reload(&path).unwrap().settings.listen_port,
            requested.settings.listen_port,
            "pending restart values remain on disk"
        );
    }

    #[test]
    fn changed_restart_required_settings_empty_when_equal_or_live_only() {
        let base = Settings::default();
        assert!(changed_restart_required_settings(&base, &base).is_empty());

        // Live-swap fields (not in RESTART_REQUIRED_SETTINGS) must not be
        // flagged: e.g. ping cadence and DNS refresh change per tick.
        let mut live_only = base.clone();
        live_only.ping_interval_secs += 1;
        live_only.dns_refresh_secs += 1;
        live_only.ping_timeout_ms += 1;
        assert!(changed_restart_required_settings(&base, &live_only).is_empty());
    }

    #[test]
    fn test_reload_action_all_cases() {
        // No pidfile: nothing to signal.
        assert_eq!(reload_action(None, |_| true), ReloadAction::NoDaemon);
        // Live daemon: signal it.
        assert_eq!(
            reload_action(Some(7), |pid| pid == 7),
            ReloadAction::Signal(7)
        );
        // Dead pid: stale leftover, refuse to signal.
        assert_eq!(reload_action(Some(7), |_| false), ReloadAction::Stale(7));
    }
}

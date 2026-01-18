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
mod ip_ranges;
mod iptables;
mod proxy;
mod state;
mod util;

use config::{infer_provider, AppConfig, Provider, ProxyAuth, ProxyConfig, TargetSpec};
use proxy::{RetryConfig, UpstreamProxy};
use state::{State, StateStore};

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
            config.proxies.push(ProxyConfig { id, url, auth });
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
        let payload = serde_json::json!({
            "active_proxy": config.active_proxy,
            "rules_active": rules_active,
            "targets": config.targets,
            "stats": state,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    let active = config
        .active_proxy
        .clone()
        .unwrap_or_else(|| "-".to_string());
    println!("Active proxy: {}", active);
    println!("Rules active: {}", if rules_active { "yes" } else { "no" });
    println!("Targets: {}", config.targets.len());
    Ok(())
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

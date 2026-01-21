use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const APP_QUALIFIER: &str = "dev";
const APP_ORG: &str = "rustproxy";
const APP_NAME: &str = "rust_proxy";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyAuth {
    pub username: Option<String>,
    pub password: Option<String>,
    pub username_env: Option<String>,
    pub password_env: Option<String>,
}

impl ProxyAuth {
    pub fn resolve(&self) -> (Option<String>, Option<String>) {
        let user = self
            .username_env
            .as_deref()
            .and_then(|key| std::env::var(key).ok())
            .or_else(|| self.username.clone());
        let pass = self
            .password_env
            .as_deref()
            .and_then(|key| std::env::var(key).ok())
            .or_else(|| self.password.clone());
        (user, pass)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub id: String,
    pub url: String,
    #[serde(default)]
    pub auth: ProxyAuth,
    /// Priority for failover selection (lower = higher priority)
    #[serde(default)]
    pub priority: Option<u32>,
    /// Optional custom health check URL
    #[serde(default)]
    pub health_check_url: Option<String>,
    /// Weight for weighted load balancing (default: 100)
    #[serde(default = "default_proxy_weight")]
    pub weight: u32,
}

fn default_proxy_weight() -> u32 {
    100
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Anthropic,
    Openai,
    Google,
    Amazon,
    Cloudflare,
    Vercel,
    Supabase,
}

impl Provider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::Openai => "openai",
            Provider::Google => "google",
            Provider::Amazon => "amazon",
            Provider::Cloudflare => "cloudflare",
            Provider::Vercel => "vercel",
            Provider::Supabase => "supabase",
        }
    }
}

/// Policy when all proxies become unhealthy
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DegradationPolicy {
    /// Reject all connections when no healthy proxy (most secure)
    #[default]
    FailClosed,
    /// Try each proxy in order until one works
    TryAll,
    /// Use the most recently healthy proxy
    UseLast,
    /// Connect directly without proxy (must enable allow_direct_fallback)
    Direct,
}

/// Load balancing strategy for distributing requests across proxies
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    /// Use single active proxy with failover (current default behavior)
    #[default]
    Single,
    /// Cycle through healthy proxies sequentially
    RoundRobin,
    /// Prefer proxy with lowest recent latency
    LeastLatency,
    /// Distribute by configured weights
    Weighted,
}

impl LoadBalanceStrategy {
    /// Returns a human-readable description of the strategy.
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            LoadBalanceStrategy::Single => "single",
            LoadBalanceStrategy::RoundRobin => "round_robin",
            LoadBalanceStrategy::LeastLatency => "least_latency",
            LoadBalanceStrategy::Weighted => "weighted",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TargetSpec {
    Simple(String),
    Detailed { domain: String, provider: Provider },
}

impl TargetSpec {
    pub fn domain(&self) -> &str {
        match self {
            TargetSpec::Simple(domain) => domain,
            TargetSpec::Detailed { domain, .. } => domain,
        }
    }

    pub fn provider(&self) -> Provider {
        match self {
            TargetSpec::Detailed { provider, .. } => *provider,
            TargetSpec::Simple(domain) => infer_provider(domain).unwrap_or(Provider::Google),
        }
    }
}

pub fn infer_provider(domain: &str) -> Option<Provider> {
    let domain = domain.to_ascii_lowercase();
    if domain.ends_with("anthropic.com")
        || domain.ends_with("claude.ai")
        || domain.ends_with("claude.com")
    {
        return Some(Provider::Anthropic);
    }
    if domain.ends_with("openai.com")
        || domain.ends_with("chatgpt.com")
        || domain.ends_with("oaistatic.com")
        || domain.ends_with("oaiusercontent.com")
        || domain.ends_with("sora.com")
        || domain.ends_with("openaicdn.com")
        || domain.ends_with("openai.dev")
    {
        return Some(Provider::Openai);
    }
    if domain.ends_with("amazon.com")
        || domain.ends_with("amazonaws.com")
        || domain.ends_with("aws.amazon.com")
        || domain.ends_with("awsstatic.com")
        || domain.ends_with("cloudfront.net")
        || domain.ends_with("awsapps.com")
    {
        return Some(Provider::Amazon);
    }
    if domain.ends_with("cloudflare.com")
        || domain.ends_with("cloudflareinsights.com")
        || domain.ends_with("cloudflareaccess.com")
        || domain.ends_with("cloudflarestatus.com")
    {
        return Some(Provider::Cloudflare);
    }
    if domain.ends_with("vercel.com") || domain.ends_with("vercel.app") {
        return Some(Provider::Vercel);
    }
    if domain.ends_with("supabase.com") || domain.ends_with("supabase.co") {
        return Some(Provider::Supabase);
    }
    if domain.ends_with("google.com")
        || domain.ends_with("gstatic.com")
        || domain.ends_with("googleapis.com")
        || domain.ends_with("ggpht.com")
        || domain.ends_with("googleusercontent.com")
        || domain.ends_with("withgoogle.com")
    {
        return Some(Provider::Google);
    }
    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub listen_port: u16,
    pub dns_refresh_secs: u64,
    pub ping_interval_secs: u64,
    pub ping_timeout_ms: u64,
    pub ipset_name: String,
    pub chain_name: String,
    pub include_aws_ip_ranges: bool,
    pub include_cloudflare_ip_ranges: bool,
    pub include_google_ip_ranges: bool,
    /// Enable Prometheus metrics endpoint (default: true)
    #[serde(default = "default_metrics_enabled")]
    pub metrics_enabled: bool,
    /// Port for metrics HTTP server (default: 9090)
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    /// Path for metrics endpoint (default: "/metrics")
    #[serde(default = "default_metrics_path")]
    pub metrics_path: String,
    /// Bind address for metrics server (default: "0.0.0.0")
    #[serde(default = "default_metrics_bind")]
    pub metrics_bind: String,
    /// Max retry attempts for upstream proxy connections (0 = no retries)
    #[serde(default = "default_connect_max_retries")]
    pub connect_max_retries: u32,
    /// Initial backoff delay in milliseconds for retries
    #[serde(default = "default_connect_initial_backoff_ms")]
    pub connect_initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds for retries
    #[serde(default = "default_connect_max_backoff_ms")]
    pub connect_max_backoff_ms: u64,
    /// Enable automatic health checks for proxies
    #[serde(default = "default_health_check_enabled")]
    pub health_check_enabled: bool,
    /// Interval between health checks in seconds
    #[serde(default = "default_health_check_interval_secs")]
    pub health_check_interval_secs: u64,
    /// Timeout for health check connections in milliseconds
    #[serde(default = "default_health_check_timeout_ms")]
    pub health_check_timeout_ms: u64,
    /// Number of consecutive failures before marking proxy unhealthy
    #[serde(default = "default_consecutive_failures_threshold")]
    pub consecutive_failures_threshold: u32,
    /// Automatically switch to healthy proxy when active becomes unhealthy
    #[serde(default = "default_auto_failover")]
    pub auto_failover: bool,
    /// Automatically return to original proxy when it recovers
    #[serde(default = "default_auto_failback")]
    pub auto_failback: bool,
    /// Delay in seconds before failing back after recovery
    #[serde(default = "default_failback_delay_secs")]
    pub failback_delay_secs: u64,
    /// Policy when all proxies are unhealthy
    #[serde(default)]
    pub degradation_policy: DegradationPolicy,
    /// Seconds to wait before applying degradation (debounce)
    #[serde(default = "default_degradation_delay_secs")]
    pub degradation_delay_secs: u64,
    /// Allow direct connections as fallback (required for Direct policy)
    #[serde(default)]
    pub allow_direct_fallback: bool,
    /// Load balancing strategy for distributing requests across proxies
    #[serde(default)]
    pub load_balance_strategy: LoadBalanceStrategy,
}

fn default_connect_max_retries() -> u32 {
    3
}

fn default_connect_initial_backoff_ms() -> u64 {
    100
}

fn default_connect_max_backoff_ms() -> u64 {
    5000
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9090
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

fn default_metrics_bind() -> String {
    "0.0.0.0".to_string()
}

fn default_health_check_enabled() -> bool {
    true
}

fn default_health_check_interval_secs() -> u64 {
    30
}

fn default_health_check_timeout_ms() -> u64 {
    5000
}

fn default_consecutive_failures_threshold() -> u32 {
    3
}

fn default_auto_failover() -> bool {
    true
}

fn default_auto_failback() -> bool {
    true
}

fn default_failback_delay_secs() -> u64 {
    60
}

fn default_degradation_delay_secs() -> u64 {
    5
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            listen_port: 12345,
            dns_refresh_secs: 300,
            ping_interval_secs: 60,
            ping_timeout_ms: 1500,
            ipset_name: "rust_proxy_targets".to_string(),
            chain_name: "RUST_PROXY".to_string(),
            include_aws_ip_ranges: true,
            include_cloudflare_ip_ranges: true,
            include_google_ip_ranges: true,
            metrics_enabled: default_metrics_enabled(),
            metrics_port: default_metrics_port(),
            metrics_path: default_metrics_path(),
            metrics_bind: default_metrics_bind(),
            connect_max_retries: default_connect_max_retries(),
            connect_initial_backoff_ms: default_connect_initial_backoff_ms(),
            connect_max_backoff_ms: default_connect_max_backoff_ms(),
            health_check_enabled: default_health_check_enabled(),
            health_check_interval_secs: default_health_check_interval_secs(),
            health_check_timeout_ms: default_health_check_timeout_ms(),
            consecutive_failures_threshold: default_consecutive_failures_threshold(),
            auto_failover: default_auto_failover(),
            auto_failback: default_auto_failback(),
            failback_delay_secs: default_failback_delay_secs(),
            degradation_policy: DegradationPolicy::default(),
            degradation_delay_secs: default_degradation_delay_secs(),
            allow_direct_fallback: false,
            load_balance_strategy: LoadBalanceStrategy::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,
    #[serde(default)]
    pub targets: Vec<TargetSpec>,
    pub active_proxy: Option<String>,
    #[serde(default)]
    pub settings: Settings,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            proxies: Vec::new(),
            targets: vec![
                // Anthropic
                TargetSpec::Detailed {
                    domain: "api.anthropic.com".to_string(),
                    provider: Provider::Anthropic,
                },
                TargetSpec::Detailed {
                    domain: "console.anthropic.com".to_string(),
                    provider: Provider::Anthropic,
                },
                TargetSpec::Detailed {
                    domain: "docs.anthropic.com".to_string(),
                    provider: Provider::Anthropic,
                },
                TargetSpec::Detailed {
                    domain: "support.anthropic.com".to_string(),
                    provider: Provider::Anthropic,
                },
                TargetSpec::Detailed {
                    domain: "claude.ai".to_string(),
                    provider: Provider::Anthropic,
                },
                TargetSpec::Detailed {
                    domain: "status.anthropic.com".to_string(),
                    provider: Provider::Anthropic,
                },
                TargetSpec::Detailed {
                    domain: "anthropic.com".to_string(),
                    provider: Provider::Anthropic,
                },
                TargetSpec::Detailed {
                    domain: "www.anthropic.com".to_string(),
                    provider: Provider::Anthropic,
                },
                // OpenAI
                TargetSpec::Detailed {
                    domain: "api.openai.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "platform.openai.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "auth.openai.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "setup.auth.openai.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "chat.openai.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "openai.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "www.openai.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "chatgpt.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "www.chatgpt.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "status.openai.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "help.openai.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "community.openai.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "cookbook.openai.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "oaistatic.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "oaiusercontent.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "files.oaiusercontent.com".to_string(),
                    provider: Provider::Openai,
                },
                TargetSpec::Detailed {
                    domain: "sora.com".to_string(),
                    provider: Provider::Openai,
                },
                // Amazon / AWS
                TargetSpec::Detailed {
                    domain: "amazon.com".to_string(),
                    provider: Provider::Amazon,
                },
                TargetSpec::Detailed {
                    domain: "www.amazon.com".to_string(),
                    provider: Provider::Amazon,
                },
                TargetSpec::Detailed {
                    domain: "aws.amazon.com".to_string(),
                    provider: Provider::Amazon,
                },
                TargetSpec::Detailed {
                    domain: "signin.aws.amazon.com".to_string(),
                    provider: Provider::Amazon,
                },
                TargetSpec::Detailed {
                    domain: "console.aws.amazon.com".to_string(),
                    provider: Provider::Amazon,
                },
                TargetSpec::Detailed {
                    domain: "iam.amazonaws.com".to_string(),
                    provider: Provider::Amazon,
                },
                TargetSpec::Detailed {
                    domain: "ec2.amazonaws.com".to_string(),
                    provider: Provider::Amazon,
                },
                TargetSpec::Detailed {
                    domain: "lambda.amazonaws.com".to_string(),
                    provider: Provider::Amazon,
                },
                TargetSpec::Detailed {
                    domain: "sts.amazonaws.com".to_string(),
                    provider: Provider::Amazon,
                },
                TargetSpec::Detailed {
                    domain: "sso.amazonaws.com".to_string(),
                    provider: Provider::Amazon,
                },
                // Cloudflare
                TargetSpec::Detailed {
                    domain: "cloudflare.com".to_string(),
                    provider: Provider::Cloudflare,
                },
                TargetSpec::Detailed {
                    domain: "www.cloudflare.com".to_string(),
                    provider: Provider::Cloudflare,
                },
                TargetSpec::Detailed {
                    domain: "api.cloudflare.com".to_string(),
                    provider: Provider::Cloudflare,
                },
                TargetSpec::Detailed {
                    domain: "dash.cloudflare.com".to_string(),
                    provider: Provider::Cloudflare,
                },
                TargetSpec::Detailed {
                    domain: "developers.cloudflare.com".to_string(),
                    provider: Provider::Cloudflare,
                },
                TargetSpec::Detailed {
                    domain: "cloudflareinsights.com".to_string(),
                    provider: Provider::Cloudflare,
                },
                TargetSpec::Detailed {
                    domain: "www.cloudflarestatus.com".to_string(),
                    provider: Provider::Cloudflare,
                },
                // Vercel
                TargetSpec::Detailed {
                    domain: "vercel.com".to_string(),
                    provider: Provider::Vercel,
                },
                TargetSpec::Detailed {
                    domain: "api.vercel.com".to_string(),
                    provider: Provider::Vercel,
                },
                TargetSpec::Detailed {
                    domain: "oidc.vercel.com".to_string(),
                    provider: Provider::Vercel,
                },
                TargetSpec::Detailed {
                    domain: "vercel.app".to_string(),
                    provider: Provider::Vercel,
                },
                // Supabase
                TargetSpec::Detailed {
                    domain: "supabase.com".to_string(),
                    provider: Provider::Supabase,
                },
                TargetSpec::Detailed {
                    domain: "supabase.co".to_string(),
                    provider: Provider::Supabase,
                },
                TargetSpec::Detailed {
                    domain: "status.supabase.com".to_string(),
                    provider: Provider::Supabase,
                },
                TargetSpec::Detailed {
                    domain: "realtime.supabase.com".to_string(),
                    provider: Provider::Supabase,
                },
                // Google (core + auth)
                TargetSpec::Detailed {
                    domain: "google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "www.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "cloud.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "console.cloud.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "reauth.cloud.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "accounts.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "accounts.gstatic.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "apis.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "oauth2.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "www.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "developers.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "clients6.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "www.gstatic.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "ssl.gstatic.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "fonts.gstatic.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "csi.gstatic.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "csp.withgoogle.com".to_string(),
                    provider: Provider::Google,
                },
                // Google Maps Platform (official domain list)
                TargetSpec::Detailed {
                    domain: "maps.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "mapsresources-pa.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "maps.gstatic.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "fonts.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khmdb0.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khmdb0.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khmdb1.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khmdb1.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khm.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khm.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khm0.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khm0.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khm1.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khm1.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khms0.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khms0.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khms1.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khms1.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khms2.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khms2.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khms3.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khms3.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "keyhole-pa.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "streetviewpixels-pa.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "googleapis.l.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "clients.l.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "maps.l.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "mt.l.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "khm.l.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "geo0.ggpht.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "geo1.ggpht.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "geo2.ggpht.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "geo3.ggpht.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "lh3.ggpht.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "lh4.ggpht.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "lh5.ggpht.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "lh6.ggpht.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "cbks0.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "cbks0.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "cbks1.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "cbks1.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "cbks2.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "cbks2.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "cbks3.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "cbks3.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "lh3.googleusercontent.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "lh4.googleusercontent.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "lh5.googleusercontent.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "lh6.googleusercontent.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "clients4.google.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "addressvalidation.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "aerialview.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "airquality.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "places.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "areainsights.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "pollen.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "roads.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "routes.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "routeoptimization.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "solar.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "tile.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "mapsplatformdatasets.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
                TargetSpec::Detailed {
                    domain: "weather.googleapis.com".to_string(),
                    provider: Provider::Google,
                },
            ],
            active_proxy: None,
            settings: Settings::default(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed reading config {}", path.display()))?;
        let config: AppConfig = toml::from_str(&content)
            .with_context(|| format!("Failed parsing config {}", path.display()))?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed creating config dir {}", parent.display()))?;
        }
        let content = toml::to_string_pretty(self)?;
        fs::write(&path, content)
            .with_context(|| format!("Failed writing config {}", path.display()))?;
        Ok(())
    }
}

pub fn default_config_template() -> Result<String> {
    let base = toml::to_string_pretty(&AppConfig::default())?;
    Ok(insert_metrics_comments(&base))
}

pub fn write_config_template(path: &PathBuf) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed creating config dir {}", parent.display()))?;
    }
    let content = default_config_template()?;
    fs::write(path, content)
        .with_context(|| format!("Failed writing config {}", path.display()))?;
    Ok(())
}

fn insert_metrics_comments(content: &str) -> String {
    let metrics_comment = "\n# Prometheus metrics\n# metrics_enabled = true\n# metrics_port = 9090\n# metrics_path = \"/metrics\"\n# metrics_bind = \"127.0.0.1\"  # Bind to localhost only for security\n";
    content.replacen(
        "metrics_enabled = ",
        &format!("{metrics_comment}metrics_enabled = "),
        1,
    )
}

pub fn config_path() -> Result<PathBuf> {
    let proj = ProjectDirs::from(APP_QUALIFIER, APP_ORG, APP_NAME)
        .context("Failed to resolve project dirs")?;
    Ok(proj.config_dir().join("config.toml"))
}

pub fn state_dir() -> Result<PathBuf> {
    let proj = ProjectDirs::from(APP_QUALIFIER, APP_ORG, APP_NAME)
        .context("Failed to resolve project dirs")?;
    let dir = proj.state_dir().context("Failed to resolve state dir")?;
    Ok(dir.to_path_buf())
}

// =============================================================================
// Config Holder — Thread-safe config access with atomic reload
// =============================================================================

use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// Thread-safe configuration holder with atomic reload support.
///
/// This struct provides:
/// - Concurrent read access via `get()` (cheap Arc clone)
/// - Atomic config reload via `reload()`
/// - Change notifications via broadcast channel
///
/// Components that need to react to config changes should call `subscribe()`
/// and listen for `ConfigDiff` messages.
#[allow(dead_code)]
#[derive(Clone)]
pub struct ConfigHolder {
    inner: Arc<RwLock<AppConfig>>,
    path: PathBuf,
    change_tx: broadcast::Sender<ConfigDiff>,
}

#[allow(dead_code)]
impl ConfigHolder {
    /// Create a new ConfigHolder with the given config and path.
    ///
    /// # Arguments
    ///
    /// * `config` - Initial configuration
    /// * `path` - Path to the config file (for reload)
    pub fn new(config: AppConfig, path: PathBuf) -> Self {
        // Channel capacity of 16 should be plenty for config changes
        let (change_tx, _) = broadcast::channel(16);
        Self {
            inner: Arc::new(RwLock::new(config)),
            path,
            change_tx,
        }
    }

    /// Load config from the default path and create a holder.
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        let config = AppConfig::load()?;
        Ok(Self::new(config, path))
    }

    /// Load config from a specific path and create a holder.
    pub fn load_from(path: PathBuf) -> Result<Self> {
        let config = if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed reading config {}", path.display()))?;
            toml::from_str(&content)
                .with_context(|| format!("Failed parsing config {}", path.display()))?
        } else {
            AppConfig::default()
        };
        Ok(Self::new(config, path))
    }

    /// Get current config (cheap clone of Arc contents).
    ///
    /// This acquires a read lock briefly to clone the config.
    /// For hot paths that need the config frequently, consider
    /// caching the result locally for the duration of the operation.
    pub async fn get(&self) -> AppConfig {
        self.inner.read().await.clone()
    }

    /// Get the path to the config file.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Subscribe to config change notifications.
    ///
    /// Returns a receiver that will receive `ConfigDiff` messages
    /// whenever the config is reloaded with changes.
    pub fn subscribe(&self) -> broadcast::Receiver<ConfigDiff> {
        self.change_tx.subscribe()
    }

    /// Attempt to reload config from disk.
    ///
    /// Returns:
    /// - `Ok(Some(diff))` if reload succeeded with changes
    /// - `Ok(None)` if config unchanged
    /// - `Err` if config invalid (keeps running with old config)
    ///
    /// On successful reload with changes:
    /// 1. Logs all changes
    /// 2. Atomically swaps the config
    /// 3. Sends `ConfigDiff` to all subscribers
    pub async fn reload(&self) -> Result<Option<ConfigDiff>> {
        // 1. Load new config from disk
        let new_config = match Self::load_config_from_path(&self.path) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    path = %self.path.display(),
                    error = %e,
                    "Failed to parse config, keeping current"
                );
                return Err(e);
            }
        };

        // 2. Validate new config (basic validation)
        if let Err(e) = Self::validate_config(&new_config) {
            tracing::error!(
                error = %e,
                "New config invalid, keeping current"
            );
            return Err(e);
        }

        // 3. Compute diff (hold read lock briefly)
        let diff = {
            let old_config = self.inner.read().await;
            diff_configs(&old_config, &new_config)
        };

        if diff.is_empty() {
            tracing::debug!("Config unchanged, no reload needed");
            return Ok(None);
        }

        // 4. Log what's changing
        diff.log();

        // 5. Atomic swap (hold write lock briefly)
        {
            let mut config = self.inner.write().await;
            *config = new_config;
        }

        tracing::info!(
            summary = %diff.summary(),
            "Configuration reloaded successfully"
        );

        // 6. Notify subscribers (ignore send errors if no receivers)
        let _ = self.change_tx.send(diff.clone());

        Ok(Some(diff))
    }

    /// Load config from a specific path (internal helper).
    fn load_config_from_path(path: &PathBuf) -> Result<AppConfig> {
        if !path.exists() {
            return Ok(AppConfig::default());
        }
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed reading config {}", path.display()))?;
        let config: AppConfig = toml::from_str(&content)
            .with_context(|| format!("Failed parsing config {}", path.display()))?;
        Ok(config)
    }

    /// Basic validation of config (internal helper).
    ///
    /// Returns Err if config has obvious problems that would cause
    /// runtime failures.
    fn validate_config(config: &AppConfig) -> Result<()> {
        // Validate listen port is in valid range
        if config.settings.listen_port == 0 {
            anyhow::bail!("listen_port cannot be 0");
        }

        // Validate active_proxy references a valid proxy if set
        if let Some(ref active) = config.active_proxy {
            if !config.proxies.iter().any(|p| &p.id == active) {
                anyhow::bail!(
                    "active_proxy '{}' does not match any configured proxy",
                    active
                );
            }
        }

        // Validate proxy IDs are unique
        let mut seen_ids = std::collections::HashSet::new();
        for proxy in &config.proxies {
            if !seen_ids.insert(&proxy.id) {
                anyhow::bail!("duplicate proxy id: {}", proxy.id);
            }
        }

        // Validate proxy URLs are non-empty
        for proxy in &config.proxies {
            if proxy.url.is_empty() {
                anyhow::bail!("proxy '{}' has empty url", proxy.id);
            }
        }

        // Validate metrics port if metrics enabled
        if config.settings.metrics_enabled && config.settings.metrics_port == 0 {
            anyhow::bail!("metrics_port cannot be 0 when metrics are enabled");
        }

        Ok(())
    }
}

// =============================================================================
// Config Diff — Detect changes between two AppConfig instances
// =============================================================================

/// Represents a change to a single setting field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct SettingChange {
    pub name: String,
    pub old_value: String,
    pub new_value: String,
}

/// Represents a modification to an existing proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct ProxyModification {
    pub proxy_id: String,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

/// Captures all differences between two AppConfig instances.
///
/// Used for targeted reload (only update what changed) and clear logging.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct ConfigDiff {
    /// Proxy IDs that were added
    pub proxies_added: Vec<String>,
    /// Proxy IDs that were removed
    pub proxies_removed: Vec<String>,
    /// Proxies whose configuration changed
    pub proxies_modified: Vec<ProxyModification>,
    /// Target domains that were added
    pub targets_added: Vec<String>,
    /// Target domains that were removed
    pub targets_removed: Vec<String>,
    /// Settings that changed
    pub settings_changed: Vec<SettingChange>,
    /// Whether the active proxy selection changed
    pub active_proxy_changed: bool,
    /// Whether the listen port changed (requires restart)
    pub listen_port_changed: bool,
}

#[allow(dead_code)]
impl ConfigDiff {
    /// Returns true if there are no differences.
    pub fn is_empty(&self) -> bool {
        self.proxies_added.is_empty()
            && self.proxies_removed.is_empty()
            && self.proxies_modified.is_empty()
            && self.targets_added.is_empty()
            && self.targets_removed.is_empty()
            && self.settings_changed.is_empty()
            && !self.active_proxy_changed
            && !self.listen_port_changed
    }

    /// Returns true if the changes require a daemon restart to take effect.
    ///
    /// Currently, only listen port changes require restart.
    pub fn requires_restart(&self) -> bool {
        self.listen_port_changed
    }

    /// Log all changes using tracing.
    pub fn log(&self) {
        for id in &self.proxies_added {
            tracing::info!(proxy_id = %id, "Proxy added");
        }
        for id in &self.proxies_removed {
            tracing::info!(proxy_id = %id, "Proxy removed");
        }
        for modification in &self.proxies_modified {
            tracing::info!(
                proxy_id = %modification.proxy_id,
                field = %modification.field,
                old = %modification.old_value,
                new = %modification.new_value,
                "Proxy modified"
            );
        }
        for domain in &self.targets_added {
            tracing::info!(domain = %domain, "Target added");
        }
        for domain in &self.targets_removed {
            tracing::info!(domain = %domain, "Target removed");
        }
        for change in &self.settings_changed {
            tracing::info!(
                setting = %change.name,
                old = %change.old_value,
                new = %change.new_value,
                "Setting changed"
            );
        }
        if self.active_proxy_changed {
            tracing::info!("Active proxy selection changed");
        }
        if self.listen_port_changed {
            tracing::warn!("Listen port changed - restart required for this to take effect");
        }
    }

    /// Returns a human-readable summary of changes.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.proxies_added.is_empty() {
            parts.push(format!("{} proxy(s) added", self.proxies_added.len()));
        }
        if !self.proxies_removed.is_empty() {
            parts.push(format!("{} proxy(s) removed", self.proxies_removed.len()));
        }
        if !self.proxies_modified.is_empty() {
            parts.push(format!("{} proxy(s) modified", self.proxies_modified.len()));
        }
        if !self.targets_added.is_empty() {
            parts.push(format!("{} target(s) added", self.targets_added.len()));
        }
        if !self.targets_removed.is_empty() {
            parts.push(format!("{} target(s) removed", self.targets_removed.len()));
        }
        if !self.settings_changed.is_empty() {
            parts.push(format!(
                "{} setting(s) changed",
                self.settings_changed.len()
            ));
        }
        if self.active_proxy_changed {
            parts.push("active proxy changed".to_string());
        }
        if self.listen_port_changed {
            parts.push("listen port changed (restart required)".to_string());
        }
        if parts.is_empty() {
            "No changes".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Compare two AppConfig instances and produce a ConfigDiff.
///
/// This enables targeted reload (only update what changed) and clear logging.
#[allow(dead_code)]
pub fn diff_configs(old: &AppConfig, new: &AppConfig) -> ConfigDiff {
    use std::collections::HashSet;

    let mut diff = ConfigDiff::default();

    // Compare proxy lists
    let old_proxy_ids: HashSet<_> = old.proxies.iter().map(|p| p.id.as_str()).collect();
    let new_proxy_ids: HashSet<_> = new.proxies.iter().map(|p| p.id.as_str()).collect();

    // Find added proxies
    for id in new_proxy_ids.difference(&old_proxy_ids) {
        diff.proxies_added.push((*id).to_string());
    }

    // Find removed proxies
    for id in old_proxy_ids.difference(&new_proxy_ids) {
        diff.proxies_removed.push((*id).to_string());
    }

    // Find modified proxies (those that exist in both but have changed)
    for new_proxy in &new.proxies {
        if let Some(old_proxy) = old.proxies.iter().find(|p| p.id == new_proxy.id) {
            diff_proxy(old_proxy, new_proxy, &mut diff.proxies_modified);
        }
    }

    // Compare target lists
    let old_domains: HashSet<_> = old.targets.iter().map(|t| t.domain()).collect();
    let new_domains: HashSet<_> = new.targets.iter().map(|t| t.domain()).collect();

    for domain in new_domains.difference(&old_domains) {
        diff.targets_added.push((*domain).to_string());
    }
    for domain in old_domains.difference(&new_domains) {
        diff.targets_removed.push((*domain).to_string());
    }

    // Compare active proxy
    if old.active_proxy != new.active_proxy {
        diff.active_proxy_changed = true;
    }

    // Compare settings
    diff_settings(&old.settings, &new.settings, &mut diff);

    diff
}

/// Compare two ProxyConfig instances and record modifications.
#[allow(dead_code)]
fn diff_proxy(old: &ProxyConfig, new: &ProxyConfig, modifications: &mut Vec<ProxyModification>) {
    let proxy_id = &new.id;

    if old.url != new.url {
        modifications.push(ProxyModification {
            proxy_id: proxy_id.clone(),
            field: "url".to_string(),
            old_value: old.url.clone(),
            new_value: new.url.clone(),
        });
    }

    if old.priority != new.priority {
        modifications.push(ProxyModification {
            proxy_id: proxy_id.clone(),
            field: "priority".to_string(),
            old_value: format!("{:?}", old.priority),
            new_value: format!("{:?}", new.priority),
        });
    }

    if old.weight != new.weight {
        modifications.push(ProxyModification {
            proxy_id: proxy_id.clone(),
            field: "weight".to_string(),
            old_value: old.weight.to_string(),
            new_value: new.weight.to_string(),
        });
    }

    if old.health_check_url != new.health_check_url {
        modifications.push(ProxyModification {
            proxy_id: proxy_id.clone(),
            field: "health_check_url".to_string(),
            old_value: format!("{:?}", old.health_check_url),
            new_value: format!("{:?}", new.health_check_url),
        });
    }

    // Compare auth (check if credentials changed without exposing values)
    let old_auth = old.auth.resolve();
    let new_auth = new.auth.resolve();
    if old_auth != new_auth {
        modifications.push(ProxyModification {
            proxy_id: proxy_id.clone(),
            field: "auth".to_string(),
            old_value: "[credentials]".to_string(),
            new_value: "[credentials changed]".to_string(),
        });
    }
}

/// Compare two Settings instances and record changes.
#[allow(dead_code)]
fn diff_settings(old: &Settings, new: &Settings, diff: &mut ConfigDiff) {
    // Listen port - special handling as it requires restart
    if old.listen_port != new.listen_port {
        diff.listen_port_changed = true;
        diff.settings_changed.push(SettingChange {
            name: "listen_port".to_string(),
            old_value: old.listen_port.to_string(),
            new_value: new.listen_port.to_string(),
        });
    }

    // DNS and ping settings
    if old.dns_refresh_secs != new.dns_refresh_secs {
        diff.settings_changed.push(SettingChange {
            name: "dns_refresh_secs".to_string(),
            old_value: old.dns_refresh_secs.to_string(),
            new_value: new.dns_refresh_secs.to_string(),
        });
    }

    if old.ping_interval_secs != new.ping_interval_secs {
        diff.settings_changed.push(SettingChange {
            name: "ping_interval_secs".to_string(),
            old_value: old.ping_interval_secs.to_string(),
            new_value: new.ping_interval_secs.to_string(),
        });
    }

    if old.ping_timeout_ms != new.ping_timeout_ms {
        diff.settings_changed.push(SettingChange {
            name: "ping_timeout_ms".to_string(),
            old_value: old.ping_timeout_ms.to_string(),
            new_value: new.ping_timeout_ms.to_string(),
        });
    }

    // iptables/ipset settings
    if old.ipset_name != new.ipset_name {
        diff.settings_changed.push(SettingChange {
            name: "ipset_name".to_string(),
            old_value: old.ipset_name.clone(),
            new_value: new.ipset_name.clone(),
        });
    }

    if old.chain_name != new.chain_name {
        diff.settings_changed.push(SettingChange {
            name: "chain_name".to_string(),
            old_value: old.chain_name.clone(),
            new_value: new.chain_name.clone(),
        });
    }

    // IP range toggles
    if old.include_aws_ip_ranges != new.include_aws_ip_ranges {
        diff.settings_changed.push(SettingChange {
            name: "include_aws_ip_ranges".to_string(),
            old_value: old.include_aws_ip_ranges.to_string(),
            new_value: new.include_aws_ip_ranges.to_string(),
        });
    }

    if old.include_cloudflare_ip_ranges != new.include_cloudflare_ip_ranges {
        diff.settings_changed.push(SettingChange {
            name: "include_cloudflare_ip_ranges".to_string(),
            old_value: old.include_cloudflare_ip_ranges.to_string(),
            new_value: new.include_cloudflare_ip_ranges.to_string(),
        });
    }

    if old.include_google_ip_ranges != new.include_google_ip_ranges {
        diff.settings_changed.push(SettingChange {
            name: "include_google_ip_ranges".to_string(),
            old_value: old.include_google_ip_ranges.to_string(),
            new_value: new.include_google_ip_ranges.to_string(),
        });
    }

    // Metrics settings
    if old.metrics_enabled != new.metrics_enabled {
        diff.settings_changed.push(SettingChange {
            name: "metrics_enabled".to_string(),
            old_value: old.metrics_enabled.to_string(),
            new_value: new.metrics_enabled.to_string(),
        });
    }

    if old.metrics_port != new.metrics_port {
        diff.settings_changed.push(SettingChange {
            name: "metrics_port".to_string(),
            old_value: old.metrics_port.to_string(),
            new_value: new.metrics_port.to_string(),
        });
    }

    if old.metrics_path != new.metrics_path {
        diff.settings_changed.push(SettingChange {
            name: "metrics_path".to_string(),
            old_value: old.metrics_path.clone(),
            new_value: new.metrics_path.clone(),
        });
    }

    if old.metrics_bind != new.metrics_bind {
        diff.settings_changed.push(SettingChange {
            name: "metrics_bind".to_string(),
            old_value: old.metrics_bind.clone(),
            new_value: new.metrics_bind.clone(),
        });
    }

    // Connection retry settings
    if old.connect_max_retries != new.connect_max_retries {
        diff.settings_changed.push(SettingChange {
            name: "connect_max_retries".to_string(),
            old_value: old.connect_max_retries.to_string(),
            new_value: new.connect_max_retries.to_string(),
        });
    }

    if old.connect_initial_backoff_ms != new.connect_initial_backoff_ms {
        diff.settings_changed.push(SettingChange {
            name: "connect_initial_backoff_ms".to_string(),
            old_value: old.connect_initial_backoff_ms.to_string(),
            new_value: new.connect_initial_backoff_ms.to_string(),
        });
    }

    if old.connect_max_backoff_ms != new.connect_max_backoff_ms {
        diff.settings_changed.push(SettingChange {
            name: "connect_max_backoff_ms".to_string(),
            old_value: old.connect_max_backoff_ms.to_string(),
            new_value: new.connect_max_backoff_ms.to_string(),
        });
    }

    // Health check settings
    if old.health_check_enabled != new.health_check_enabled {
        diff.settings_changed.push(SettingChange {
            name: "health_check_enabled".to_string(),
            old_value: old.health_check_enabled.to_string(),
            new_value: new.health_check_enabled.to_string(),
        });
    }

    if old.health_check_interval_secs != new.health_check_interval_secs {
        diff.settings_changed.push(SettingChange {
            name: "health_check_interval_secs".to_string(),
            old_value: old.health_check_interval_secs.to_string(),
            new_value: new.health_check_interval_secs.to_string(),
        });
    }

    if old.health_check_timeout_ms != new.health_check_timeout_ms {
        diff.settings_changed.push(SettingChange {
            name: "health_check_timeout_ms".to_string(),
            old_value: old.health_check_timeout_ms.to_string(),
            new_value: new.health_check_timeout_ms.to_string(),
        });
    }

    if old.consecutive_failures_threshold != new.consecutive_failures_threshold {
        diff.settings_changed.push(SettingChange {
            name: "consecutive_failures_threshold".to_string(),
            old_value: old.consecutive_failures_threshold.to_string(),
            new_value: new.consecutive_failures_threshold.to_string(),
        });
    }

    // Failover settings
    if old.auto_failover != new.auto_failover {
        diff.settings_changed.push(SettingChange {
            name: "auto_failover".to_string(),
            old_value: old.auto_failover.to_string(),
            new_value: new.auto_failover.to_string(),
        });
    }

    if old.auto_failback != new.auto_failback {
        diff.settings_changed.push(SettingChange {
            name: "auto_failback".to_string(),
            old_value: old.auto_failback.to_string(),
            new_value: new.auto_failback.to_string(),
        });
    }

    if old.failback_delay_secs != new.failback_delay_secs {
        diff.settings_changed.push(SettingChange {
            name: "failback_delay_secs".to_string(),
            old_value: old.failback_delay_secs.to_string(),
            new_value: new.failback_delay_secs.to_string(),
        });
    }

    // Degradation settings
    if old.degradation_policy != new.degradation_policy {
        diff.settings_changed.push(SettingChange {
            name: "degradation_policy".to_string(),
            old_value: format!("{:?}", old.degradation_policy),
            new_value: format!("{:?}", new.degradation_policy),
        });
    }

    if old.degradation_delay_secs != new.degradation_delay_secs {
        diff.settings_changed.push(SettingChange {
            name: "degradation_delay_secs".to_string(),
            old_value: old.degradation_delay_secs.to_string(),
            new_value: new.degradation_delay_secs.to_string(),
        });
    }

    if old.allow_direct_fallback != new.allow_direct_fallback {
        diff.settings_changed.push(SettingChange {
            name: "allow_direct_fallback".to_string(),
            old_value: old.allow_direct_fallback.to_string(),
            new_value: new.allow_direct_fallback.to_string(),
        });
    }

    // Load balancing
    if old.load_balance_strategy != new.load_balance_strategy {
        diff.settings_changed.push(SettingChange {
            name: "load_balance_strategy".to_string(),
            old_value: format!("{:?}", old.load_balance_strategy),
            new_value: format!("{:?}", new.load_balance_strategy),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_provider_anthropic() {
        assert_eq!(
            infer_provider("api.anthropic.com"),
            Some(Provider::Anthropic)
        );
        assert_eq!(infer_provider("claude.ai"), Some(Provider::Anthropic));
        assert_eq!(infer_provider("www.claude.com"), Some(Provider::Anthropic));
    }

    #[test]
    fn test_infer_provider_openai() {
        assert_eq!(infer_provider("api.openai.com"), Some(Provider::Openai));
        assert_eq!(infer_provider("chatgpt.com"), Some(Provider::Openai));
        assert_eq!(infer_provider("oaistatic.com"), Some(Provider::Openai));
        assert_eq!(infer_provider("sora.com"), Some(Provider::Openai));
    }

    #[test]
    fn test_infer_provider_amazon() {
        assert_eq!(infer_provider("aws.amazon.com"), Some(Provider::Amazon));
        assert_eq!(infer_provider("iam.amazonaws.com"), Some(Provider::Amazon));
        assert_eq!(infer_provider("cloudfront.net"), Some(Provider::Amazon));
    }

    #[test]
    fn test_infer_provider_cloudflare() {
        assert_eq!(infer_provider("cloudflare.com"), Some(Provider::Cloudflare));
        assert_eq!(
            infer_provider("dash.cloudflare.com"),
            Some(Provider::Cloudflare)
        );
        assert_eq!(
            infer_provider("cloudflareinsights.com"),
            Some(Provider::Cloudflare)
        );
    }

    #[test]
    fn test_infer_provider_vercel() {
        assert_eq!(infer_provider("vercel.com"), Some(Provider::Vercel));
        assert_eq!(infer_provider("myapp.vercel.app"), Some(Provider::Vercel));
    }

    #[test]
    fn test_infer_provider_supabase() {
        assert_eq!(infer_provider("supabase.com"), Some(Provider::Supabase));
        assert_eq!(
            infer_provider("myproject.supabase.co"),
            Some(Provider::Supabase)
        );
    }

    #[test]
    fn test_infer_provider_google() {
        assert_eq!(infer_provider("google.com"), Some(Provider::Google));
        assert_eq!(
            infer_provider("maps.googleapis.com"),
            Some(Provider::Google)
        );
        assert_eq!(infer_provider("fonts.gstatic.com"), Some(Provider::Google));
    }

    #[test]
    fn test_infer_provider_unknown() {
        assert_eq!(infer_provider("example.com"), None);
        assert_eq!(infer_provider("random.org"), None);
    }

    #[test]
    fn test_infer_provider_case_insensitive() {
        assert_eq!(
            infer_provider("API.ANTHROPIC.COM"),
            Some(Provider::Anthropic)
        );
        assert_eq!(infer_provider("Claude.AI"), Some(Provider::Anthropic));
    }

    #[test]
    fn test_provider_as_str() {
        assert_eq!(Provider::Anthropic.as_str(), "anthropic");
        assert_eq!(Provider::Openai.as_str(), "openai");
        assert_eq!(Provider::Google.as_str(), "google");
        assert_eq!(Provider::Amazon.as_str(), "amazon");
        assert_eq!(Provider::Cloudflare.as_str(), "cloudflare");
        assert_eq!(Provider::Vercel.as_str(), "vercel");
        assert_eq!(Provider::Supabase.as_str(), "supabase");
    }

    #[test]
    fn test_target_spec_simple_domain() {
        let target = TargetSpec::Simple("example.com".to_string());
        assert_eq!(target.domain(), "example.com");
    }

    #[test]
    fn test_target_spec_detailed_domain() {
        let target = TargetSpec::Detailed {
            domain: "api.anthropic.com".to_string(),
            provider: Provider::Anthropic,
        };
        assert_eq!(target.domain(), "api.anthropic.com");
        assert_eq!(target.provider(), Provider::Anthropic);
    }

    #[test]
    fn test_target_spec_simple_infers_provider() {
        let target = TargetSpec::Simple("api.openai.com".to_string());
        assert_eq!(target.provider(), Provider::Openai);
    }

    #[test]
    fn test_target_spec_simple_defaults_to_google() {
        let target = TargetSpec::Simple("unknown.example.org".to_string());
        assert_eq!(target.provider(), Provider::Google);
    }

    #[test]
    fn test_proxy_auth_resolve_direct() {
        let auth = ProxyAuth {
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            username_env: None,
            password_env: None,
        };
        let (user, pass) = auth.resolve();
        assert_eq!(user, Some("user".to_string()));
        assert_eq!(pass, Some("pass".to_string()));
    }

    #[test]
    fn test_proxy_auth_resolve_empty() {
        let auth = ProxyAuth::default();
        let (user, pass) = auth.resolve();
        assert_eq!(user, None);
        assert_eq!(pass, None);
    }

    #[test]
    fn test_settings_default() {
        let settings = Settings::default();
        assert_eq!(settings.listen_port, 12345);
        assert_eq!(settings.dns_refresh_secs, 300);
        assert_eq!(settings.ping_interval_secs, 60);
        assert_eq!(settings.ping_timeout_ms, 1500);
        assert_eq!(settings.ipset_name, "rust_proxy_targets");
        assert_eq!(settings.chain_name, "RUST_PROXY");
        assert!(settings.include_aws_ip_ranges);
        assert!(settings.include_cloudflare_ip_ranges);
        assert!(settings.include_google_ip_ranges);
        assert!(settings.metrics_enabled);
        assert_eq!(settings.metrics_port, 9090);
        assert_eq!(settings.metrics_path, "/metrics");
        assert_eq!(settings.metrics_bind, "0.0.0.0");
        // Health check settings
        assert!(settings.health_check_enabled);
        assert_eq!(settings.health_check_interval_secs, 30);
        assert_eq!(settings.health_check_timeout_ms, 5000);
        assert_eq!(settings.consecutive_failures_threshold, 3);
        assert!(settings.auto_failover);
        assert!(settings.auto_failback);
        assert_eq!(settings.failback_delay_secs, 60);
        // Degradation settings
        assert_eq!(settings.degradation_policy, DegradationPolicy::FailClosed);
        assert_eq!(settings.degradation_delay_secs, 5);
        assert!(!settings.allow_direct_fallback);
    }

    #[test]
    fn test_degradation_policy_default() {
        assert_eq!(DegradationPolicy::default(), DegradationPolicy::FailClosed);
    }

    #[test]
    fn test_degradation_policy_serde() {
        // Test that all variants serialize/deserialize correctly
        let policies = [
            (DegradationPolicy::FailClosed, "\"fail_closed\""),
            (DegradationPolicy::TryAll, "\"try_all\""),
            (DegradationPolicy::UseLast, "\"use_last\""),
            (DegradationPolicy::Direct, "\"direct\""),
        ];
        for (policy, expected_json) in policies {
            let json = serde_json::to_string(&policy).unwrap();
            assert_eq!(json, expected_json);
            let parsed: DegradationPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, policy);
        }
    }

    #[test]
    fn test_proxy_config_priority() {
        let proxy = ProxyConfig {
            id: "test".to_string(),
            url: "http://proxy:8080".to_string(),
            auth: ProxyAuth::default(),
            priority: Some(1),
            health_check_url: Some("http://example.com".to_string()),
            weight: 100,
        };
        assert_eq!(proxy.priority, Some(1));
        assert_eq!(
            proxy.health_check_url,
            Some("http://example.com".to_string())
        );
    }

    #[test]
    fn test_app_config_default_has_targets() {
        let config = AppConfig::default();
        assert!(!config.targets.is_empty());
        assert!(config.proxies.is_empty());
        assert!(config.active_proxy.is_none());
    }

    #[test]
    fn test_default_config_template_includes_metrics_comments() {
        let template = default_config_template().unwrap();
        assert!(template.contains("# Prometheus metrics"));
        assert!(template.contains("metrics_enabled = true"));
        assert!(template.contains("metrics_port = 9090"));
        assert!(template.contains("metrics_path = \"/metrics\""));
        assert!(template.contains("metrics_bind = \"0.0.0.0\""));
    }

    // ==========================================================================
    // ConfigDiff Tests
    // ==========================================================================

    fn make_test_proxy(id: &str, url: &str) -> ProxyConfig {
        ProxyConfig {
            id: id.to_string(),
            url: url.to_string(),
            auth: ProxyAuth::default(),
            priority: None,
            health_check_url: None,
            weight: 100,
        }
    }

    fn make_minimal_config() -> AppConfig {
        AppConfig {
            proxies: vec![],
            targets: vec![],
            active_proxy: None,
            settings: Settings::default(),
        }
    }

    #[test]
    fn test_config_diff_identical_configs() {
        let config1 = make_minimal_config();
        let config2 = config1.clone();
        let diff = diff_configs(&config1, &config2);

        assert!(diff.is_empty());
        assert!(!diff.requires_restart());
        assert_eq!(diff.summary(), "No changes");
    }

    #[test]
    fn test_config_diff_proxy_added() {
        let old = make_minimal_config();
        let mut new = make_minimal_config();

        new.proxies
            .push(make_test_proxy("new-proxy", "http://proxy:8080"));

        let diff = diff_configs(&old, &new);

        assert!(!diff.is_empty());
        assert_eq!(diff.proxies_added, vec!["new-proxy"]);
        assert!(diff.proxies_removed.is_empty());
        assert!(diff.proxies_modified.is_empty());
        assert!(diff.summary().contains("1 proxy(s) added"));
    }

    #[test]
    fn test_config_diff_proxy_removed() {
        let mut old = make_minimal_config();
        old.proxies
            .push(make_test_proxy("old-proxy", "http://proxy:8080"));

        let new = make_minimal_config();

        let diff = diff_configs(&old, &new);

        assert!(!diff.is_empty());
        assert_eq!(diff.proxies_removed, vec!["old-proxy"]);
        assert!(diff.proxies_added.is_empty());
    }

    #[test]
    fn test_config_diff_proxy_modified() {
        let mut old = make_minimal_config();
        old.proxies
            .push(make_test_proxy("my-proxy", "http://old:8080"));

        let mut new = make_minimal_config();
        new.proxies
            .push(make_test_proxy("my-proxy", "http://new:9090"));

        let diff = diff_configs(&old, &new);

        assert!(!diff.is_empty());
        assert!(diff.proxies_added.is_empty());
        assert!(diff.proxies_removed.is_empty());
        assert_eq!(diff.proxies_modified.len(), 1);
        assert_eq!(diff.proxies_modified[0].proxy_id, "my-proxy");
        assert_eq!(diff.proxies_modified[0].field, "url");
        assert_eq!(diff.proxies_modified[0].old_value, "http://old:8080");
        assert_eq!(diff.proxies_modified[0].new_value, "http://new:9090");
    }

    #[test]
    fn test_config_diff_proxy_weight_changed() {
        let mut old = make_minimal_config();
        let mut proxy = make_test_proxy("my-proxy", "http://proxy:8080");
        proxy.weight = 100;
        old.proxies.push(proxy);

        let mut new = make_minimal_config();
        let mut proxy = make_test_proxy("my-proxy", "http://proxy:8080");
        proxy.weight = 200;
        new.proxies.push(proxy);

        let diff = diff_configs(&old, &new);

        assert_eq!(diff.proxies_modified.len(), 1);
        assert_eq!(diff.proxies_modified[0].field, "weight");
    }

    #[test]
    fn test_config_diff_target_added() {
        let old = make_minimal_config();
        let mut new = make_minimal_config();

        new.targets
            .push(TargetSpec::Simple("api.anthropic.com".to_string()));

        let diff = diff_configs(&old, &new);

        assert!(!diff.is_empty());
        assert_eq!(diff.targets_added, vec!["api.anthropic.com"]);
        assert!(diff.targets_removed.is_empty());
    }

    #[test]
    fn test_config_diff_target_removed() {
        let mut old = make_minimal_config();
        old.targets
            .push(TargetSpec::Simple("api.openai.com".to_string()));

        let new = make_minimal_config();

        let diff = diff_configs(&old, &new);

        assert!(!diff.is_empty());
        assert_eq!(diff.targets_removed, vec!["api.openai.com"]);
    }

    #[test]
    fn test_config_diff_active_proxy_changed() {
        let mut old = make_minimal_config();
        old.active_proxy = Some("proxy-a".to_string());

        let mut new = make_minimal_config();
        new.active_proxy = Some("proxy-b".to_string());

        let diff = diff_configs(&old, &new);

        assert!(!diff.is_empty());
        assert!(diff.active_proxy_changed);
        assert!(diff.summary().contains("active proxy changed"));
    }

    #[test]
    fn test_config_diff_active_proxy_cleared() {
        let mut old = make_minimal_config();
        old.active_proxy = Some("proxy-a".to_string());

        let new = make_minimal_config();

        let diff = diff_configs(&old, &new);

        assert!(diff.active_proxy_changed);
    }

    #[test]
    fn test_config_diff_listen_port_requires_restart() {
        let mut old = make_minimal_config();
        old.settings.listen_port = 12345;

        let mut new = make_minimal_config();
        new.settings.listen_port = 54321;

        let diff = diff_configs(&old, &new);

        assert!(!diff.is_empty());
        assert!(diff.requires_restart());
        assert!(diff.listen_port_changed);
        assert!(diff.summary().contains("restart required"));
    }

    #[test]
    fn test_config_diff_setting_changed() {
        let mut old = make_minimal_config();
        old.settings.health_check_interval_secs = 30;

        let mut new = make_minimal_config();
        new.settings.health_check_interval_secs = 60;

        let diff = diff_configs(&old, &new);

        assert!(!diff.is_empty());
        assert!(!diff.requires_restart());
        assert_eq!(diff.settings_changed.len(), 1);
        assert_eq!(diff.settings_changed[0].name, "health_check_interval_secs");
        assert_eq!(diff.settings_changed[0].old_value, "30");
        assert_eq!(diff.settings_changed[0].new_value, "60");
    }

    #[test]
    fn test_config_diff_multiple_settings_changed() {
        let mut old = make_minimal_config();
        old.settings.dns_refresh_secs = 300;
        old.settings.ping_interval_secs = 60;

        let mut new = make_minimal_config();
        new.settings.dns_refresh_secs = 600;
        new.settings.ping_interval_secs = 120;

        let diff = diff_configs(&old, &new);

        assert_eq!(diff.settings_changed.len(), 2);
        let names: Vec<_> = diff
            .settings_changed
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert!(names.contains(&"dns_refresh_secs"));
        assert!(names.contains(&"ping_interval_secs"));
    }

    #[test]
    fn test_config_diff_load_balance_strategy_changed() {
        let mut old = make_minimal_config();
        old.settings.load_balance_strategy = LoadBalanceStrategy::Single;

        let mut new = make_minimal_config();
        new.settings.load_balance_strategy = LoadBalanceStrategy::RoundRobin;

        let diff = diff_configs(&old, &new);

        assert_eq!(diff.settings_changed.len(), 1);
        assert_eq!(diff.settings_changed[0].name, "load_balance_strategy");
    }

    #[test]
    fn test_config_diff_degradation_policy_changed() {
        let mut old = make_minimal_config();
        old.settings.degradation_policy = DegradationPolicy::FailClosed;

        let mut new = make_minimal_config();
        new.settings.degradation_policy = DegradationPolicy::TryAll;

        let diff = diff_configs(&old, &new);

        assert_eq!(diff.settings_changed.len(), 1);
        assert_eq!(diff.settings_changed[0].name, "degradation_policy");
    }

    #[test]
    fn test_config_diff_complex_changes() {
        let mut old = make_minimal_config();
        old.proxies
            .push(make_test_proxy("proxy-a", "http://a:8080"));
        old.proxies
            .push(make_test_proxy("proxy-b", "http://b:8080"));
        old.targets.push(TargetSpec::Simple("old.com".to_string()));
        old.active_proxy = Some("proxy-a".to_string());
        old.settings.health_check_interval_secs = 30;

        let mut new = make_minimal_config();
        // proxy-a removed, proxy-b kept, proxy-c added
        new.proxies
            .push(make_test_proxy("proxy-b", "http://b:8080"));
        new.proxies
            .push(make_test_proxy("proxy-c", "http://c:8080"));
        // old.com removed, new.com added
        new.targets.push(TargetSpec::Simple("new.com".to_string()));
        new.active_proxy = Some("proxy-c".to_string());
        new.settings.health_check_interval_secs = 60;

        let diff = diff_configs(&old, &new);

        assert!(!diff.is_empty());
        assert_eq!(diff.proxies_added, vec!["proxy-c"]);
        assert_eq!(diff.proxies_removed, vec!["proxy-a"]);
        assert_eq!(diff.targets_added, vec!["new.com"]);
        assert_eq!(diff.targets_removed, vec!["old.com"]);
        assert!(diff.active_proxy_changed);
        assert_eq!(diff.settings_changed.len(), 1);

        // Check summary contains multiple parts
        let summary = diff.summary();
        assert!(summary.contains("proxy(s) added"));
        assert!(summary.contains("proxy(s) removed"));
        assert!(summary.contains("target(s) added"));
        assert!(summary.contains("target(s) removed"));
        assert!(summary.contains("active proxy changed"));
        assert!(summary.contains("setting(s) changed"));
    }

    #[test]
    fn test_config_diff_is_empty() {
        let diff = ConfigDiff::default();
        assert!(diff.is_empty());

        let mut diff_with_proxy = ConfigDiff::default();
        diff_with_proxy.proxies_added.push("test".to_string());
        assert!(!diff_with_proxy.is_empty());
    }

    #[test]
    fn test_config_diff_requires_restart() {
        let diff = ConfigDiff::default();
        assert!(!diff.requires_restart());

        let diff_with_listen = ConfigDiff {
            listen_port_changed: true,
            ..Default::default()
        };
        assert!(diff_with_listen.requires_restart());
    }

    // ==========================================================================
    // ConfigHolder Tests
    // ==========================================================================

    #[test]
    fn test_config_holder_new() {
        let config = make_minimal_config();
        let path = PathBuf::from("/tmp/test-config.toml");
        let holder = ConfigHolder::new(config.clone(), path.clone());

        assert_eq!(holder.path(), &path);
    }

    #[tokio::test]
    async fn test_config_holder_get() {
        let mut config = make_minimal_config();
        config.active_proxy = Some("test-proxy".to_string());
        let holder = ConfigHolder::new(config, PathBuf::from("/tmp/test.toml"));

        let retrieved = holder.get().await;
        assert_eq!(retrieved.active_proxy, Some("test-proxy".to_string()));
    }

    #[tokio::test]
    async fn test_config_holder_subscribe() {
        let config = make_minimal_config();
        let holder = ConfigHolder::new(config, PathBuf::from("/tmp/test.toml"));

        // Should be able to create multiple subscribers
        let _rx1 = holder.subscribe();
        let _rx2 = holder.subscribe();
    }

    #[test]
    fn test_config_holder_validate_empty_url() {
        let mut config = make_minimal_config();
        config.proxies.push(ProxyConfig {
            id: "bad-proxy".to_string(),
            url: "".to_string(),
            auth: ProxyAuth::default(),
            priority: None,
            health_check_url: None,
            weight: 100,
        });

        let result = ConfigHolder::validate_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty url"));
    }

    #[test]
    fn test_config_holder_validate_duplicate_proxy_id() {
        let mut config = make_minimal_config();
        config
            .proxies
            .push(make_test_proxy("same-id", "http://a:8080"));
        config
            .proxies
            .push(make_test_proxy("same-id", "http://b:8080"));

        let result = ConfigHolder::validate_config(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("duplicate proxy id"));
    }

    #[test]
    fn test_config_holder_validate_invalid_active_proxy() {
        let mut config = make_minimal_config();
        config.active_proxy = Some("nonexistent".to_string());

        let result = ConfigHolder::validate_config(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("does not match any configured proxy"));
    }

    #[test]
    fn test_config_holder_validate_zero_listen_port() {
        let mut config = make_minimal_config();
        config.settings.listen_port = 0;

        let result = ConfigHolder::validate_config(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("listen_port cannot be 0"));
    }

    #[test]
    fn test_config_holder_validate_zero_metrics_port_when_enabled() {
        let mut config = make_minimal_config();
        config.settings.metrics_enabled = true;
        config.settings.metrics_port = 0;

        let result = ConfigHolder::validate_config(&config);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("metrics_port cannot be 0"));
    }

    #[test]
    fn test_config_holder_validate_valid_config() {
        let mut config = make_minimal_config();
        config
            .proxies
            .push(make_test_proxy("proxy-1", "http://proxy:8080"));
        config.active_proxy = Some("proxy-1".to_string());

        let result = ConfigHolder::validate_config(&config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_config_holder_reload_nonexistent_file() {
        let config = make_minimal_config();
        let path = PathBuf::from("/tmp/nonexistent-config-12345.toml");
        let holder = ConfigHolder::new(config, path);

        // Reload should return Ok(None) for nonexistent file (uses default)
        // The file doesn't exist, so it loads default, which is same as what we started with
        let result = holder.reload().await;
        assert!(result.is_ok());
        // Since we started with minimal config (similar to default), diff may be non-empty
        // due to default targets. Let's just check it doesn't error.
    }

    #[tokio::test]
    async fn test_config_holder_reload_with_temp_file() {
        use std::io::Write;

        // Create initial config
        let mut config = make_minimal_config();
        config
            .proxies
            .push(make_test_proxy("proxy-1", "http://old:8080"));
        config.active_proxy = Some("proxy-1".to_string());

        // Create temp file with updated config
        // Note: active_proxy must come BEFORE [[proxies]] in TOML
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        let new_config_toml = r#"
active_proxy = "proxy-1"

[[proxies]]
id = "proxy-1"
url = "http://new:9090"
weight = 100

[settings]
listen_port = 12345
dns_refresh_secs = 300
ping_interval_secs = 60
ping_timeout_ms = 1500
ipset_name = "rust_proxy_targets"
chain_name = "RUST_PROXY"
include_aws_ip_ranges = true
include_cloudflare_ip_ranges = true
include_google_ip_ranges = true
"#;
        temp_file.write_all(new_config_toml.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let holder = ConfigHolder::new(config, temp_file.path().to_path_buf());

        // Subscribe before reload
        let mut rx = holder.subscribe();

        // Reload should detect the URL change
        let result = holder.reload().await;
        assert!(result.is_ok());
        let diff = result.unwrap();
        assert!(diff.is_some());

        let diff = diff.unwrap();
        assert!(!diff.proxies_modified.is_empty());

        // Check subscriber received notification
        let received_diff = rx.try_recv();
        assert!(received_diff.is_ok());
    }

    #[tokio::test]
    async fn test_config_holder_reload_no_changes() {
        use std::io::Write;

        // Create config with full settings to match what TOML will parse with defaults
        let mut config = make_minimal_config();
        config
            .proxies
            .push(make_test_proxy("proxy-1", "http://proxy:8080"));
        config.active_proxy = Some("proxy-1".to_string());

        // Create temp file with same config
        // Note: active_proxy must come BEFORE [[proxies]] in TOML
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        let config_toml = r#"
active_proxy = "proxy-1"

[[proxies]]
id = "proxy-1"
url = "http://proxy:8080"
weight = 100

[settings]
listen_port = 12345
dns_refresh_secs = 300
ping_interval_secs = 60
ping_timeout_ms = 1500
ipset_name = "rust_proxy_targets"
chain_name = "RUST_PROXY"
include_aws_ip_ranges = true
include_cloudflare_ip_ranges = true
include_google_ip_ranges = true
"#;
        temp_file.write_all(config_toml.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let holder = ConfigHolder::new(config, temp_file.path().to_path_buf());

        // Reload should return None (no changes)
        let result = holder.reload().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_config_holder_reload_invalid_toml() {
        use std::io::Write;

        let config = make_minimal_config();

        // Create temp file with invalid TOML
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        temp_file.write_all(b"this is not valid toml [[[").unwrap();
        temp_file.flush().unwrap();

        let holder = ConfigHolder::new(config, temp_file.path().to_path_buf());

        // Reload should fail
        let result = holder.reload().await;
        assert!(result.is_err());

        // Original config should be preserved
        let current = holder.get().await;
        assert!(current.proxies.is_empty()); // Still minimal config
    }

    #[tokio::test]
    async fn test_config_holder_reload_invalid_config() {
        use std::io::Write;

        let mut config = make_minimal_config();
        config
            .proxies
            .push(make_test_proxy("proxy-1", "http://proxy:8080"));

        // Create temp file with config that has invalid active_proxy reference
        // Note: active_proxy must come BEFORE [[proxies]] in TOML, otherwise
        // it gets parsed as part of the proxies array entry
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        let config_toml = r#"
active_proxy = "nonexistent-proxy"

[[proxies]]
id = "proxy-1"
url = "http://proxy:8080"
weight = 100

[settings]
listen_port = 12345
dns_refresh_secs = 300
ping_interval_secs = 60
ping_timeout_ms = 1500
ipset_name = "rust_proxy_targets"
chain_name = "RUST_PROXY"
include_aws_ip_ranges = true
include_cloudflare_ip_ranges = true
include_google_ip_ranges = true
"#;
        temp_file.write_all(config_toml.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let holder = ConfigHolder::new(config, temp_file.path().to_path_buf());

        // Reload should fail validation
        let result = holder.reload().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("does not match any configured proxy"));
    }

    #[tokio::test]
    async fn test_config_holder_concurrent_access() {
        let config = make_minimal_config();
        let holder = ConfigHolder::new(config, PathBuf::from("/tmp/test.toml"));

        // Spawn multiple concurrent readers
        let mut handles = vec![];
        for _ in 0..10 {
            let h = holder.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    let _ = h.get().await;
                }
            }));
        }

        // All should complete without deadlock
        for handle in handles {
            handle.await.unwrap();
        }
    }
}

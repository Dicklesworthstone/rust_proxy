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
}

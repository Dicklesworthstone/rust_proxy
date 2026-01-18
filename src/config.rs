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

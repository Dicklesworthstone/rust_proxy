use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

use crate::config::state_dir;

/// Health status of a proxy
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Not yet checked
    #[default]
    Unknown,
    /// Passing health checks
    Healthy,
    /// Slow but working
    Degraded,
    /// Failing health checks
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_active: Option<DateTime<Utc>>,
    pub activated_at: Option<DateTime<Utc>>,
    pub ping_avg_ms: Option<f64>,
    pub ping_samples: u64,
    pub last_ping_at: Option<DateTime<Utc>>,
    /// Current health status
    #[serde(default)]
    pub health_status: HealthStatus,
    /// Number of consecutive health check failures
    #[serde(default)]
    pub consecutive_failures: u32,
    /// When the last health check was performed
    #[serde(default)]
    pub last_health_check: Option<DateTime<Utc>>,
    /// When the proxy was last known to be healthy
    #[serde(default)]
    pub last_healthy: Option<DateTime<Utc>>,
    /// Reason for the last health check failure
    #[serde(default)]
    pub last_failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub proxies: HashMap<String, ProxyStats>,
}

impl State {
    pub fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed reading state {}", path.display()))?;
        let state: State = serde_json::from_str(&content)
            .with_context(|| format!("Failed parsing state {}", path.display()))?;
        Ok(state)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed creating state dir {}", parent.display()))?;
        }
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)
            .with_context(|| format!("Failed writing state {}", path.display()))?;
        Ok(())
    }
}

pub fn state_path() -> Result<PathBuf> {
    let dir = state_dir()?;
    Ok(dir.join("state.json"))
}

#[derive(Clone)]
pub struct StateStore {
    inner: Arc<RwLock<State>>,
    path: PathBuf,
}

impl StateStore {
    pub async fn load() -> Result<Self> {
        let path = state_path()?;
        let state = State::load(&path)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(state)),
            path,
        })
    }

    pub async fn record_activated(&self, proxy_id: &str, at: DateTime<Utc>) {
        let mut state = self.inner.write().await;
        let stats = state.proxies.entry(proxy_id.to_string()).or_default();
        stats.activated_at = Some(at);
        stats.last_active = Some(at);
    }

    pub async fn record_traffic(&self, proxy_id: &str, sent: u64, received: u64) {
        let now = Utc::now();
        let mut state = self.inner.write().await;
        let stats = state.proxies.entry(proxy_id.to_string()).or_default();
        stats.bytes_sent = stats.bytes_sent.saturating_add(sent);
        stats.bytes_received = stats.bytes_received.saturating_add(received);
        stats.last_active = Some(now);
    }

    pub async fn record_ping(&self, proxy_id: &str, ms: f64) {
        let now = Utc::now();
        let mut state = self.inner.write().await;
        let stats = state.proxies.entry(proxy_id.to_string()).or_default();
        let next_count = stats.ping_samples.saturating_add(1);
        let next_avg = match stats.ping_avg_ms {
            None => ms,
            Some(avg) => avg + (ms - avg) / next_count as f64,
        };
        stats.ping_avg_ms = Some(next_avg);
        stats.ping_samples = next_count;
        stats.last_ping_at = Some(now);
    }

    /// Record the result of a health check for a proxy
    #[allow(dead_code)]
    pub async fn record_health_check(
        &self,
        proxy_id: &str,
        success: bool,
        latency_ms: Option<f64>,
        failure_reason: Option<String>,
        threshold: u32,
    ) {
        let now = Utc::now();
        let mut state = self.inner.write().await;
        let stats = state.proxies.entry(proxy_id.to_string()).or_default();

        stats.last_health_check = Some(now);

        if success {
            stats.consecutive_failures = 0;
            stats.last_healthy = Some(now);
            stats.last_failure_reason = None;
            stats.health_status = HealthStatus::Healthy;

            // Also record ping if latency was measured
            if let Some(ms) = latency_ms {
                let next_count = stats.ping_samples.saturating_add(1);
                let next_avg = match stats.ping_avg_ms {
                    None => ms,
                    Some(avg) => avg + (ms - avg) / next_count as f64,
                };
                stats.ping_avg_ms = Some(next_avg);
                stats.ping_samples = next_count;
                stats.last_ping_at = Some(now);
            }
        } else {
            stats.consecutive_failures = stats.consecutive_failures.saturating_add(1);
            stats.last_failure_reason = failure_reason;

            if stats.consecutive_failures >= threshold {
                stats.health_status = HealthStatus::Unhealthy;
            }
        }
    }

    /// Get the current health status of a proxy
    #[allow(dead_code)]
    pub async fn get_health_status(&self, proxy_id: &str) -> HealthStatus {
        let state = self.inner.read().await;
        state
            .proxies
            .get(proxy_id)
            .map(|s| s.health_status)
            .unwrap_or(HealthStatus::Unknown)
    }

    /// Get a list of proxy IDs that are currently healthy
    #[allow(dead_code)]
    pub async fn get_healthy_proxies(&self) -> Vec<String> {
        let state = self.inner.read().await;
        state
            .proxies
            .iter()
            .filter(|(_, stats)| stats.health_status == HealthStatus::Healthy)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get all proxy stats for display
    #[allow(dead_code)]
    pub async fn get_all_stats(&self) -> HashMap<String, ProxyStats> {
        let state = self.inner.read().await;
        state.proxies.clone()
    }

    pub async fn flush(&self) -> Result<()> {
        let state = self.inner.read().await;
        state.save(&self.path)
    }

    pub fn start_flush_loop(self: Arc<Self>, interval: Duration) {
        let store = self.clone();
        tokio::spawn(async move {
            let mut next = Instant::now() + interval;
            loop {
                tokio::time::sleep_until(next).await;
                if let Err(err) = store.flush().await {
                    tracing::warn!("State flush failed: {err}");
                }
                next += interval;
            }
        });
    }
}

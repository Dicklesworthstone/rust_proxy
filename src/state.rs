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

/// Runtime state that can change during daemon operation.
/// Separate from Config (user intent) and StateStore (persistent stats).
/// This manages dynamic proxy switching for failover/failback.
#[derive(Debug)]
struct RuntimeStateInner {
    /// Currently effective proxy (may differ from config during failover)
    effective_proxy: Option<String>,
    /// Original active proxy from config (for failback)
    original_proxy: Option<String>,
    /// When current failover state began (None if no active failover)
    failover_at: Option<DateTime<Utc>>,
    /// When last failover/failback occurred (for min interval check)
    last_switch_at: Option<DateTime<Utc>>,
    /// Recovery detection timestamp (for failback delay)
    recovery_detected_at: Option<DateTime<Utc>>,
}

/// Thread-safe runtime state for dynamic proxy management
#[derive(Clone)]
pub struct RuntimeState {
    inner: Arc<RwLock<RuntimeStateInner>>,
}

impl RuntimeState {
    /// Create from the active proxy ID on daemon startup
    pub fn new(active_proxy: Option<String>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(RuntimeStateInner {
                effective_proxy: active_proxy.clone(),
                original_proxy: active_proxy,
                failover_at: None,
                last_switch_at: None,
                recovery_detected_at: None,
            })),
        }
    }

    /// Get currently effective proxy ID (may be failover target)
    pub async fn get_effective_proxy(&self) -> Option<String> {
        let inner = self.inner.read().await;
        inner.effective_proxy.clone()
    }

    /// Get the original proxy ID from config (for failback reference)
    pub async fn get_original_proxy(&self) -> Option<String> {
        let inner = self.inner.read().await;
        inner.original_proxy.clone()
    }

    /// Check if we're currently in a failover state
    pub async fn is_failed_over(&self) -> bool {
        let inner = self.inner.read().await;
        inner.failover_at.is_some()
    }

    /// Get failover timestamp if in failover state
    #[allow(dead_code)] // Will be used by status command
    pub async fn get_failover_at(&self) -> Option<DateTime<Utc>> {
        let inner = self.inner.read().await;
        inner.failover_at
    }

    /// Perform failover to a new proxy
    pub async fn failover_to(&self, new_proxy: &str) {
        let now = Utc::now();
        let mut inner = self.inner.write().await;
        inner.effective_proxy = Some(new_proxy.to_string());
        inner.failover_at = Some(now);
        inner.last_switch_at = Some(now);
        inner.recovery_detected_at = None;

        tracing::info!(
            from = ?inner.original_proxy,
            to = new_proxy,
            "Failover performed"
        );
    }

    /// Perform failback to original proxy
    pub async fn failback(&self) {
        let now = Utc::now();
        let mut inner = self.inner.write().await;
        let original = inner.original_proxy.clone();
        inner.effective_proxy = original.clone();
        inner.failover_at = None;
        inner.last_switch_at = Some(now);
        inner.recovery_detected_at = None;

        tracing::info!(
            to = ?original,
            "Failback performed"
        );
    }

    /// Record that original proxy has recovered (start failback timer)
    pub async fn record_recovery_detected(&self) {
        let mut inner = self.inner.write().await;
        if inner.recovery_detected_at.is_none() {
            inner.recovery_detected_at = Some(Utc::now());
            tracing::debug!(
                proxy = ?inner.original_proxy,
                "Original proxy recovery detected, starting failback timer"
            );
        }
    }

    /// Clear recovery detection (original failed again)
    pub async fn clear_recovery_detected(&self) {
        let mut inner = self.inner.write().await;
        if inner.recovery_detected_at.is_some() {
            inner.recovery_detected_at = None;
            tracing::debug!(
                proxy = ?inner.original_proxy,
                "Original proxy recovery cleared (failed again)"
            );
        }
    }

    /// Check if enough time has passed for failback
    pub async fn failback_delay_passed(&self, delay_secs: u64) -> bool {
        let inner = self.inner.read().await;
        inner
            .recovery_detected_at
            .map(|t| Utc::now().signed_duration_since(t).num_seconds() >= delay_secs as i64)
            .unwrap_or(false)
    }

    /// Check if enough time has passed since last switch (flapping prevention)
    #[allow(dead_code)] // Will be used for flapping prevention
    pub async fn can_switch(&self, min_interval_secs: u64) -> bool {
        let inner = self.inner.read().await;
        inner
            .last_switch_at
            .map(|t| Utc::now().signed_duration_since(t).num_seconds() >= min_interval_secs as i64)
            .unwrap_or(true)
    }

    /// Get a snapshot of runtime state for status display
    #[allow(dead_code)] // Will be used by status command
    pub async fn get_status_snapshot(&self) -> RuntimeStateSnapshot {
        let inner = self.inner.read().await;
        RuntimeStateSnapshot {
            effective_proxy: inner.effective_proxy.clone(),
            original_proxy: inner.original_proxy.clone(),
            is_failed_over: inner.failover_at.is_some(),
            failover_at: inner.failover_at,
            last_switch_at: inner.last_switch_at,
        }
    }
}

/// Snapshot of runtime state for display purposes
#[derive(Debug, Clone)]
#[allow(dead_code)] // Will be used by status command
pub struct RuntimeStateSnapshot {
    pub effective_proxy: Option<String>,
    pub original_proxy: Option<String>,
    pub is_failed_over: bool,
    pub failover_at: Option<DateTime<Utc>>,
    pub last_switch_at: Option<DateTime<Utc>>,
}

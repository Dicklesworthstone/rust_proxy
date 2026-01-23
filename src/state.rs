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

    /// Create an in-memory StateStore for testing (no file persistence)
    #[cfg(test)]
    pub fn new_for_testing() -> Self {
        Self {
            inner: Arc::new(RwLock::new(State::default())),
            path: PathBuf::from("/tmp/test-state.json"),
        }
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

    /// Get the average latency for a proxy (used by LeastLatency load balancing)
    #[allow(dead_code)]
    pub async fn get_latency(&self, proxy_id: &str) -> Option<f64> {
        let state = self.inner.read().await;
        state.proxies.get(proxy_id).and_then(|s| s.ping_avg_ms)
    }

    /// Get the proxy ID that was most recently healthy (used by UseLast degradation policy)
    pub async fn get_last_healthy_proxy(&self) -> Option<String> {
        let state = self.inner.read().await;
        state
            .proxies
            .iter()
            .filter_map(|(id, stats)| stats.last_healthy.map(|ts| (id.clone(), ts)))
            .max_by_key(|(_, ts)| *ts)
            .map(|(id, _)| id)
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
    /// When all proxies first became unhealthy
    all_unhealthy_since: Option<DateTime<Utc>>,
    /// Whether degradation policy is currently active
    degradation_active: bool,
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
                all_unhealthy_since: None,
                degradation_active: false,
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

    /// Update degradation state based on healthy proxy list and delay.
    ///
    /// Returns true if degradation_active changed during this call.
    pub async fn update_degradation_state(
        &self,
        healthy_proxies: &[String],
        delay_secs: u64,
    ) -> bool {
        let mut inner = self.inner.write().await;
        let now = Utc::now();

        if healthy_proxies.is_empty() {
            if inner.all_unhealthy_since.is_none() {
                inner.all_unhealthy_since = Some(now);
                tracing::warn!("All proxies unhealthy, starting degradation delay");
            }

            if let Some(since) = inner.all_unhealthy_since {
                let elapsed = now.signed_duration_since(since).num_seconds();
                if elapsed >= delay_secs as i64 && !inner.degradation_active {
                    inner.degradation_active = true;
                    tracing::warn!(elapsed_secs = elapsed, "Degradation mode activated");
                    return true;
                }
            }
        } else {
            if inner.degradation_active {
                tracing::info!("Degradation mode deactivated, healthy proxy available");
            }
            inner.all_unhealthy_since = None;
            inner.degradation_active = false;
        }

        false
    }

    /// Check if degradation policy is currently active.
    #[allow(dead_code)] // Will be used by status/diagnostics
    pub async fn is_degraded(&self) -> bool {
        let inner = self.inner.read().await;
        inner.degradation_active
    }

    /// Get degradation status for display.
    #[allow(dead_code)] // Will be used by status/diagnostics
    pub async fn get_degradation_status(&self) -> Option<DegradationStatus> {
        let inner = self.inner.read().await;
        inner.all_unhealthy_since.map(|since| DegradationStatus {
            unhealthy_since: since,
            active: inner.degradation_active,
        })
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
            degradation_active: inner.degradation_active,
            all_unhealthy_since: inner.all_unhealthy_since,
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
    pub degradation_active: bool,
    pub all_unhealthy_since: Option<DateTime<Utc>>,
}

/// Degradation status for display/diagnostics.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Will be used by status/diagnostics
pub struct DegradationStatus {
    pub unhealthy_since: DateTime<Utc>,
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // RuntimeState degradation tracking tests

    #[tokio::test]
    async fn test_runtime_state_initial_not_degraded() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));
        assert!(!state.is_degraded().await);
    }

    #[tokio::test]
    async fn test_runtime_state_degradation_delay_debounces() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));
        let delay_secs = 2;

        // All proxies become unhealthy - should not immediately degrade
        let healthy: Vec<String> = vec![];
        let changed = state.update_degradation_state(&healthy, delay_secs).await;
        assert!(!changed); // Not yet degraded
        assert!(!state.is_degraded().await);
    }

    #[tokio::test]
    async fn test_runtime_state_degradation_activates_after_delay() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));
        let delay_secs = 0; // Zero delay means immediate activation

        // With zero delay, degradation should activate immediately
        let healthy: Vec<String> = vec![];
        let _changed = state.update_degradation_state(&healthy, delay_secs).await;
        assert!(state.is_degraded().await);
    }

    #[tokio::test]
    async fn test_runtime_state_recovery_resets_degradation() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));

        // First, trigger degradation with zero delay
        let empty: Vec<String> = vec![];
        state.update_degradation_state(&empty, 0).await;
        assert!(state.is_degraded().await);

        // Now a proxy becomes healthy - should reset
        let healthy = vec!["proxy-a".to_string()];
        state.update_degradation_state(&healthy, 0).await;
        assert!(!state.is_degraded().await);
    }

    #[tokio::test]
    async fn test_runtime_state_degradation_status_tracking() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));

        // Initially no degradation status
        assert!(state.get_degradation_status().await.is_none());

        // After all unhealthy, should have status
        let empty: Vec<String> = vec![];
        state.update_degradation_state(&empty, 5).await;
        let status = state.get_degradation_status().await;
        assert!(status.is_some());
        let status = status.unwrap();
        assert!(!status.active); // Not yet active (delay not elapsed)
    }

    #[tokio::test]
    async fn test_runtime_state_failover_tracking() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));

        // Initially not failed over
        assert!(!state.is_failed_over().await);
        assert_eq!(
            state.get_effective_proxy().await,
            Some("proxy-a".to_string())
        );

        // Perform failover
        state.failover_to("proxy-b").await;
        assert!(state.is_failed_over().await);
        assert_eq!(
            state.get_effective_proxy().await,
            Some("proxy-b".to_string())
        );
        assert_eq!(
            state.get_original_proxy().await,
            Some("proxy-a".to_string())
        );

        // Perform failback
        state.failback().await;
        assert!(!state.is_failed_over().await);
        assert_eq!(
            state.get_effective_proxy().await,
            Some("proxy-a".to_string())
        );
    }

    #[tokio::test]
    async fn test_runtime_state_failback_delay() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));

        // Initially failback delay has not passed (no recovery detected)
        assert!(!state.failback_delay_passed(5).await);

        // Record recovery
        state.record_recovery_detected().await;

        // With 0 delay, should pass immediately
        assert!(state.failback_delay_passed(0).await);
    }

    #[tokio::test]
    async fn test_runtime_state_recovery_detection_cleared() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));

        // Record recovery
        state.record_recovery_detected().await;
        assert!(state.failback_delay_passed(0).await);

        // Clear recovery (proxy failed again)
        state.clear_recovery_detected().await;
        assert!(!state.failback_delay_passed(0).await);
    }

    #[tokio::test]
    async fn test_runtime_state_snapshot() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));

        // Get initial snapshot
        let snapshot = state.get_status_snapshot().await;
        assert_eq!(snapshot.effective_proxy, Some("proxy-a".to_string()));
        assert_eq!(snapshot.original_proxy, Some("proxy-a".to_string()));
        assert!(!snapshot.is_failed_over);
        assert!(!snapshot.degradation_active);
        assert!(snapshot.all_unhealthy_since.is_none());
    }

    // StateStore tests

    #[tokio::test]
    async fn test_state_store_last_healthy_proxy() {
        let store = StateStore::new_for_testing();

        // Initially no last healthy proxy
        assert!(store.get_last_healthy_proxy().await.is_none());

        // Record a health check success
        store
            .record_health_check("proxy-a", true, Some(50.0), None, 3)
            .await;

        // Now should have last healthy proxy
        assert_eq!(
            store.get_last_healthy_proxy().await,
            Some("proxy-a".to_string())
        );
    }

    #[tokio::test]
    async fn test_state_store_health_status_tracking() {
        let store = StateStore::new_for_testing();

        // Initially unknown status
        assert_eq!(
            store.get_health_status("proxy-a").await,
            HealthStatus::Unknown
        );

        // Record success - should become healthy
        store
            .record_health_check("proxy-a", true, Some(50.0), None, 3)
            .await;
        assert_eq!(
            store.get_health_status("proxy-a").await,
            HealthStatus::Healthy
        );

        // Record failures - after threshold should become unhealthy
        for _ in 0..3 {
            store
                .record_health_check("proxy-a", false, None, Some("timeout".to_string()), 3)
                .await;
        }
        assert_eq!(
            store.get_health_status("proxy-a").await,
            HealthStatus::Unhealthy
        );
    }

    #[tokio::test]
    async fn test_state_store_healthy_proxies_list() {
        let store = StateStore::new_for_testing();

        // No healthy proxies initially
        assert!(store.get_healthy_proxies().await.is_empty());

        // Add some healthy proxies
        store
            .record_health_check("proxy-a", true, Some(50.0), None, 3)
            .await;
        store
            .record_health_check("proxy-b", true, Some(60.0), None, 3)
            .await;

        let healthy = store.get_healthy_proxies().await;
        assert_eq!(healthy.len(), 2);
        assert!(healthy.contains(&"proxy-a".to_string()));
        assert!(healthy.contains(&"proxy-b".to_string()));
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(format!("{}", HealthStatus::Unknown), "unknown");
        assert_eq!(format!("{}", HealthStatus::Healthy), "healthy");
        assert_eq!(format!("{}", HealthStatus::Degraded), "degraded");
        assert_eq!(format!("{}", HealthStatus::Unhealthy), "unhealthy");
    }
}

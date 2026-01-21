// Allow dead_code warnings - these are public APIs integrated in bd-51u.
#![allow(dead_code)]

//! Load balancer for distributing requests across proxies.
//!
//! This module implements the core proxy selection logic for all load balancing
//! strategies defined in [`LoadBalanceStrategy`].
//!
//! # Strategies
//!
//! - **Single**: Use highest-priority healthy proxy (traditional failover model)
//! - **RoundRobin**: Cycle through healthy proxies sequentially
//! - **LeastLatency**: Prefer proxy with lowest average latency
//! - **Weighted**: Distribute based on configured proxy weights

use crate::config::{LoadBalanceStrategy, ProxyConfig};
use crate::state::{HealthStatus, StateStore};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;

/// Statistics about proxy selections (ephemeral, resets on daemon restart).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SelectionStats {
    /// Number of times each proxy was selected
    pub selections: HashMap<String, u64>,
    /// Total number of selections across all proxies
    pub total: u64,
}

impl SelectionStats {
    /// Calculate selection percentage for a proxy
    pub fn percentage(&self, proxy_id: &str) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let count = self.selections.get(proxy_id).copied().unwrap_or(0);
        (count as f64 / self.total as f64) * 100.0
    }
}

/// Load balancer for selecting proxies based on configured strategy.
///
/// Thread-safe and designed for concurrent access from the proxy handler.
pub struct LoadBalancer {
    /// Counter for round-robin rotation
    round_robin_counter: AtomicUsize,
    /// Random number generator seed for weighted selection
    weighted_counter: AtomicUsize,
    /// Selection counts per proxy (ephemeral stats)
    selection_counts: RwLock<HashMap<String, AtomicU64>>,
    /// Total selection count
    total_selections: AtomicU64,
}

impl LoadBalancer {
    /// Create a new load balancer.
    pub fn new() -> Self {
        Self {
            round_robin_counter: AtomicUsize::new(0),
            weighted_counter: AtomicUsize::new(0),
            selection_counts: RwLock::new(HashMap::new()),
            total_selections: AtomicU64::new(0),
        }
    }

    /// Record that a proxy was selected.
    fn record_selection(&self, proxy_id: &str) {
        self.total_selections.fetch_add(1, Ordering::Relaxed);

        // Try to increment existing counter first (read lock)
        {
            let counts = self.selection_counts.read().unwrap();
            if let Some(counter) = counts.get(proxy_id) {
                counter.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        // Need to insert new entry (write lock)
        let mut counts = self.selection_counts.write().unwrap();
        // Double-check after acquiring write lock
        if let Some(counter) = counts.get(proxy_id) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            counts.insert(proxy_id.to_string(), AtomicU64::new(1));
        }
    }

    /// Get current selection statistics.
    pub fn get_stats(&self) -> SelectionStats {
        let counts = self.selection_counts.read().unwrap();
        let selections: HashMap<String, u64> = counts
            .iter()
            .map(|(id, counter)| (id.clone(), counter.load(Ordering::Relaxed)))
            .collect();
        SelectionStats {
            selections,
            total: self.total_selections.load(Ordering::Relaxed),
        }
    }

    /// Select a proxy based on the configured strategy.
    ///
    /// Returns the ID of the selected proxy, or None if no healthy proxies
    /// are available (which should trigger the degradation policy).
    ///
    /// # Arguments
    ///
    /// * `strategy` - The load balancing strategy to use
    /// * `proxies` - List of configured proxies
    /// * `state` - State store for health status and latency data
    ///
    /// # Example
    ///
    /// ```ignore
    /// let balancer = LoadBalancer::new();
    /// let proxy_id = balancer.select_proxy(
    ///     LoadBalanceStrategy::RoundRobin,
    ///     &config.proxies,
    ///     &state,
    /// ).await;
    /// ```
    pub async fn select_proxy(
        &self,
        strategy: LoadBalanceStrategy,
        proxies: &[ProxyConfig],
        state: &StateStore,
    ) -> Option<String> {
        // Collect healthy proxies with their data
        let mut healthy = Vec::with_capacity(proxies.len());
        for proxy in proxies {
            let status = state.get_health_status(&proxy.id).await;
            if status == HealthStatus::Healthy || status == HealthStatus::Unknown {
                healthy.push(proxy);
            }
        }

        if healthy.is_empty() {
            tracing::debug!("No healthy proxies available for load balancing");
            return None;
        }

        let selected = match strategy {
            LoadBalanceStrategy::Single => self.select_single(&healthy),
            LoadBalanceStrategy::RoundRobin => self.select_round_robin(&healthy),
            LoadBalanceStrategy::LeastLatency => self.select_least_latency(&healthy, state).await,
            LoadBalanceStrategy::Weighted => self.select_weighted(&healthy),
        };

        // Record the selection for statistics
        if let Some(ref proxy_id) = selected {
            self.record_selection(proxy_id);
        }

        selected
    }

    /// Select the highest-priority healthy proxy (Single strategy).
    ///
    /// Lower priority number = higher priority. Proxies without explicit
    /// priority default to 100.
    fn select_single(&self, healthy: &[&ProxyConfig]) -> Option<String> {
        healthy
            .iter()
            .min_by_key(|p| p.priority.unwrap_or(100))
            .map(|p| p.id.clone())
    }

    /// Select using round-robin rotation (RoundRobin strategy).
    ///
    /// Cycles through healthy proxies fairly, ensuring even distribution
    /// over time.
    fn select_round_robin(&self, healthy: &[&ProxyConfig]) -> Option<String> {
        if healthy.is_empty() {
            return None;
        }

        let idx = self.round_robin_counter.fetch_add(1, Ordering::Relaxed);
        let proxy = healthy.get(idx % healthy.len())?;
        Some(proxy.id.clone())
    }

    /// Select proxy with lowest latency (LeastLatency strategy).
    ///
    /// Uses average ping latency from health checks. Proxies without
    /// latency data are treated as having maximum latency.
    async fn select_least_latency(
        &self,
        healthy: &[&ProxyConfig],
        state: &StateStore,
    ) -> Option<String> {
        if healthy.is_empty() {
            return None;
        }

        let mut best_proxy: Option<&ProxyConfig> = None;
        let mut best_latency = f64::MAX;

        for proxy in healthy {
            let latency = state.get_latency(&proxy.id).await.unwrap_or(f64::MAX);
            if latency < best_latency {
                best_latency = latency;
                best_proxy = Some(proxy);
            }
        }

        best_proxy.map(|p| p.id.clone())
    }

    /// Select using weighted distribution (Weighted strategy).
    ///
    /// Distributes requests proportionally to proxy weights.
    /// Uses a simple deterministic rotation to approximate weighted distribution
    /// without requiring a random number generator.
    fn select_weighted(&self, healthy: &[&ProxyConfig]) -> Option<String> {
        if healthy.is_empty() {
            return None;
        }

        // Filter out zero-weight proxies
        let weighted: Vec<_> = healthy.iter().filter(|p| p.weight > 0).collect();
        if weighted.is_empty() {
            // All weights are zero, fall back to first proxy
            return healthy.first().map(|p| p.id.clone());
        }

        // Calculate total weight
        let total_weight: u32 = weighted.iter().map(|p| p.weight).sum();

        // Use atomic counter to deterministically rotate through weights
        let counter = self.weighted_counter.fetch_add(1, Ordering::Relaxed);
        let target = (counter as u32) % total_weight;

        // Find the proxy at this weight position
        let mut cumulative: u32 = 0;
        for proxy in &weighted {
            cumulative += proxy.weight;
            if target < cumulative {
                return Some(proxy.id.clone());
            }
        }

        // Fallback (shouldn't happen)
        weighted.last().map(|p| p.id.clone())
    }

    /// Reset the round-robin counter.
    ///
    /// Useful when proxy list changes significantly.
    #[allow(dead_code)]
    pub fn reset_round_robin(&self) {
        self.round_robin_counter.store(0, Ordering::Relaxed);
    }
}

impl Default for LoadBalancer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyAuth;

    fn make_proxy(id: &str, priority: Option<u32>, weight: u32) -> ProxyConfig {
        ProxyConfig {
            id: id.to_string(),
            url: format!("http://{}:8080", id),
            auth: ProxyAuth::default(),
            priority,
            health_check_url: None,
            weight,
        }
    }

    #[test]
    fn test_select_single_by_priority() {
        let balancer = LoadBalancer::new();

        let proxies = vec![
            make_proxy("low-priority", Some(100), 100),
            make_proxy("high-priority", Some(1), 100),
            make_proxy("medium-priority", Some(50), 100),
        ];
        let refs: Vec<_> = proxies.iter().collect();

        let selected = balancer.select_single(&refs);
        assert_eq!(selected, Some("high-priority".to_string()));
    }

    #[test]
    fn test_select_single_default_priority() {
        let balancer = LoadBalancer::new();

        let proxies = vec![
            make_proxy("no-priority", None, 100),
            make_proxy("explicit-priority", Some(50), 100),
        ];
        let refs: Vec<_> = proxies.iter().collect();

        let selected = balancer.select_single(&refs);
        assert_eq!(selected, Some("explicit-priority".to_string()));
    }

    #[test]
    fn test_round_robin_cycles() {
        let balancer = LoadBalancer::new();

        let proxies = vec![
            make_proxy("a", None, 100),
            make_proxy("b", None, 100),
            make_proxy("c", None, 100),
        ];
        let refs: Vec<_> = proxies.iter().collect();

        // Should cycle through a, b, c, a, b, c, ...
        assert_eq!(balancer.select_round_robin(&refs), Some("a".to_string()));
        assert_eq!(balancer.select_round_robin(&refs), Some("b".to_string()));
        assert_eq!(balancer.select_round_robin(&refs), Some("c".to_string()));
        assert_eq!(balancer.select_round_robin(&refs), Some("a".to_string()));
    }

    #[test]
    fn test_weighted_distribution() {
        let balancer = LoadBalancer::new();

        // Proxy A has weight 3, proxy B has weight 1
        // Total weight = 4
        // Over 4 selections, A should be selected ~3 times, B ~1 time
        let proxies = vec![make_proxy("a", None, 3), make_proxy("b", None, 1)];
        let refs: Vec<_> = proxies.iter().collect();

        let mut a_count = 0;
        let mut b_count = 0;
        for _ in 0..4 {
            let selected = balancer.select_weighted(&refs);
            match selected.as_deref() {
                Some("a") => a_count += 1,
                Some("b") => b_count += 1,
                _ => panic!("Unexpected selection"),
            }
        }

        assert_eq!(a_count, 3);
        assert_eq!(b_count, 1);
    }

    #[test]
    fn test_weighted_zero_weight_skipped() {
        let balancer = LoadBalancer::new();

        let proxies = vec![
            make_proxy("zero", None, 0),
            make_proxy("nonzero", None, 100),
        ];
        let refs: Vec<_> = proxies.iter().collect();

        // Zero-weight proxy should never be selected
        for _ in 0..10 {
            let selected = balancer.select_weighted(&refs);
            assert_eq!(selected, Some("nonzero".to_string()));
        }
    }

    #[test]
    fn test_weighted_all_zero_fallback() {
        let balancer = LoadBalancer::new();

        let proxies = vec![make_proxy("zero1", None, 0), make_proxy("zero2", None, 0)];
        let refs: Vec<_> = proxies.iter().collect();

        // Should fall back to first proxy when all weights are zero
        let selected = balancer.select_weighted(&refs);
        assert_eq!(selected, Some("zero1".to_string()));
    }

    #[test]
    fn test_empty_proxies() {
        let balancer = LoadBalancer::new();
        let refs: Vec<&ProxyConfig> = vec![];

        assert_eq!(balancer.select_single(&refs), None);
        assert_eq!(balancer.select_round_robin(&refs), None);
        assert_eq!(balancer.select_weighted(&refs), None);
    }

    #[test]
    fn test_selection_stats_tracking() {
        let balancer = LoadBalancer::new();

        // Initial stats should be empty
        let stats = balancer.get_stats();
        assert_eq!(stats.total, 0);
        assert!(stats.selections.is_empty());

        // Record some selections
        balancer.record_selection("proxy-a");
        balancer.record_selection("proxy-a");
        balancer.record_selection("proxy-b");

        let stats = balancer.get_stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.selections.get("proxy-a"), Some(&2));
        assert_eq!(stats.selections.get("proxy-b"), Some(&1));

        // Check percentages
        assert!((stats.percentage("proxy-a") - 66.67).abs() < 0.1);
        assert!((stats.percentage("proxy-b") - 33.33).abs() < 0.1);
        assert_eq!(stats.percentage("proxy-c"), 0.0); // Non-existent
    }

    #[test]
    fn test_selection_stats_percentage_zero_total() {
        let stats = SelectionStats {
            selections: HashMap::new(),
            total: 0,
        };

        // Should return 0.0 when total is 0, not panic
        assert_eq!(stats.percentage("any"), 0.0);
    }
}

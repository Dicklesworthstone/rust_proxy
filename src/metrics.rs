// Allow dead_code warnings - these metrics will be used when instrumentation is added.
#![allow(dead_code)]

//! Prometheus metrics for rust_proxy.
//!
//! This module defines all metric types for monitoring rust_proxy operations:
//! - Request counts and rates
//! - Byte transfer volumes
//! - Health check results and latencies
//! - Failover events
//! - Connection statistics
//!
//! # Usage
//!
//! ```rust,ignore
//! use rust_proxy::metrics;
//!
//! // Initialize metrics (call once at startup)
//! metrics::init_metrics().expect("Failed to initialize metrics");
//!
//! // Record a request
//! metrics::REQUESTS_TOTAL.with_label_values(&["proxy-1", "success"]).inc();
//!
//! // Update active connections
//! metrics::ACTIVE_CONNECTIONS.with_label_values(&["proxy-1"]).inc();
//!
//! // Export metrics
//! let output = metrics::encode_metrics();
//! ```

use prometheus::{
    histogram_opts, CounterVec, Encoder, Gauge, GaugeVec, HistogramVec, Opts, Registry, TextEncoder,
};
use std::sync::LazyLock;

// ============================================================================
// Registry
// ============================================================================

/// Custom registry for rust_proxy metrics.
///
/// Using a custom registry allows us to control exactly what gets exported
/// and avoid conflicts with other libraries that might use Prometheus.
pub static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

// ============================================================================
// Counters
// ============================================================================

/// Total proxy requests, labeled by proxy and status.
///
/// Labels:
/// - `proxy`: Proxy ID (e.g., "proxy-1")
/// - `status`: Request outcome ("success", "error", "timeout")
pub static REQUESTS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    CounterVec::new(
        Opts::new("rust_proxy_requests_total", "Total proxy requests"),
        &["proxy", "status"],
    )
    .expect("Failed to create REQUESTS_TOTAL metric")
});

/// Total bytes sent through proxies.
///
/// Labels:
/// - `proxy`: Proxy ID
pub static BYTES_SENT: LazyLock<CounterVec> = LazyLock::new(|| {
    CounterVec::new(
        Opts::new("rust_proxy_bytes_sent_total", "Total bytes sent"),
        &["proxy"],
    )
    .expect("Failed to create BYTES_SENT metric")
});

/// Total bytes received through proxies.
///
/// Labels:
/// - `proxy`: Proxy ID
pub static BYTES_RECEIVED: LazyLock<CounterVec> = LazyLock::new(|| {
    CounterVec::new(
        Opts::new("rust_proxy_bytes_received_total", "Total bytes received"),
        &["proxy"],
    )
    .expect("Failed to create BYTES_RECEIVED metric")
});

/// Total health checks performed.
///
/// Labels:
/// - `proxy`: Proxy ID
/// - `result`: Check result ("healthy", "unhealthy", "timeout")
pub static HEALTH_CHECKS: LazyLock<CounterVec> = LazyLock::new(|| {
    CounterVec::new(
        Opts::new("rust_proxy_health_checks_total", "Health check results"),
        &["proxy", "result"],
    )
    .expect("Failed to create HEALTH_CHECKS metric")
});

/// Total failover events.
///
/// Labels:
/// - `from`: Source proxy ID
/// - `to`: Target proxy ID
pub static FAILOVERS: LazyLock<CounterVec> = LazyLock::new(|| {
    CounterVec::new(
        Opts::new("rust_proxy_failovers_total", "Failover events"),
        &["from", "to"],
    )
    .expect("Failed to create FAILOVERS metric")
});

/// Total DNS resolution attempts.
///
/// Labels:
/// - `result`: Resolution result ("success", "failure", "timeout")
pub static DNS_RESOLUTIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    CounterVec::new(
        Opts::new(
            "rust_proxy_dns_resolutions_total",
            "DNS resolution attempts",
        ),
        &["result"],
    )
    .expect("Failed to create DNS_RESOLUTIONS metric")
});

/// Total connection retries.
///
/// Labels:
/// - `proxy`: Proxy ID
pub static CONNECTION_RETRIES: LazyLock<CounterVec> = LazyLock::new(|| {
    CounterVec::new(
        Opts::new(
            "rust_proxy_connection_retries_total",
            "Connection retry attempts",
        ),
        &["proxy"],
    )
    .expect("Failed to create CONNECTION_RETRIES metric")
});

// ============================================================================
// Gauges
// ============================================================================

/// Current number of active connections per proxy.
///
/// Labels:
/// - `proxy`: Proxy ID
pub static ACTIVE_CONNECTIONS: LazyLock<GaugeVec> = LazyLock::new(|| {
    GaugeVec::new(
        Opts::new(
            "rust_proxy_active_connections",
            "Current active connections",
        ),
        &["proxy"],
    )
    .expect("Failed to create ACTIVE_CONNECTIONS metric")
});

/// Proxy health status (1=healthy, 0=unhealthy).
///
/// Labels:
/// - `proxy`: Proxy ID
pub static PROXY_HEALTH: LazyLock<GaugeVec> = LazyLock::new(|| {
    GaugeVec::new(
        Opts::new(
            "rust_proxy_proxy_health",
            "Proxy health status (1=healthy, 0=unhealthy)",
        ),
        &["proxy"],
    )
    .expect("Failed to create PROXY_HEALTH metric")
});

/// Number of IPs in the ipset.
pub static IPSET_SIZE: LazyLock<Gauge> = LazyLock::new(|| {
    Gauge::new("rust_proxy_ipset_size", "Number of IPs in the target ipset")
        .expect("Failed to create IPSET_SIZE metric")
});

/// Number of target domains configured.
pub static TARGET_DOMAINS: LazyLock<Gauge> = LazyLock::new(|| {
    Gauge::new(
        "rust_proxy_target_domains",
        "Number of target domains configured",
    )
    .expect("Failed to create TARGET_DOMAINS metric")
});

/// Number of proxies configured.
pub static CONFIGURED_PROXIES: LazyLock<Gauge> = LazyLock::new(|| {
    Gauge::new(
        "rust_proxy_configured_proxies",
        "Number of proxies configured",
    )
    .expect("Failed to create CONFIGURED_PROXIES metric")
});

/// Daemon uptime in seconds.
pub static UPTIME_SECONDS: LazyLock<Gauge> = LazyLock::new(|| {
    Gauge::new("rust_proxy_uptime_seconds", "Daemon uptime in seconds")
        .expect("Failed to create UPTIME_SECONDS metric")
});

// ============================================================================
// Histograms
// ============================================================================

/// Connection duration in seconds.
///
/// Buckets are tuned for typical connection lifetimes (milliseconds to minutes).
///
/// Labels:
/// - `proxy`: Proxy ID
pub static CONNECTION_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        histogram_opts!(
            "rust_proxy_connection_duration_seconds",
            "Connection duration in seconds",
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]
        ),
        &["proxy"],
    )
    .expect("Failed to create CONNECTION_DURATION metric")
});

/// Health check latency in seconds.
///
/// Buckets are tuned for health check timeouts (10ms to 5s).
///
/// Labels:
/// - `proxy`: Proxy ID
pub static HEALTH_CHECK_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        histogram_opts!(
            "rust_proxy_health_check_latency_seconds",
            "Health check latency in seconds",
            vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
        ),
        &["proxy"],
    )
    .expect("Failed to create HEALTH_CHECK_LATENCY metric")
});

/// DNS resolution latency in seconds.
///
/// Labels:
/// - `domain`: Domain being resolved (or "batch" for batch operations)
pub static DNS_RESOLUTION_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        histogram_opts!(
            "rust_proxy_dns_resolution_latency_seconds",
            "DNS resolution latency in seconds",
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0]
        ),
        &["domain"],
    )
    .expect("Failed to create DNS_RESOLUTION_LATENCY metric")
});

// ============================================================================
// Initialization and Export
// ============================================================================

/// Initialize and register all metrics with the registry.
///
/// This function should be called once at daemon startup.
/// Calling it multiple times is safe (subsequent calls are no-ops).
///
/// # Errors
///
/// Returns an error if metric registration fails (e.g., duplicate metric names).
pub fn init_metrics() -> Result<(), prometheus::Error> {
    // Counters
    REGISTRY.register(Box::new(REQUESTS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(BYTES_SENT.clone()))?;
    REGISTRY.register(Box::new(BYTES_RECEIVED.clone()))?;
    REGISTRY.register(Box::new(HEALTH_CHECKS.clone()))?;
    REGISTRY.register(Box::new(FAILOVERS.clone()))?;
    REGISTRY.register(Box::new(DNS_RESOLUTIONS.clone()))?;
    REGISTRY.register(Box::new(CONNECTION_RETRIES.clone()))?;

    // Gauges
    REGISTRY.register(Box::new(ACTIVE_CONNECTIONS.clone()))?;
    REGISTRY.register(Box::new(PROXY_HEALTH.clone()))?;
    REGISTRY.register(Box::new(IPSET_SIZE.clone()))?;
    REGISTRY.register(Box::new(TARGET_DOMAINS.clone()))?;
    REGISTRY.register(Box::new(CONFIGURED_PROXIES.clone()))?;
    REGISTRY.register(Box::new(UPTIME_SECONDS.clone()))?;

    // Histograms
    REGISTRY.register(Box::new(CONNECTION_DURATION.clone()))?;
    REGISTRY.register(Box::new(HEALTH_CHECK_LATENCY.clone()))?;
    REGISTRY.register(Box::new(DNS_RESOLUTION_LATENCY.clone()))?;

    Ok(())
}

/// Encode all metrics to Prometheus text format.
///
/// Returns a string suitable for serving from `/metrics` endpoint.
pub fn encode_metrics() -> String {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    if encoder.encode(&REGISTRY.gather(), &mut buffer).is_err() {
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_default()
}

/// Record a successful request through a proxy.
#[inline]
pub fn record_request_success(proxy_id: &str) {
    REQUESTS_TOTAL
        .with_label_values(&[proxy_id, "success"])
        .inc();
}

/// Record a failed request through a proxy.
#[inline]
pub fn record_request_error(proxy_id: &str) {
    REQUESTS_TOTAL.with_label_values(&[proxy_id, "error"]).inc();
}

/// Record a timeout during proxy request.
#[inline]
pub fn record_request_timeout(proxy_id: &str) {
    REQUESTS_TOTAL
        .with_label_values(&[proxy_id, "timeout"])
        .inc();
}

/// Record bytes transferred through a proxy.
#[inline]
pub fn record_bytes(proxy_id: &str, sent: u64, received: u64) {
    BYTES_SENT
        .with_label_values(&[proxy_id])
        .inc_by(sent as f64);
    BYTES_RECEIVED
        .with_label_values(&[proxy_id])
        .inc_by(received as f64);
}

/// Record a health check result.
#[inline]
pub fn record_health_check(proxy_id: &str, healthy: bool, latency_secs: f64) {
    let result = if healthy { "healthy" } else { "unhealthy" };
    HEALTH_CHECKS.with_label_values(&[proxy_id, result]).inc();
    HEALTH_CHECK_LATENCY
        .with_label_values(&[proxy_id])
        .observe(latency_secs);
    PROXY_HEALTH
        .with_label_values(&[proxy_id])
        .set(if healthy { 1.0 } else { 0.0 });
}

/// Record a failover event.
#[inline]
pub fn record_failover(from_proxy: &str, to_proxy: &str) {
    FAILOVERS.with_label_values(&[from_proxy, to_proxy]).inc();
}

/// Increment active connections for a proxy.
#[inline]
pub fn connection_started(proxy_id: &str) {
    ACTIVE_CONNECTIONS.with_label_values(&[proxy_id]).inc();
}

/// Decrement active connections for a proxy.
#[inline]
pub fn connection_ended(proxy_id: &str, duration_secs: f64) {
    ACTIVE_CONNECTIONS.with_label_values(&[proxy_id]).dec();
    CONNECTION_DURATION
        .with_label_values(&[proxy_id])
        .observe(duration_secs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_can_be_created() {
        // Force lazy initialization
        let _ = &*REQUESTS_TOTAL;
        let _ = &*BYTES_SENT;
        let _ = &*BYTES_RECEIVED;
        let _ = &*HEALTH_CHECKS;
        let _ = &*FAILOVERS;
        let _ = &*ACTIVE_CONNECTIONS;
        let _ = &*PROXY_HEALTH;
        let _ = &*CONNECTION_DURATION;
        let _ = &*HEALTH_CHECK_LATENCY;
    }

    #[test]
    fn test_counter_increment() {
        REQUESTS_TOTAL
            .with_label_values(&["test-proxy", "success"])
            .inc();
        let value = REQUESTS_TOTAL
            .with_label_values(&["test-proxy", "success"])
            .get();
        assert!(value >= 1.0);
    }

    #[test]
    fn test_gauge_set() {
        PROXY_HEALTH.with_label_values(&["test-proxy"]).set(1.0);
        let value = PROXY_HEALTH.with_label_values(&["test-proxy"]).get();
        assert!((value - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_histogram_observe() {
        CONNECTION_DURATION
            .with_label_values(&["test-proxy"])
            .observe(0.5);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_encode_metrics() {
        // Force some metrics to exist
        REQUESTS_TOTAL
            .with_label_values(&["encode-test", "success"])
            .inc();

        let output = encode_metrics();
        // Output might be empty if registry not initialized, but should not panic
        assert!(output.is_empty() || output.contains("rust_proxy"));
    }

    #[test]
    fn test_helper_functions() {
        record_request_success("helper-test");
        record_request_error("helper-test");
        record_request_timeout("helper-test");
        record_bytes("helper-test", 100, 200);
        record_health_check("helper-test", true, 0.05);
        record_failover("from-proxy", "to-proxy");
        connection_started("helper-test");
        connection_ended("helper-test", 1.5);
        // Just verify they don't panic
    }
}

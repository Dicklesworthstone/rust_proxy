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
    core::Collector, histogram_opts, CounterVec, Encoder, Gauge, GaugeVec, HistogramVec, Opts,
    Registry, TextEncoder,
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
/// - `status`: Request outcome ("success", "failure")
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

/// Total connections established.
///
/// Labels:
/// - `proxy`: Proxy ID
pub static CONNECTIONS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    CounterVec::new(
        Opts::new(
            "rust_proxy_connections_total",
            "Total connections established",
        ),
        &["proxy"],
    )
    .expect("Failed to create CONNECTIONS_TOTAL metric")
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

/// Which proxy is currently effective (1=active, 0=inactive).
///
/// Labels:
/// - `proxy`: Proxy ID
pub static EFFECTIVE_PROXY: LazyLock<GaugeVec> = LazyLock::new(|| {
    GaugeVec::new(
        Opts::new(
            "rust_proxy_effective_proxy",
            "Which proxy is currently effective (1=active, 0=inactive)",
        ),
        &["proxy"],
    )
    .expect("Failed to create EFFECTIVE_PROXY metric")
});

/// Number of IPs in the ipset.
pub static IPSET_SIZE: LazyLock<Gauge> = LazyLock::new(|| {
    Gauge::new("rust_proxy_ipset_size", "Number of IPs in the target ipset")
        .expect("Failed to create IPSET_SIZE metric")
});

/// Number of target domains configured.
pub static TARGETS_COUNT: LazyLock<Gauge> = LazyLock::new(|| {
    Gauge::new(
        "rust_proxy_targets_count",
        "Number of target domains configured",
    )
    .expect("Failed to create TARGETS_COUNT metric")
});

/// Number of proxies configured.
pub static PROXIES_COUNT: LazyLock<Gauge> = LazyLock::new(|| {
    Gauge::new("rust_proxy_proxies_count", "Number of proxies configured")
        .expect("Failed to create PROXIES_COUNT metric")
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
    register_or_ignore(REQUESTS_TOTAL.clone())?;
    register_or_ignore(BYTES_SENT.clone())?;
    register_or_ignore(BYTES_RECEIVED.clone())?;
    register_or_ignore(HEALTH_CHECKS.clone())?;
    register_or_ignore(FAILOVERS.clone())?;
    register_or_ignore(DNS_RESOLUTIONS.clone())?;
    register_or_ignore(CONNECTION_RETRIES.clone())?;
    register_or_ignore(CONNECTIONS_TOTAL.clone())?;

    // Gauges
    register_or_ignore(ACTIVE_CONNECTIONS.clone())?;
    register_or_ignore(PROXY_HEALTH.clone())?;
    register_or_ignore(EFFECTIVE_PROXY.clone())?;
    register_or_ignore(IPSET_SIZE.clone())?;
    register_or_ignore(TARGETS_COUNT.clone())?;
    register_or_ignore(PROXIES_COUNT.clone())?;
    register_or_ignore(UPTIME_SECONDS.clone())?;

    // Histograms
    register_or_ignore(CONNECTION_DURATION.clone())?;
    register_or_ignore(HEALTH_CHECK_LATENCY.clone())?;
    register_or_ignore(DNS_RESOLUTION_LATENCY.clone())?;

    Ok(())
}

fn register_or_ignore<C>(collector: C) -> Result<(), prometheus::Error>
where
    C: Collector + 'static,
{
    match REGISTRY.register(Box::new(collector)) {
        Ok(()) => Ok(()),
        Err(prometheus::Error::AlreadyReg) => Ok(()),
        Err(err) => Err(err),
    }
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
    REQUESTS_TOTAL
        .with_label_values(&[proxy_id, "failure"])
        .inc();
}

/// Record a timeout during proxy request.
#[inline]
pub fn record_request_timeout(proxy_id: &str) {
    REQUESTS_TOTAL
        .with_label_values(&[proxy_id, "failure"])
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
    CONNECTIONS_TOTAL.with_label_values(&[proxy_id]).inc();
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

/// Set the configured target/proxy counts.
#[inline]
pub fn set_target_proxy_counts(targets: usize, proxies: usize) {
    TARGETS_COUNT.set(targets as f64);
    PROXIES_COUNT.set(proxies as f64);
}

/// Mark the currently effective proxy (1=active, 0=inactive).
pub fn set_effective_proxy<I, S>(proxy_ids: I, effective: Option<&str>)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    for proxy_id in proxy_ids {
        let id = proxy_id.as_ref();
        let value = match effective {
            Some(current) if current == id => 1.0,
            _ => 0.0,
        };
        EFFECTIVE_PROXY.with_label_values(&[id]).set(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::OnceLock;

    static INIT: OnceLock<()> = OnceLock::new();
    static LABEL_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn init_metrics_once() {
        INIT.get_or_init(|| {
            init_metrics().expect("metrics init failed");
        });
    }

    fn unique_label(prefix: &str) -> String {
        let id = LABEL_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{id}")
    }

    #[test]
    fn test_metrics_can_be_created() {
        // Force lazy initialization
        let _ = &*REQUESTS_TOTAL;
        let _ = &*BYTES_SENT;
        let _ = &*BYTES_RECEIVED;
        let _ = &*HEALTH_CHECKS;
        let _ = &*FAILOVERS;
        let _ = &*CONNECTIONS_TOTAL;
        let _ = &*ACTIVE_CONNECTIONS;
        let _ = &*PROXY_HEALTH;
        let _ = &*EFFECTIVE_PROXY;
        let _ = &*TARGETS_COUNT;
        let _ = &*PROXIES_COUNT;
        let _ = &*CONNECTION_DURATION;
        let _ = &*HEALTH_CHECK_LATENCY;
    }

    #[test]
    fn test_init_metrics_idempotent() {
        init_metrics().expect("first init should succeed");
        init_metrics().expect("second init should be idempotent");
    }

    #[test]
    fn test_counter_increment() {
        let proxy_id = unique_label("counter");
        let before = REQUESTS_TOTAL
            .with_label_values(&[proxy_id.as_str(), "success"])
            .get();
        record_request_success(&proxy_id);
        let after = REQUESTS_TOTAL
            .with_label_values(&[proxy_id.as_str(), "success"])
            .get();
        assert!(after >= before + 1.0);
    }

    #[test]
    fn test_gauge_set() {
        let proxy_id = unique_label("gauge");
        PROXY_HEALTH
            .with_label_values(&[proxy_id.as_str()])
            .set(0.0);
        let before = PROXY_HEALTH.with_label_values(&[proxy_id.as_str()]).get();
        PROXY_HEALTH
            .with_label_values(&[proxy_id.as_str()])
            .set(1.0);
        let after = PROXY_HEALTH.with_label_values(&[proxy_id.as_str()]).get();
        assert!((before - 0.0).abs() < f64::EPSILON);
        assert!((after - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_histogram_observe() {
        let proxy_id = unique_label("hist");
        let histogram = CONNECTION_DURATION.with_label_values(&[proxy_id.as_str()]);
        let before = histogram.get_sample_count();
        histogram.observe(0.5);
        let after = histogram.get_sample_count();
        assert!(after > before);
    }

    #[test]
    fn test_encode_metrics() {
        init_metrics_once();
        let proxy_id = unique_label("encode");
        record_request_success(&proxy_id);

        let output = encode_metrics();
        assert!(output.contains("rust_proxy_requests_total"));
    }

    #[test]
    fn test_helper_functions() {
        record_request_success("helper-test");
        record_request_error("helper-test");
        record_request_timeout("helper-test");
        record_bytes("helper-test", 100, 200);
        record_health_check("helper-test", true, 0.05);
        record_failover("from-proxy", "to-proxy");
        set_target_proxy_counts(3, 2);
        set_effective_proxy(["helper-test"], Some("helper-test"));
        connection_started("helper-test");
        connection_ended("helper-test", 1.5);
        // Just verify they don't panic
    }

    #[tokio::test]
    async fn test_concurrent_metric_updates() {
        init_metrics_once();
        let proxy_id = unique_label("concurrent");
        let before = REQUESTS_TOTAL
            .with_label_values(&[proxy_id.as_str(), "success"])
            .get();

        let handles: Vec<_> = (0..25)
            .map(|_| {
                let proxy_id = proxy_id.clone();
                tokio::spawn(async move {
                    record_request_success(&proxy_id);
                })
            })
            .collect();

        for handle in handles {
            handle.await.expect("task join failed");
        }

        let after = REQUESTS_TOTAL
            .with_label_values(&[proxy_id.as_str(), "success"])
            .get();
        assert!(after >= before + 25.0);
    }
}

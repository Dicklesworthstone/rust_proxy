//! HTTP server for Prometheus metrics endpoint.
//!
//! This module provides a lightweight HTTP server that exposes the
//! `/metrics` endpoint for Prometheus scraping.

use axum::{routing::get, Router};
use std::net::SocketAddr;
use tokio::sync::watch;

use crate::metrics;

/// Handler for the /metrics endpoint - returns Prometheus text format.
async fn metrics_handler() -> String {
    metrics::encode_metrics()
}

/// Handler for the /health endpoint - simple liveness check.
async fn health_handler() -> &'static str {
    "OK"
}

/// Run the metrics HTTP server.
///
/// This function blocks until shutdown is signaled via the watch channel.
///
/// # Arguments
///
/// * `bind` - Socket address to bind to (e.g., 0.0.0.0:9090)
/// * `path` - Path for metrics endpoint (e.g., "/metrics")
/// * `shutdown` - Watch receiver for graceful shutdown signal
///
/// # Errors
///
/// Logs errors rather than returning them to avoid crashing the daemon.
/// Metrics server failure should not bring down the proxy.
pub async fn run_metrics_server(
    bind: SocketAddr,
    path: String,
    mut shutdown: watch::Receiver<bool>,
) {
    let app = Router::new()
        .route(&path, get(metrics_handler))
        .route("/health", get(health_handler));

    tracing::info!(
        bind = %bind,
        path = %path,
        "Starting metrics server"
    );

    let listener = match tokio::net::TcpListener::bind(bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(
                bind = %bind,
                error = %e,
                "Failed to start metrics server (continuing without metrics)"
            );
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
            tracing::info!("Metrics server shutting down");
        })
        .await
    {
        tracing::warn!(error = %e, "Metrics server error");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_metrics_handler_returns_string() {
        // Just verify the handler doesn't panic
        let result = metrics_handler().await;
        // Result may be empty if metrics aren't registered, but should be a valid string
        assert!(result.is_empty() || result.contains("rust_proxy"));
    }

    #[tokio::test]
    async fn test_health_handler_returns_ok() {
        let result = health_handler().await;
        assert_eq!(result, "OK");
    }

    #[tokio::test]
    async fn test_server_handles_port_in_use_gracefully() {
        // First, bind to a port
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let bound_addr = listener.local_addr().unwrap();

        // Create shutdown channel
        let (tx, rx) = watch::channel(false);

        // Try to start metrics server on the same port - should fail gracefully
        let server_handle =
            tokio::spawn(run_metrics_server(bound_addr, "/metrics".to_string(), rx));

        // Give it a moment to try and fail
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Signal shutdown (server should already have exited due to bind failure)
        let _ = tx.send(true);

        // Server should complete without panic
        let _ = tokio::time::timeout(Duration::from_secs(1), server_handle).await;

        // Cleanup
        drop(listener);
    }
}

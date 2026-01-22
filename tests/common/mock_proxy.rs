//! Mock proxy server for E2E testing.
//!
//! Provides a configurable mock HTTP proxy that can:
//! - Respond to CONNECT requests
//! - Simulate various failure modes
//! - Log requests for assertions
//! - Support custom response behaviors

use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::sleep;

/// Error types that can be simulated
#[derive(Debug, Clone)]
pub enum MockError {
    /// Connection refused
    ConnectionRefused,
    /// Connection timeout
    Timeout,
    /// Send HTTP 502 Bad Gateway
    BadGateway,
    /// Send HTTP 407 Proxy Authentication Required
    AuthRequired,
    /// Close connection immediately
    ConnectionReset,
    /// Custom HTTP status code
    HttpStatus(u16, String),
}

impl std::fmt::Display for MockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionRefused => write!(f, "connection refused"),
            Self::Timeout => write!(f, "timeout"),
            Self::BadGateway => write!(f, "bad gateway"),
            Self::AuthRequired => write!(f, "auth required"),
            Self::ConnectionReset => write!(f, "connection reset"),
            Self::HttpStatus(code, msg) => write!(f, "HTTP {} {}", code, msg),
        }
    }
}

/// Configurable behavior for mock proxy
#[derive(Debug, Clone)]
pub enum MockBehavior {
    /// Always succeed with configurable latency
    Healthy { latency_ms: u64 },
    /// Always fail with specific error
    Failing { error: MockError },
    /// Succeed N times then fail
    FailAfter { successes: u32, error: MockError },
    /// Random failures at given rate
    Flaky { failure_rate: f64 },
    /// Custom sequence of responses
    Sequence { responses: Vec<MockResponse> },
}

impl Default for MockBehavior {
    fn default() -> Self {
        Self::Healthy { latency_ms: 0 }
    }
}

/// A mock response to return
#[derive(Debug, Clone)]
pub enum MockResponse {
    /// Success (HTTP 200 Connection Established)
    Success { latency_ms: u64 },
    /// Error response
    Error(MockError),
}

/// A request received by the mock proxy
#[derive(Debug, Clone)]
pub struct MockRequest {
    /// Request line (e.g., "CONNECT example.com:443 HTTP/1.1")
    pub request_line: String,
    /// Request headers
    pub headers: Vec<(String, String)>,
    /// Timestamp when request was received
    pub timestamp: std::time::Instant,
    /// Remote address
    pub remote_addr: SocketAddr,
}

/// Mock proxy server
pub struct MockProxy {
    /// Port the mock is listening on
    pub port: u16,
    /// Socket address
    pub addr: SocketAddr,
    /// Unique ID for this mock
    pub id: String,
    /// Configurable behavior
    behavior: Arc<Mutex<MockBehavior>>,
    /// Request log for assertions
    requests: Arc<Mutex<VecDeque<MockRequest>>>,
    /// Success counter for FailAfter behavior
    success_count: Arc<AtomicU32>,
    /// Flag to signal shutdown
    shutdown_flag: Arc<AtomicBool>,
    /// Shutdown sender
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl MockProxy {
    /// Create and start a new mock proxy
    pub async fn new(port: u16, behavior: MockBehavior) -> Result<Self> {
        let bind_addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("Failed to bind mock proxy to {}", bind_addr))?;

        // Get the actual bound address (important when port is 0)
        let addr = listener.local_addr()?;
        let actual_port = addr.port();
        let id = format!("mock-{}", actual_port);
        let behavior = Arc::new(Mutex::new(behavior));
        let requests = Arc::new(Mutex::new(VecDeque::new()));
        let success_count = Arc::new(AtomicU32::new(0));
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        // Start accept loop
        let b = behavior.clone();
        let r = requests.clone();
        let sc = success_count.clone();
        let sf = shutdown_flag.clone();

        tokio::spawn(async move {
            Self::accept_loop(listener, b, r, sc, sf, shutdown_rx).await;
        });

        Ok(Self {
            port: actual_port,
            addr,
            id,
            behavior,
            requests,
            success_count,
            shutdown_flag,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Accept loop for incoming connections
    async fn accept_loop(
        listener: TcpListener,
        behavior: Arc<Mutex<MockBehavior>>,
        requests: Arc<Mutex<VecDeque<MockRequest>>>,
        success_count: Arc<AtomicU32>,
        shutdown_flag: Arc<AtomicBool>,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((socket, addr)) => {
                            let b = behavior.clone();
                            let r = requests.clone();
                            let sc = success_count.clone();
                            let sf = shutdown_flag.clone();
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(socket, addr, b, r, sc, sf).await {
                                    tracing::debug!("Mock proxy connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::debug!("Mock proxy accept error: {}", e);
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::debug!("Mock proxy shutting down");
                    break;
                }
            }
        }
    }

    /// Handle a single connection
    async fn handle_connection(
        mut socket: TcpStream,
        addr: SocketAddr,
        behavior: Arc<Mutex<MockBehavior>>,
        requests: Arc<Mutex<VecDeque<MockRequest>>>,
        success_count: Arc<AtomicU32>,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Result<()> {
        if shutdown_flag.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Read request
        let mut buf = vec![0u8; 4096];
        let n = socket.read(&mut buf).await?;
        let request_str = String::from_utf8_lossy(&buf[..n]);

        // Parse request
        let mut lines = request_str.lines();
        let request_line = lines.next().unwrap_or_default().to_string();
        let mut headers = Vec::new();

        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }

        // Log request
        let request = MockRequest {
            request_line: request_line.clone(),
            headers,
            timestamp: std::time::Instant::now(),
            remote_addr: addr,
        };

        {
            let mut reqs = requests.lock().unwrap();
            reqs.push_back(request);
            // Keep only last 100 requests
            while reqs.len() > 100 {
                reqs.pop_front();
            }
        }

        // Determine response based on behavior
        let response = {
            let behavior = behavior.lock().unwrap();
            Self::determine_response(&behavior, &success_count)
        };

        // Send response
        match response {
            MockResponse::Success { latency_ms } => {
                if latency_ms > 0 {
                    sleep(Duration::from_millis(latency_ms)).await;
                }
                socket
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                success_count.fetch_add(1, Ordering::SeqCst);
            }
            MockResponse::Error(error) => {
                Self::send_error(&mut socket, &error).await?;
            }
        }

        Ok(())
    }

    /// Determine response based on configured behavior
    fn determine_response(behavior: &MockBehavior, success_count: &AtomicU32) -> MockResponse {
        match behavior {
            MockBehavior::Healthy { latency_ms } => MockResponse::Success {
                latency_ms: *latency_ms,
            },
            MockBehavior::Failing { error } => MockResponse::Error(error.clone()),
            MockBehavior::FailAfter { successes, error } => {
                let current = success_count.load(Ordering::SeqCst);
                if current >= *successes {
                    MockResponse::Error(error.clone())
                } else {
                    MockResponse::Success { latency_ms: 0 }
                }
            }
            MockBehavior::Flaky { failure_rate } => {
                if rand_float() < *failure_rate {
                    MockResponse::Error(MockError::ConnectionReset)
                } else {
                    MockResponse::Success { latency_ms: 0 }
                }
            }
            MockBehavior::Sequence { responses } => {
                let idx = success_count.load(Ordering::SeqCst) as usize;
                responses
                    .get(idx)
                    .cloned()
                    .unwrap_or(MockResponse::Success { latency_ms: 0 })
            }
        }
    }

    /// Send an error response
    async fn send_error(socket: &mut TcpStream, error: &MockError) -> Result<()> {
        match error {
            MockError::ConnectionRefused | MockError::ConnectionReset => {
                // Just close the connection
                socket.shutdown().await?;
            }
            MockError::Timeout => {
                // Hang for a while then close
                sleep(Duration::from_secs(30)).await;
                socket.shutdown().await?;
            }
            MockError::BadGateway => {
                socket
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
            }
            MockError::AuthRequired => {
                socket
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=\"Test\"\r\n\r\n",
                    )
                    .await?;
            }
            MockError::HttpStatus(code, message) => {
                let response = format!("HTTP/1.1 {} {}\r\n\r\n", code, message);
                socket.write_all(response.as_bytes()).await?;
            }
        }
        Ok(())
    }

    /// Change the mock's behavior
    pub fn set_behavior(&self, behavior: MockBehavior) {
        let mut b = self.behavior.lock().unwrap();
        *b = behavior;
        // Reset success count
        self.success_count.store(0, Ordering::SeqCst);
    }

    /// Get the request log
    pub fn get_requests(&self) -> Vec<MockRequest> {
        let reqs = self.requests.lock().unwrap();
        reqs.iter().cloned().collect()
    }

    /// Get number of requests received
    pub fn request_count(&self) -> usize {
        let reqs = self.requests.lock().unwrap();
        reqs.len()
    }

    /// Clear the request log
    pub fn clear_requests(&self) {
        let mut reqs = self.requests.lock().unwrap();
        reqs.clear();
    }

    /// Get number of successful responses sent
    pub fn success_count(&self) -> u32 {
        self.success_count.load(Ordering::SeqCst)
    }

    /// Reset success count
    pub fn reset_success_count(&self) {
        self.success_count.store(0, Ordering::SeqCst);
    }

    /// Get the proxy URL for configuration
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Signal shutdown
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
    }
}

impl Drop for MockProxy {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Simple random float generator (no external crate needed)
fn rand_float() -> f64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    (nanos as f64) / (u32::MAX as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_proxy_healthy() {
        let mock = MockProxy::new(0, MockBehavior::Healthy { latency_ms: 0 })
            .await
            .unwrap();

        // Connect and send CONNECT request
        let mut stream = TcpStream::connect(mock.addr).await.unwrap();
        stream
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);

        assert!(response.contains("200"));
        assert_eq!(mock.request_count(), 1);
    }

    #[tokio::test]
    async fn test_mock_proxy_failing() {
        let mock = MockProxy::new(
            0,
            MockBehavior::Failing {
                error: MockError::BadGateway,
            },
        )
        .await
        .unwrap();

        let mut stream = TcpStream::connect(mock.addr).await.unwrap();
        stream
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);

        assert!(response.contains("502"));
    }

    #[tokio::test]
    async fn test_mock_proxy_fail_after() {
        let mock = MockProxy::new(
            0,
            MockBehavior::FailAfter {
                successes: 2,
                error: MockError::BadGateway,
            },
        )
        .await
        .unwrap();

        // First two requests succeed
        for _ in 0..2 {
            let mut stream = TcpStream::connect(mock.addr).await.unwrap();
            stream
                .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            let response = String::from_utf8_lossy(&buf[..n]);
            assert!(response.contains("200"));
        }

        // Third request fails
        let mut stream = TcpStream::connect(mock.addr).await.unwrap();
        stream
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("502"));
    }
}

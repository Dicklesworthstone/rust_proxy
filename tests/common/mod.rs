//! Test harness for rust_proxy E2E tests.
//!
//! Provides infrastructure for:
//! - Creating isolated test environments with temp directories
//! - Starting/stopping the daemon
//! - Running CLI commands
//! - Managing mock proxy servers
//! - Test logging and debugging

pub mod assertions;
pub mod fixtures;
pub mod mock_proxy;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

use crate::common::mock_proxy::MockProxy;

/// Global port allocator to prevent port conflicts between tests
static NEXT_PORT: AtomicU16 = AtomicU16::new(30000);

/// Allocate a unique port for testing
pub fn allocate_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::SeqCst)
}

/// Result of running a CLI command
#[derive(Debug)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub success: bool,
}

#[expect(dead_code)]
impl CommandResult {
    /// Check if stdout contains a string
    pub fn stdout_contains(&self, s: &str) -> bool {
        self.stdout.contains(s)
    }

    /// Check if stderr contains a string
    pub fn stderr_contains(&self, s: &str) -> bool {
        self.stderr.contains(s)
    }

    /// Parse stdout as JSON
    pub fn json(&self) -> Result<serde_json::Value> {
        serde_json::from_str(&self.stdout).context("Failed to parse stdout as JSON")
    }
}

/// Handle to a running daemon process
pub struct DaemonHandle {
    child: Child,
    #[allow(dead_code)]
    pid: u32,
}

impl DaemonHandle {
    /// Check if daemon is still running
    pub fn is_running(&self) -> bool {
        // Check if process exists by trying to get its status
        match Command::new("kill")
            .args(["-0", &self.child.id().to_string()])
            .output()
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    /// Stop the daemon gracefully
    pub fn stop(&mut self) -> Result<()> {
        // Send SIGTERM
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .output();

        // Wait for process to exit with timeout
        let mut attempts = 0;
        while attempts < 50 {
            match self.child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {
                    std::thread::sleep(Duration::from_millis(100));
                    attempts += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }

        // Force kill if still running
        let _ = Command::new("kill")
            .args(["-9", &self.child.id().to_string()])
            .output();
        self.child.wait()?;
        Ok(())
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Test logging verbosity
#[derive(Debug, Clone, Copy, Default)]
#[expect(dead_code)]
pub enum LogVerbosity {
    #[default]
    Normal,
    Verbose,
    Debug,
}

/// Test logger for debugging failures
pub struct TestLogger {
    log_path: PathBuf,
    verbosity: LogVerbosity,
}

#[expect(dead_code)]
impl TestLogger {
    /// Create a new test logger
    pub fn new(log_path: PathBuf, verbosity: LogVerbosity) -> Self {
        Self {
            log_path,
            verbosity,
        }
    }

    /// Log a test phase
    pub fn phase(&self, name: &str) {
        let msg = format!("[PHASE] {}\n", name);
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, msg.as_bytes()));

        if matches!(self.verbosity, LogVerbosity::Verbose | LogVerbosity::Debug) {
            eprintln!("[PHASE] {}", name);
        }
    }

    /// Log a command execution
    pub fn command(&self, cmd: &str, result: &CommandResult) {
        let msg = format!(
            "[CMD] {}\n  exit_code: {}\n  stdout: {}\n  stderr: {}\n",
            cmd, result.exit_code, result.stdout, result.stderr
        );
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, msg.as_bytes()));

        if matches!(self.verbosity, LogVerbosity::Debug) {
            eprintln!("{}", msg);
        }
    }

    /// Log an assertion
    pub fn assertion(&self, name: &str, expected: &str, actual: &str) {
        let msg = format!(
            "[ASSERT] {}\n  expected: {}\n  actual: {}\n",
            name, expected, actual
        );
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, msg.as_bytes()));

        if matches!(self.verbosity, LogVerbosity::Debug) {
            eprintln!("{}", msg);
        }
    }
}

/// Main test harness for E2E tests
pub struct TestHarness {
    /// Temporary directory for test artifacts
    #[allow(dead_code)]
    pub temp_dir: TempDir,
    /// Test configuration file path
    pub config_path: PathBuf,
    /// State directory path
    pub state_dir: PathBuf,
    /// Path to the rust_proxy binary
    #[allow(dead_code)]
    binary_path: PathBuf,
    /// Mock proxy servers
    pub mock_proxies: Vec<MockProxy>,
    /// The daemon process handle
    daemon: Option<DaemonHandle>,
    /// Test logger
    logger: TestLogger,
    /// Listen port for the transparent proxy
    #[allow(dead_code)]
    listen_port: u16,
}

#[expect(dead_code)]
impl TestHarness {
    /// Create a new test harness with default configuration
    pub async fn new() -> Result<Self> {
        let temp_dir = TempDir::new().context("Failed to create temp directory")?;
        let config_path = temp_dir.path().join("config.toml");
        let state_dir = temp_dir.path().join("state");
        let log_path = temp_dir.path().join("test.log");
        let listen_port = allocate_port();

        std::fs::create_dir_all(&state_dir)?;

        // Write default config
        let default_config = fixtures::minimal_config(listen_port);
        std::fs::write(&config_path, &default_config)?;

        // Find the binary - try cargo build first
        let binary_path = Self::find_binary()?;

        let verbosity = if std::env::var("TEST_VERBOSE").is_ok() {
            LogVerbosity::Debug
        } else {
            LogVerbosity::Normal
        };

        Ok(Self {
            temp_dir,
            config_path,
            state_dir,
            binary_path,
            mock_proxies: Vec::new(),
            daemon: None,
            logger: TestLogger::new(log_path, verbosity),
            listen_port,
        })
    }

    /// Create a test harness with custom configuration
    pub async fn with_config(config: &str) -> Result<Self> {
        let harness = Self::new().await?;
        std::fs::write(&harness.config_path, config)?;
        Ok(harness)
    }

    /// Find the rust_proxy binary
    fn find_binary() -> Result<PathBuf> {
        // First try the cargo-provided env var for the test binary location
        // During `cargo test`, binaries are in target/{profile}/deps or target/{profile}
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        // Try release build first
        let release_path = manifest_dir
            .join("target")
            .join("release")
            .join("rust_proxy");
        if release_path.exists() {
            return Ok(release_path);
        }

        // Try debug build
        let debug_path = manifest_dir.join("target").join("debug").join("rust_proxy");
        if debug_path.exists() {
            return Ok(debug_path);
        }

        // Try finding via which command (for installed binary)
        if let Ok(output) = Command::new("which").arg("rust_proxy").output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(PathBuf::from(path));
                }
            }
        }

        // For tests that don't need the actual binary, return a placeholder
        // Tests should check binary_path.exists() before using
        Ok(manifest_dir.join("target").join("debug").join("rust_proxy"))
    }

    /// Get the listen port for this test
    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// Add a mock proxy server and return its details
    pub async fn add_mock_proxy(
        &mut self,
        behavior: mock_proxy::MockBehavior,
    ) -> Result<&MockProxy> {
        let port = allocate_port();
        let mock = MockProxy::new(port, behavior).await?;
        self.mock_proxies.push(mock);
        Ok(self.mock_proxies.last().unwrap())
    }

    /// Run a CLI command and capture output
    pub fn run_command(&self, args: &[&str]) -> CommandResult {
        self.logger.phase(&format!("Running command: {:?}", args));

        let output = Command::new(&self.binary_path)
            .args(args)
            .env("RUST_PROXY_CONFIG", &self.config_path)
            .env("RUST_PROXY_STATE_DIR", &self.state_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        let result = match output {
            Ok(output) => self.output_to_result(output),
            Err(e) => CommandResult {
                stdout: String::new(),
                stderr: e.to_string(),
                exit_code: -1,
                success: false,
            },
        };

        self.logger.command(&format!("{:?}", args), &result);
        result
    }

    /// Run a CLI command that returns JSON
    pub fn run_json_command(&self, args: &[&str]) -> Result<serde_json::Value> {
        let result = self.run_command(args);
        if !result.success {
            anyhow::bail!("Command failed: {}", result.stderr);
        }
        result.json()
    }

    /// Start the daemon (requires root for iptables)
    pub async fn start_daemon(&mut self) -> Result<()> {
        self.logger.phase("Starting daemon");

        // Note: In real tests, this would need sudo
        // For now, we skip iptables operations in test mode
        let child = Command::new(&self.binary_path)
            .args(["daemon"])
            .env("RUST_PROXY_CONFIG", &self.config_path)
            .env("RUST_PROXY_STATE_DIR", &self.state_dir)
            .env("RUST_PROXY_TEST_MODE", "1") // Skip iptables in tests
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start daemon")?;

        let pid = child.id();
        self.daemon = Some(DaemonHandle { child, pid });

        // Give daemon time to initialize
        sleep(Duration::from_millis(500)).await;

        if !self.daemon_is_running() {
            anyhow::bail!("Daemon failed to start");
        }

        Ok(())
    }

    /// Stop the daemon
    pub async fn stop_daemon(&mut self) -> Result<()> {
        self.logger.phase("Stopping daemon");

        if let Some(mut daemon) = self.daemon.take() {
            daemon.stop()?;
        }
        Ok(())
    }

    /// Check if daemon is currently running
    pub fn daemon_is_running(&self) -> bool {
        self.daemon.as_ref().is_some_and(|d| d.is_running())
    }

    /// Convert process output to CommandResult
    fn output_to_result(&self, output: Output) -> CommandResult {
        CommandResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
            success: output.status.success(),
        }
    }

    /// Get the test log contents
    pub fn get_log(&self) -> String {
        std::fs::read_to_string(self.temp_dir.path().join("test.log")).unwrap_or_default()
    }

    /// Clean up test resources
    pub async fn cleanup(mut self) {
        self.logger.phase("Cleanup");

        // Stop daemon if running
        if let Some(mut daemon) = self.daemon.take() {
            let _ = daemon.stop();
        }

        // Stop mock proxies
        for mock in &self.mock_proxies {
            mock.shutdown();
        }

        // TempDir will clean up automatically on drop
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        // Stop daemon if still running
        if let Some(mut daemon) = self.daemon.take() {
            let _ = daemon.stop();
        }

        // Stop mock proxies
        for mock in &self.mock_proxies {
            mock.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_allocation() {
        let port1 = allocate_port();
        let port2 = allocate_port();
        assert_ne!(port1, port2);
        assert!(port1 >= 30000);
        assert!(port2 >= 30000);
    }

    #[tokio::test]
    async fn test_harness_creation() {
        let harness = TestHarness::new().await;
        assert!(harness.is_ok());
        let harness = harness.unwrap();
        assert!(harness.config_path.exists());
        assert!(harness.state_dir.exists());
    }
}

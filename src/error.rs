// Allow dead_code warnings - these are public APIs that will be used in future integration.
// The module provides infrastructure for typed error handling across rust_proxy.
#![allow(dead_code)]

//! Rich error types with context for rust_proxy.
//!
//! This module defines typed errors with embedded context to enable:
//! - Precise error matching and handling
//! - Rich error messages with actionable information
//! - Context preservation across error boundaries
//!
//! # Error Categories
//!
//! - [`ConfigError`] - Configuration loading, parsing, and validation failures
//! - [`ProxyError`] - Proxy connection and communication failures
//! - [`DnsError`] - DNS resolution failures
//! - [`IptablesError`] - iptables/ipset rule management failures
//! - [`StateError`] - Runtime state persistence failures
//!
//! # Example
//!
//! ```rust,ignore
//! use rust_proxy::error::{ConfigError, RustProxyError};
//!
//! fn load_config() -> Result<Config, RustProxyError> {
//!     let path = config_path()?;
//!     let content = std::fs::read_to_string(&path)
//!         .map_err(|e| ConfigError::ReadFailed {
//!             path: path.clone(),
//!             source: e,
//!         })?;
//!     // ...
//! }
//! ```

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Top-level error type for rust_proxy operations.
#[derive(Debug)]
pub enum RustProxyError {
    /// Configuration-related errors
    Config(ConfigError),
    /// Proxy connection and communication errors
    Proxy(ProxyError),
    /// DNS resolution errors
    Dns(DnsError),
    /// iptables/ipset management errors
    Iptables(IptablesError),
    /// Runtime state persistence errors
    State(StateError),
    /// Validation errors
    Validation(ValidationError),
    /// Generic IO errors
    Io(IoError),
}

impl fmt::Display for RustProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "{e}"),
            Self::Proxy(e) => write!(f, "{e}"),
            Self::Dns(e) => write!(f, "{e}"),
            Self::Iptables(e) => write!(f, "{e}"),
            Self::State(e) => write!(f, "{e}"),
            Self::Validation(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RustProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(e) => e.source(),
            Self::Proxy(e) => e.source(),
            Self::Dns(e) => e.source(),
            Self::Iptables(e) => e.source(),
            Self::State(e) => e.source(),
            Self::Validation(e) => e.source(),
            Self::Io(e) => e.source(),
        }
    }
}

// Implement From for each error category
impl From<ConfigError> for RustProxyError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}

impl From<ProxyError> for RustProxyError {
    fn from(e: ProxyError) -> Self {
        Self::Proxy(e)
    }
}

impl From<DnsError> for RustProxyError {
    fn from(e: DnsError) -> Self {
        Self::Dns(e)
    }
}

impl From<IptablesError> for RustProxyError {
    fn from(e: IptablesError) -> Self {
        Self::Iptables(e)
    }
}

impl From<StateError> for RustProxyError {
    fn from(e: StateError) -> Self {
        Self::State(e)
    }
}

impl From<ValidationError> for RustProxyError {
    fn from(e: ValidationError) -> Self {
        Self::Validation(e)
    }
}

impl From<IoError> for RustProxyError {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

// ============================================================================
// Configuration Errors
// ============================================================================

/// Errors related to configuration loading, parsing, and validation.
#[derive(Debug)]
pub enum ConfigError {
    /// Failed to read configuration file
    ReadFailed { path: PathBuf, source: io::Error },
    /// Failed to parse configuration file (TOML syntax error)
    ParseFailed {
        path: PathBuf,
        source: toml::de::Error,
    },
    /// Failed to write configuration file
    WriteFailed { path: PathBuf, source: io::Error },
    /// Failed to create configuration directory
    DirCreationFailed { path: PathBuf, source: io::Error },
    /// Configuration file not found (when required)
    NotFound { path: PathBuf },
    /// Failed to resolve project directories
    ProjectDirsNotFound,
    /// Proxy with given ID not found in configuration
    ProxyNotFound { proxy_id: String },
    /// Proxy with given ID already exists
    ProxyAlreadyExists { proxy_id: String },
    /// Invalid proxy URL format
    InvalidProxyUrl {
        proxy_id: String,
        url: String,
        reason: String,
    },
    /// Target domain not found in configuration
    TargetNotFound { domain: String },
    /// Target domain already exists
    TargetAlreadyExists { domain: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadFailed { path, source } => {
                write!(
                    f,
                    "Failed to read config file '{}': {}",
                    path.display(),
                    source
                )
            }
            Self::ParseFailed { path, source } => {
                write!(
                    f,
                    "Failed to parse config file '{}': {}",
                    path.display(),
                    source
                )
            }
            Self::WriteFailed { path, source } => {
                write!(
                    f,
                    "Failed to write config file '{}': {}",
                    path.display(),
                    source
                )
            }
            Self::DirCreationFailed { path, source } => {
                write!(
                    f,
                    "Failed to create config directory '{}': {}",
                    path.display(),
                    source
                )
            }
            Self::NotFound { path } => {
                write!(f, "Configuration file not found: {}", path.display())
            }
            Self::ProjectDirsNotFound => {
                write!(f, "Failed to resolve project directories")
            }
            Self::ProxyNotFound { proxy_id } => {
                write!(f, "Proxy '{}' not found in configuration", proxy_id)
            }
            Self::ProxyAlreadyExists { proxy_id } => {
                write!(f, "Proxy '{}' already exists in configuration", proxy_id)
            }
            Self::InvalidProxyUrl {
                proxy_id,
                url,
                reason,
            } => {
                write!(
                    f,
                    "Invalid proxy URL for '{}': '{}' - {}",
                    proxy_id, url, reason
                )
            }
            Self::TargetNotFound { domain } => {
                write!(f, "Target domain '{}' not found in configuration", domain)
            }
            Self::TargetAlreadyExists { domain } => {
                write!(
                    f,
                    "Target domain '{}' already exists in configuration",
                    domain
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFailed { source, .. } => Some(source),
            Self::ParseFailed { source, .. } => Some(source),
            Self::WriteFailed { source, .. } => Some(source),
            Self::DirCreationFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

// ============================================================================
// Proxy Connection Errors
// ============================================================================

/// Errors related to proxy connections and communication.
#[derive(Debug)]
pub enum ProxyError {
    /// Failed to connect to proxy server
    ConnectionFailed {
        proxy_id: String,
        address: String,
        source: io::Error,
    },
    /// Connection timed out
    ConnectionTimeout {
        proxy_id: String,
        address: String,
        timeout_ms: u64,
    },
    /// Proxy authentication failed
    AuthenticationFailed { proxy_id: String, address: String },
    /// Proxy returned an error response
    ProxyResponseError {
        proxy_id: String,
        status_code: u16,
        message: String,
    },
    /// Failed to establish tunnel (CONNECT method)
    TunnelFailed {
        proxy_id: String,
        target_host: String,
        target_port: u16,
        reason: String,
    },
    /// No healthy proxies available
    NoHealthyProxies,
    /// All retry attempts exhausted
    RetriesExhausted {
        proxy_id: String,
        attempts: u32,
        last_error: String,
    },
    /// Failed to retrieve original destination (SO_ORIGINAL_DST)
    OriginalDestFailed { source: io::Error },
    /// Failed to parse proxy URL
    InvalidUrl {
        proxy_id: String,
        url: String,
        reason: String,
    },
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionFailed {
                proxy_id,
                address,
                source,
            } => {
                write!(
                    f,
                    "Failed to connect to proxy '{}' at {}: {}",
                    proxy_id, address, source
                )
            }
            Self::ConnectionTimeout {
                proxy_id,
                address,
                timeout_ms,
            } => {
                write!(
                    f,
                    "Connection to proxy '{}' at {} timed out after {}ms",
                    proxy_id, address, timeout_ms
                )
            }
            Self::AuthenticationFailed { proxy_id, address } => {
                write!(
                    f,
                    "Authentication failed for proxy '{}' at {}",
                    proxy_id, address
                )
            }
            Self::ProxyResponseError {
                proxy_id,
                status_code,
                message,
            } => {
                write!(
                    f,
                    "Proxy '{}' returned error {}: {}",
                    proxy_id, status_code, message
                )
            }
            Self::TunnelFailed {
                proxy_id,
                target_host,
                target_port,
                reason,
            } => {
                write!(
                    f,
                    "Failed to establish tunnel through '{}' to {}:{}: {}",
                    proxy_id, target_host, target_port, reason
                )
            }
            Self::NoHealthyProxies => {
                write!(f, "No healthy proxies available")
            }
            Self::RetriesExhausted {
                proxy_id,
                attempts,
                last_error,
            } => {
                write!(
                    f,
                    "All {} retry attempts exhausted for proxy '{}': {}",
                    attempts, proxy_id, last_error
                )
            }
            Self::OriginalDestFailed { source } => {
                write!(f, "Failed to retrieve original destination: {}", source)
            }
            Self::InvalidUrl {
                proxy_id,
                url,
                reason,
            } => {
                write!(
                    f,
                    "Invalid proxy URL for '{}': '{}' - {}",
                    proxy_id, url, reason
                )
            }
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConnectionFailed { source, .. } => Some(source),
            Self::OriginalDestFailed { source } => Some(source),
            _ => None,
        }
    }
}

// ============================================================================
// DNS Resolution Errors
// ============================================================================

/// Errors related to DNS resolution.
#[derive(Debug)]
pub enum DnsError {
    /// DNS lookup failed for domain
    LookupFailed { domain: String, source: io::Error },
    /// DNS lookup timed out
    LookupTimeout { domain: String, timeout_ms: u64 },
    /// Domain does not exist (NXDOMAIN)
    DomainNotFound { domain: String },
    /// Transient DNS failure (SERVFAIL, etc.)
    TransientFailure { domain: String, message: String },
    /// No addresses returned for domain
    NoAddresses { domain: String },
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LookupFailed { domain, source } => {
                write!(f, "DNS lookup failed for '{}': {}", domain, source)
            }
            Self::LookupTimeout { domain, timeout_ms } => {
                write!(
                    f,
                    "DNS lookup for '{}' timed out after {}ms",
                    domain, timeout_ms
                )
            }
            Self::DomainNotFound { domain } => {
                write!(f, "Domain '{}' does not exist (NXDOMAIN)", domain)
            }
            Self::TransientFailure { domain, message } => {
                write!(f, "Transient DNS failure for '{}': {}", domain, message)
            }
            Self::NoAddresses { domain } => {
                write!(f, "DNS lookup for '{}' returned no addresses", domain)
            }
        }
    }
}

impl std::error::Error for DnsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LookupFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

// ============================================================================
// iptables/ipset Errors
// ============================================================================

/// Errors related to iptables and ipset management.
#[derive(Debug)]
pub enum IptablesError {
    /// iptables command failed
    CommandFailed {
        command: String,
        exit_code: i32,
        stderr: String,
    },
    /// ipset command failed
    IpsetFailed {
        command: String,
        exit_code: i32,
        stderr: String,
    },
    /// Operation requires root privileges
    PermissionDenied { operation: String },
    /// iptables binary not found
    BinaryNotFound { binary: String },
    /// Failed to parse iptables output
    ParseError { output: String, reason: String },
    /// Chain already exists
    ChainExists { chain_name: String },
    /// Chain not found
    ChainNotFound { chain_name: String },
    /// ipset already exists
    IpsetExists { set_name: String },
    /// ipset not found
    IpsetNotFound { set_name: String },
}

impl fmt::Display for IptablesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandFailed {
                command,
                exit_code,
                stderr,
            } => {
                write!(
                    f,
                    "iptables command '{}' failed with exit code {}: {}",
                    command, exit_code, stderr
                )
            }
            Self::IpsetFailed {
                command,
                exit_code,
                stderr,
            } => {
                write!(
                    f,
                    "ipset command '{}' failed with exit code {}: {}",
                    command, exit_code, stderr
                )
            }
            Self::PermissionDenied { operation } => {
                write!(
                    f,
                    "Permission denied for '{}' - requires root/sudo",
                    operation
                )
            }
            Self::BinaryNotFound { binary } => {
                write!(f, "Required binary '{}' not found in PATH", binary)
            }
            Self::ParseError { output, reason } => {
                write!(
                    f,
                    "Failed to parse iptables output: {} - {}",
                    reason, output
                )
            }
            Self::ChainExists { chain_name } => {
                write!(f, "iptables chain '{}' already exists", chain_name)
            }
            Self::ChainNotFound { chain_name } => {
                write!(f, "iptables chain '{}' not found", chain_name)
            }
            Self::IpsetExists { set_name } => {
                write!(f, "ipset '{}' already exists", set_name)
            }
            Self::IpsetNotFound { set_name } => {
                write!(f, "ipset '{}' not found", set_name)
            }
        }
    }
}

impl std::error::Error for IptablesError {}

// ============================================================================
// State Persistence Errors
// ============================================================================

/// Errors related to runtime state persistence.
#[derive(Debug)]
pub enum StateError {
    /// Failed to read state file
    ReadFailed { path: PathBuf, source: io::Error },
    /// Failed to parse state file
    ParseFailed {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// Failed to write state file
    WriteFailed { path: PathBuf, source: io::Error },
    /// Failed to create state directory
    DirCreationFailed { path: PathBuf, source: io::Error },
    /// State file corrupted or invalid
    Corrupted { path: PathBuf, reason: String },
    /// Failed to acquire state lock
    LockFailed { path: PathBuf, reason: String },
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadFailed { path, source } => {
                write!(
                    f,
                    "Failed to read state file '{}': {}",
                    path.display(),
                    source
                )
            }
            Self::ParseFailed { path, source } => {
                write!(
                    f,
                    "Failed to parse state file '{}': {}",
                    path.display(),
                    source
                )
            }
            Self::WriteFailed { path, source } => {
                write!(
                    f,
                    "Failed to write state file '{}': {}",
                    path.display(),
                    source
                )
            }
            Self::DirCreationFailed { path, source } => {
                write!(
                    f,
                    "Failed to create state directory '{}': {}",
                    path.display(),
                    source
                )
            }
            Self::Corrupted { path, reason } => {
                write!(
                    f,
                    "State file '{}' is corrupted: {}",
                    path.display(),
                    reason
                )
            }
            Self::LockFailed { path, reason } => {
                write!(
                    f,
                    "Failed to acquire lock on state file '{}': {}",
                    path.display(),
                    reason
                )
            }
        }
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFailed { source, .. } => Some(source),
            Self::ParseFailed { source, .. } => Some(source),
            Self::WriteFailed { source, .. } => Some(source),
            Self::DirCreationFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

// ============================================================================
// Validation Errors
// ============================================================================

/// Errors related to input validation.
#[derive(Debug)]
pub enum ValidationError {
    /// Invalid port number
    InvalidPort { value: String, reason: String },
    /// Invalid IP address
    InvalidIpAddress { value: String, reason: String },
    /// Invalid domain name
    InvalidDomain { value: String, reason: String },
    /// Invalid URL format
    InvalidUrl { value: String, reason: String },
    /// Required field is empty
    EmptyField { field_name: String },
    /// Field value is too long
    TooLong {
        field_name: String,
        max_length: usize,
        actual_length: usize,
    },
    /// Invalid identifier format
    InvalidIdentifier { value: String, reason: String },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPort { value, reason } => {
                write!(f, "Invalid port '{}': {}", value, reason)
            }
            Self::InvalidIpAddress { value, reason } => {
                write!(f, "Invalid IP address '{}': {}", value, reason)
            }
            Self::InvalidDomain { value, reason } => {
                write!(f, "Invalid domain '{}': {}", value, reason)
            }
            Self::InvalidUrl { value, reason } => {
                write!(f, "Invalid URL '{}': {}", value, reason)
            }
            Self::EmptyField { field_name } => {
                write!(f, "Required field '{}' cannot be empty", field_name)
            }
            Self::TooLong {
                field_name,
                max_length,
                actual_length,
            } => {
                write!(
                    f,
                    "Field '{}' exceeds maximum length ({} > {})",
                    field_name, actual_length, max_length
                )
            }
            Self::InvalidIdentifier { value, reason } => {
                write!(f, "Invalid identifier '{}': {}", value, reason)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

// ============================================================================
// Generic IO Errors
// ============================================================================

/// Generic IO errors with context.
#[derive(Debug)]
pub struct IoError {
    pub operation: String,
    pub path: Option<PathBuf>,
    pub source: io::Error,
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(path) => write!(
                f,
                "{} '{}': {}",
                self.operation,
                path.display(),
                self.source
            ),
            None => write!(f, "{}: {}", self.operation, self.source),
        }
    }
}

impl std::error::Error for IoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

// ============================================================================
// Helper Traits for Rich Context
// ============================================================================

/// Extension trait to add context to error types.
pub trait ErrorContext<T> {
    /// Add proxy context to an error.
    fn with_proxy_context(self, proxy_id: &str, address: &str) -> Result<T, ProxyError>;

    /// Add domain context for DNS errors.
    fn with_dns_context(self, domain: &str) -> Result<T, DnsError>;
}

impl<T> ErrorContext<T> for Result<T, io::Error> {
    fn with_proxy_context(self, proxy_id: &str, address: &str) -> Result<T, ProxyError> {
        self.map_err(|e| ProxyError::ConnectionFailed {
            proxy_id: proxy_id.to_string(),
            address: address.to_string(),
            source: e,
        })
    }

    fn with_dns_context(self, domain: &str) -> Result<T, DnsError> {
        self.map_err(|e| DnsError::LookupFailed {
            domain: domain.to_string(),
            source: e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::ProxyNotFound {
            proxy_id: "my-proxy".to_string(),
        };
        assert!(err.to_string().contains("my-proxy"));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_proxy_error_display() {
        let err = ProxyError::ConnectionTimeout {
            proxy_id: "test-proxy".to_string(),
            address: "192.168.1.1:8080".to_string(),
            timeout_ms: 5000,
        };
        assert!(err.to_string().contains("test-proxy"));
        assert!(err.to_string().contains("5000ms"));
    }

    #[test]
    fn test_dns_error_display() {
        let err = DnsError::DomainNotFound {
            domain: "invalid.example".to_string(),
        };
        assert!(err.to_string().contains("invalid.example"));
        assert!(err.to_string().contains("NXDOMAIN"));
    }

    #[test]
    fn test_iptables_error_display() {
        let err = IptablesError::PermissionDenied {
            operation: "create chain".to_string(),
        };
        assert!(err.to_string().contains("Permission denied"));
        assert!(err.to_string().contains("root"));
    }

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::InvalidPort {
            value: "99999".to_string(),
            reason: "must be between 1 and 65535".to_string(),
        };
        assert!(err.to_string().contains("99999"));
        assert!(err.to_string().contains("65535"));
    }

    #[test]
    fn test_rust_proxy_error_from_config() {
        let config_err = ConfigError::ProxyNotFound {
            proxy_id: "test".to_string(),
        };
        let err: RustProxyError = config_err.into();
        assert!(matches!(err, RustProxyError::Config(_)));
    }

    #[test]
    fn test_rust_proxy_error_from_proxy() {
        let proxy_err = ProxyError::NoHealthyProxies;
        let err: RustProxyError = proxy_err.into();
        assert!(matches!(err, RustProxyError::Proxy(_)));
    }

    #[test]
    fn test_error_source_chain() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let config_err = ConfigError::ReadFailed {
            path: PathBuf::from("/test/config.toml"),
            source: io_err,
        };

        // Check that source() returns the underlying io::Error
        let source = std::error::Error::source(&config_err);
        assert!(source.is_some());
    }
}

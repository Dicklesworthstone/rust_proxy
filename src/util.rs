use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;

// =============================================================================
// Shell Detection
// =============================================================================

/// Supported shell types for completion installation.
/// Note: Currently unused as main.rs uses clap_complete::Shell directly.
/// Kept for potential future shell detection/installation features.
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// GNU Bash shell
    Bash,
    /// Z shell
    Zsh,
    /// Fish shell
    Fish,
    /// PowerShell (Windows/cross-platform)
    PowerShell,
    /// Elvish shell
    Elvish,
    /// Unknown or unsupported shell
    Unknown,
}

#[allow(dead_code)]
impl Shell {
    /// Returns the canonical name of the shell.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::PowerShell => "powershell",
            Self::Elvish => "elvish",
            Self::Unknown => "unknown",
        }
    }

    /// Returns a human-readable display name for the shell.
    #[must_use]
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::Bash => "Bash",
            Self::Zsh => "Zsh",
            Self::Fish => "Fish",
            Self::PowerShell => "PowerShell",
            Self::Elvish => "Elvish",
            Self::Unknown => "Unknown",
        }
    }

    /// Returns true if this is a known, supported shell.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// Convert to clap_complete::Shell if supported.
    #[must_use]
    pub fn to_clap_shell(self) -> Option<clap_complete::Shell> {
        match self {
            Self::Bash => Some(clap_complete::Shell::Bash),
            Self::Zsh => Some(clap_complete::Shell::Zsh),
            Self::Fish => Some(clap_complete::Shell::Fish),
            Self::PowerShell => Some(clap_complete::Shell::PowerShell),
            Self::Elvish => Some(clap_complete::Shell::Elvish),
            Self::Unknown => None,
        }
    }

    /// Returns the standard installation path for completions for this shell.
    ///
    /// Respects XDG_DATA_HOME and XDG_CONFIG_HOME environment variables where applicable.
    ///
    /// # Paths by shell
    ///
    /// - **Bash**: `$XDG_DATA_HOME/bash-completion/completions/rust_proxy`
    ///   (defaults to `~/.local/share/bash-completion/completions/rust_proxy`)
    /// - **Zsh**: `~/.zsh/completions/_rust_proxy`
    /// - **Fish**: `$XDG_CONFIG_HOME/fish/completions/rust_proxy.fish`
    ///   (defaults to `~/.config/fish/completions/rust_proxy.fish`)
    /// - **PowerShell**: `~/.config/powershell/completions/rust_proxy.ps1`
    /// - **Elvish**: `~/.config/elvish/lib/rust_proxy.elv`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The home directory cannot be determined
    /// - The shell is `Shell::Unknown`
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rust_proxy::util::Shell;
    ///
    /// let path = Shell::Bash.completion_path()?;
    /// println!("Install bash completions to: {}", path.display());
    /// ```
    pub fn completion_path(self) -> Result<PathBuf> {
        let base_dirs = directories::BaseDirs::new()
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
        let home = base_dirs.home_dir();

        match self {
            Self::Bash => {
                // XDG spec: ~/.local/share/bash-completion/completions/
                let xdg_data = std::env::var("XDG_DATA_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| home.join(".local").join("share"));
                Ok(xdg_data
                    .join("bash-completion")
                    .join("completions")
                    .join("rust_proxy"))
            }
            Self::Zsh => {
                // Standard user completions directory
                // Note: User should ensure ~/.zsh/completions is in fpath
                Ok(home.join(".zsh").join("completions").join("_rust_proxy"))
            }
            Self::Fish => {
                // Fish XDG: ~/.config/fish/completions/
                let xdg_config = std::env::var("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| home.join(".config"));
                Ok(xdg_config
                    .join("fish")
                    .join("completions")
                    .join("rust_proxy.fish"))
            }
            Self::PowerShell => {
                // PowerShell completions in config directory
                let xdg_config = std::env::var("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| home.join(".config"));
                Ok(xdg_config
                    .join("powershell")
                    .join("completions")
                    .join("rust_proxy.ps1"))
            }
            Self::Elvish => {
                // Elvish lib directory for modules
                let xdg_config = std::env::var("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| home.join(".config"));
                Ok(xdg_config.join("elvish").join("lib").join("rust_proxy.elv"))
            }
            Self::Unknown => {
                bail!("Cannot determine completion path for unknown shell")
            }
        }
    }

    /// Returns shell-specific instructions for activating the completions after installation.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rust_proxy::util::Shell;
    ///
    /// let shell = Shell::Zsh;
    /// println!("{}", shell.activation_hint());
    /// // Prints: "Add to ~/.zshrc: fpath=(~/.zsh/completions $fpath); autoload -Uz compinit && compinit"
    /// ```
    #[must_use]
    pub const fn activation_hint(self) -> &'static str {
        match self {
            Self::Bash => "Restart your shell or run: source ~/.bashrc",
            Self::Zsh => "Add to ~/.zshrc: fpath=(~/.zsh/completions $fpath); autoload -Uz compinit && compinit",
            Self::Fish => "Completions are active automatically on next shell start",
            Self::PowerShell => "Add to your PowerShell profile: . ~/.config/powershell/completions/rust_proxy.ps1",
            Self::Elvish => "Add to ~/.config/elvish/rc.elv: use rust_proxy",
            Self::Unknown => "",
        }
    }
}

impl std::fmt::Display for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// =============================================================================
// Completion Script Generation
// =============================================================================

/// Generate shell completion script for the given shell.
///
/// Returns the completion script as a String, which can be written to a file
/// or printed to stdout.
///
/// # Arguments
///
/// * `shell` - The shell to generate completions for (must be a known shell)
/// * `cmd` - The clap Command to generate completions from
/// * `bin_name` - The binary name to use in the completions
///
/// # Panics
///
/// Panics if the shell is `Shell::Unknown` as we cannot generate completions
/// for an unknown shell type.
///
/// # Example
///
/// ```rust,ignore
/// use clap::CommandFactory;
/// use rust_proxy::util::{generate_completions, Shell};
///
/// let mut cmd = Cli::command();
/// let script = generate_completions(Shell::Bash, &mut cmd, "rust_proxy");
/// println!("{}", script);
/// ```
#[allow(dead_code)]
pub fn generate_completions(shell: Shell, cmd: &mut clap::Command, bin_name: &str) -> String {
    let clap_shell = shell
        .to_clap_shell()
        .expect("Cannot generate completions for unknown shell");

    let mut buf = Vec::new();
    clap_complete::generate(clap_shell, cmd, bin_name, &mut buf);
    String::from_utf8(buf).expect("clap_complete generates valid UTF-8")
}

// =============================================================================
// Completion Installation
// =============================================================================

/// Result of a completion installation operation.
#[derive(Debug)]
#[allow(dead_code)]
pub struct InstallResult {
    /// Path where completions were installed (or would be installed in dry-run mode)
    pub path: PathBuf,
    /// Whether the parent directory was created
    pub created_dir: bool,
    /// Warning message if any (e.g., zsh fpath warning)
    pub warning: Option<String>,
}

/// Install shell completions to the standard location for the given shell.
///
/// Creates parent directories as needed and writes the completion script.
///
/// # Arguments
///
/// * `shell` - The shell to install completions for
/// * `cmd` - The clap Command to generate completions from
/// * `bin_name` - The binary name to use in the completions
/// * `dry_run` - If true, print what would be done without making changes
///
/// # Returns
///
/// Returns an `InstallResult` containing the installation path and any warnings.
///
/// # Errors
///
/// Returns an error if:
/// - The shell is `Shell::Unknown`
/// - Home directory cannot be determined
/// - Parent directory creation fails
/// - Writing the completion script fails
///
/// # Example
///
/// ```rust,ignore
/// use rust_proxy::util::{install_completions, Shell};
/// use clap::CommandFactory;
///
/// let mut cmd = Cli::command();
/// let result = install_completions(Shell::Bash, &mut cmd, "rust_proxy", false)?;
/// println!("Installed completions to: {}", result.path.display());
/// if let Some(warning) = result.warning {
///     println!("Warning: {}", warning);
/// }
/// println!("Activation: {}", Shell::Bash.activation_hint());
/// ```
#[allow(dead_code)]
pub fn install_completions(
    shell: Shell,
    cmd: &mut clap::Command,
    bin_name: &str,
    dry_run: bool,
) -> Result<InstallResult> {
    let path = shell.completion_path()?;
    let script = generate_completions(shell, cmd, bin_name);

    // Check for zsh fpath warning before any modifications
    let warning = if shell == Shell::Zsh {
        check_zsh_fpath_warning(&path)
    } else {
        None
    };

    if dry_run {
        println!(
            "{} Install {} completions to {}",
            "Would:".yellow().bold(),
            shell.display_name(),
            path.display()
        );
        return Ok(InstallResult {
            path,
            created_dir: false,
            warning,
        });
    }

    // Create parent directory if needed
    let created_dir = if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
            true
        } else {
            false
        }
    } else {
        false
    };

    // Write the completion script
    std::fs::write(&path, &script)
        .with_context(|| format!("Failed to write completions to {}", path.display()))?;

    Ok(InstallResult {
        path,
        created_dir,
        warning,
    })
}

/// Uninstall shell completions by removing the completion file.
///
/// # Arguments
///
/// * `shell` - The shell whose completions should be removed
/// * `dry_run` - If true, print what would be done without making changes
///
/// # Returns
///
/// Returns the path that was removed (or would be removed in dry-run mode).
///
/// # Errors
///
/// Returns an error if:
/// - The shell is `Shell::Unknown`
/// - Home directory cannot be determined
/// - File removal fails (except for file not found, which is ok)
#[allow(dead_code)]
pub fn uninstall_completions(shell: Shell, dry_run: bool) -> Result<PathBuf> {
    let path = shell.completion_path()?;

    if dry_run {
        println!(
            "{} Remove {} completions from {}",
            "Would:".yellow().bold(),
            shell.display_name(),
            path.display()
        );
        return Ok(path);
    }

    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to remove completions from {}", path.display()))?;
    }

    Ok(path)
}

/// Check if the zsh completion directory is in the user's fpath.
///
/// Returns a warning message if the directory is not in fpath, or None if it is.
#[allow(dead_code)]
fn check_zsh_fpath_warning(completion_path: &Path) -> Option<String> {
    let completion_dir = completion_path.parent()?;

    // Try to get fpath from environment (it's set by zsh as an array)
    // Note: This won't work reliably from a non-zsh context, but we try anyway
    if let Ok(fpath) = std::env::var("fpath") {
        if fpath.split(':').any(|p| Path::new(p) == completion_dir) {
            return None; // Directory is in fpath, no warning needed
        }
    }

    // Also check FPATH (colon-separated string version)
    if let Ok(fpath) = std::env::var("FPATH") {
        if fpath.split(':').any(|p| Path::new(p) == completion_dir) {
            return None;
        }
    }

    // Directory is likely not in fpath, return a warning
    Some(format!(
        "The directory {} may not be in your zsh fpath. \
        Add this to ~/.zshrc: fpath=(~/.zsh/completions $fpath)",
        completion_dir.display()
    ))
}

/// Check if zsh completions directory is properly configured.
///
/// This is a public version of the fpath check that can be called independently.
///
/// # Returns
///
/// `true` if the completion directory appears to be in fpath, `false` otherwise.
/// Note: This check may return false positives when not running from zsh.
#[allow(dead_code)]
#[must_use]
pub fn is_zsh_fpath_configured() -> bool {
    let Ok(path) = Shell::Zsh.completion_path() else {
        return false;
    };
    let Some(completion_dir) = path.parent() else {
        return false;
    };

    // Check FPATH environment variable
    if let Ok(fpath) = std::env::var("FPATH") {
        if fpath.split(':').any(|p| Path::new(p) == completion_dir) {
            return true;
        }
    }

    // Also check lowercase fpath (some environments export this)
    if let Ok(fpath) = std::env::var("fpath") {
        if fpath.split(':').any(|p| Path::new(p) == completion_dir) {
            return true;
        }
    }

    false
}

/// Detect the user's current shell using multiple fallback methods.
///
/// Detection order:
/// 1. `$SHELL` environment variable (most reliable)
/// 2. Parent process name on Linux (via `/proc`)
/// 3. Common shell config files in home directory
///
/// Returns `Shell::Unknown` if detection fails rather than guessing.
///
/// # Example
///
/// ```rust,ignore
/// use rust_proxy::util::detect_shell;
///
/// let shell = detect_shell();
/// if shell.is_known() {
///     println!("Detected shell: {}", shell.display_name());
/// } else {
///     println!("Could not detect shell");
/// }
/// ```
#[allow(dead_code)]
#[must_use]
pub fn detect_shell() -> Shell {
    // Method 1: Check $SHELL environment variable (most common and reliable)
    if let Some(shell) = detect_from_shell_env() {
        return shell;
    }

    // Method 2: Check parent process name (Linux only)
    #[cfg(target_os = "linux")]
    if let Some(shell) = detect_from_parent_process() {
        return shell;
    }

    // Method 3: Check for common shell config files
    if let Some(shell) = detect_from_config_files() {
        return shell;
    }

    Shell::Unknown
}

/// Detect shell from the $SHELL environment variable.
#[allow(dead_code)]
fn detect_from_shell_env() -> Option<Shell> {
    let shell_path = std::env::var("SHELL").ok()?;
    let shell_path = shell_path.to_lowercase();

    // Check common shell binary names at end of path
    if shell_path.ends_with("/bash") || shell_path.ends_with("/bash.exe") {
        return Some(Shell::Bash);
    }
    if shell_path.ends_with("/zsh") || shell_path.ends_with("/zsh.exe") {
        return Some(Shell::Zsh);
    }
    if shell_path.ends_with("/fish") || shell_path.ends_with("/fish.exe") {
        return Some(Shell::Fish);
    }
    if shell_path.ends_with("/pwsh")
        || shell_path.ends_with("/powershell")
        || shell_path.ends_with("/powershell.exe")
        || shell_path.ends_with("/pwsh.exe")
    {
        return Some(Shell::PowerShell);
    }
    if shell_path.ends_with("/elvish") || shell_path.ends_with("/elvish.exe") {
        return Some(Shell::Elvish);
    }

    // Also check if the binary name appears in the path (handles unusual paths)
    let lower = shell_path.to_lowercase();
    if lower.contains("bash") {
        return Some(Shell::Bash);
    }
    if lower.contains("zsh") {
        return Some(Shell::Zsh);
    }
    if lower.contains("fish") {
        return Some(Shell::Fish);
    }
    if lower.contains("pwsh") || lower.contains("powershell") {
        return Some(Shell::PowerShell);
    }
    if lower.contains("elvish") {
        return Some(Shell::Elvish);
    }

    None
}

/// Detect shell from the parent process name (Linux only).
#[allow(dead_code)]
#[cfg(target_os = "linux")]
fn detect_from_parent_process() -> Option<Shell> {
    // Get parent process ID
    let ppid = std::os::unix::process::parent_id();

    // Read the process name from /proc/<ppid>/comm
    let comm_path = format!("/proc/{ppid}/comm");
    let name = std::fs::read_to_string(comm_path).ok()?;
    let name = name.trim().to_lowercase();

    match name.as_str() {
        "bash" => Some(Shell::Bash),
        "zsh" => Some(Shell::Zsh),
        "fish" => Some(Shell::Fish),
        "pwsh" | "powershell" => Some(Shell::PowerShell),
        "elvish" => Some(Shell::Elvish),
        _ => None,
    }
}

/// Detect shell by checking for common shell config files in home directory.
#[allow(dead_code)]
fn detect_from_config_files() -> Option<Shell> {
    let base_dirs = directories::BaseDirs::new()?;
    let home = base_dirs.home_dir();

    // Check in order of popularity/specificity
    // Zsh config
    if home.join(".zshrc").exists() || home.join(".zshenv").exists() {
        return Some(Shell::Zsh);
    }

    // Fish config (in .config/fish/)
    let fish_config = home.join(".config").join("fish").join("config.fish");
    if fish_config.exists() {
        return Some(Shell::Fish);
    }

    // Bash config
    if home.join(".bashrc").exists() || home.join(".bash_profile").exists() {
        return Some(Shell::Bash);
    }

    // Elvish config (in .config/elvish/ or .elvish/)
    let elvish_config1 = home.join(".config").join("elvish").join("rc.elv");
    let elvish_config2 = home.join(".elvish").join("rc.elv");
    if elvish_config1.exists() || elvish_config2.exists() {
        return Some(Shell::Elvish);
    }

    // PowerShell profile locations vary, skip for now
    // (PowerShell users typically know they're using PowerShell)

    None
}

/// Helper for dry-run mode that provides consistent messaging across commands.
///
/// When dry-run is enabled, actions are printed with "Would: <action>" prefix
/// and the actual operation is skipped.
///
/// # Example
/// ```ignore
/// let dry_run = DryRun::new(args.dry_run);
/// if dry_run.would_do("remove proxy 'test'") {
///     return Ok(());
/// }
/// // Actually remove the proxy...
/// ```
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Infrastructure for future dry-run implementations
pub struct DryRun {
    enabled: bool,
}

#[allow(dead_code)] // Infrastructure for future dry-run implementations
impl DryRun {
    /// Create a new DryRun helper
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Returns true if dry-run mode is enabled
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Print what would happen and return true if dry-run is enabled (caller should skip action).
    ///
    /// # Example
    /// ```ignore
    /// let dry_run = DryRun::new(true);
    /// if dry_run.would_do("delete config file") {
    ///     return Ok(()); // Skip the actual deletion
    /// }
    /// // Actually delete the file...
    /// ```
    pub fn would_do(&self, action: &str) -> bool {
        if self.enabled {
            println!("{} {}", "Would:".yellow().bold(), action);
            true
        } else {
            false
        }
    }

    /// Print what would happen using a format string and return true if dry-run is enabled.
    ///
    /// # Example
    /// ```ignore
    /// let dry_run = DryRun::new(true);
    /// if dry_run.would_do_fmt(format_args!("remove proxy '{}'", proxy_id)) {
    ///     return Ok(());
    /// }
    /// ```
    pub fn would_do_fmt(&self, action: std::fmt::Arguments<'_>) -> bool {
        if self.enabled {
            println!("{} {}", "Would:".yellow().bold(), action);
            true
        } else {
            false
        }
    }

    /// Execute an action only if not in dry-run mode.
    /// If in dry-run mode, prints what would happen and returns Ok(default).
    ///
    /// # Example
    /// ```ignore
    /// let dry_run = DryRun::new(true);
    /// let result = dry_run.execute_or_skip(
    ///     "save configuration",
    ///     || config.save(),
    ///     || Ok(())
    /// )?;
    /// ```
    pub fn execute_or_skip<T, E, F, D>(
        &self,
        action: &str,
        op: F,
        default: D,
    ) -> std::result::Result<T, E>
    where
        F: FnOnce() -> std::result::Result<T, E>,
        D: FnOnce() -> std::result::Result<T, E>,
    {
        if self.would_do(action) {
            default()
        } else {
            op()
        }
    }
}

impl Default for DryRun {
    fn default() -> Self {
        Self::new(false)
    }
}

impl From<bool> for DryRun {
    fn from(enabled: bool) -> Self {
        Self::new(enabled)
    }
}

#[derive(Debug, Clone)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
}

pub fn parse_proxy_url(raw: &str) -> Result<ProxyEndpoint> {
    let normalized = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{}", raw)
    };
    let url = Url::parse(&normalized).with_context(|| format!("Invalid proxy URL: {raw}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Proxy URL missing host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("Proxy URL missing port"))?;
    Ok(ProxyEndpoint {
        host: host.to_string(),
        port,
    })
}

#[allow(dead_code)]
pub fn generate_service_file(
    binary_path: &Path,
    config_path: &Path,
    user: &str,
    group: &str,
    hardened: bool,
) -> String {
    let mut service = format!(
        r#"[Unit]
Description=rust_proxy - Targeted transparent proxy daemon
Documentation=https://github.com/Dicklesworthstone/rust_proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary} daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

User={user}
Group={group}

# Config file path (for reference)
Environment=RUST_PROXY_CONFIG={config}

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rust_proxy

# Resource limits
LimitNOFILE=65535
"#,
        binary = binary_path.display(),
        config = config_path.display(),
        user = user,
        group = group
    );

    if hardened {
        service.push_str(&hardening_section(config_path));
    }

    service.push_str(
        r#"
[Install]
WantedBy=multi-user.target
"#,
    );

    service
}

#[allow(dead_code)]
fn hardening_section(config_path: &Path) -> String {
    let config_dir = config_path.parent().unwrap_or(config_path);
    let mut section = String::new();
    section.push_str("\n# Security hardening (limited due to iptables requirement)\n");
    section.push_str("ProtectSystem=strict\n");
    section.push_str(&format!("ReadWritePaths={}\n", config_dir.display()));
    if let Ok(state_dir) = crate::config::state_dir() {
        section.push_str(&format!("ReadWritePaths={}\n", state_dir.display()));
    }
    section.push_str("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n");
    section.push_str("NoNewPrivileges=no\n");
    section.push_str("PrivateTmp=true\n");
    section.push_str("ProtectHome=read-only\n");
    section.push_str("ProtectKernelTunables=true\n");
    section.push_str("ProtectKernelModules=true\n");
    section.push_str("ProtectControlGroups=true\n");
    section
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let value = bytes as f64;
    if value < KB {
        format!("{} B", bytes)
    } else if value < MB {
        format!("{:.1} KB", value / KB)
    } else if value < GB {
        format!("{:.1} MB", value / MB)
    } else {
        format!("{:.2} GB", value / GB)
    }
}

pub fn format_duration_since(when: Option<DateTime<Utc>>) -> String {
    let Some(ts) = when else {
        return "-".to_string();
    };
    let now = Utc::now();
    let delta = now.signed_duration_since(ts);
    if delta.num_seconds() < 0 {
        return "0s".to_string();
    }
    format_duration(delta.to_std().unwrap_or(Duration::from_secs(0)))
}

pub fn format_duration(duration: Duration) -> String {
    let mut secs = duration.as_secs();
    let days = secs / 86400;
    secs %= 86400;
    let hours = secs / 3600;
    secs %= 3600;
    let minutes = secs / 60;
    let seconds = secs % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 || !parts.is_empty() {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 || !parts.is_empty() {
        parts.push(format!("{}m", minutes));
    }
    parts.push(format!("{}s", seconds));

    parts.join(" ")
}

pub fn format_timeout(ms: u64) -> Result<Duration> {
    if ms == 0 {
        bail!("Timeout must be greater than 0")
    }
    Ok(Duration::from_millis(ms))
}

pub fn format_since_label(when: Option<DateTime<Utc>>) -> String {
    if let Some(ts) = when {
        let now = Utc::now();
        let delta = now.signed_duration_since(ts);
        let pretty = format_duration(delta.to_std().unwrap_or(Duration::from_secs(0)));
        format!("{pretty} ago")
    } else {
        "-".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proxy_url_with_scheme() {
        let result = parse_proxy_url("http://proxy.example.com:8080").unwrap();
        assert_eq!(result.host, "proxy.example.com");
        assert_eq!(result.port, 8080);
    }

    #[test]
    fn test_parse_proxy_url_without_scheme() {
        let result = parse_proxy_url("proxy.example.com:3128").unwrap();
        assert_eq!(result.host, "proxy.example.com");
        assert_eq!(result.port, 3128);
    }

    #[test]
    fn test_parse_proxy_url_default_http_port() {
        let result = parse_proxy_url("http://proxy.example.com").unwrap();
        assert_eq!(result.host, "proxy.example.com");
        assert_eq!(result.port, 80);
    }

    #[test]
    fn test_parse_proxy_url_https_default_port() {
        let result = parse_proxy_url("https://proxy.example.com").unwrap();
        assert_eq!(result.host, "proxy.example.com");
        assert_eq!(result.port, 443);
    }

    #[test]
    fn test_parse_proxy_url_invalid() {
        let result = parse_proxy_url("not a valid url ::::");
        assert!(result.is_err());
    }

    #[test]
    fn test_format_bytes_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn test_format_bytes_kb() {
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(10240), "10.0 KB");
    }

    #[test]
    fn test_format_bytes_mb() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 5), "5.0 MB");
    }

    #[test]
    fn test_format_bytes_gb() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_bytes(1024 * 1024 * 1024 * 2), "2.00 GB");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(Duration::from_secs(60)), "1m 0s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3599)), "59m 59s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h 0m 0s");
        assert_eq!(format_duration(Duration::from_secs(7200)), "2h 0m 0s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
    }

    #[test]
    fn test_format_duration_days() {
        assert_eq!(format_duration(Duration::from_secs(86400)), "1d 0h 0m 0s");
        assert_eq!(format_duration(Duration::from_secs(90061)), "1d 1h 1m 1s");
    }

    #[test]
    fn test_format_timeout_valid() {
        let result = format_timeout(1000).unwrap();
        assert_eq!(result, Duration::from_millis(1000));
    }

    #[test]
    fn test_format_timeout_zero() {
        let result = format_timeout(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_duration_since_none() {
        assert_eq!(format_duration_since(None), "-");
    }

    #[test]
    fn test_format_since_label_none() {
        assert_eq!(format_since_label(None), "-");
    }

    #[test]
    fn test_dry_run_new() {
        let dry_run = DryRun::new(true);
        assert!(dry_run.is_enabled());

        let dry_run = DryRun::new(false);
        assert!(!dry_run.is_enabled());
    }

    #[test]
    fn test_dry_run_default() {
        let dry_run = DryRun::default();
        assert!(!dry_run.is_enabled());
    }

    #[test]
    fn test_dry_run_from_bool() {
        let dry_run: DryRun = true.into();
        assert!(dry_run.is_enabled());

        let dry_run: DryRun = false.into();
        assert!(!dry_run.is_enabled());
    }

    #[test]
    fn test_dry_run_would_do_enabled() {
        let dry_run = DryRun::new(true);
        // When enabled, would_do returns true (skip action)
        assert!(dry_run.would_do("test action"));
    }

    #[test]
    fn test_dry_run_would_do_disabled() {
        let dry_run = DryRun::new(false);
        // When disabled, would_do returns false (execute action)
        assert!(!dry_run.would_do("test action"));
    }

    #[test]
    fn test_dry_run_would_do_fmt_enabled() {
        let dry_run = DryRun::new(true);
        let proxy_id = "test-proxy";
        // When enabled, would_do_fmt returns true (skip action)
        assert!(dry_run.would_do_fmt(format_args!("remove proxy '{}'", proxy_id)));
    }

    #[test]
    fn test_dry_run_would_do_fmt_disabled() {
        let dry_run = DryRun::new(false);
        let proxy_id = "test-proxy";
        // When disabled, would_do_fmt returns false (execute action)
        assert!(!dry_run.would_do_fmt(format_args!("remove proxy '{}'", proxy_id)));
    }

    #[test]
    fn test_dry_run_execute_or_skip_enabled() {
        let dry_run = DryRun::new(true);
        let mut executed = false;
        let result: std::result::Result<i32, &str> = dry_run.execute_or_skip(
            "test action",
            || {
                executed = true;
                Ok(42)
            },
            || Ok(0),
        );
        assert!(!executed);
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_dry_run_execute_or_skip_disabled() {
        let dry_run = DryRun::new(false);
        let mut executed = false;
        let result: std::result::Result<i32, &str> = dry_run.execute_or_skip(
            "test action",
            || {
                executed = true;
                Ok(42)
            },
            || Ok(0),
        );
        assert!(executed);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_generate_service_file_basic() {
        let binary = std::path::Path::new("/usr/local/bin/rust_proxy");
        let config = std::path::Path::new("/etc/rust_proxy/config.toml");
        let service = generate_service_file(binary, config, "root", "root", false);
        assert!(service.contains("ExecStart=/usr/local/bin/rust_proxy daemon"));
        assert!(service.contains("Environment=RUST_PROXY_CONFIG=/etc/rust_proxy/config.toml"));
        assert!(service.contains("User=root"));
        assert!(service.contains("Group=root"));
        assert!(!service.contains("ProtectSystem=strict"));
    }

    #[test]
    fn test_generate_service_file_hardened() {
        let binary = std::path::Path::new("/usr/local/bin/rust_proxy");
        let config = std::path::Path::new("/etc/rust_proxy/config.toml");
        let service = generate_service_file(binary, config, "root", "root", true);
        assert!(service.contains("ProtectSystem=strict"));
        assert!(service.contains("ReadWritePaths=/etc/rust_proxy"));
    }

    // =========================================================================
    // Shell Detection Tests
    // =========================================================================

    #[test]
    fn test_shell_name() {
        assert_eq!(Shell::Bash.name(), "bash");
        assert_eq!(Shell::Zsh.name(), "zsh");
        assert_eq!(Shell::Fish.name(), "fish");
        assert_eq!(Shell::PowerShell.name(), "powershell");
        assert_eq!(Shell::Elvish.name(), "elvish");
        assert_eq!(Shell::Unknown.name(), "unknown");
    }

    #[test]
    fn test_shell_display_name() {
        assert_eq!(Shell::Bash.display_name(), "Bash");
        assert_eq!(Shell::Zsh.display_name(), "Zsh");
        assert_eq!(Shell::Fish.display_name(), "Fish");
        assert_eq!(Shell::PowerShell.display_name(), "PowerShell");
        assert_eq!(Shell::Elvish.display_name(), "Elvish");
        assert_eq!(Shell::Unknown.display_name(), "Unknown");
    }

    #[test]
    fn test_shell_is_known() {
        assert!(Shell::Bash.is_known());
        assert!(Shell::Zsh.is_known());
        assert!(Shell::Fish.is_known());
        assert!(Shell::PowerShell.is_known());
        assert!(Shell::Elvish.is_known());
        assert!(!Shell::Unknown.is_known());
    }

    #[test]
    fn test_shell_to_clap_shell() {
        assert_eq!(
            Shell::Bash.to_clap_shell(),
            Some(clap_complete::Shell::Bash)
        );
        assert_eq!(Shell::Zsh.to_clap_shell(), Some(clap_complete::Shell::Zsh));
        assert_eq!(
            Shell::Fish.to_clap_shell(),
            Some(clap_complete::Shell::Fish)
        );
        assert_eq!(
            Shell::PowerShell.to_clap_shell(),
            Some(clap_complete::Shell::PowerShell)
        );
        assert_eq!(
            Shell::Elvish.to_clap_shell(),
            Some(clap_complete::Shell::Elvish)
        );
        assert_eq!(Shell::Unknown.to_clap_shell(), None);
    }

    #[test]
    fn test_shell_display() {
        assert_eq!(format!("{}", Shell::Bash), "Bash");
        assert_eq!(format!("{}", Shell::Zsh), "Zsh");
        assert_eq!(format!("{}", Shell::Fish), "Fish");
        assert_eq!(format!("{}", Shell::PowerShell), "PowerShell");
        assert_eq!(format!("{}", Shell::Elvish), "Elvish");
        assert_eq!(format!("{}", Shell::Unknown), "Unknown");
    }

    // Helper to test shell detection with a specific SHELL value
    // This uses a direct parsing approach to avoid environment variable race conditions
    fn parse_shell_from_path(path: &str) -> Option<Shell> {
        let shell_path = path.to_lowercase();

        // Check common shell binary names at end of path
        if shell_path.ends_with("/bash") || shell_path.ends_with("/bash.exe") {
            return Some(Shell::Bash);
        }
        if shell_path.ends_with("/zsh") || shell_path.ends_with("/zsh.exe") {
            return Some(Shell::Zsh);
        }
        if shell_path.ends_with("/fish") || shell_path.ends_with("/fish.exe") {
            return Some(Shell::Fish);
        }
        if shell_path.ends_with("/pwsh")
            || shell_path.ends_with("/powershell")
            || shell_path.ends_with("/powershell.exe")
            || shell_path.ends_with("/pwsh.exe")
        {
            return Some(Shell::PowerShell);
        }
        if shell_path.ends_with("/elvish") || shell_path.ends_with("/elvish.exe") {
            return Some(Shell::Elvish);
        }

        // Also check if the binary name appears in the path
        let lower = shell_path.to_lowercase();
        if lower.contains("bash") {
            return Some(Shell::Bash);
        }
        if lower.contains("zsh") {
            return Some(Shell::Zsh);
        }
        if lower.contains("fish") {
            return Some(Shell::Fish);
        }
        if lower.contains("pwsh") || lower.contains("powershell") {
            return Some(Shell::PowerShell);
        }
        if lower.contains("elvish") {
            return Some(Shell::Elvish);
        }

        None
    }

    #[test]
    fn test_shell_path_parsing_bash() {
        // Test various bash path formats
        assert_eq!(parse_shell_from_path("/bin/bash"), Some(Shell::Bash));
        assert_eq!(parse_shell_from_path("/usr/bin/bash"), Some(Shell::Bash));
        assert_eq!(
            parse_shell_from_path("/usr/local/bin/bash"),
            Some(Shell::Bash)
        );
        assert_eq!(
            parse_shell_from_path("C:\\Program Files\\bash.exe"),
            Some(Shell::Bash)
        );
    }

    #[test]
    fn test_shell_path_parsing_zsh() {
        assert_eq!(parse_shell_from_path("/bin/zsh"), Some(Shell::Zsh));
        assert_eq!(parse_shell_from_path("/usr/bin/zsh"), Some(Shell::Zsh));
        assert_eq!(
            parse_shell_from_path("/opt/homebrew/bin/zsh"),
            Some(Shell::Zsh)
        );
    }

    #[test]
    fn test_shell_path_parsing_fish() {
        assert_eq!(parse_shell_from_path("/usr/bin/fish"), Some(Shell::Fish));
        assert_eq!(
            parse_shell_from_path("/usr/local/bin/fish"),
            Some(Shell::Fish)
        );
    }

    #[test]
    fn test_shell_path_parsing_powershell() {
        assert_eq!(
            parse_shell_from_path("/usr/bin/pwsh"),
            Some(Shell::PowerShell)
        );
        assert_eq!(
            parse_shell_from_path("/usr/local/bin/powershell"),
            Some(Shell::PowerShell)
        );
        assert_eq!(
            parse_shell_from_path("C:\\Windows\\System32\\powershell.exe"),
            Some(Shell::PowerShell)
        );
    }

    #[test]
    fn test_shell_path_parsing_elvish() {
        assert_eq!(
            parse_shell_from_path("/usr/bin/elvish"),
            Some(Shell::Elvish)
        );
        assert_eq!(
            parse_shell_from_path("/usr/local/bin/elvish"),
            Some(Shell::Elvish)
        );
    }

    #[test]
    fn test_shell_path_parsing_unknown() {
        assert_eq!(parse_shell_from_path("/bin/sh"), None);
        assert_eq!(parse_shell_from_path("/usr/bin/dash"), None);
        assert_eq!(parse_shell_from_path("/usr/bin/ksh"), None);
        assert_eq!(parse_shell_from_path("/usr/bin/tcsh"), None);
    }

    #[test]
    fn test_shell_path_parsing_case_insensitive() {
        // Should handle uppercase SHELL values
        assert_eq!(parse_shell_from_path("/BIN/BASH"), Some(Shell::Bash));
        assert_eq!(parse_shell_from_path("/usr/BIN/ZSH"), Some(Shell::Zsh));
        assert_eq!(parse_shell_from_path("/USR/BIN/FISH"), Some(Shell::Fish));
    }

    #[test]
    fn test_detect_shell_returns_something() {
        // This test just ensures detect_shell() runs without panicking.
        // The actual result depends on the environment.
        let shell = detect_shell();
        // Shell should be one of the valid variants
        let _ = shell.name();
        let _ = shell.is_known();
    }

    #[test]
    fn test_shell_equality() {
        assert_eq!(Shell::Bash, Shell::Bash);
        assert_ne!(Shell::Bash, Shell::Zsh);
        assert_ne!(Shell::Unknown, Shell::Bash);
    }

    #[test]
    fn test_shell_clone_and_copy() {
        let shell = Shell::Bash;
        let cloned = shell; // Shell is Copy, no need for .clone()
        let copied = shell;
        assert_eq!(shell, cloned);
        assert_eq!(shell, copied);
    }

    #[test]
    fn test_shell_debug() {
        // Ensure Debug is implemented correctly
        let debug_str = format!("{:?}", Shell::Bash);
        assert!(debug_str.contains("Bash"));
    }

    // =========================================================================
    // Completion Generation Tests
    // =========================================================================

    // Helper: create a minimal test CLI command for completion testing
    fn test_cli_command() -> clap::Command {
        clap::Command::new("rust_proxy")
            .version("0.1.0")
            .about("Test CLI for completion generation")
            .subcommand(clap::Command::new("init").about("Initialize configuration"))
            .subcommand(clap::Command::new("status").about("Show status"))
            .subcommand(
                clap::Command::new("proxy")
                    .about("Manage proxies")
                    .subcommand(clap::Command::new("add").about("Add a proxy"))
                    .subcommand(clap::Command::new("remove").about("Remove a proxy"))
                    .subcommand(clap::Command::new("list").about("List proxies")),
            )
    }

    #[test]
    fn test_bash_completions() {
        let mut cmd = test_cli_command();
        let script = generate_completions(Shell::Bash, &mut cmd, "rust_proxy");

        // Bash completions should contain the complete builtin
        assert!(
            script.contains("complete -F") || script.contains("complete -C"),
            "Bash completions should contain complete -F or -C, got: {}",
            &script[..script.len().min(200)]
        );
        // Should contain the binary name
        assert!(
            script.contains("rust_proxy"),
            "Bash completions should contain binary name 'rust_proxy'"
        );
    }

    #[test]
    fn test_zsh_completions() {
        let mut cmd = test_cli_command();
        let script = generate_completions(Shell::Zsh, &mut cmd, "rust_proxy");

        // Zsh completions should contain compdef directive
        assert!(
            script.contains("#compdef rust_proxy"),
            "Zsh completions should contain '#compdef rust_proxy'"
        );
        // Should contain the binary name
        assert!(
            script.contains("rust_proxy"),
            "Zsh completions should contain binary name 'rust_proxy'"
        );
    }

    #[test]
    fn test_fish_completions() {
        let mut cmd = test_cli_command();
        let script = generate_completions(Shell::Fish, &mut cmd, "rust_proxy");

        // Fish completions should contain complete -c <command>
        assert!(
            script.contains("complete -c rust_proxy"),
            "Fish completions should contain 'complete -c rust_proxy'"
        );
    }

    #[test]
    fn test_powershell_completions() {
        let mut cmd = test_cli_command();
        let script = generate_completions(Shell::PowerShell, &mut cmd, "rust_proxy");

        // PowerShell completions should contain Register-ArgumentCompleter
        assert!(
            script.contains("Register-ArgumentCompleter"),
            "PowerShell completions should contain 'Register-ArgumentCompleter'"
        );
        // Should contain the binary name
        assert!(
            script.contains("rust_proxy"),
            "PowerShell completions should contain binary name 'rust_proxy'"
        );
    }

    #[test]
    fn test_elvish_completions() {
        let mut cmd = test_cli_command();
        let script = generate_completions(Shell::Elvish, &mut cmd, "rust_proxy");

        // Elvish completions should contain set-env or edit:completion
        assert!(
            script.contains("edit:completion") || script.contains("rust_proxy"),
            "Elvish completions should be valid Elvish script"
        );
    }

    #[test]
    fn test_completions_are_valid_utf8() {
        let cmd = test_cli_command();

        // All shell completions should produce valid UTF-8
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            let script = generate_completions(shell, &mut cmd.clone(), "rust_proxy");
            assert!(
                !script.is_empty(),
                "Completions for {:?} should not be empty",
                shell
            );
            // The script being a valid String already proves it's valid UTF-8
        }
    }

    #[test]
    #[should_panic(expected = "Cannot generate completions for unknown shell")]
    fn test_unknown_shell_completions_panics() {
        let mut cmd = test_cli_command();
        // This should panic
        let _ = generate_completions(Shell::Unknown, &mut cmd, "rust_proxy");
    }

    // =========================================================================
    // Completion Path Tests
    // =========================================================================

    #[test]
    fn test_completion_path_bash() {
        let path = Shell::Bash.completion_path().unwrap();
        let path_str = path.to_string_lossy();
        // Should end with the correct filename
        assert!(
            path_str.ends_with("bash-completion/completions/rust_proxy"),
            "Bash completion path should end with bash-completion/completions/rust_proxy, got: {}",
            path_str
        );
    }

    #[test]
    fn test_completion_path_zsh() {
        let path = Shell::Zsh.completion_path().unwrap();
        let path_str = path.to_string_lossy();
        // Should end with _rust_proxy (zsh convention)
        assert!(
            path_str.ends_with(".zsh/completions/_rust_proxy"),
            "Zsh completion path should end with .zsh/completions/_rust_proxy, got: {}",
            path_str
        );
    }

    #[test]
    fn test_completion_path_fish() {
        let path = Shell::Fish.completion_path().unwrap();
        let path_str = path.to_string_lossy();
        // Should end with .fish extension
        assert!(
            path_str.ends_with("fish/completions/rust_proxy.fish"),
            "Fish completion path should end with fish/completions/rust_proxy.fish, got: {}",
            path_str
        );
    }

    #[test]
    fn test_completion_path_powershell() {
        let path = Shell::PowerShell.completion_path().unwrap();
        let path_str = path.to_string_lossy();
        // Should end with .ps1 extension
        assert!(
            path_str.ends_with("powershell/completions/rust_proxy.ps1"),
            "PowerShell completion path should end with powershell/completions/rust_proxy.ps1, got: {}",
            path_str
        );
    }

    #[test]
    fn test_completion_path_elvish() {
        let path = Shell::Elvish.completion_path().unwrap();
        let path_str = path.to_string_lossy();
        // Should end with .elv extension
        assert!(
            path_str.ends_with("elvish/lib/rust_proxy.elv"),
            "Elvish completion path should end with elvish/lib/rust_proxy.elv, got: {}",
            path_str
        );
    }

    #[test]
    fn test_completion_path_unknown_errors() {
        let result = Shell::Unknown.completion_path();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown shell"));
    }

    #[test]
    fn test_completion_paths_are_absolute() {
        // All known shells should return absolute paths
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            let path = shell.completion_path().unwrap();
            assert!(
                path.is_absolute(),
                "Completion path for {:?} should be absolute, got: {}",
                shell,
                path.display()
            );
        }
    }

    // =========================================================================
    // Activation Hint Tests
    // =========================================================================

    #[test]
    fn test_activation_hint_bash() {
        let hint = Shell::Bash.activation_hint();
        assert!(
            hint.contains("bashrc") || hint.contains("Restart"),
            "Bash activation hint should mention bashrc or restart"
        );
    }

    #[test]
    fn test_activation_hint_zsh() {
        let hint = Shell::Zsh.activation_hint();
        assert!(
            hint.contains("fpath") && hint.contains("compinit"),
            "Zsh activation hint should mention fpath and compinit"
        );
    }

    #[test]
    fn test_activation_hint_fish() {
        let hint = Shell::Fish.activation_hint();
        assert!(
            hint.contains("automatic"),
            "Fish activation hint should mention automatic activation"
        );
    }

    #[test]
    fn test_activation_hint_powershell() {
        let hint = Shell::PowerShell.activation_hint();
        assert!(
            hint.contains("profile") || hint.contains(".ps1"),
            "PowerShell activation hint should mention profile or .ps1"
        );
    }

    #[test]
    fn test_activation_hint_elvish() {
        let hint = Shell::Elvish.activation_hint();
        assert!(
            hint.contains("rc.elv") || hint.contains("use"),
            "Elvish activation hint should mention rc.elv or use statement"
        );
    }

    #[test]
    fn test_activation_hint_unknown_empty() {
        let hint = Shell::Unknown.activation_hint();
        assert!(
            hint.is_empty(),
            "Unknown shell activation hint should be empty"
        );
    }

    // =========================================================================
    // Installation Tests (with temp directory)
    // =========================================================================

    #[test]
    fn test_install_completions_dry_run() {
        // Dry run should not create files
        let mut cmd = test_cli_command();
        let result = install_completions(Shell::Bash, &mut cmd, "rust_proxy", true).unwrap();

        // Should return a path
        assert!(
            result.path.to_string_lossy().contains("rust_proxy"),
            "Install result should contain rust_proxy in path"
        );
        // Should not have created a directory (dry run)
        assert!(!result.created_dir, "Dry run should not create directories");
    }

    #[test]
    fn test_install_completions_returns_valid_result() {
        // Test that install_completions returns proper InstallResult structure
        let cmd = test_cli_command();

        // Just test with dry_run to avoid filesystem side effects in unit tests
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let result = install_completions(shell, &mut cmd.clone(), "rust_proxy", true).unwrap();
            assert!(
                !result.path.as_os_str().is_empty(),
                "Install result path should not be empty for {:?}",
                shell
            );
        }
    }

    #[test]
    fn test_uninstall_completions_dry_run() {
        // Dry run should not remove files
        let result = uninstall_completions(Shell::Bash, true).unwrap();

        // Should return a path
        assert!(
            result.to_string_lossy().contains("rust_proxy"),
            "Uninstall result should contain rust_proxy in path"
        );
    }

    #[test]
    fn test_zsh_fpath_check_function_exists() {
        // Just verify the function runs without panicking
        let _ = is_zsh_fpath_configured();
    }
}

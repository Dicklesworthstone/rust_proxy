// Allow dead_code warnings for this module - these are public APIs that will be
// integrated in bd-thy. The module provides infrastructure for rich_rust integration.
#![allow(dead_code)]

//! Output module for centralized output routing and theming.
//!
//! This module provides:
//! - [`OutputDispatcher`] - Centralized output routing for agent-safe output
//! - [`theme`] - Semantic color theme for consistent visual identity
//! - [`theme::styles`] - Pre-configured style presets for common UI elements
//! - [`formatters`] - Data formatters with consistent styling (bytes, latency, etc.)
//!
//! # Output Modes
//!
//! - **Human**: Interactive terminal - show rich formatted output
//! - **Machine**: JSON flag, piped output, or CI environment - show plain/JSON only
//! - **Quiet**: Minimal output for scripting
//!
//! # Example
//!
//! ```rust,ignore
//! use rust_proxy::output::{OutputDispatcher, OutputMode};
//!
//! // From CLI flags
//! let output = OutputDispatcher::from_flags(args.json, args.quiet, args.format);
//!
//! // Print based on mode
//! output.print_rich("[bold green]Success![/]");
//! output.print_plain("Operation completed");
//! ```

pub mod formatters;
pub mod theme;
pub mod widgets;

use rich_rust::prelude::*;
use rich_rust::renderables::Renderable;
use serde::Serialize;
use std::io::{self, IsTerminal, Write};

/// Output mode determines how content is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Interactive terminal - show rich output with colors and formatting.
    Human,
    /// JSON/TOON flag or piped output - show plain text or machine output only.
    Machine,
    /// Minimal output for scripting - only essential messages.
    Quiet,
}

/// Machine output format for structured responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// JSON output (pretty-printed for human readability).
    #[default]
    Json,
    /// Token-Optimized Object Notation (TOON).
    Toon,
}

impl OutputFormat {
    /// Parse from CLI or environment values.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "toon" => Some(Self::Toon),
            _ => None,
        }
    }

    /// Resolve output format from flags and environment.
    #[must_use]
    pub fn detect(format_flag: Option<Self>) -> Self {
        Self::detect_with_env(format_flag, &RealEnv)
    }

    /// Resolve output format with explicit environment lookup.
    #[must_use]
    pub fn detect_with_env<E: EnvLookup>(format_flag: Option<Self>, env: &E) -> Self {
        if let Some(flag) = format_flag {
            return flag;
        }

        if let Some(value) = env.var_value("RUST_PROXY_OUTPUT_FORMAT") {
            if let Some(parsed) = Self::parse(&value) {
                return parsed;
            }
        }

        if let Some(value) = env.var_value("TOON_DEFAULT_FORMAT") {
            if let Some(parsed) = Self::parse(&value) {
                return parsed;
            }
        }

        Self::Json
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Toon => write!(f, "toon"),
        }
    }
}

/// TTY state for testable mode detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtyState {
    /// stdout is a TTY (interactive terminal)
    Yes,
    /// stdout is not a TTY (piped or redirected)
    No,
}

impl TtyState {
    /// Detect actual TTY state from stdout.
    #[must_use]
    pub fn detect() -> Self {
        if io::stdout().is_terminal() {
            Self::Yes
        } else {
            Self::No
        }
    }

    /// Returns true if this represents a TTY.
    #[must_use]
    pub const fn is_tty(&self) -> bool {
        matches!(self, Self::Yes)
    }
}

/// Environment variable lookup trait for testability.
pub trait EnvLookup {
    /// Check if an environment variable is set (exists).
    fn var_exists(&self, key: &str) -> bool;
    /// Return the environment variable value if present.
    fn var_value(&self, key: &str) -> Option<String>;
}

/// Real environment lookup using std::env.
pub struct RealEnv;

impl EnvLookup for RealEnv {
    fn var_exists(&self, key: &str) -> bool {
        std::env::var(key).is_ok()
    }

    fn var_value(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// Test environment using a HashMap.
#[cfg(test)]
pub struct TestEnv {
    vars: std::collections::HashMap<String, String>,
}

#[cfg(test)]
impl TestEnv {
    pub fn new() -> Self {
        Self {
            vars: std::collections::HashMap::new(),
        }
    }

    pub fn with_var(mut self, key: &str, value: &str) -> Self {
        self.vars.insert(key.to_string(), value.to_string());
        self
    }
}

#[cfg(test)]
impl EnvLookup for TestEnv {
    fn var_exists(&self, key: &str) -> bool {
        self.vars.contains_key(key)
    }

    fn var_value(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned()
    }
}

impl OutputMode {
    /// Detect the appropriate output mode based on flags and environment.
    ///
    /// Detection order (first match wins):
    /// 1. Machine output flag (`--json` or `--format`) → Machine
    /// 2. `--quiet` flag → Quiet
    /// 3. stdout is not a TTY → Machine
    /// 4. CI env var is set → Machine
    /// 5. GITHUB_ACTIONS env var is set → Machine
    /// 6. CLAUDE_CODE env var is set → Machine
    /// 7. CODEX_CLI env var is set → Machine
    /// 8. NO_COLOR env var is set → Machine
    /// 9. Otherwise → Human
    #[must_use]
    pub fn detect(json_flag: bool, quiet_flag: bool) -> Self {
        Self::detect_with_env(json_flag, quiet_flag, TtyState::detect(), &RealEnv)
    }

    /// Detect output mode with explicit TTY state and environment lookup.
    ///
    /// This is the core detection logic, made testable by accepting
    /// the TTY state and environment lookup as parameters.
    #[must_use]
    pub fn detect_with_env<E: EnvLookup>(
        json_flag: bool,
        quiet_flag: bool,
        tty_state: TtyState,
        env: &E,
    ) -> Self {
        // 1. Explicit machine output flag (--json or --format)
        if json_flag {
            return Self::Machine;
        }

        // 2. Explicit --quiet flag
        if quiet_flag {
            return Self::Quiet;
        }

        // 3. stdout is not a TTY (piped or redirected)
        if !tty_state.is_tty() {
            return Self::Machine;
        }

        // 4-7. CI/agent environment variables
        if env.var_exists("CI") {
            return Self::Machine;
        }
        if env.var_exists("GITHUB_ACTIONS") {
            return Self::Machine;
        }
        if env.var_exists("CLAUDE_CODE") {
            return Self::Machine;
        }
        if env.var_exists("CODEX_CLI") {
            return Self::Machine;
        }

        // 8. NO_COLOR convention
        if env.var_exists("NO_COLOR") {
            return Self::Machine;
        }

        // 9. Default to human mode
        Self::Human
    }

    /// Returns true if this mode should show rich formatting.
    #[must_use]
    pub const fn is_rich(&self) -> bool {
        matches!(self, Self::Human)
    }

    /// Returns true if this mode should output machine format (JSON/TOON).
    #[must_use]
    pub const fn is_json(&self) -> bool {
        matches!(self, Self::Machine)
    }

    /// Returns true if this mode should minimize output.
    #[must_use]
    pub const fn is_quiet(&self) -> bool {
        matches!(self, Self::Quiet)
    }
}

/// Centralized output dispatcher for all CLI output.
///
/// All output in rust_proxy flows through this dispatcher, which decides
/// whether to show rich formatted output (Human mode) or plain/JSON output
/// (Machine mode).
///
/// # Example
///
/// ```rust,ignore
/// let output = OutputDispatcher::from_flags(false, false, None);
///
/// // Human mode: shows rich formatting
/// output.print_rich("[bold]Hello[/] World");
///
/// // Machine mode: shows plain text
/// output.print_plain("Hello World");
/// ```
pub struct OutputDispatcher {
    mode: OutputMode,
    format: OutputFormat,
    /// Console is only created for Human mode to save resources.
    console: Option<Console>,
}

impl OutputDispatcher {
    /// Create a new dispatcher with the given mode.
    #[must_use]
    pub fn new(mode: OutputMode, format: OutputFormat) -> Self {
        let console = if mode.is_rich() {
            Some(Console::new())
        } else {
            None
        };

        Self {
            mode,
            format,
            console,
        }
    }

    /// Create a dispatcher by detecting mode from CLI flags.
    ///
    /// This is the primary constructor for CLI commands.
    #[must_use]
    pub fn from_flags(json: bool, quiet: bool, format_flag: Option<OutputFormat>) -> Self {
        let force_machine = json || format_flag.is_some();
        let mode = OutputMode::detect(force_machine, quiet);
        let format = OutputFormat::detect(format_flag);
        Self::new(mode, format)
    }

    /// Get the current output mode.
    #[must_use]
    pub const fn mode(&self) -> OutputMode {
        self.mode
    }

    /// Get the current machine output format.
    #[must_use]
    pub const fn format(&self) -> OutputFormat {
        self.format
    }

    /// Print text with rich markup formatting.
    ///
    /// In Human mode, parses markup like `[bold red]text[/]` and renders
    /// with colors and styles. In Machine/Quiet mode, this is a no-op.
    pub fn print_rich(&self, markup: &str) {
        if let Some(console) = &self.console {
            console.print(markup);
        }
    }

    /// Print plain text without formatting.
    ///
    /// This always prints in Human and Machine modes. In Quiet mode,
    /// this is a no-op.
    pub fn print_plain(&self, text: &str) {
        if self.mode.is_quiet() {
            return;
        }
        println!("{text}");
    }

    /// Print plain text to stderr.
    ///
    /// This always prints in Human and Machine modes. In Quiet mode,
    /// this is a no-op.
    pub fn eprint_plain(&self, text: &str) {
        if self.mode.is_quiet() {
            return;
        }
        eprintln!("{text}");
    }

    /// Print a value as JSON/TOON.
    ///
    /// In Machine mode, serializes to the configured machine format and prints.
    /// In Human mode, this is a no-op (use `print_rich` or `print_renderable` instead).
    pub fn print_json<T: Serialize>(&self, value: &T) {
        if !self.mode.is_json() {
            return;
        }
        if let Some(output) = self.encode_machine(value, true) {
            println!("{output}");
        }
    }

    /// Print a value as JSON/TOON (compact format for JSON).
    ///
    /// In Machine mode, serializes to compact JSON or TOON and prints.
    pub fn print_json_compact<T: Serialize>(&self, value: &T) {
        if !self.mode.is_json() {
            return;
        }
        if let Some(output) = self.encode_machine(value, false) {
            println!("{output}");
        }
    }

    fn encode_machine<T: Serialize>(&self, value: &T, pretty: bool) -> Option<String> {
        match self.format {
            OutputFormat::Json => {
                let json = if pretty {
                    serde_json::to_string_pretty(value)
                } else {
                    serde_json::to_string(value)
                };
                json.ok()
            }
            OutputFormat::Toon => {
                let json_value = serde_json::to_value(value).ok()?;
                Some(toon_rust::encode(json_value, None))
            }
        }
    }

    /// Print a rich renderable widget (table, panel, tree, etc.).
    ///
    /// In Human mode, renders the widget with full formatting.
    /// In Machine/Quiet mode, this is a no-op.
    pub fn print_renderable<R: Renderable>(&self, renderable: &R) {
        if let Some(console) = &self.console {
            console.print_renderable(renderable);
        }
    }

    /// Print a horizontal rule with an optional title.
    ///
    /// In Human mode, shows a styled divider line. In Machine/Quiet mode,
    /// this is a no-op.
    pub fn rule(&self, title: Option<&str>) {
        if let Some(console) = &self.console {
            let rule = match title {
                Some(t) => Rule::with_title(t),
                None => Rule::new(),
            };
            console.print_renderable(&rule);
        }
    }

    /// Print a blank line.
    ///
    /// In Human mode, prints a newline. In Machine/Quiet mode, this is a no-op.
    pub fn newline(&self) {
        if self.mode.is_rich() {
            println!();
        }
    }

    /// Flush stdout.
    ///
    /// Useful after writing partial output that should be displayed immediately.
    pub fn flush(&self) {
        let _ = io::stdout().flush();
    }

    /// Print styled text with a specific style.
    ///
    /// In Human mode, applies the style. In Machine mode, prints plain text.
    /// In Quiet mode, this is a no-op.
    pub fn print_styled(&self, text: &str, style: &Style) {
        match self.mode {
            OutputMode::Human => {
                if let Some(console) = &self.console {
                    let styled_text = Text::styled(text, style.clone());
                    console.print_text(&styled_text);
                }
            }
            OutputMode::Machine => println!("{text}"),
            OutputMode::Quiet => {}
        }
    }

    /// Check if rich output is available.
    #[must_use]
    pub const fn has_rich(&self) -> bool {
        self.console.is_some()
    }

    /// Display an error with optional context and suggestions.
    ///
    /// This provides a consistent error presentation across all commands:
    /// - In Human mode: Rich formatted error panel with suggestions
    /// - In Machine mode: JSON object with error details
    /// - In Quiet mode: Plain error message to stderr only
    ///
    /// # Arguments
    ///
    /// * `title` - Brief error title (e.g., "Connection Failed")
    /// * `message` - Detailed error message
    /// * `context` - Optional additional context (e.g., proxy ID, file path)
    /// * `suggestions` - Optional list of actionable suggestions
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// output.display_error(
    ///     "Unable to start daemon",
    ///     "Port 12345 is already in use",
    ///     Some("listen_port: 12345"),
    ///     Some(&["Check if another proxy is running", "Use a different port with --port"]),
    /// );
    /// ```
    pub fn display_error(
        &self,
        title: &str,
        message: &str,
        context: Option<&str>,
        suggestions: Option<&[&str]>,
    ) {
        match self.mode {
            OutputMode::Human => {
                if let Some(console) = &self.console {
                    // Build panel content
                    let mut content = format!("[bold red]{}[/]\n\n{}", title, message);

                    if let Some(ctx) = context {
                        content.push_str(&format!("\n\n[dim]Context:[/] {}", ctx));
                    }

                    if let Some(suggestions) = suggestions {
                        if !suggestions.is_empty() {
                            content.push_str("\n\n[dim]Suggestions:[/]");
                            for suggestion in suggestions {
                                content.push_str(&format!("\n  • {}", suggestion));
                            }
                        }
                    }

                    let panel = Panel::from_text(&content)
                        .title("Error")
                        .border_style(theme::styles::error_msg());
                    console.print_renderable(&panel);
                }
            }
            OutputMode::Machine => {
                // Machine format for structured consumption
                let mut error_obj = serde_json::json!({
                    "error": true,
                    "title": title,
                    "message": message,
                });

                if let Some(ctx) = context {
                    error_obj["context"] = serde_json::Value::String(ctx.to_string());
                }

                if let Some(suggestions) = suggestions {
                    error_obj["suggestions"] = serde_json::json!(suggestions);
                }

                if let Some(output) = self.encode_machine(&error_obj, true) {
                    eprintln!("{output}");
                }
            }
            OutputMode::Quiet => {
                // Minimal output to stderr
                eprintln!("Error: {}", message);
            }
        }
    }

    /// Display a warning with optional suggestions.
    ///
    /// Similar to display_error but uses warning styling.
    pub fn display_warning(&self, title: &str, message: &str, suggestions: Option<&[&str]>) {
        match self.mode {
            OutputMode::Human => {
                if let Some(console) = &self.console {
                    let mut content = format!("[bold yellow]{}[/]\n\n{}", title, message);

                    if let Some(suggestions) = suggestions {
                        if !suggestions.is_empty() {
                            content.push_str("\n\n[dim]Suggestions:[/]");
                            for suggestion in suggestions {
                                content.push_str(&format!("\n  • {}", suggestion));
                            }
                        }
                    }

                    let panel = Panel::from_text(&content)
                        .title("Warning")
                        .border_style(theme::styles::warning_msg());
                    console.print_renderable(&panel);
                }
            }
            OutputMode::Machine => {
                let mut warning_obj = serde_json::json!({
                    "warning": true,
                    "title": title,
                    "message": message,
                });

                if let Some(suggestions) = suggestions {
                    warning_obj["suggestions"] = serde_json::json!(suggestions);
                }

                if let Some(output) = self.encode_machine(&warning_obj, true) {
                    println!("{output}");
                }
            }
            OutputMode::Quiet => {
                // Warnings are suppressed in quiet mode
            }
        }
    }
}

impl Default for OutputDispatcher {
    fn default() -> Self {
        Self::from_flags(false, false, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // TtyState Tests
    // =========================================================================

    #[test]
    fn test_tty_state_is_tty() {
        assert!(TtyState::Yes.is_tty());
        assert!(!TtyState::No.is_tty());
    }

    // =========================================================================
    // Flag Override Tests
    // =========================================================================

    #[test]
    fn test_json_flag_forces_machine_mode() {
        let env = TestEnv::new();
        let mode = OutputMode::detect_with_env(true, false, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_quiet_flag_forces_quiet_mode() {
        let env = TestEnv::new();
        let mode = OutputMode::detect_with_env(false, true, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Quiet);
    }

    #[test]
    fn test_json_takes_precedence_over_quiet() {
        let env = TestEnv::new();
        let mode = OutputMode::detect_with_env(true, true, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_json_flag_overrides_tty() {
        let env = TestEnv::new();
        // Even with TTY, --json should force Machine mode
        let mode = OutputMode::detect_with_env(true, false, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_quiet_flag_overrides_tty() {
        let env = TestEnv::new();
        // Even with TTY, --quiet should force Quiet mode
        let mode = OutputMode::detect_with_env(false, true, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Quiet);
    }

    // =========================================================================
    // TTY Detection Tests
    // =========================================================================

    #[test]
    fn test_human_mode_when_tty() {
        let env = TestEnv::new();
        let mode = OutputMode::detect_with_env(false, false, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Human);
    }

    #[test]
    fn test_machine_mode_when_piped() {
        let env = TestEnv::new();
        let mode = OutputMode::detect_with_env(false, false, TtyState::No, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_no_tty_forces_machine_before_env_checks() {
        // Even if no env vars are set, non-TTY should be Machine
        let env = TestEnv::new();
        let mode = OutputMode::detect_with_env(false, false, TtyState::No, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    // =========================================================================
    // Environment Variable Tests - CI/Agent Detection
    // =========================================================================

    #[test]
    fn test_ci_env_forces_machine() {
        let env = TestEnv::new().with_var("CI", "true");
        let mode = OutputMode::detect_with_env(false, false, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_github_actions_env_forces_machine() {
        let env = TestEnv::new().with_var("GITHUB_ACTIONS", "true");
        let mode = OutputMode::detect_with_env(false, false, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_claude_code_env_forces_machine() {
        let env = TestEnv::new().with_var("CLAUDE_CODE", "1");
        let mode = OutputMode::detect_with_env(false, false, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_codex_cli_env_forces_machine() {
        let env = TestEnv::new().with_var("CODEX_CLI", "1");
        let mode = OutputMode::detect_with_env(false, false, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_no_color_env_forces_machine() {
        let env = TestEnv::new().with_var("NO_COLOR", "1");
        let mode = OutputMode::detect_with_env(false, false, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    // =========================================================================
    // Environment Variable Priority Tests
    // =========================================================================

    #[test]
    fn test_env_var_only_checked_when_tty() {
        // With TTY + env var, should be Machine
        let env = TestEnv::new().with_var("CI", "true");
        let mode = OutputMode::detect_with_env(false, false, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_multiple_env_vars_still_machine() {
        // Multiple env vars set - should still be Machine
        let env = TestEnv::new()
            .with_var("CI", "true")
            .with_var("GITHUB_ACTIONS", "true")
            .with_var("CLAUDE_CODE", "1");
        let mode = OutputMode::detect_with_env(false, false, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_ci_env_value_irrelevant() {
        // CI env var with any value should trigger Machine mode
        let env = TestEnv::new().with_var("CI", "false");
        let mode = OutputMode::detect_with_env(false, false, TtyState::Yes, &env);
        // The mere presence of CI forces Machine mode (value doesn't matter)
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_no_color_value_irrelevant() {
        // NO_COLOR with any value (even empty) should force Machine
        let env = TestEnv::new().with_var("NO_COLOR", "");
        let mode = OutputMode::detect_with_env(false, false, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    // =========================================================================
    // OutputMode is_* Method Tests
    // =========================================================================

    #[test]
    fn test_human_mode_is_methods() {
        assert!(OutputMode::Human.is_rich());
        assert!(!OutputMode::Human.is_json());
        assert!(!OutputMode::Human.is_quiet());
    }

    #[test]
    fn test_machine_mode_is_methods() {
        assert!(!OutputMode::Machine.is_rich());
        assert!(OutputMode::Machine.is_json());
        assert!(!OutputMode::Machine.is_quiet());
    }

    #[test]
    fn test_quiet_mode_is_methods() {
        assert!(!OutputMode::Quiet.is_rich());
        assert!(!OutputMode::Quiet.is_json());
        assert!(OutputMode::Quiet.is_quiet());
    }

    // =========================================================================
    // OutputFormat Tests
    // =========================================================================

    #[test]
    fn test_output_format_parse() {
        assert_eq!(OutputFormat::parse("json"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::parse("toon"), Some(OutputFormat::Toon));
        assert_eq!(OutputFormat::parse("  TOON "), Some(OutputFormat::Toon));
        assert_eq!(OutputFormat::parse("unknown"), None);
    }

    #[test]
    fn test_output_format_flag_precedence() {
        let env = TestEnv::new().with_var("RUST_PROXY_OUTPUT_FORMAT", "toon");
        let format = OutputFormat::detect_with_env(Some(OutputFormat::Json), &env);
        assert_eq!(format, OutputFormat::Json);
    }

    #[test]
    fn test_output_format_env_precedence() {
        let env = TestEnv::new()
            .with_var("RUST_PROXY_OUTPUT_FORMAT", "toon")
            .with_var("TOON_DEFAULT_FORMAT", "json");
        let format = OutputFormat::detect_with_env(None, &env);
        assert_eq!(format, OutputFormat::Toon);
    }

    #[test]
    fn test_output_format_env_fallback() {
        let env = TestEnv::new().with_var("TOON_DEFAULT_FORMAT", "toon");
        let format = OutputFormat::detect_with_env(None, &env);
        assert_eq!(format, OutputFormat::Toon);
    }

    #[test]
    fn test_output_format_invalid_env_defaults_json() {
        let env = TestEnv::new().with_var("RUST_PROXY_OUTPUT_FORMAT", "bogus");
        let format = OutputFormat::detect_with_env(None, &env);
        assert_eq!(format, OutputFormat::Json);
    }

    // =========================================================================
    // OutputDispatcher Construction Tests
    // =========================================================================

    #[test]
    fn test_dispatcher_human_mode_has_console() {
        let dispatcher = OutputDispatcher::new(OutputMode::Human, OutputFormat::Json);
        assert_eq!(dispatcher.mode(), OutputMode::Human);
        assert!(dispatcher.has_rich());
    }

    #[test]
    fn test_dispatcher_machine_mode_no_console() {
        let dispatcher = OutputDispatcher::new(OutputMode::Machine, OutputFormat::Json);
        assert_eq!(dispatcher.mode(), OutputMode::Machine);
        assert!(!dispatcher.has_rich());
    }

    #[test]
    fn test_dispatcher_quiet_mode_no_console() {
        let dispatcher = OutputDispatcher::new(OutputMode::Quiet, OutputFormat::Json);
        assert_eq!(dispatcher.mode(), OutputMode::Quiet);
        assert!(!dispatcher.has_rich());
    }

    #[test]
    fn test_dispatcher_from_flags_json() {
        let dispatcher = OutputDispatcher::from_flags(true, false, None);
        assert_eq!(dispatcher.mode(), OutputMode::Machine);
        assert!(!dispatcher.has_rich());
    }

    #[test]
    fn test_dispatcher_from_flags_format_forces_machine() {
        let dispatcher = OutputDispatcher::from_flags(false, false, Some(OutputFormat::Toon));
        assert_eq!(dispatcher.mode(), OutputMode::Machine);
        assert_eq!(dispatcher.format(), OutputFormat::Toon);
        assert!(!dispatcher.has_rich());
    }

    #[test]
    fn test_dispatcher_from_flags_quiet() {
        let dispatcher = OutputDispatcher::from_flags(false, true, None);
        assert_eq!(dispatcher.mode(), OutputMode::Quiet);
        assert!(!dispatcher.has_rich());
    }

    #[test]
    fn test_dispatcher_default() {
        // Default should detect mode from environment
        // In test environment (no TTY), this should be Machine
        let dispatcher = OutputDispatcher::default();
        // Note: actual mode depends on test runner TTY state
        // Just verify it doesn't panic
        let _ = dispatcher.mode();
    }

    #[test]
    fn test_encode_machine_toon_roundtrip() {
        #[derive(Serialize)]
        struct Sample {
            id: String,
            enabled: bool,
            ports: Vec<u16>,
        }

        let sample = Sample {
            id: "proxy-1".to_string(),
            enabled: true,
            ports: vec![80, 443],
        };

        let dispatcher = OutputDispatcher::new(OutputMode::Machine, OutputFormat::Toon);
        let output = dispatcher
            .encode_machine(&sample, true)
            .expect("toon output should serialize");
        let decoded = toon_rust::try_decode(&output, None).expect("toon decode failed");
        let expected = serde_json::to_value(&sample).expect("json encode failed");
        assert_eq!(decoded, expected.into());
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[test]
    fn test_human_mode_with_clean_env() {
        // TTY with no special env vars should be Human
        let env = TestEnv::new();
        let mode = OutputMode::detect_with_env(false, false, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Human);
    }

    #[test]
    fn test_all_flags_false_no_tty_is_machine() {
        let env = TestEnv::new();
        let mode = OutputMode::detect_with_env(false, false, TtyState::No, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_detection_order_json_before_quiet() {
        // Verify --json takes precedence over --quiet
        let env = TestEnv::new();
        let mode = OutputMode::detect_with_env(true, true, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_detection_order_flags_before_tty() {
        // Verify flags take precedence over TTY state
        let env = TestEnv::new();

        // --json should override non-TTY being Machine
        let mode = OutputMode::detect_with_env(true, false, TtyState::No, &env);
        assert_eq!(mode, OutputMode::Machine);

        // --quiet should work with TTY
        let mode = OutputMode::detect_with_env(false, true, TtyState::Yes, &env);
        assert_eq!(mode, OutputMode::Quiet);
    }

    #[test]
    fn test_detection_order_tty_before_env() {
        // Non-TTY should force Machine before env vars are checked
        let env = TestEnv::new(); // No CI env vars
        let mode = OutputMode::detect_with_env(false, false, TtyState::No, &env);
        assert_eq!(mode, OutputMode::Machine);
    }

    // =========================================================================
    // TestEnv Tests (meta-tests for test infrastructure)
    // =========================================================================

    #[test]
    fn test_test_env_empty() {
        let env = TestEnv::new();
        assert!(!env.var_exists("CI"));
        assert!(!env.var_exists("NONEXISTENT"));
    }

    #[test]
    fn test_test_env_with_var() {
        let env = TestEnv::new().with_var("CI", "true");
        assert!(env.var_exists("CI"));
        assert!(!env.var_exists("GITHUB_ACTIONS"));
    }

    #[test]
    fn test_test_env_multiple_vars() {
        let env = TestEnv::new()
            .with_var("CI", "true")
            .with_var("GITHUB_ACTIONS", "true")
            .with_var("CUSTOM", "value");
        assert!(env.var_exists("CI"));
        assert!(env.var_exists("GITHUB_ACTIONS"));
        assert!(env.var_exists("CUSTOM"));
        assert!(!env.var_exists("NONEXISTENT"));
    }

    #[test]
    fn test_test_env_chainable() {
        // Verify fluent API works
        let env = TestEnv::new()
            .with_var("A", "1")
            .with_var("B", "2")
            .with_var("C", "3");
        assert!(env.var_exists("A"));
        assert!(env.var_exists("B"));
        assert!(env.var_exists("C"));
    }
}

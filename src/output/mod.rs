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
//! let output = OutputDispatcher::from_flags(args.json, args.quiet);
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
    /// JSON flag or piped output - show plain text or JSON only.
    Machine,
    /// Minimal output for scripting - only essential messages.
    Quiet,
}

impl OutputMode {
    /// Detect the appropriate output mode based on flags and environment.
    ///
    /// Detection order (first match wins):
    /// 1. `--json` flag → Machine
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
        // 1. Explicit --json flag
        if json_flag {
            return Self::Machine;
        }

        // 2. Explicit --quiet flag
        if quiet_flag {
            return Self::Quiet;
        }

        // 3. stdout is not a TTY (piped or redirected)
        if !io::stdout().is_terminal() {
            return Self::Machine;
        }

        // 4-7. CI/agent environment variables
        if std::env::var("CI").is_ok() {
            return Self::Machine;
        }
        if std::env::var("GITHUB_ACTIONS").is_ok() {
            return Self::Machine;
        }
        if std::env::var("CLAUDE_CODE").is_ok() {
            return Self::Machine;
        }
        if std::env::var("CODEX_CLI").is_ok() {
            return Self::Machine;
        }

        // 8. NO_COLOR convention
        if std::env::var("NO_COLOR").is_ok() {
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

    /// Returns true if this mode should output JSON.
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
/// let output = OutputDispatcher::from_flags(false, false);
///
/// // Human mode: shows rich formatting
/// output.print_rich("[bold]Hello[/] World");
///
/// // Machine mode: shows plain text
/// output.print_plain("Hello World");
/// ```
pub struct OutputDispatcher {
    mode: OutputMode,
    /// Console is only created for Human mode to save resources.
    console: Option<Console>,
}

impl OutputDispatcher {
    /// Create a new dispatcher with the given mode.
    #[must_use]
    pub fn new(mode: OutputMode) -> Self {
        let console = if mode.is_rich() {
            Some(Console::new())
        } else {
            None
        };

        Self { mode, console }
    }

    /// Create a dispatcher by detecting mode from CLI flags.
    ///
    /// This is the primary constructor for CLI commands.
    #[must_use]
    pub fn from_flags(json: bool, quiet: bool) -> Self {
        Self::new(OutputMode::detect(json, quiet))
    }

    /// Get the current output mode.
    #[must_use]
    pub const fn mode(&self) -> OutputMode {
        self.mode
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

    /// Print a value as JSON.
    ///
    /// In Machine mode, serializes to JSON and prints. In Human mode,
    /// this is a no-op (use `print_rich` or `print_renderable` instead).
    pub fn print_json<T: Serialize>(&self, value: &T) {
        if !self.mode.is_json() {
            return;
        }
        if let Ok(json) = serde_json::to_string_pretty(value) {
            println!("{json}");
        }
    }

    /// Print a value as JSON (compact format).
    ///
    /// In Machine mode, serializes to compact JSON and prints.
    pub fn print_json_compact<T: Serialize>(&self, value: &T) {
        if !self.mode.is_json() {
            return;
        }
        if let Ok(json) = serde_json::to_string(value) {
            println!("{json}");
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
}

impl Default for OutputDispatcher {
    fn default() -> Self {
        Self::from_flags(false, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_from_json_flag() {
        let mode = OutputMode::detect(true, false);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_mode_from_quiet_flag() {
        let mode = OutputMode::detect(false, true);
        assert_eq!(mode, OutputMode::Quiet);
    }

    #[test]
    fn test_json_takes_precedence_over_quiet() {
        let mode = OutputMode::detect(true, true);
        assert_eq!(mode, OutputMode::Machine);
    }

    #[test]
    fn test_mode_is_methods() {
        assert!(OutputMode::Human.is_rich());
        assert!(!OutputMode::Human.is_json());
        assert!(!OutputMode::Human.is_quiet());

        assert!(!OutputMode::Machine.is_rich());
        assert!(OutputMode::Machine.is_json());
        assert!(!OutputMode::Machine.is_quiet());

        assert!(!OutputMode::Quiet.is_rich());
        assert!(!OutputMode::Quiet.is_json());
        assert!(OutputMode::Quiet.is_quiet());
    }

    #[test]
    fn test_dispatcher_from_flags() {
        let dispatcher = OutputDispatcher::from_flags(true, false);
        assert_eq!(dispatcher.mode(), OutputMode::Machine);
        assert!(!dispatcher.has_rich());

        let dispatcher = OutputDispatcher::from_flags(false, true);
        assert_eq!(dispatcher.mode(), OutputMode::Quiet);
        assert!(!dispatcher.has_rich());
    }
}

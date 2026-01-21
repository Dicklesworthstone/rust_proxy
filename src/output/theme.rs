// Allow dead_code warnings - these are public APIs that will be used in bd-thy integration.
#![allow(dead_code)]

//! Semantic color theme for rust_proxy's visual identity.
//!
//! This module defines a cohesive color palette that creates a professional,
//! consistent experience across all CLI commands. Colors are chosen to:
//!
//! - Convey trust and security (blues, cyans for networking themes)
//! - Use traffic-light semantics (green/yellow/red) for status
//! - Maintain clarity in 256-color terminals (no truecolor-only colors)
//!
//! # Example
//!
//! ```rust,ignore
//! use rust_proxy::output::theme::{theme, styles};
//!
//! // Access theme colors
//! let t = theme();
//! let style = Style::new().color(t.success.clone());
//!
//! // Use style presets
//! let header_style = styles::header();
//! ```

use rich_rust::prelude::*;
use std::sync::OnceLock;

/// Semantic color theme for rust_proxy.
///
/// All colors are chosen to work in 256-color terminals and follow
/// established conventions (green=good, red=bad, etc.).
#[derive(Debug, Clone)]
pub struct Theme {
    // Status colors (traffic light semantics)
    /// Green - operations succeeded, positive outcomes
    pub success: Color,
    /// Yellow - attention needed, caution
    pub warning: Color,
    /// Red - failures, errors
    pub error: Color,
    /// Blue - informational messages
    pub info: Color,

    // Element colors
    /// Cyan - headers, primary elements, active items
    pub primary: Color,
    /// Bright blue - secondary accent, supporting elements
    pub secondary: Color,
    /// Gray (bright black) - dim/inactive content, timestamps
    pub muted: Color,
    /// Bright white - emphasized values, key data
    pub highlight: Color,

    // Proxy health colors (match HealthStatus enum in state.rs)
    /// Bright green - proxy is healthy and responding
    pub healthy: Color,
    /// Bright yellow - proxy is slow but working (degraded)
    pub degraded: Color,
    /// Bright red - proxy is failing health checks
    pub unhealthy: Color,
    /// Gray - health status not yet checked
    pub unknown: Color,

    // Data type colors (consistent highlighting across commands)
    /// Bright magenta - byte counts (sent/received)
    pub bytes: Color,
    /// Bright cyan - latency/ping times
    pub latency: Color,
    /// Bright black (gray) - timestamps, dates
    pub timestamp: Color,
    /// Bright blue - target domains
    pub domain: Color,
    /// Bright yellow - IP addresses
    pub ip: Color,
    /// Magenta - provider names (AWS, Cloudflare, etc.)
    pub provider: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            // Status colors
            success: Color::parse("green").unwrap_or_else(|_| Color::from_ansi(2)),
            warning: Color::parse("yellow").unwrap_or_else(|_| Color::from_ansi(3)),
            error: Color::parse("red").unwrap_or_else(|_| Color::from_ansi(1)),
            info: Color::parse("blue").unwrap_or_else(|_| Color::from_ansi(4)),

            // Element colors
            primary: Color::parse("cyan").unwrap_or_else(|_| Color::from_ansi(6)),
            secondary: Color::parse("bright_blue").unwrap_or_else(|_| Color::from_ansi(12)),
            muted: Color::parse("bright_black").unwrap_or_else(|_| Color::from_ansi(8)),
            highlight: Color::parse("bright_white").unwrap_or_else(|_| Color::from_ansi(15)),

            // Health colors
            healthy: Color::parse("bright_green").unwrap_or_else(|_| Color::from_ansi(10)),
            degraded: Color::parse("bright_yellow").unwrap_or_else(|_| Color::from_ansi(11)),
            unhealthy: Color::parse("bright_red").unwrap_or_else(|_| Color::from_ansi(9)),
            unknown: Color::parse("bright_black").unwrap_or_else(|_| Color::from_ansi(8)),

            // Data type colors
            bytes: Color::parse("bright_magenta").unwrap_or_else(|_| Color::from_ansi(13)),
            latency: Color::parse("bright_cyan").unwrap_or_else(|_| Color::from_ansi(14)),
            timestamp: Color::parse("bright_black").unwrap_or_else(|_| Color::from_ansi(8)),
            domain: Color::parse("bright_blue").unwrap_or_else(|_| Color::from_ansi(12)),
            ip: Color::parse("bright_yellow").unwrap_or_else(|_| Color::from_ansi(11)),
            provider: Color::parse("magenta").unwrap_or_else(|_| Color::from_ansi(5)),
        }
    }
}

impl Theme {
    /// Create a new theme with default colors.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a color for the given health status.
    ///
    /// Maps the `HealthStatus` enum values to appropriate colors:
    /// - Healthy → bright green
    /// - Degraded → bright yellow
    /// - Unhealthy → bright red
    /// - Unknown → gray
    #[must_use]
    pub fn health_color(&self, status: &str) -> Color {
        match status.to_lowercase().as_str() {
            "healthy" => self.healthy.clone(),
            "degraded" => self.degraded.clone(),
            "unhealthy" => self.unhealthy.clone(),
            _ => self.unknown.clone(),
        }
    }
}

/// Global theme accessor.
///
/// Returns a reference to the singleton theme instance. The theme is
/// initialized on first access and cached for the lifetime of the program.
///
/// # Example
///
/// ```rust,ignore
/// use rust_proxy::output::theme::theme;
///
/// let t = theme();
/// println!("Success color: {:?}", t.success);
/// ```
#[must_use]
pub fn theme() -> &'static Theme {
    static THEME: OnceLock<Theme> = OnceLock::new();
    THEME.get_or_init(Theme::default)
}

/// Style presets for common UI elements.
///
/// These functions create pre-configured styles that ensure visual consistency
/// across all commands. Use these instead of manually creating styles.
pub mod styles {
    use super::*;

    /// Style for main headers and titles.
    ///
    /// Bold + primary color (cyan).
    #[must_use]
    pub fn header() -> Style {
        Style::new().bold().color(theme().primary.clone())
    }

    /// Style for subheaders and secondary titles.
    ///
    /// Secondary color (bright blue).
    #[must_use]
    pub fn subheader() -> Style {
        Style::new().color(theme().secondary.clone())
    }

    /// Style for labels and field names.
    ///
    /// Muted color (gray) for de-emphasis.
    #[must_use]
    pub fn label() -> Style {
        Style::new().color(theme().muted.clone())
    }

    /// Style for values and primary data.
    ///
    /// Highlight color (bright white) for emphasis.
    #[must_use]
    pub fn value() -> Style {
        Style::new().color(theme().highlight.clone())
    }

    /// Style for success messages.
    ///
    /// Bold + success color (green).
    #[must_use]
    pub fn success_msg() -> Style {
        Style::new().bold().color(theme().success.clone())
    }

    /// Style for error messages.
    ///
    /// Bold + error color (red).
    #[must_use]
    pub fn error_msg() -> Style {
        Style::new().bold().color(theme().error.clone())
    }

    /// Style for warning messages.
    ///
    /// Bold + warning color (yellow).
    #[must_use]
    pub fn warning_msg() -> Style {
        Style::new().bold().color(theme().warning.clone())
    }

    /// Style for informational messages.
    ///
    /// Info color (blue).
    #[must_use]
    pub fn info_msg() -> Style {
        Style::new().color(theme().info.clone())
    }

    /// Style for byte count values.
    ///
    /// Bytes color (bright magenta).
    #[must_use]
    pub fn bytes() -> Style {
        Style::new().color(theme().bytes.clone())
    }

    /// Style for latency/ping values.
    ///
    /// Latency color (bright cyan).
    #[must_use]
    pub fn latency() -> Style {
        Style::new().color(theme().latency.clone())
    }

    /// Style for timestamps and dates.
    ///
    /// Timestamp color (gray).
    #[must_use]
    pub fn timestamp() -> Style {
        Style::new().color(theme().timestamp.clone())
    }

    /// Style for domain names.
    ///
    /// Domain color (bright blue).
    #[must_use]
    pub fn domain() -> Style {
        Style::new().color(theme().domain.clone())
    }

    /// Style for IP addresses.
    ///
    /// IP color (bright yellow).
    #[must_use]
    pub fn ip() -> Style {
        Style::new().color(theme().ip.clone())
    }

    /// Style for provider names.
    ///
    /// Provider color (magenta).
    #[must_use]
    pub fn provider() -> Style {
        Style::new().color(theme().provider.clone())
    }

    /// Style for healthy status.
    ///
    /// Bold + healthy color (bright green).
    #[must_use]
    pub fn healthy() -> Style {
        Style::new().bold().color(theme().healthy.clone())
    }

    /// Style for degraded status.
    ///
    /// Bold + degraded color (bright yellow).
    #[must_use]
    pub fn degraded() -> Style {
        Style::new().bold().color(theme().degraded.clone())
    }

    /// Style for unhealthy status.
    ///
    /// Bold + unhealthy color (bright red).
    #[must_use]
    pub fn unhealthy() -> Style {
        Style::new().bold().color(theme().unhealthy.clone())
    }

    /// Style for unknown status.
    ///
    /// Dim + unknown color (gray).
    #[must_use]
    pub fn unknown() -> Style {
        Style::new().dim().color(theme().unknown.clone())
    }

    /// Get the appropriate health style for a status string.
    ///
    /// # Arguments
    ///
    /// * `status` - One of "healthy", "degraded", "unhealthy", or "unknown"
    #[must_use]
    pub fn health(status: &str) -> Style {
        match status.to_lowercase().as_str() {
            "healthy" => healthy(),
            "degraded" => degraded(),
            "unhealthy" => unhealthy(),
            _ => unknown(),
        }
    }

    /// Style for active/enabled items.
    ///
    /// Bold + primary color (cyan).
    #[must_use]
    pub fn active() -> Style {
        Style::new().bold().color(theme().primary.clone())
    }

    /// Style for inactive/disabled items.
    ///
    /// Dim + muted color (gray).
    #[must_use]
    pub fn inactive() -> Style {
        Style::new().dim().color(theme().muted.clone())
    }

    /// Style for emphasized/important text.
    ///
    /// Bold + highlight color (bright white).
    #[must_use]
    pub fn emphasis() -> Style {
        Style::new().bold().color(theme().highlight.clone())
    }

    /// Style for dimmed/de-emphasized text.
    ///
    /// Dim only, no color override.
    #[must_use]
    pub fn dimmed() -> Style {
        Style::new().dim()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_theme_singleton() {
        let t1 = theme();
        let t2 = theme();
        // Both should point to the same instance
        assert!(std::ptr::eq(t1, t2));
    }

    #[test]
    fn test_theme_colors_initialized() {
        let t = theme();
        // All colors should be valid (not default/empty)
        // We can't easily test Color equality, but we can ensure they're created
        let _ = &t.success;
        let _ = &t.warning;
        let _ = &t.error;
        let _ = &t.info;
        let _ = &t.primary;
        let _ = &t.secondary;
        let _ = &t.muted;
        let _ = &t.highlight;
        let _ = &t.healthy;
        let _ = &t.degraded;
        let _ = &t.unhealthy;
        let _ = &t.unknown;
        let _ = &t.bytes;
        let _ = &t.latency;
        let _ = &t.timestamp;
        let _ = &t.domain;
        let _ = &t.ip;
        let _ = &t.provider;
    }

    #[test]
    fn test_health_color_mapping() {
        let t = theme();

        // Test case-insensitive matching
        let _ = t.health_color("healthy");
        let _ = t.health_color("HEALTHY");
        let _ = t.health_color("Degraded");
        let _ = t.health_color("unhealthy");
        let _ = t.health_color("unknown");
        let _ = t.health_color("invalid"); // Should return unknown
    }

    #[test]
    fn test_style_presets() {
        // Ensure all style presets can be created without panicking
        let _ = styles::header();
        let _ = styles::subheader();
        let _ = styles::label();
        let _ = styles::value();
        let _ = styles::success_msg();
        let _ = styles::error_msg();
        let _ = styles::warning_msg();
        let _ = styles::info_msg();
        let _ = styles::bytes();
        let _ = styles::latency();
        let _ = styles::timestamp();
        let _ = styles::domain();
        let _ = styles::ip();
        let _ = styles::provider();
        let _ = styles::healthy();
        let _ = styles::degraded();
        let _ = styles::unhealthy();
        let _ = styles::unknown();
        let _ = styles::active();
        let _ = styles::inactive();
        let _ = styles::emphasis();
        let _ = styles::dimmed();
    }

    #[test]
    fn test_health_style_mapping() {
        // Test the health() function with various inputs
        let _ = styles::health("healthy");
        let _ = styles::health("degraded");
        let _ = styles::health("unhealthy");
        let _ = styles::health("unknown");
        let _ = styles::health("anything_else");
    }
}

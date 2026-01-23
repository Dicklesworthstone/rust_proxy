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

    // =========================================================================
    // Theme Singleton & Construction Tests
    // =========================================================================

    #[test]
    fn test_theme_singleton() {
        let t1 = theme();
        let t2 = theme();
        // Both should point to the same instance
        assert!(std::ptr::eq(t1, t2));
    }

    #[test]
    fn test_theme_singleton_consistent_across_calls() {
        // Multiple calls should always return the same instance
        for _ in 0..100 {
            let t = theme();
            assert!(std::ptr::eq(t, theme()));
        }
    }

    #[test]
    fn test_theme_new_equals_default() {
        // Theme::new() should produce the same result as Theme::default()
        let new_theme = Theme::new();
        let default_theme = Theme::default();

        // Compare via Debug formatting since Color doesn't implement Eq
        assert_eq!(format!("{:?}", new_theme), format!("{:?}", default_theme));
    }

    // =========================================================================
    // Theme Colors Initialization Tests
    // =========================================================================

    #[test]
    fn test_theme_colors_initialized() {
        let t = theme();
        // All colors should be valid (not default/empty)
        // Verify each field can be accessed and has a Debug representation
        assert!(!format!("{:?}", t.success).is_empty());
        assert!(!format!("{:?}", t.warning).is_empty());
        assert!(!format!("{:?}", t.error).is_empty());
        assert!(!format!("{:?}", t.info).is_empty());
        assert!(!format!("{:?}", t.primary).is_empty());
        assert!(!format!("{:?}", t.secondary).is_empty());
        assert!(!format!("{:?}", t.muted).is_empty());
        assert!(!format!("{:?}", t.highlight).is_empty());
        assert!(!format!("{:?}", t.healthy).is_empty());
        assert!(!format!("{:?}", t.degraded).is_empty());
        assert!(!format!("{:?}", t.unhealthy).is_empty());
        assert!(!format!("{:?}", t.unknown).is_empty());
        assert!(!format!("{:?}", t.bytes).is_empty());
        assert!(!format!("{:?}", t.latency).is_empty());
        assert!(!format!("{:?}", t.timestamp).is_empty());
        assert!(!format!("{:?}", t.domain).is_empty());
        assert!(!format!("{:?}", t.ip).is_empty());
        assert!(!format!("{:?}", t.provider).is_empty());
    }

    #[test]
    fn test_theme_clone() {
        let t = theme();
        let cloned = t.clone();

        // Cloned theme should have the same values
        assert_eq!(format!("{:?}", t), format!("{:?}", cloned));
    }

    // =========================================================================
    // Semantic Color Tests - Traffic Light Semantics
    // =========================================================================

    /// Helper to check if a color Debug output matches expected ANSI codes
    fn color_matches_ansi(debug: &str, codes: &[u8]) -> bool {
        // Color debug format: Color { name: "color(N)", ..., number: Some(N), ... }
        for code in codes {
            if debug.contains(&format!("number: Some({})", code))
                || debug.contains(&format!("color({})", code))
            {
                return true;
            }
        }
        false
    }

    #[test]
    fn test_success_color_is_green_family() {
        let t = Theme::default();
        let debug = format!("{:?}", t.success);
        // Green family: ANSI 2 (green) or 10 (bright green)
        assert!(
            debug.to_lowercase().contains("green") || color_matches_ansi(&debug, &[2, 10]),
            "Success color should be green family, got: {}",
            debug
        );
    }

    #[test]
    fn test_warning_color_is_yellow_family() {
        let t = Theme::default();
        let debug = format!("{:?}", t.warning);
        // Yellow family: ANSI 3 (yellow) or 11 (bright yellow)
        assert!(
            debug.to_lowercase().contains("yellow") || color_matches_ansi(&debug, &[3, 11]),
            "Warning color should be yellow family, got: {}",
            debug
        );
    }

    #[test]
    fn test_error_color_is_red_family() {
        let t = Theme::default();
        let debug = format!("{:?}", t.error);
        // Red family: ANSI 1 (red) or 9 (bright red)
        assert!(
            debug.to_lowercase().contains("red") || color_matches_ansi(&debug, &[1, 9]),
            "Error color should be red family, got: {}",
            debug
        );
    }

    #[test]
    fn test_info_color_is_blue_family() {
        let t = Theme::default();
        let debug = format!("{:?}", t.info);
        // Blue family: ANSI 4 (blue) or 12 (bright blue)
        assert!(
            debug.to_lowercase().contains("blue") || color_matches_ansi(&debug, &[4, 12]),
            "Info color should be blue family, got: {}",
            debug
        );
    }

    #[test]
    fn test_primary_color_is_cyan_family() {
        let t = Theme::default();
        let debug = format!("{:?}", t.primary);
        // Cyan family: ANSI 6 (cyan) or 14 (bright cyan)
        assert!(
            debug.to_lowercase().contains("cyan") || color_matches_ansi(&debug, &[6, 14]),
            "Primary color should be cyan family, got: {}",
            debug
        );
    }

    // =========================================================================
    // Health Status Color Tests
    // =========================================================================

    #[test]
    fn test_healthy_color_is_bright_green() {
        let t = Theme::default();
        let debug = format!("{:?}", t.healthy);
        // Bright green is ANSI 10
        assert!(
            debug.to_lowercase().contains("green") || color_matches_ansi(&debug, &[2, 10]),
            "Healthy color should be bright green, got: {}",
            debug
        );
    }

    #[test]
    fn test_degraded_color_is_bright_yellow() {
        let t = Theme::default();
        let debug = format!("{:?}", t.degraded);
        // Bright yellow is ANSI 11
        assert!(
            debug.to_lowercase().contains("yellow") || color_matches_ansi(&debug, &[3, 11]),
            "Degraded color should be bright yellow, got: {}",
            debug
        );
    }

    #[test]
    fn test_unhealthy_color_is_bright_red() {
        let t = Theme::default();
        let debug = format!("{:?}", t.unhealthy);
        // Bright red is ANSI 9
        assert!(
            debug.to_lowercase().contains("red") || color_matches_ansi(&debug, &[1, 9]),
            "Unhealthy color should be bright red, got: {}",
            debug
        );
    }

    #[test]
    fn test_unknown_color_is_gray() {
        let t = Theme::default();
        let debug = format!("{:?}", t.unknown);
        // Gray is typically bright_black (ANSI 8)
        assert!(
            debug.to_lowercase().contains("black")
                || debug.to_lowercase().contains("gray")
                || debug.to_lowercase().contains("grey")
                || color_matches_ansi(&debug, &[8]),
            "Unknown color should be gray (bright black), got: {}",
            debug
        );
    }

    // =========================================================================
    // health_color Method Tests
    // =========================================================================

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
    fn test_health_color_case_insensitivity() {
        let t = theme();

        // All case variations should produce the same color
        let healthy_lower = format!("{:?}", t.health_color("healthy"));
        let healthy_upper = format!("{:?}", t.health_color("HEALTHY"));
        let healthy_mixed = format!("{:?}", t.health_color("HeAlThY"));

        assert_eq!(healthy_lower, healthy_upper);
        assert_eq!(healthy_lower, healthy_mixed);

        let degraded_lower = format!("{:?}", t.health_color("degraded"));
        let degraded_upper = format!("{:?}", t.health_color("DEGRADED"));
        assert_eq!(degraded_lower, degraded_upper);

        let unhealthy_lower = format!("{:?}", t.health_color("unhealthy"));
        let unhealthy_upper = format!("{:?}", t.health_color("UNHEALTHY"));
        assert_eq!(unhealthy_lower, unhealthy_upper);
    }

    #[test]
    fn test_health_color_invalid_returns_unknown() {
        let t = theme();

        // Any unrecognized status should return the unknown color
        let unknown_color = format!("{:?}", t.health_color("unknown"));
        let invalid_color = format!("{:?}", t.health_color("invalid"));
        let random_color = format!("{:?}", t.health_color("random_status"));
        let empty_color = format!("{:?}", t.health_color(""));

        assert_eq!(unknown_color, invalid_color);
        assert_eq!(unknown_color, random_color);
        assert_eq!(unknown_color, empty_color);
    }

    #[test]
    fn test_health_color_distinct_values() {
        let t = theme();

        // Each health status should have a distinct color
        let healthy = format!("{:?}", t.health_color("healthy"));
        let degraded = format!("{:?}", t.health_color("degraded"));
        let unhealthy = format!("{:?}", t.health_color("unhealthy"));
        let unknown = format!("{:?}", t.health_color("unknown"));

        // All statuses should have different colors
        assert_ne!(healthy, degraded, "healthy and degraded should differ");
        assert_ne!(healthy, unhealthy, "healthy and unhealthy should differ");
        assert_ne!(degraded, unhealthy, "degraded and unhealthy should differ");
        // Note: unknown color might match muted/timestamp which is OK
    }

    // =========================================================================
    // Data Type Color Tests
    // =========================================================================

    #[test]
    fn test_bytes_color_is_magenta_family() {
        let t = Theme::default();
        let debug = format!("{:?}", t.bytes);
        // Magenta family: ANSI 5 (magenta) or 13 (bright magenta)
        assert!(
            debug.to_lowercase().contains("magenta") || color_matches_ansi(&debug, &[5, 13]),
            "Bytes color should be magenta family, got: {}",
            debug
        );
    }

    #[test]
    fn test_latency_color_is_cyan_family() {
        let t = Theme::default();
        let debug = format!("{:?}", t.latency);
        // Cyan family: ANSI 6 (cyan) or 14 (bright cyan)
        assert!(
            debug.to_lowercase().contains("cyan") || color_matches_ansi(&debug, &[6, 14]),
            "Latency color should be cyan family, got: {}",
            debug
        );
    }

    #[test]
    fn test_ip_color_is_yellow_family() {
        let t = Theme::default();
        let debug = format!("{:?}", t.ip);
        // Yellow family: ANSI 3 (yellow) or 11 (bright yellow)
        assert!(
            debug.to_lowercase().contains("yellow") || color_matches_ansi(&debug, &[3, 11]),
            "IP color should be yellow family, got: {}",
            debug
        );
    }

    // =========================================================================
    // Style Preset Tests - Basic Creation
    // =========================================================================

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

    // =========================================================================
    // Style Preset Tests - Expected Properties
    // =========================================================================

    #[test]
    fn test_header_style_is_bold() {
        let style = styles::header();
        let debug = format!("{:?}", style);
        // Style should include bold attribute
        assert!(
            debug.to_lowercase().contains("bold"),
            "Header style should be bold, got: {}",
            debug
        );
    }

    #[test]
    fn test_success_msg_style_is_bold() {
        let style = styles::success_msg();
        let debug = format!("{:?}", style);
        assert!(
            debug.to_lowercase().contains("bold"),
            "Success message style should be bold, got: {}",
            debug
        );
    }

    #[test]
    fn test_error_msg_style_is_bold() {
        let style = styles::error_msg();
        let debug = format!("{:?}", style);
        assert!(
            debug.to_lowercase().contains("bold"),
            "Error message style should be bold, got: {}",
            debug
        );
    }

    #[test]
    fn test_warning_msg_style_is_bold() {
        let style = styles::warning_msg();
        let debug = format!("{:?}", style);
        assert!(
            debug.to_lowercase().contains("bold"),
            "Warning message style should be bold, got: {}",
            debug
        );
    }

    #[test]
    fn test_dimmed_style_is_dim() {
        let style = styles::dimmed();
        let debug = format!("{:?}", style);
        assert!(
            debug.to_lowercase().contains("dim"),
            "Dimmed style should be dim, got: {}",
            debug
        );
    }

    #[test]
    fn test_unknown_style_is_dim() {
        let style = styles::unknown();
        let debug = format!("{:?}", style);
        assert!(
            debug.to_lowercase().contains("dim"),
            "Unknown style should be dim, got: {}",
            debug
        );
    }

    #[test]
    fn test_inactive_style_is_dim() {
        let style = styles::inactive();
        let debug = format!("{:?}", style);
        assert!(
            debug.to_lowercase().contains("dim"),
            "Inactive style should be dim, got: {}",
            debug
        );
    }

    #[test]
    fn test_emphasis_style_is_bold() {
        let style = styles::emphasis();
        let debug = format!("{:?}", style);
        assert!(
            debug.to_lowercase().contains("bold"),
            "Emphasis style should be bold, got: {}",
            debug
        );
    }

    #[test]
    fn test_healthy_style_is_bold() {
        let style = styles::healthy();
        let debug = format!("{:?}", style);
        assert!(
            debug.to_lowercase().contains("bold"),
            "Healthy style should be bold, got: {}",
            debug
        );
    }

    #[test]
    fn test_unhealthy_style_is_bold() {
        let style = styles::unhealthy();
        let debug = format!("{:?}", style);
        assert!(
            debug.to_lowercase().contains("bold"),
            "Unhealthy style should be bold, got: {}",
            debug
        );
    }

    // =========================================================================
    // styles::health() Function Tests
    // =========================================================================

    #[test]
    fn test_health_style_mapping() {
        // Test the health() function with various inputs
        let _ = styles::health("healthy");
        let _ = styles::health("degraded");
        let _ = styles::health("unhealthy");
        let _ = styles::health("unknown");
        let _ = styles::health("anything_else");
    }

    #[test]
    fn test_health_style_case_insensitive() {
        // All case variations should work
        let healthy_lower = format!("{:?}", styles::health("healthy"));
        let healthy_upper = format!("{:?}", styles::health("HEALTHY"));
        let healthy_mixed = format!("{:?}", styles::health("Healthy"));

        assert_eq!(healthy_lower, healthy_upper);
        assert_eq!(healthy_lower, healthy_mixed);
    }

    #[test]
    fn test_health_style_returns_unknown_for_invalid() {
        let unknown_style = format!("{:?}", styles::health("unknown"));
        let invalid_style = format!("{:?}", styles::health("invalid"));
        let empty_style = format!("{:?}", styles::health(""));

        assert_eq!(unknown_style, invalid_style);
        assert_eq!(unknown_style, empty_style);
    }

    #[test]
    fn test_health_styles_are_distinct() {
        let healthy = format!("{:?}", styles::health("healthy"));
        let degraded = format!("{:?}", styles::health("degraded"));
        let unhealthy = format!("{:?}", styles::health("unhealthy"));

        // Each status should have a distinct style
        assert_ne!(healthy, degraded);
        assert_ne!(healthy, unhealthy);
        assert_ne!(degraded, unhealthy);
    }

    // =========================================================================
    // Style Consistency Tests
    // =========================================================================

    #[test]
    fn test_active_and_header_use_same_color() {
        // Both should use primary color (cyan family: ANSI 6 or 14)
        let header = format!("{:?}", styles::header());
        let active = format!("{:?}", styles::active());

        // Both should contain the primary/cyan color
        assert!(
            header.to_lowercase().contains("cyan") || color_matches_ansi(&header, &[6, 14]),
            "Header should use primary (cyan) color"
        );
        assert!(
            active.to_lowercase().contains("cyan") || color_matches_ansi(&active, &[6, 14]),
            "Active should use primary (cyan) color"
        );
    }

    #[test]
    fn test_muted_and_timestamp_use_same_color() {
        // Both should use bright_black/gray
        let t = Theme::default();
        let muted = format!("{:?}", t.muted);
        let timestamp = format!("{:?}", t.timestamp);

        assert_eq!(muted, timestamp, "Muted and timestamp should use the same color");
    }

    // =========================================================================
    // Color Fallback Tests - Ensure fallbacks work
    // =========================================================================

    #[test]
    fn test_color_fallback_mechanism() {
        // The theme uses Color::parse() with fallback to ANSI codes
        // This test ensures the fallback mechanism doesn't panic
        // and produces valid colors even if Color::parse fails

        let t = Theme::default();

        // All fields should be populated regardless of parse success
        let colors = vec![
            &t.success,
            &t.warning,
            &t.error,
            &t.info,
            &t.primary,
            &t.secondary,
            &t.muted,
            &t.highlight,
            &t.healthy,
            &t.degraded,
            &t.unhealthy,
            &t.unknown,
            &t.bytes,
            &t.latency,
            &t.timestamp,
            &t.domain,
            &t.ip,
            &t.provider,
        ];

        for color in colors {
            // Each color should have a non-empty Debug representation
            let debug = format!("{:?}", color);
            assert!(!debug.is_empty(), "Color should have non-empty debug output");
            // Color struct has "number: Some(N)" or "number: None" - we want Some
            // The format is: Color { name: "color(N)", color_type: Standard, number: Some(N), triplet: None }
            // We check that there's a valid color number assigned
            assert!(
                debug.contains("number: Some("),
                "Color should have a number assigned: {}",
                debug
            );
        }
    }

    // =========================================================================
    // Theme Debug Implementation Tests
    // =========================================================================

    #[test]
    fn test_theme_debug_contains_all_fields() {
        let t = Theme::default();
        let debug = format!("{:?}", t);

        // Debug output should contain all field names
        let expected_fields = [
            "success",
            "warning",
            "error",
            "info",
            "primary",
            "secondary",
            "muted",
            "highlight",
            "healthy",
            "degraded",
            "unhealthy",
            "unknown",
            "bytes",
            "latency",
            "timestamp",
            "domain",
            "ip",
            "provider",
        ];

        for field in expected_fields {
            assert!(
                debug.contains(field),
                "Theme debug should contain field '{}', got: {}",
                field,
                debug
            );
        }
    }
}

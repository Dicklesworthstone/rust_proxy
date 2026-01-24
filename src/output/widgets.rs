// Allow dead_code warnings - these are public APIs that will be used in bd-thy integration.
#![allow(dead_code)]

//! Reusable rich widgets for consistent visual output.
//!
//! This module provides pre-built rich components that are reused across multiple
//! commands. Centralizing these ensures visual consistency and reduces code duplication.
//!
//! Most functions return markup strings that can be passed to `console.print()`.
//!
//! # Example
//!
//! ```rust,ignore
//! use rust_proxy::output::widgets;
//!
//! // Create health badge
//! let badge = widgets::health_badge("healthy");
//! console.print(&badge);
//! ```

use rich_rust::prelude::*;

use super::theme::{styles, theme};

// ============================================================================
// Section Rules
// ============================================================================

/// Create a section divider rule with a title.
///
/// Uses the primary theme color for consistency.
#[must_use]
pub fn section_rule(title: &str) -> Rule {
    Rule::with_title(title).style(styles::header())
}

/// Create a plain section divider rule without a title.
#[must_use]
pub fn plain_rule() -> Rule {
    Rule::new().style(Style::new().color(theme().muted.clone()))
}

// ============================================================================
// Status Panel Markup
// ============================================================================

/// Create success panel markup.
///
/// Returns a bordered success message that can be printed.
#[must_use]
pub fn success_box(message: &str) -> String {
    format!(
        "[bold green]╭─ Success ─────────────────────────────╮[/]\n\
         [green]│[/] {}[green]│[/]\n\
         [bold green]╰───────────────────────────────────────╯[/]",
        pad_to_width(message, 38)
    )
}

/// Create error panel markup.
#[must_use]
pub fn error_box(message: &str) -> String {
    format!(
        "[bold red]╭─ Error ───────────────────────────────╮[/]\n\
         [red]│[/] {}[red]│[/]\n\
         [bold red]╰───────────────────────────────────────╯[/]",
        pad_to_width(message, 38)
    )
}

/// Create warning panel markup.
#[must_use]
pub fn warning_box(message: &str) -> String {
    format!(
        "[bold yellow]╭─ Warning ─────────────────────────────╮[/]\n\
         [yellow]│[/] {}[yellow]│[/]\n\
         [bold yellow]╰───────────────────────────────────────╯[/]",
        pad_to_width(message, 38)
    )
}

/// Create info panel markup.
#[must_use]
pub fn info_box(title: &str, message: &str) -> String {
    let title_display = if title.len() > 36 {
        &title[..36]
    } else {
        title
    };
    let padding = 36 - title_display.len();
    format!(
        "[bold blue]╭─ {} {}╮[/]\n\
         [blue]│[/] {}[blue]│[/]\n\
         [bold blue]╰───────────────────────────────────────╯[/]",
        title_display,
        "─".repeat(padding),
        pad_to_width(message, 38)
    )
}

/// Pad a string to a specific width with trailing spaces.
fn pad_to_width(s: &str, width: usize) -> String {
    if s.len() >= width {
        s[..width].to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - s.len()))
    }
}

// ============================================================================
// Panel Builders (for when you need actual Panel objects)
// ============================================================================

/// Create a Panel from text content with a title.
///
/// Use this when you need an actual Panel renderable.
#[must_use]
pub fn panel_with_title<'a>(content: &'a str, title: &str) -> Panel<'a> {
    Panel::from_text(content).title(title)
}

/// Create a success-styled Panel.
#[must_use]
pub fn success_panel(content: &str) -> Panel<'_> {
    Panel::from_text(content)
        .title("Success")
        .border_style(styles::success_msg())
}

/// Create an error-styled Panel.
#[must_use]
pub fn error_panel(content: &str) -> Panel<'_> {
    Panel::from_text(content)
        .title("Error")
        .border_style(styles::error_msg())
}

/// Create a warning-styled Panel.
#[must_use]
pub fn warning_panel(content: &str) -> Panel<'_> {
    Panel::from_text(content)
        .title("Warning")
        .border_style(styles::warning_msg())
}

/// Create an info-styled Panel.
#[must_use]
pub fn info_panel<'a>(content: &'a str, title: &str) -> Panel<'a> {
    Panel::from_text(content)
        .title(title)
        .border_style(styles::info_msg())
}

// ============================================================================
// Key-Value Display
// ============================================================================

/// Format key-value pairs as markup lines.
///
/// Returns a multi-line string suitable for display.
#[must_use]
pub fn kv_lines(items: &[(&str, &str)]) -> String {
    items
        .iter()
        .map(|(key, value)| format!("[bright_black]{}:[/] {}", key, value))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Create a Panel displaying key-value pairs.
#[must_use]
pub fn kv_panel<'a>(title: &str, content: &'a str) -> Panel<'a> {
    Panel::from_text(content)
        .title(title)
        .border_style(styles::subheader())
}

// ============================================================================
// Health Status Indicators
// ============================================================================

/// Create a health status badge with colored symbol.
///
/// Returns a markup string with appropriate coloring:
/// - Healthy → green filled circle (●)
/// - Degraded → yellow half circle (◐)
/// - Unhealthy → red empty circle (○)
/// - Unknown → gray question mark (?)
///
/// Note: No emojis used - agents may misparse them.
#[must_use]
pub fn health_badge(status: &str) -> String {
    match status.to_lowercase().as_str() {
        "healthy" => "[bright_green]●[/]".to_string(),
        "degraded" => "[bright_yellow]◐[/]".to_string(),
        "unhealthy" => "[bright_red]○[/]".to_string(),
        _ => "[bright_black]?[/]".to_string(),
    }
}

/// Create a health status badge with label.
///
/// Returns markup string like "[green]● Healthy[/]"
#[must_use]
pub fn health_badge_with_label(status: &str) -> String {
    let label = match status.to_lowercase().as_str() {
        "healthy" => "Healthy",
        "degraded" => "Degraded",
        "unhealthy" => "Unhealthy",
        _ => "Unknown",
    };

    match status.to_lowercase().as_str() {
        "healthy" => format!("[bright_green]● {}[/]", label),
        "degraded" => format!("[bright_yellow]◐ {}[/]", label),
        "unhealthy" => format!("[bright_red]○ {}[/]", label),
        _ => format!("[bright_black]? {}[/]", label),
    }
}

// ============================================================================
// Active/Selection Indicators
// ============================================================================

/// Create an active indicator arrow.
///
/// Returns "►" (play symbol) for active items, space for inactive.
#[must_use]
pub fn active_indicator(is_active: bool) -> String {
    if is_active {
        "[bold green]►[/]".to_string()
    } else {
        " ".to_string()
    }
}

/// Create an active indicator with label.
///
/// Returns "► label" for active, "  label" for inactive.
#[must_use]
pub fn active_indicator_with_label(is_active: bool, label: &str) -> String {
    if is_active {
        format!("[bold green]►[/] [bold]{}[/]", label)
    } else {
        format!("  {}", label)
    }
}

// ============================================================================
// Checkmark/X Indicators
// ============================================================================

/// Create a passing check indicator.
///
/// Returns "[green]✓[/] label"
#[must_use]
pub fn check_pass(label: &str) -> String {
    format!("[green]✓[/] {}", label)
}

/// Create a failing check indicator.
///
/// Returns "[red]✗[/] label"
#[must_use]
pub fn check_fail(label: &str) -> String {
    format!("[red]✗[/] {}", label)
}

/// Create a warning check indicator.
///
/// Returns "[yellow]⚠[/] label"
#[must_use]
pub fn check_warn(label: &str) -> String {
    format!("[yellow]⚠[/] {}", label)
}

/// Create an info check indicator.
///
/// Returns "[blue]ℹ[/] label"
#[must_use]
pub fn check_info(label: &str) -> String {
    format!("[blue]ℹ[/] {}", label)
}

// ============================================================================
// Tree-style Progress
// ============================================================================

/// Create a tree item with proper prefix.
///
/// Uses box-drawing characters for tree structure:
/// - "├" for non-last items
/// - "└" for last items
#[must_use]
pub fn tree_item(label: &str, is_last: bool) -> String {
    let prefix = if is_last { "└" } else { "├" };
    format!("[dim]{}─[/] {}", prefix, label)
}

/// Create a tree item with status indicator.
///
/// Combines tree structure with a status check.
#[must_use]
pub fn tree_item_with_status(label: &str, is_last: bool, passed: bool) -> String {
    let prefix = if is_last { "└" } else { "├" };
    let status = if passed {
        "[green]✓[/]"
    } else {
        "[red]✗[/]"
    };
    format!("[dim]{}─[/] {} {}", prefix, status, label)
}

/// Create a nested tree item with indentation.
///
/// For multi-level tree structures.
#[must_use]
pub fn tree_item_nested(label: &str, is_last: bool, depth: usize) -> String {
    let indent = "  ".repeat(depth);
    let prefix = if is_last { "└" } else { "├" };
    format!("{}[dim]{}─[/] {}", indent, prefix, label)
}

// ============================================================================
// Data Formatting Helpers
// ============================================================================

/// Format a byte count with appropriate color.
#[must_use]
pub fn colored_bytes(bytes: u64) -> String {
    let formatted = crate::util::format_bytes(bytes);
    format!("[bright_magenta]{}[/]", formatted)
}

/// Format a latency value with appropriate color.
///
/// - < 100ms: green (fast)
/// - 100-300ms: yellow (medium)
/// - > 300ms: red (slow)
#[must_use]
pub fn colored_latency(ms: f64) -> String {
    let color = if ms < 100.0 {
        "bright_green"
    } else if ms < 300.0 {
        "bright_yellow"
    } else {
        "bright_red"
    };
    format!("[{}]{:.0}ms[/]", color, ms)
}

/// Format a domain with appropriate color.
#[must_use]
pub fn colored_domain(domain: &str) -> String {
    format!("[bright_blue]{}[/]", domain)
}

/// Format an IP address with appropriate color.
#[must_use]
pub fn colored_ip(ip: &str) -> String {
    format!("[bright_yellow]{}[/]", ip)
}

/// Format a provider name with appropriate color.
#[must_use]
pub fn colored_provider(provider: &str) -> String {
    format!("[magenta]{}[/]", provider)
}

/// Format a timestamp with appropriate color.
#[must_use]
pub fn colored_timestamp(timestamp: &str) -> String {
    format!("[bright_black]{}[/]", timestamp)
}

// ============================================================================
// Compound Widgets
// ============================================================================

/// Create a labeled value display.
///
/// Returns "label: value" with label in muted color.
#[must_use]
pub fn labeled_value(label: &str, value: &str) -> String {
    format!("[bright_black]{}:[/] {}", label, value)
}

/// Create a labeled value display with colored value.
///
/// Returns "label: value" with label muted and value highlighted.
#[must_use]
pub fn labeled_value_highlight(label: &str, value: &str) -> String {
    format!("[bright_black]{}:[/] [bright_white]{}[/]", label, value)
}

/// Create a status line with icon and message.
///
/// Combines status indicator with a message.
#[must_use]
pub fn status_line(status: &str, message: &str) -> String {
    let icon = match status {
        "success" | "ok" | "pass" => "[green]✓[/]",
        "error" | "fail" | "failed" => "[red]✗[/]",
        "warning" | "warn" => "[yellow]⚠[/]",
        "info" => "[blue]ℹ[/]",
        "running" | "active" => "[cyan]●[/]",
        "pending" | "waiting" => "[bright_black]○[/]",
        _ => "[bright_black]·[/]",
    };
    format!("{} {}", icon, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Section Rule Tests
    // =========================================================================

    #[test]
    fn test_section_rule_basic() {
        let rule = section_rule("Test Section");
        // Rule should be created successfully
        let _ = rule;
    }

    #[test]
    fn test_section_rule_with_long_title() {
        let rule = section_rule("This Is A Very Long Section Title That Might Cause Issues");
        let _ = rule;
    }

    #[test]
    fn test_section_rule_with_empty_title() {
        let rule = section_rule("");
        let _ = rule;
    }

    #[test]
    fn test_section_rule_with_unicode_title() {
        let rule = section_rule("セクション 🎯");
        let _ = rule;
    }

    #[test]
    fn test_plain_rule() {
        let rule = plain_rule();
        let _ = rule;
    }

    // =========================================================================
    // Status Box Tests (Markup-based Panels)
    // =========================================================================

    #[test]
    fn test_success_box_contains_header() {
        let markup = success_box("Done!");
        assert!(markup.contains("Success"));
    }

    #[test]
    fn test_success_box_contains_message() {
        let markup = success_box("Done!");
        assert!(markup.contains("Done!"));
    }

    #[test]
    fn test_success_box_has_green_color() {
        let markup = success_box("Done!");
        assert!(markup.contains("green"));
    }

    #[test]
    fn test_success_box_has_box_characters() {
        let markup = success_box("Done!");
        assert!(markup.contains("╭"));
        assert!(markup.contains("╰"));
        assert!(markup.contains("│"));
    }

    #[test]
    fn test_error_box_contains_header() {
        let markup = error_box("Failed!");
        assert!(markup.contains("Error"));
    }

    #[test]
    fn test_error_box_contains_message() {
        let markup = error_box("Failed!");
        assert!(markup.contains("Failed!"));
    }

    #[test]
    fn test_error_box_has_red_color() {
        let markup = error_box("Failed!");
        assert!(markup.contains("red"));
    }

    #[test]
    fn test_warning_box_contains_header() {
        let markup = warning_box("Caution!");
        assert!(markup.contains("Warning"));
    }

    #[test]
    fn test_warning_box_contains_message() {
        let markup = warning_box("Caution!");
        assert!(markup.contains("Caution!"));
    }

    #[test]
    fn test_warning_box_has_yellow_color() {
        let markup = warning_box("Caution!");
        assert!(markup.contains("yellow"));
    }

    #[test]
    fn test_info_box_contains_title() {
        let markup = info_box("Details", "Some info");
        assert!(markup.contains("Details"));
    }

    #[test]
    fn test_info_box_contains_message() {
        let markup = info_box("Details", "Some info");
        assert!(markup.contains("Some info"));
    }

    #[test]
    fn test_info_box_has_blue_color() {
        let markup = info_box("Details", "Some info");
        assert!(markup.contains("blue"));
    }

    #[test]
    fn test_info_box_truncates_long_title() {
        let long_title = "A".repeat(50);
        let markup = info_box(&long_title, "msg");
        // Title should be truncated to 36 chars max
        assert!(!markup.contains(&"A".repeat(50)));
    }

    #[test]
    fn test_box_with_empty_message() {
        let markup = success_box("");
        assert!(markup.contains("Success"));
    }

    #[test]
    fn test_box_with_unicode_message() {
        let markup = success_box("完成 ✓");
        assert!(markup.contains("完成"));
    }

    // =========================================================================
    // Panel Builder Tests
    // =========================================================================

    #[test]
    fn test_panel_with_title() {
        let panel = panel_with_title("Content", "My Title");
        let _ = panel;
    }

    #[test]
    fn test_success_panel_creation() {
        let panel = success_panel("Content");
        let _ = panel;
    }

    #[test]
    fn test_error_panel_creation() {
        let panel = error_panel("Content");
        let _ = panel;
    }

    #[test]
    fn test_warning_panel_creation() {
        let panel = warning_panel("Content");
        let _ = panel;
    }

    #[test]
    fn test_info_panel_creation() {
        let panel = info_panel("Content", "Title");
        let _ = panel;
    }

    #[test]
    fn test_kv_panel_creation() {
        let panel = kv_panel("Config", "key1: value1\nkey2: value2");
        let _ = panel;
    }

    // =========================================================================
    // Key-Value Display Tests
    // =========================================================================

    #[test]
    fn test_kv_lines_basic() {
        let items = [("Key1", "Val1"), ("Key2", "Val2")];
        let lines = kv_lines(&items);
        assert!(lines.contains("Key1"));
        assert!(lines.contains("Val1"));
        assert!(lines.contains("Key2"));
        assert!(lines.contains("Val2"));
    }

    #[test]
    fn test_kv_lines_empty() {
        let items: [(&str, &str); 0] = [];
        let lines = kv_lines(&items);
        assert!(lines.is_empty());
    }

    #[test]
    fn test_kv_lines_single_item() {
        let items = [("Name", "rust_proxy")];
        let lines = kv_lines(&items);
        assert!(lines.contains("Name"));
        assert!(lines.contains("rust_proxy"));
        assert!(!lines.contains('\n')); // Single item, no newlines
    }

    #[test]
    fn test_kv_lines_has_muted_styling() {
        let items = [("Key", "Value")];
        let lines = kv_lines(&items);
        assert!(lines.contains("bright_black"));
    }

    #[test]
    fn test_kv_lines_multiline_count() {
        let items = [("A", "1"), ("B", "2"), ("C", "3")];
        let lines = kv_lines(&items);
        let line_count = lines.lines().count();
        assert_eq!(line_count, 3);
    }

    // =========================================================================
    // Health Badge Tests
    // =========================================================================

    #[test]
    fn test_health_badge_healthy_symbol() {
        assert!(health_badge("healthy").contains("●"));
    }

    #[test]
    fn test_health_badge_healthy_color() {
        assert!(health_badge("healthy").contains("bright_green"));
    }

    #[test]
    fn test_health_badge_degraded_symbol() {
        assert!(health_badge("degraded").contains("◐"));
    }

    #[test]
    fn test_health_badge_degraded_color() {
        assert!(health_badge("degraded").contains("bright_yellow"));
    }

    #[test]
    fn test_health_badge_unhealthy_symbol() {
        assert!(health_badge("unhealthy").contains("○"));
    }

    #[test]
    fn test_health_badge_unhealthy_color() {
        assert!(health_badge("unhealthy").contains("bright_red"));
    }

    #[test]
    fn test_health_badge_unknown_symbol() {
        assert!(health_badge("unknown").contains("?"));
    }

    #[test]
    fn test_health_badge_unknown_color() {
        assert!(health_badge("unknown").contains("bright_black"));
    }

    #[test]
    fn test_health_badge_case_insensitivity() {
        assert!(health_badge("HEALTHY").contains("●"));
        assert!(health_badge("Healthy").contains("●"));
        assert!(health_badge("HeAlThY").contains("●"));
        assert!(health_badge("DEGRADED").contains("◐"));
        assert!(health_badge("UNHEALTHY").contains("○"));
    }

    #[test]
    fn test_health_badge_invalid_status() {
        // Invalid status should return unknown (?)
        assert!(health_badge("invalid").contains("?"));
        assert!(health_badge("").contains("?"));
        assert!(health_badge("  ").contains("?"));
        assert!(health_badge("ok").contains("?"));
    }

    #[test]
    fn test_health_badge_with_label_healthy() {
        let badge = health_badge_with_label("healthy");
        assert!(badge.contains("Healthy"));
        assert!(badge.contains("●"));
        assert!(badge.contains("bright_green"));
    }

    #[test]
    fn test_health_badge_with_label_degraded() {
        let badge = health_badge_with_label("degraded");
        assert!(badge.contains("Degraded"));
        assert!(badge.contains("◐"));
        assert!(badge.contains("bright_yellow"));
    }

    #[test]
    fn test_health_badge_with_label_unhealthy() {
        let badge = health_badge_with_label("unhealthy");
        assert!(badge.contains("Unhealthy"));
        assert!(badge.contains("○"));
        assert!(badge.contains("bright_red"));
    }

    #[test]
    fn test_health_badge_with_label_unknown() {
        let badge = health_badge_with_label("unknown");
        assert!(badge.contains("Unknown"));
        assert!(badge.contains("?"));
    }

    #[test]
    fn test_health_badge_with_label_invalid() {
        let badge = health_badge_with_label("invalid");
        assert!(badge.contains("Unknown")); // Should default to Unknown
    }

    // =========================================================================
    // Active Indicator Tests
    // =========================================================================

    #[test]
    fn test_active_indicator_active_symbol() {
        assert!(active_indicator(true).contains("►"));
    }

    #[test]
    fn test_active_indicator_active_color() {
        assert!(active_indicator(true).contains("green"));
    }

    #[test]
    fn test_active_indicator_inactive_is_space() {
        assert_eq!(active_indicator(false), " ");
    }

    #[test]
    fn test_active_indicator_with_label_active() {
        let result = active_indicator_with_label(true, "proxy-1");
        assert!(result.contains("►"));
        assert!(result.contains("proxy-1"));
        assert!(result.contains("bold"));
    }

    #[test]
    fn test_active_indicator_with_label_inactive() {
        let result = active_indicator_with_label(false, "proxy-2");
        assert!(!result.contains("►"));
        assert!(result.contains("proxy-2"));
        assert!(result.starts_with("  ")); // Two spaces for alignment
    }

    #[test]
    fn test_active_indicator_with_empty_label() {
        let result = active_indicator_with_label(true, "");
        assert!(result.contains("►"));
    }

    // =========================================================================
    // Check Indicator Tests
    // =========================================================================

    #[test]
    fn test_check_pass_symbol() {
        assert!(check_pass("test").contains("✓"));
    }

    #[test]
    fn test_check_pass_color() {
        assert!(check_pass("test").contains("green"));
    }

    #[test]
    fn test_check_pass_label() {
        assert!(check_pass("validation").contains("validation"));
    }

    #[test]
    fn test_check_fail_symbol() {
        assert!(check_fail("test").contains("✗"));
    }

    #[test]
    fn test_check_fail_color() {
        assert!(check_fail("test").contains("red"));
    }

    #[test]
    fn test_check_warn_symbol() {
        assert!(check_warn("test").contains("⚠"));
    }

    #[test]
    fn test_check_warn_color() {
        assert!(check_warn("test").contains("yellow"));
    }

    #[test]
    fn test_check_info_symbol() {
        assert!(check_info("test").contains("ℹ"));
    }

    #[test]
    fn test_check_info_color() {
        assert!(check_info("test").contains("blue"));
    }

    #[test]
    fn test_check_indicators_empty_label() {
        // All should work with empty labels
        let _ = check_pass("");
        let _ = check_fail("");
        let _ = check_warn("");
        let _ = check_info("");
    }

    // =========================================================================
    // Tree Item Tests
    // =========================================================================

    #[test]
    fn test_tree_item_non_last_prefix() {
        let item = tree_item("child", false);
        assert!(item.contains("├"));
    }

    #[test]
    fn test_tree_item_last_prefix() {
        let item = tree_item("child", true);
        assert!(item.contains("└"));
    }

    #[test]
    fn test_tree_item_contains_dash() {
        let item = tree_item("child", false);
        assert!(item.contains("─"));
    }

    #[test]
    fn test_tree_item_contains_label() {
        let item = tree_item("my_item", false);
        assert!(item.contains("my_item"));
    }

    #[test]
    fn test_tree_item_with_status_passed() {
        let item = tree_item_with_status("check", false, true);
        assert!(item.contains("✓"));
        assert!(item.contains("check"));
        assert!(item.contains("├"));
    }

    #[test]
    fn test_tree_item_with_status_failed() {
        let item = tree_item_with_status("check", false, false);
        assert!(item.contains("✗"));
        assert!(item.contains("check"));
    }

    #[test]
    fn test_tree_item_with_status_last() {
        let item = tree_item_with_status("final", true, true);
        assert!(item.contains("└"));
    }

    #[test]
    fn test_tree_item_nested_depth_0() {
        let item = tree_item_nested("item", false, 0);
        assert!(item.starts_with("[dim]├")); // No indent at depth 0
    }

    #[test]
    fn test_tree_item_nested_depth_1() {
        let item = tree_item_nested("item", false, 1);
        assert!(item.starts_with("  ")); // 2 spaces for depth 1
    }

    #[test]
    fn test_tree_item_nested_depth_2() {
        let item = tree_item_nested("item", false, 2);
        assert!(item.starts_with("    ")); // 4 spaces for depth 2
    }

    #[test]
    fn test_tree_item_nested_depth_3() {
        let item = tree_item_nested("item", false, 3);
        assert!(item.starts_with("      ")); // 6 spaces for depth 3
    }

    // =========================================================================
    // Colored Data Formatter Tests
    // =========================================================================

    #[test]
    fn test_colored_bytes_color() {
        let formatted = colored_bytes(1024);
        assert!(formatted.contains("bright_magenta"));
    }

    #[test]
    fn test_colored_bytes_zero() {
        let formatted = colored_bytes(0);
        assert!(formatted.contains("bright_magenta"));
    }

    #[test]
    fn test_colored_bytes_large() {
        let formatted = colored_bytes(1_000_000_000);
        assert!(formatted.contains("bright_magenta"));
    }

    #[test]
    fn test_colored_latency_fast() {
        let fast = colored_latency(50.0);
        assert!(fast.contains("bright_green"));
        assert!(fast.contains("50ms"));
    }

    #[test]
    fn test_colored_latency_boundary_100() {
        // Exactly 100ms should be yellow
        let boundary = colored_latency(100.0);
        assert!(boundary.contains("bright_yellow"));
    }

    #[test]
    fn test_colored_latency_medium() {
        let medium = colored_latency(200.0);
        assert!(medium.contains("bright_yellow"));
    }

    #[test]
    fn test_colored_latency_boundary_300() {
        // Exactly 300ms should be red
        let boundary = colored_latency(300.0);
        assert!(boundary.contains("bright_red"));
    }

    #[test]
    fn test_colored_latency_slow() {
        let slow = colored_latency(500.0);
        assert!(slow.contains("bright_red"));
    }

    #[test]
    fn test_colored_latency_zero() {
        let zero = colored_latency(0.0);
        assert!(zero.contains("bright_green")); // 0 is fast
    }

    #[test]
    fn test_colored_domain_color() {
        let domain = colored_domain("example.com");
        assert!(domain.contains("bright_blue"));
    }

    #[test]
    fn test_colored_domain_content() {
        let domain = colored_domain("example.com");
        assert!(domain.contains("example.com"));
    }

    #[test]
    fn test_colored_domain_with_subdomain() {
        let domain = colored_domain("api.example.com");
        assert!(domain.contains("api.example.com"));
    }

    #[test]
    fn test_colored_ip_color() {
        let ip = colored_ip("192.168.1.1");
        assert!(ip.contains("bright_yellow"));
    }

    #[test]
    fn test_colored_ip_content() {
        let ip = colored_ip("192.168.1.1");
        assert!(ip.contains("192.168.1.1"));
    }

    #[test]
    fn test_colored_ip_ipv6_style() {
        let ip = colored_ip("::1");
        assert!(ip.contains("::1"));
    }

    #[test]
    fn test_colored_provider_color() {
        let provider = colored_provider("AWS");
        assert!(provider.contains("magenta"));
    }

    #[test]
    fn test_colored_provider_content() {
        let provider = colored_provider("AWS");
        assert!(provider.contains("AWS"));
    }

    #[test]
    fn test_colored_provider_various() {
        assert!(colored_provider("Cloudflare").contains("Cloudflare"));
        assert!(colored_provider("Google").contains("Google"));
        assert!(colored_provider("Anthropic").contains("Anthropic"));
    }

    #[test]
    fn test_colored_timestamp_color() {
        let ts = colored_timestamp("2026-01-21");
        assert!(ts.contains("bright_black"));
    }

    #[test]
    fn test_colored_timestamp_content() {
        let ts = colored_timestamp("2026-01-21 10:30:00");
        assert!(ts.contains("2026-01-21 10:30:00"));
    }

    // =========================================================================
    // Labeled Value Tests
    // =========================================================================

    #[test]
    fn test_labeled_value_format() {
        let lv = labeled_value("Status", "Active");
        assert!(lv.contains("Status"));
        assert!(lv.contains(":"));
        assert!(lv.contains("Active"));
    }

    #[test]
    fn test_labeled_value_has_muted_label() {
        let lv = labeled_value("Label", "Value");
        assert!(lv.contains("bright_black"));
    }

    #[test]
    fn test_labeled_value_highlight_format() {
        let lv = labeled_value_highlight("Port", "12345");
        assert!(lv.contains("Port"));
        assert!(lv.contains("12345"));
    }

    #[test]
    fn test_labeled_value_highlight_has_bright_value() {
        let lv = labeled_value_highlight("Port", "12345");
        assert!(lv.contains("bright_white"));
    }

    #[test]
    fn test_labeled_value_empty_value() {
        let lv = labeled_value("Key", "");
        assert!(lv.contains("Key:"));
    }

    // =========================================================================
    // Status Line Tests
    // =========================================================================

    #[test]
    fn test_status_line_success() {
        let line = status_line("success", "Done");
        assert!(line.contains("✓"));
        assert!(line.contains("Done"));
    }

    #[test]
    fn test_status_line_ok() {
        let line = status_line("ok", "Done");
        assert!(line.contains("✓"));
    }

    #[test]
    fn test_status_line_pass() {
        let line = status_line("pass", "Done");
        assert!(line.contains("✓"));
    }

    #[test]
    fn test_status_line_error() {
        let line = status_line("error", "Failed");
        assert!(line.contains("✗"));
    }

    #[test]
    fn test_status_line_fail() {
        let line = status_line("fail", "Failed");
        assert!(line.contains("✗"));
    }

    #[test]
    fn test_status_line_failed() {
        let line = status_line("failed", "Failed");
        assert!(line.contains("✗"));
    }

    #[test]
    fn test_status_line_warning() {
        let line = status_line("warning", "Caution");
        assert!(line.contains("⚠"));
    }

    #[test]
    fn test_status_line_warn() {
        let line = status_line("warn", "Caution");
        assert!(line.contains("⚠"));
    }

    #[test]
    fn test_status_line_info() {
        let line = status_line("info", "Note");
        assert!(line.contains("ℹ"));
    }

    #[test]
    fn test_status_line_running() {
        let line = status_line("running", "Active");
        assert!(line.contains("●"));
        assert!(line.contains("cyan"));
    }

    #[test]
    fn test_status_line_active() {
        let line = status_line("active", "Active");
        assert!(line.contains("●"));
    }

    #[test]
    fn test_status_line_pending() {
        let line = status_line("pending", "Waiting");
        assert!(line.contains("○"));
    }

    #[test]
    fn test_status_line_waiting() {
        let line = status_line("waiting", "Waiting");
        assert!(line.contains("○"));
    }

    #[test]
    fn test_status_line_unknown() {
        let line = status_line("unknown_status", "Something");
        assert!(line.contains("·")); // Default dot
    }

    // =========================================================================
    // pad_to_width Helper Tests
    // =========================================================================

    #[test]
    fn test_pad_to_width_shorter() {
        assert_eq!(pad_to_width("hi", 5), "hi   ");
    }

    #[test]
    fn test_pad_to_width_longer() {
        assert_eq!(pad_to_width("hello", 3), "hel");
    }

    #[test]
    fn test_pad_to_width_exact() {
        assert_eq!(pad_to_width("abc", 3), "abc");
    }

    #[test]
    fn test_pad_to_width_empty() {
        assert_eq!(pad_to_width("", 3), "   ");
    }

    #[test]
    fn test_pad_to_width_zero() {
        assert_eq!(pad_to_width("abc", 0), "");
    }

    #[test]
    fn test_pad_to_width_one() {
        assert_eq!(pad_to_width("abc", 1), "a");
    }

    #[test]
    fn test_pad_to_width_single_char() {
        assert_eq!(pad_to_width("x", 5), "x    ");
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[test]
    fn test_widgets_with_special_characters() {
        let markup = success_box("Test <>&\"'");
        assert!(markup.contains("<>&"));
    }

    #[test]
    fn test_widgets_with_newlines_in_content() {
        let markup = info_box("Title", "Line1\nLine2");
        assert!(markup.contains("Line1"));
    }

    #[test]
    fn test_tree_items_build_valid_tree() {
        let items = [
            tree_item("Root", false),
            tree_item_nested("Child1", false, 1),
            tree_item_nested("Child2", true, 1),
        ];
        assert_eq!(items.len(), 3);
        assert!(items[0].contains("├"));
        assert!(items[2].contains("└"));
    }

    #[test]
    fn test_health_badges_are_distinct() {
        let healthy = health_badge("healthy");
        let degraded = health_badge("degraded");
        let unhealthy = health_badge("unhealthy");
        let unknown = health_badge("unknown");

        // All should be different
        assert_ne!(healthy, degraded);
        assert_ne!(healthy, unhealthy);
        assert_ne!(healthy, unknown);
        assert_ne!(degraded, unhealthy);
        assert_ne!(degraded, unknown);
        assert_ne!(unhealthy, unknown);
    }

    #[test]
    fn test_all_box_types_have_consistent_structure() {
        let boxes = vec![
            success_box("msg"),
            error_box("msg"),
            warning_box("msg"),
            info_box("title", "msg"),
        ];

        for b in boxes {
            // All boxes should have top, middle, and bottom border
            assert!(b.contains("╭"));
            assert!(b.contains("│"));
            assert!(b.contains("╰"));
        }
    }

    #[test]
    fn test_latency_color_thresholds() {
        // Test exact boundaries
        assert!(colored_latency(99.9).contains("bright_green"));
        assert!(colored_latency(100.0).contains("bright_yellow"));
        assert!(colored_latency(299.9).contains("bright_yellow"));
        assert!(colored_latency(300.0).contains("bright_red"));
    }
}

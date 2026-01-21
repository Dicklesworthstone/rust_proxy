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

    #[test]
    fn test_section_rule() {
        let rule = section_rule("Test Section");
        let _ = rule;
    }

    #[test]
    fn test_plain_rule() {
        let rule = plain_rule();
        let _ = rule;
    }

    #[test]
    fn test_success_box() {
        let markup = success_box("Done!");
        assert!(markup.contains("Success"));
        assert!(markup.contains("Done!"));
    }

    #[test]
    fn test_error_box() {
        let markup = error_box("Failed!");
        assert!(markup.contains("Error"));
        assert!(markup.contains("Failed!"));
    }

    #[test]
    fn test_warning_box() {
        let markup = warning_box("Caution!");
        assert!(markup.contains("Warning"));
        assert!(markup.contains("Caution!"));
    }

    #[test]
    fn test_info_box() {
        let markup = info_box("Details", "Some info");
        assert!(markup.contains("Details"));
        assert!(markup.contains("Some info"));
    }

    #[test]
    fn test_panel_builders() {
        let sp = success_panel("Content");
        let _ = sp;
        let ep = error_panel("Content");
        let _ = ep;
        let wp = warning_panel("Content");
        let _ = wp;
        let ip = info_panel("Content", "Title");
        let _ = ip;
    }

    #[test]
    fn test_kv_lines() {
        let items = [("Key1", "Val1"), ("Key2", "Val2")];
        let lines = kv_lines(&items);
        assert!(lines.contains("Key1"));
        assert!(lines.contains("Val1"));
        assert!(lines.contains("Key2"));
        assert!(lines.contains("Val2"));
    }

    #[test]
    fn test_health_badge() {
        assert!(health_badge("healthy").contains("●"));
        assert!(health_badge("degraded").contains("◐"));
        assert!(health_badge("unhealthy").contains("○"));
        assert!(health_badge("unknown").contains("?"));
        assert!(health_badge("HEALTHY").contains("●")); // Case insensitive
    }

    #[test]
    fn test_health_badge_with_label() {
        let badge = health_badge_with_label("healthy");
        assert!(badge.contains("Healthy"));
        assert!(badge.contains("●"));
    }

    #[test]
    fn test_active_indicator() {
        assert!(active_indicator(true).contains("►"));
        assert_eq!(active_indicator(false), " ");
    }

    #[test]
    fn test_active_indicator_with_label() {
        let active = active_indicator_with_label(true, "proxy-1");
        assert!(active.contains("►"));
        assert!(active.contains("proxy-1"));

        let inactive = active_indicator_with_label(false, "proxy-2");
        assert!(!inactive.contains("►"));
        assert!(inactive.contains("proxy-2"));
    }

    #[test]
    fn test_check_indicators() {
        assert!(check_pass("test").contains("✓"));
        assert!(check_fail("test").contains("✗"));
        assert!(check_warn("test").contains("⚠"));
        assert!(check_info("test").contains("ℹ"));
    }

    #[test]
    fn test_tree_item() {
        let non_last = tree_item("item", false);
        assert!(non_last.contains("├"));

        let last = tree_item("item", true);
        assert!(last.contains("└"));
    }

    #[test]
    fn test_tree_item_with_status() {
        let passed = tree_item_with_status("check", false, true);
        assert!(passed.contains("✓"));

        let failed = tree_item_with_status("check", true, false);
        assert!(failed.contains("✗"));
        assert!(failed.contains("└"));
    }

    #[test]
    fn test_tree_item_nested() {
        let nested = tree_item_nested("item", false, 2);
        assert!(nested.starts_with("    ")); // 2 levels of indent (2 spaces each)
    }

    #[test]
    fn test_colored_bytes() {
        let formatted = colored_bytes(1024);
        assert!(formatted.contains("bright_magenta"));
    }

    #[test]
    fn test_colored_latency() {
        let fast = colored_latency(50.0);
        assert!(fast.contains("bright_green"));

        let medium = colored_latency(200.0);
        assert!(medium.contains("bright_yellow"));

        let slow = colored_latency(500.0);
        assert!(slow.contains("bright_red"));
    }

    #[test]
    fn test_colored_domain() {
        let domain = colored_domain("example.com");
        assert!(domain.contains("bright_blue"));
        assert!(domain.contains("example.com"));
    }

    #[test]
    fn test_colored_ip() {
        let ip = colored_ip("192.168.1.1");
        assert!(ip.contains("bright_yellow"));
        assert!(ip.contains("192.168.1.1"));
    }

    #[test]
    fn test_colored_provider() {
        let provider = colored_provider("AWS");
        assert!(provider.contains("magenta"));
        assert!(provider.contains("AWS"));
    }

    #[test]
    fn test_colored_timestamp() {
        let ts = colored_timestamp("2026-01-21");
        assert!(ts.contains("bright_black"));
        assert!(ts.contains("2026-01-21"));
    }

    #[test]
    fn test_labeled_value() {
        let lv = labeled_value("Status", "Active");
        assert!(lv.contains("Status"));
        assert!(lv.contains("Active"));
    }

    #[test]
    fn test_labeled_value_highlight() {
        let lv = labeled_value_highlight("Port", "12345");
        assert!(lv.contains("bright_white"));
        assert!(lv.contains("12345"));
    }

    #[test]
    fn test_status_line() {
        assert!(status_line("success", "Done").contains("✓"));
        assert!(status_line("error", "Failed").contains("✗"));
        assert!(status_line("warning", "Caution").contains("⚠"));
        assert!(status_line("info", "Note").contains("ℹ"));
        assert!(status_line("running", "Active").contains("●"));
        assert!(status_line("pending", "Waiting").contains("○"));
    }

    #[test]
    fn test_pad_to_width() {
        assert_eq!(pad_to_width("hi", 5), "hi   ");
        assert_eq!(pad_to_width("hello", 3), "hel");
        assert_eq!(pad_to_width("abc", 3), "abc");
    }
}

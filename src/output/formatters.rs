// Allow dead_code warnings - these are public APIs that will be used in bd-thy integration.
#![allow(dead_code)]

//! Data formatters for consistent rich output.
//!
//! This module provides functions that format data values (bytes, durations, IPs, etc.)
//! with consistent styling using rich markup. These formatters wrap the plain-text
//! formatters in `util.rs` and add appropriate colors from the theme.
//!
//! # Usage
//!
//! ```rust,ignore
//! use rust_proxy::output::formatters;
//!
//! // Format byte counts with color
//! let bytes_display = formatters::format_bytes_rich(1_500_000);
//! // -> "[bright_magenta]1.4 MB[/]"
//!
//! // Format latency with threshold-based coloring
//! let latency_display = formatters::format_latency_rich(Some(150.0));
//! // -> "[yellow]150ms[/]"
//! ```

use chrono::{DateTime, Utc};
use std::time::Duration;

/// Format bytes with color (bright magenta).
///
/// # Examples
///
/// ```rust,ignore
/// format_bytes_rich(1500000) // -> "[bright_magenta]1.4 MB[/]"
/// format_bytes_rich(512)     // -> "[bright_magenta]512 B[/]"
/// ```
#[must_use]
pub fn format_bytes_rich(bytes: u64) -> String {
    let formatted = crate::util::format_bytes(bytes);
    format!("[bright_magenta]{formatted}[/]")
}

/// Format duration with color (bright cyan).
///
/// # Examples
///
/// ```rust,ignore
/// format_duration_rich(Duration::from_secs(7200)) // -> "[bright_cyan]2h 0m 0s[/]"
/// ```
#[must_use]
pub fn format_duration_rich(duration: Duration) -> String {
    let formatted = crate::util::format_duration(duration);
    format!("[bright_cyan]{formatted}[/]")
}

/// Format duration in seconds with color (bright cyan).
///
/// Convenience wrapper that accepts seconds as u64.
#[must_use]
pub fn format_duration_secs_rich(secs: u64) -> String {
    format_duration_rich(Duration::from_secs(secs))
}

/// Format ping latency with threshold-based coloring.
///
/// Color coding based on latency value:
/// - < 100ms: green (excellent)
/// - < 300ms: yellow (acceptable)
/// - >= 300ms: red (slow)
/// - None: gray "--"
///
/// # Examples
///
/// ```rust,ignore
/// format_latency_rich(Some(50.0))  // -> "[green]50ms[/]"
/// format_latency_rich(Some(150.0)) // -> "[yellow]150ms[/]"
/// format_latency_rich(Some(500.0)) // -> "[red]500ms[/]"
/// format_latency_rich(None)        // -> "[bright_black]--[/]"
/// ```
#[must_use]
pub fn format_latency_rich(ms: Option<f64>) -> String {
    match ms {
        Some(ms) if ms < 100.0 => format!("[green]{ms:.0}ms[/]"),
        Some(ms) if ms < 300.0 => format!("[yellow]{ms:.0}ms[/]"),
        Some(ms) => format!("[red]{ms:.0}ms[/]"),
        None => "[bright_black]--[/]".to_string(),
    }
}

/// Format latency with plain text fallback.
///
/// Returns plain text version for machine output.
#[must_use]
pub fn format_latency_plain(ms: Option<f64>) -> String {
    match ms {
        Some(ms) => format!("{ms:.0}ms"),
        None => "--".to_string(),
    }
}

/// Format IP address with color (bright yellow for visibility).
///
/// # Examples
///
/// ```rust,ignore
/// format_ip_rich("192.168.1.1") // -> "[bright_yellow]192.168.1.1[/]"
/// ```
#[must_use]
pub fn format_ip_rich(ip: &str) -> String {
    format!("[bright_yellow]{ip}[/]")
}

/// Format domain name with color (bright blue).
///
/// # Examples
///
/// ```rust,ignore
/// format_domain_rich("example.com") // -> "[bright_blue]example.com[/]"
/// ```
#[must_use]
pub fn format_domain_rich(domain: &str) -> String {
    format!("[bright_blue]{domain}[/]")
}

/// Format provider name with color (magenta).
///
/// # Examples
///
/// ```rust,ignore
/// format_provider_rich("AWS") // -> "[magenta]AWS[/]"
/// ```
#[must_use]
pub fn format_provider_rich(provider: &str) -> String {
    format!("[magenta]{provider}[/]")
}

/// Format timestamp with color (gray, less prominent).
///
/// # Examples
///
/// ```rust,ignore
/// let dt = Utc::now();
/// format_timestamp_rich(&dt) // -> "[bright_black]2024-01-15 10:30:45[/]"
/// ```
#[must_use]
pub fn format_timestamp_rich(dt: &DateTime<Utc>) -> String {
    let formatted = dt.format("%Y-%m-%d %H:%M:%S");
    format!("[bright_black]{formatted}[/]")
}

/// Format timestamp with custom format string.
#[must_use]
pub fn format_timestamp_rich_custom(dt: &DateTime<Utc>, fmt: &str) -> String {
    let formatted = dt.format(fmt);
    format!("[bright_black]{formatted}[/]")
}

/// Format "ago" duration (gray).
///
/// Shows how long ago an event occurred.
///
/// # Examples
///
/// ```rust,ignore
/// let dt = Utc::now() - Duration::from_secs(3600);
/// format_ago_rich(Some(dt)) // -> "[bright_black]1h 0m 0s ago[/]"
/// format_ago_rich(None)     // -> "[bright_black]-[/]"
/// ```
#[must_use]
pub fn format_ago_rich(dt: Option<DateTime<Utc>>) -> String {
    let formatted = crate::util::format_since_label(dt);
    format!("[bright_black]{formatted}[/]")
}

/// Format relative time since a datetime.
///
/// Similar to `format_ago_rich` but without "ago" suffix.
#[must_use]
pub fn format_since_rich(dt: Option<DateTime<Utc>>) -> String {
    let formatted = crate::util::format_duration_since(dt);
    format!("[bright_black]{formatted}[/]")
}

/// Format count with label (bright white count, normal label).
///
/// # Examples
///
/// ```rust,ignore
/// format_count_rich(127, "domains")  // -> "[bright_white]127[/] domains"
/// format_count_rich(1, "proxy")      // -> "[bright_white]1[/] proxy"
/// ```
#[must_use]
pub fn format_count_rich(count: usize, label: &str) -> String {
    format!("[bright_white]{count}[/] {label}")
}

/// Format count with automatic pluralization.
///
/// Adds 's' suffix to label when count != 1.
///
/// # Examples
///
/// ```rust,ignore
/// format_count_plural(1, "domain")  // -> "[bright_white]1[/] domain"
/// format_count_plural(5, "domain")  // -> "[bright_white]5[/] domains"
/// ```
#[must_use]
pub fn format_count_plural(count: usize, label: &str) -> String {
    let suffix = if count == 1 { "" } else { "s" };
    format!("[bright_white]{count}[/] {label}{suffix}")
}

/// Format percentage with color based on value.
///
/// Color coding:
/// - >= 90%: green (excellent)
/// - >= 50%: yellow (moderate)
/// - < 50%: red (poor)
///
/// # Examples
///
/// ```rust,ignore
/// format_percent_rich(95.5)  // -> "[green]95.5%[/]"
/// format_percent_rich(75.0)  // -> "[yellow]75.0%[/]"
/// format_percent_rich(25.0)  // -> "[red]25.0%[/]"
/// ```
#[must_use]
pub fn format_percent_rich(percent: f64) -> String {
    let color = if percent >= 90.0 {
        "green"
    } else if percent >= 50.0 {
        "yellow"
    } else {
        "red"
    };
    format!("[{color}]{percent:.1}%[/]")
}

/// Format boolean as yes/no with color.
///
/// # Examples
///
/// ```rust,ignore
/// format_bool_rich(true)  // -> "[green]yes[/]"
/// format_bool_rich(false) // -> "[red]no[/]"
/// ```
#[must_use]
pub fn format_bool_rich(value: bool) -> String {
    if value {
        "[green]yes[/]".to_string()
    } else {
        "[red]no[/]".to_string()
    }
}

/// Format boolean as enabled/disabled with color.
///
/// # Examples
///
/// ```rust,ignore
/// format_enabled_rich(true)  // -> "[green]enabled[/]"
/// format_enabled_rich(false) // -> "[bright_black]disabled[/]"
/// ```
#[must_use]
pub fn format_enabled_rich(value: bool) -> String {
    if value {
        "[green]enabled[/]".to_string()
    } else {
        "[bright_black]disabled[/]".to_string()
    }
}

/// Format optional string with placeholder for None.
///
/// # Examples
///
/// ```rust,ignore
/// format_optional_rich(Some("value"), "n/a") // -> "value"
/// format_optional_rich(None::<&str>, "n/a")  // -> "[bright_black]n/a[/]"
/// ```
#[must_use]
pub fn format_optional_rich<T: AsRef<str>>(value: Option<T>, placeholder: &str) -> String {
    match value {
        Some(v) => v.as_ref().to_string(),
        None => format!("[bright_black]{placeholder}[/]"),
    }
}

/// Format port number with color (cyan).
#[must_use]
pub fn format_port_rich(port: u16) -> String {
    format!("[cyan]{port}[/]")
}

/// Format URL with domain highlighted.
///
/// # Examples
///
/// ```rust,ignore
/// format_url_rich("https://example.com/path")
/// // -> "https://[bright_blue]example.com[/]/path"
/// ```
#[must_use]
pub fn format_url_rich(url: &str) -> String {
    // Try to extract and highlight the domain part
    if let Some(rest) = url.strip_prefix("https://") {
        if let Some(slash_pos) = rest.find('/') {
            let (domain, path) = rest.split_at(slash_pos);
            return format!("https://[bright_blue]{domain}[/]{path}");
        }
        return format!("https://[bright_blue]{rest}[/]");
    }
    if let Some(rest) = url.strip_prefix("http://") {
        if let Some(slash_pos) = rest.find('/') {
            let (domain, path) = rest.split_at(slash_pos);
            return format!("http://[bright_blue]{domain}[/]{path}");
        }
        return format!("http://[bright_blue]{rest}[/]");
    }
    // No scheme, return as-is
    url.to_string()
}

/// Format error count with appropriate color.
///
/// Zero errors are shown in green (success), non-zero in red.
#[must_use]
pub fn format_error_count_rich(count: usize) -> String {
    if count == 0 {
        "[green]0[/]".to_string()
    } else {
        format!("[red]{count}[/]")
    }
}

/// Format success/failure rate.
///
/// Shows green for high rates, red for low rates.
#[must_use]
pub fn format_success_rate_rich(success: usize, total: usize) -> String {
    if total == 0 {
        return "[bright_black]n/a[/]".to_string();
    }
    let rate = (success as f64 / total as f64) * 100.0;
    let color = if rate >= 95.0 {
        "green"
    } else if rate >= 80.0 {
        "yellow"
    } else {
        "red"
    };
    format!("[{color}]{success}/{total}[/] ({rate:.1}%)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_rich() {
        assert!(format_bytes_rich(512).contains("[bright_magenta]"));
        assert!(format_bytes_rich(512).contains("512 B"));
        assert!(format_bytes_rich(1_500_000).contains("MB"));
    }

    #[test]
    fn test_format_duration_rich() {
        let result = format_duration_rich(Duration::from_secs(3661));
        assert!(result.contains("[bright_cyan]"));
        assert!(result.contains("1h"));
    }

    #[test]
    fn test_format_duration_secs_rich() {
        let result = format_duration_secs_rich(3600);
        assert!(result.contains("[bright_cyan]"));
    }

    #[test]
    fn test_format_latency_rich_good() {
        let result = format_latency_rich(Some(50.0));
        assert!(result.contains("[green]"));
        assert!(result.contains("50ms"));
    }

    #[test]
    fn test_format_latency_rich_acceptable() {
        let result = format_latency_rich(Some(150.0));
        assert!(result.contains("[yellow]"));
    }

    #[test]
    fn test_format_latency_rich_slow() {
        let result = format_latency_rich(Some(500.0));
        assert!(result.contains("[red]"));
    }

    #[test]
    fn test_format_latency_rich_none() {
        let result = format_latency_rich(None);
        assert!(result.contains("[bright_black]"));
        assert!(result.contains("--"));
    }

    #[test]
    fn test_format_latency_plain() {
        assert_eq!(format_latency_plain(Some(100.0)), "100ms");
        assert_eq!(format_latency_plain(None), "--");
    }

    #[test]
    fn test_format_ip_rich() {
        let result = format_ip_rich("192.168.1.1");
        assert!(result.contains("[bright_yellow]"));
        assert!(result.contains("192.168.1.1"));
    }

    #[test]
    fn test_format_domain_rich() {
        let result = format_domain_rich("example.com");
        assert!(result.contains("[bright_blue]"));
        assert!(result.contains("example.com"));
    }

    #[test]
    fn test_format_provider_rich() {
        let result = format_provider_rich("AWS");
        assert!(result.contains("[magenta]"));
        assert!(result.contains("AWS"));
    }

    #[test]
    fn test_format_timestamp_rich() {
        let dt = Utc::now();
        let result = format_timestamp_rich(&dt);
        assert!(result.contains("[bright_black]"));
        // Should contain date format
        assert!(result.contains("-"));
    }

    #[test]
    fn test_format_ago_rich() {
        let result = format_ago_rich(None);
        assert!(result.contains("[bright_black]"));
    }

    #[test]
    fn test_format_count_rich() {
        let result = format_count_rich(42, "items");
        assert!(result.contains("[bright_white]42[/]"));
        assert!(result.contains("items"));
    }

    #[test]
    fn test_format_count_plural() {
        assert!(format_count_plural(1, "item").ends_with("item"));
        assert!(format_count_plural(5, "item").ends_with("items"));
    }

    #[test]
    fn test_format_percent_rich_excellent() {
        let result = format_percent_rich(95.5);
        assert!(result.contains("[green]"));
    }

    #[test]
    fn test_format_percent_rich_moderate() {
        let result = format_percent_rich(75.0);
        assert!(result.contains("[yellow]"));
    }

    #[test]
    fn test_format_percent_rich_poor() {
        let result = format_percent_rich(25.0);
        assert!(result.contains("[red]"));
    }

    #[test]
    fn test_format_bool_rich() {
        assert!(format_bool_rich(true).contains("[green]yes"));
        assert!(format_bool_rich(false).contains("[red]no"));
    }

    #[test]
    fn test_format_enabled_rich() {
        assert!(format_enabled_rich(true).contains("[green]enabled"));
        assert!(format_enabled_rich(false).contains("disabled"));
    }

    #[test]
    fn test_format_optional_rich() {
        assert_eq!(format_optional_rich(Some("value"), "n/a"), "value");
        let none_result = format_optional_rich(None::<&str>, "n/a");
        assert!(none_result.contains("[bright_black]n/a"));
    }

    #[test]
    fn test_format_port_rich() {
        let result = format_port_rich(8080);
        assert!(result.contains("[cyan]8080"));
    }

    #[test]
    fn test_format_url_rich_https() {
        let result = format_url_rich("https://example.com/path");
        assert!(result.contains("[bright_blue]example.com[/]"));
        assert!(result.contains("/path"));
    }

    #[test]
    fn test_format_url_rich_http() {
        let result = format_url_rich("http://example.com");
        assert!(result.contains("[bright_blue]example.com[/]"));
    }

    #[test]
    fn test_format_url_rich_no_scheme() {
        let result = format_url_rich("plain-text");
        assert_eq!(result, "plain-text");
    }

    #[test]
    fn test_format_error_count_rich() {
        assert!(format_error_count_rich(0).contains("[green]0"));
        assert!(format_error_count_rich(5).contains("[red]5"));
    }

    #[test]
    fn test_format_success_rate_rich_high() {
        let result = format_success_rate_rich(99, 100);
        assert!(result.contains("[green]"));
        assert!(result.contains("99/100"));
    }

    #[test]
    fn test_format_success_rate_rich_medium() {
        let result = format_success_rate_rich(85, 100);
        assert!(result.contains("[yellow]"));
    }

    #[test]
    fn test_format_success_rate_rich_low() {
        let result = format_success_rate_rich(50, 100);
        assert!(result.contains("[red]"));
    }

    #[test]
    fn test_format_success_rate_rich_zero_total() {
        let result = format_success_rate_rich(0, 0);
        assert!(result.contains("n/a"));
    }
}

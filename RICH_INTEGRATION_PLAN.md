# rust_proxy + rich_rust Integration Plan

> Comprehensive plan for integrating rich_rust throughout rust_proxy to create premium, stylish console output while preserving agent compatibility.

---

## Executive Summary

This plan outlines how to integrate `rich_rust` into every aspect of `rust_proxy`'s console output, transforming it from basic terminal text into a visually stunning, professional CLI experience. The key constraint is **agent safety**: AI coding agents (Claude, Codex, Gemini) are primary users, so machine-readable output must be preserved while human-facing output becomes beautiful.

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [Agent-Safe Output Strategy](#2-agent-safe-output-strategy)
3. [Color Palette & Theme System](#3-color-palette--theme-system)
4. [Output Infrastructure](#4-output-infrastructure)
5. [Per-Command Integration](#5-per-command-integration)
6. [Daemon Output](#6-daemon-output)
7. [Error & Warning Presentation](#7-error--warning-presentation)
8. [Progress & Status Indicators](#8-progress--status-indicators)
9. [Implementation Order](#9-implementation-order)
10. [Testing Strategy](#10-testing-strategy)

---

## 1. Design Philosophy

### 1.1 Core Principles

| Principle | Description |
|-----------|-------------|
| **Agent-First** | Never break `--json` output; agents must parse output reliably |
| **Human Delight** | When humans watch, output should feel premium and polished |
| **Semantic Color** | Colors convey meaning (success=green, error=red, warning=yellow) |
| **Consistent Theme** | Unified visual language across all commands |
| **Graceful Degradation** | Works in any terminal (truecolor → 256 → 16 → plain) |
| **Non-Intrusive** | Rich output shouldn't slow down operations or add latency |

### 1.2 Visual Identity

rust_proxy deals with **networking, security, and proxies**. The visual identity should convey:

- **Trust & Security**: Blues, cyans for networking themes
- **Activity & Flow**: Animated spinners for daemon tasks
- **Health & Status**: Traffic-light semantics (green/yellow/red)
- **Professional Polish**: Consistent borders, spacing, alignment

### 1.3 What NOT to Do

- Never use emojis (agents may misparse)
- Never use blinking text (annoying, accessibility concern)
- Never output rich formatting when `--json` is requested
- Never add unnecessary animation that could confuse log parsers
- Never break existing exit codes or output structure

---

## 2. Agent-Safe Output Strategy

### 2.1 Detection Heuristics

Create a centralized output mode detector:

```rust
// src/output.rs (new file)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,      // Interactive terminal, show rich output
    Machine,    // --json flag or piped, show plain/JSON
    Quiet,      // Minimal output for scripting
}

impl OutputMode {
    pub fn detect(json_flag: bool, quiet_flag: bool) -> Self {
        if json_flag {
            return Self::Machine;
        }
        if quiet_flag {
            return Self::Quiet;
        }

        // Check if stdout is a TTY
        if !std::io::stdout().is_terminal() {
            return Self::Machine;
        }

        // Check for CI/agent environment variables
        if std::env::var("CI").is_ok()
            || std::env::var("GITHUB_ACTIONS").is_ok()
            || std::env::var("CLAUDE_CODE").is_ok()
            || std::env::var("CODEX_CLI").is_ok()
            || std::env::var("NO_COLOR").is_ok()
        {
            return Self::Machine;
        }

        Self::Human
    }
}
```

### 2.2 Output Routing

All output goes through a central dispatcher:

```rust
pub struct OutputDispatcher {
    mode: OutputMode,
    console: Option<Console>,  // Only created for Human mode
}

impl OutputDispatcher {
    pub fn new(mode: OutputMode) -> Self {
        let console = match mode {
            OutputMode::Human => Some(Console::new()),
            _ => None,
        };
        Self { mode, console }
    }

    /// Print human-friendly text (ignored in Machine mode)
    pub fn print_rich(&self, markup: &str) {
        if let Some(console) = &self.console {
            console.print(markup);
        }
    }

    /// Print plain text (always)
    pub fn print_plain(&self, text: &str) {
        println!("{}", text);
    }

    /// Print JSON (only in Machine mode)
    pub fn print_json<T: serde::Serialize>(&self, value: &T) {
        if self.mode == OutputMode::Machine {
            println!("{}", serde_json::to_string_pretty(value).unwrap());
        }
    }

    /// Print a renderable (ignored in Machine mode)
    pub fn print_renderable<R: Renderable>(&self, renderable: &R) {
        if let Some(console) = &self.console {
            console.print_renderable(renderable);
        }
    }
}
```

### 2.3 Preserving JSON Output

Every command with `--json` must:
1. Check the flag FIRST
2. If set, output ONLY valid JSON to stdout
3. Never mix rich output with JSON

```rust
// Pattern for all commands:
fn handle_list_command(args: &ListArgs) -> Result<()> {
    let mode = OutputMode::detect(args.json, args.quiet);
    let output = OutputDispatcher::new(mode);

    // Gather data
    let proxies = load_proxies()?;

    // Output based on mode
    match mode {
        OutputMode::Machine => {
            output.print_json(&proxies);
        }
        OutputMode::Human => {
            output.print_rich("[bold cyan]Configured Proxies[/]");
            output.print_renderable(&build_proxy_table(&proxies));
        }
        OutputMode::Quiet => {
            for p in proxies {
                output.print_plain(&p.id);
            }
        }
    }
    Ok(())
}
```

---

## 3. Color Palette & Theme System

### 3.1 Semantic Color Definitions

```rust
// src/theme.rs (new file)

use rich_rust::prelude::*;

/// rust_proxy color theme
pub struct Theme {
    // Status colors
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub info: Color,

    // Element colors
    pub primary: Color,      // Main accent (headers, active items)
    pub secondary: Color,    // Secondary accent
    pub muted: Color,        // Dim/inactive items
    pub highlight: Color,    // Emphasized values

    // Proxy health colors
    pub healthy: Color,
    pub degraded: Color,
    pub unhealthy: Color,
    pub unknown: Color,

    // Data colors
    pub bytes: Color,        // Byte counts
    pub latency: Color,      // Ping times
    pub timestamp: Color,    // Dates/times
    pub domain: Color,       // Target domains
    pub ip: Color,           // IP addresses
    pub provider: Color,     // Provider names
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            // Status (traffic light)
            success: Color::parse("green").unwrap(),
            warning: Color::parse("yellow").unwrap(),
            error: Color::parse("red").unwrap(),
            info: Color::parse("blue").unwrap(),

            // Elements (networking/trust theme)
            primary: Color::parse("cyan").unwrap(),
            secondary: Color::parse("bright_blue").unwrap(),
            muted: Color::parse("bright_black").unwrap(),  // Gray
            highlight: Color::parse("bright_white").unwrap(),

            // Health
            healthy: Color::parse("bright_green").unwrap(),
            degraded: Color::parse("bright_yellow").unwrap(),
            unhealthy: Color::parse("bright_red").unwrap(),
            unknown: Color::parse("bright_black").unwrap(),

            // Data types
            bytes: Color::parse("bright_magenta").unwrap(),
            latency: Color::parse("bright_cyan").unwrap(),
            timestamp: Color::parse("bright_black").unwrap(),
            domain: Color::parse("bright_blue").unwrap(),
            ip: Color::parse("bright_yellow").unwrap(),
            provider: Color::parse("magenta").unwrap(),
        }
    }
}

impl Theme {
    /// Get style for health status
    pub fn health_style(&self, status: &HealthStatus) -> Style {
        let color = match status {
            HealthStatus::Healthy => self.healthy,
            HealthStatus::Degraded => self.degraded,
            HealthStatus::Unhealthy => self.unhealthy,
            HealthStatus::Unknown => self.unknown,
        };
        Style::new().color(color)
    }

    /// Get style for proxy being active
    pub fn active_style(&self, is_active: bool) -> Style {
        if is_active {
            Style::new().bold().color(self.success)
        } else {
            Style::new().color(self.muted)
        }
    }
}

// Global theme accessor
pub fn theme() -> &'static Theme {
    static THEME: std::sync::OnceLock<Theme> = std::sync::OnceLock::new();
    THEME.get_or_init(Theme::default)
}
```

### 3.2 Style Presets

```rust
// Pre-defined styles for common elements
pub mod styles {
    use super::*;

    pub fn header() -> Style {
        Style::new().bold().color(theme().primary)
    }

    pub fn subheader() -> Style {
        Style::new().color(theme().secondary)
    }

    pub fn label() -> Style {
        Style::new().color(theme().muted)
    }

    pub fn value() -> Style {
        Style::new().color(theme().highlight)
    }

    pub fn success_msg() -> Style {
        Style::new().bold().color(theme().success)
    }

    pub fn error_msg() -> Style {
        Style::new().bold().color(theme().error)
    }

    pub fn warning_msg() -> Style {
        Style::new().bold().color(theme().warning)
    }

    pub fn info_msg() -> Style {
        Style::new().color(theme().info)
    }
}
```

---

## 4. Output Infrastructure

### 4.1 New Module Structure

```
src/
├── output/
│   ├── mod.rs           # OutputDispatcher, OutputMode
│   ├── theme.rs         # Theme, colors, styles
│   ├── widgets.rs       # Reusable rich widgets
│   └── formatters.rs    # Data formatters (bytes, duration, etc.)
```

### 4.2 Reusable Widgets

```rust
// src/output/widgets.rs

use rich_rust::prelude::*;

/// Create a section header rule
pub fn section_rule(title: &str) -> Rule {
    Rule::with_title(title)
        .style(Style::new().color(theme().primary))
}

/// Create a success panel
pub fn success_panel(message: &str) -> Panel {
    Panel::new(message)
        .border_style(Style::new().color(theme().success))
        .title("Success")
        .title_align(JustifyMethod::Left)
}

/// Create an error panel
pub fn error_panel(message: &str) -> Panel {
    Panel::new(message)
        .border_style(Style::new().color(theme().error))
        .title("Error")
        .title_align(JustifyMethod::Left)
}

/// Create a warning panel
pub fn warning_panel(message: &str) -> Panel {
    Panel::new(message)
        .border_style(Style::new().color(theme().warning))
        .title("Warning")
        .title_align(JustifyMethod::Left)
}

/// Create an info panel
pub fn info_panel(title: &str, content: &str) -> Panel {
    Panel::new(content)
        .border_style(Style::new().color(theme().info))
        .title(title)
        .title_align(JustifyMethod::Left)
}

/// Create a key-value display panel
pub fn kv_panel(title: &str, items: &[(&str, String)]) -> Panel {
    let mut content = String::new();
    for (key, value) in items {
        content.push_str(&format!("[bold]{key}:[/] {value}\n"));
    }
    content.pop(); // Remove trailing newline

    Panel::new(&content)
        .title(title)
        .border_style(Style::new().color(theme().primary))
}

/// Health status badge
pub fn health_badge(status: &HealthStatus) -> String {
    let (symbol, color) = match status {
        HealthStatus::Healthy => ("●", "green"),
        HealthStatus::Degraded => ("◐", "yellow"),
        HealthStatus::Unhealthy => ("○", "red"),
        HealthStatus::Unknown => ("?", "bright_black"),
    };
    format!("[{color}]{symbol}[/]")
}

/// Active indicator
pub fn active_indicator(is_active: bool) -> String {
    if is_active {
        "[bold green]►[/]".to_string()
    } else {
        " ".to_string()
    }
}
```

### 4.3 Data Formatters

```rust
// src/output/formatters.rs

use rich_rust::prelude::*;

/// Format bytes with color
pub fn format_bytes_rich(bytes: u64) -> String {
    let formatted = crate::util::format_bytes(bytes);
    format!("[bright_magenta]{}[/]", formatted)
}

/// Format duration with color
pub fn format_duration_rich(secs: u64) -> String {
    let formatted = crate::util::format_duration(secs);
    format!("[bright_cyan]{}[/]", formatted)
}

/// Format ping latency with color coding
pub fn format_latency_rich(ms: Option<f64>) -> String {
    match ms {
        Some(ms) if ms < 100.0 => format!("[green]{:.0}ms[/]", ms),
        Some(ms) if ms < 300.0 => format!("[yellow]{:.0}ms[/]", ms),
        Some(ms) => format!("[red]{:.0}ms[/]", ms),
        None => "[bright_black]--[/]".to_string(),
    }
}

/// Format IP address with color
pub fn format_ip_rich(ip: &str) -> String {
    format!("[bright_yellow]{}[/]", ip)
}

/// Format domain with color
pub fn format_domain_rich(domain: &str) -> String {
    format!("[bright_blue]{}[/]", domain)
}

/// Format provider with color
pub fn format_provider_rich(provider: &str) -> String {
    format!("[magenta]{}[/]", provider)
}

/// Format timestamp with color
pub fn format_timestamp_rich(dt: &DateTime<Utc>) -> String {
    let formatted = dt.format("%Y-%m-%d %H:%M:%S");
    format!("[bright_black]{}[/]", formatted)
}

/// Format "ago" duration with color
pub fn format_ago_rich(dt: &DateTime<Utc>) -> String {
    let ago = crate::util::format_duration_since(*dt);
    format!("[bright_black]{}[/]", ago)
}
```

---

## 5. Per-Command Integration

### 5.1 `rust_proxy init`

**Current Output:**
```
Config file created at ~/.config/rust_proxy/config.toml
```

**Rich Output:**
```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  [bold cyan]rust_proxy[/] initialized successfully!                       │
│                                                             │
│  Config:  ~/.config/rust_proxy/config.toml                  │
│  State:   ~/.local/state/rust_proxy/state.json              │
│                                                             │
│  [bold]Next steps:[/]                                               │
│  1. Add a proxy:    rust_proxy proxy add <id> <host:port>   │
│  2. Add targets:    rust_proxy targets add <domain>         │
│  3. Activate:       rust_proxy activate --select            │
│  4. Start daemon:   sudo rust_proxy daemon                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Implementation:**
```rust
fn cmd_init_rich(output: &OutputDispatcher, config_path: &Path, state_path: &Path) {
    let content = format!(
        "[bold cyan]rust_proxy[/] initialized successfully!\n\n\
         [bold]Config:[/]  {}\n\
         [bold]State:[/]   {}\n\n\
         [bold]Next steps:[/]\n\
         1. Add a proxy:    [dim]rust_proxy proxy add <id> <host:port>[/]\n\
         2. Add targets:    [dim]rust_proxy targets add <domain>[/]\n\
         3. Activate:       [dim]rust_proxy activate --select[/]\n\
         4. Start daemon:   [dim]sudo rust_proxy daemon[/]",
        config_path.display(),
        state_path.display()
    );

    let panel = Panel::new(&content)
        .border_style(Style::new().color(theme().success))
        .rounded();

    output.print_renderable(&panel);
}
```

### 5.2 `rust_proxy proxy add`

**Current Output:**
```
Added proxy 'mesh-us' (http://us-wa.proxymesh.com:31280)
```

**Rich Output:**
```
[green]✓[/] Added proxy [bold]mesh-us[/]

┌─ Proxy Details ─────────────────────────────────────────────┐
│ ID:       mesh-us                                           │
│ URL:      http://us-wa.proxymesh.com:31280                  │
│ Auth:     Environment variables (PROXY_USER, PROXY_PASS)    │
│ Priority: 0 (default)                                       │
└─────────────────────────────────────────────────────────────┘

[dim]Tip: Run 'rust_proxy activate mesh-us' to use this proxy[/]
```

### 5.3 `rust_proxy proxy list`

**Current Output:**
```
mesh-us: http://us-wa.proxymesh.com:31280 (env auth)
mesh-eu: http://eu.proxymesh.com:31280 (env auth)
```

**Rich Output:**
```
───────────────────── Configured Proxies ─────────────────────

┌────────────┬──────────────────────────────────┬────────────┐
│ ID         │ URL                              │ Auth       │
├────────────┼──────────────────────────────────┼────────────┤
│ ► mesh-us  │ http://us-wa.proxymesh.com:31280 │ env vars   │
│   mesh-eu  │ http://eu.proxymesh.com:31280    │ env vars   │
└────────────┴──────────────────────────────────┴────────────┘

[dim]► = active proxy    Total: 2 proxies[/]
```

**Implementation:**
```rust
fn build_proxy_list_table(proxies: &[ProxyConfig], active_id: Option<&str>) -> Table {
    let mut table = Table::new()
        .with_column(Column::new("ID").style(Style::new().bold()))
        .with_column(Column::new("URL"))
        .with_column(Column::new("Auth").justify(JustifyMethod::Center));

    for proxy in proxies {
        let is_active = active_id == Some(&proxy.id);
        let indicator = if is_active { "►" } else { " " };
        let id_cell = format!("{} {}", indicator, proxy.id);
        let auth_type = describe_auth(&proxy.auth);

        let mut row = Row::new();
        if is_active {
            row = row.style(Style::new().color(theme().success));
        }
        row = row.cell(&id_cell).cell(&proxy.url).cell(&auth_type);
        table.add_row(row);
    }

    table
}
```

### 5.4 `rust_proxy list` (Stats)

**Current Output:**
```
mesh-us: sent=1.2GB recv=3.4GB ping=45ms active=2d 3h
mesh-eu: sent=0B recv=0B ping=-- active=never
```

**Rich Output:**
```
───────────────────── Proxy Statistics ───────────────────────

┌───┬────────────┬─────────┬─────────┬─────────┬────────────┐
│   │ Proxy      │ Sent    │ Recv    │ Latency │ Health     │
├───┼────────────┼─────────┼─────────┼─────────┼────────────┤
│ ► │ mesh-us    │ 1.2 GB  │ 3.4 GB  │  45ms   │ ● Healthy  │
│   │ mesh-eu    │ 0 B     │ 0 B     │   --    │ ? Unknown  │
└───┴────────────┴─────────┴─────────┴─────────┴────────────┘

Last updated: 2 minutes ago
```

### 5.5 `rust_proxy targets list`

**Current Output:**
```
api.openai.com (openai)
api.anthropic.com (anthropic)
...
```

**Rich Output:**
```
───────────────────── Target Domains ─────────────────────────

┌─────────────────────────────────┬────────────┬─────────────┐
│ Domain                          │ Provider   │ IP Ranges   │
├─────────────────────────────────┼────────────┼─────────────┤
│ api.openai.com                  │ OpenAI     │ ✗           │
│ api.anthropic.com               │ Anthropic  │ ✗           │
│ *.amazonaws.com                 │ AWS        │ ✓ (AWS)     │
│ *.cloudflare.com                │ Cloudflare │ ✓ (CF)      │
└─────────────────────────────────┴────────────┴─────────────┘

Total: 127 domains │ IP ranges: AWS ✓  Cloudflare ✓  Google ✓
```

### 5.6 `rust_proxy status`

**Current Output:**
```
Active proxy: mesh-us
Status: Running
Uptime: 2d 3h 45m
```

**Rich Output:**
```
┌─ rust_proxy Status ─────────────────────────────────────────┐
│                                                             │
│  [bold]Active Proxy:[/]  mesh-us                                    │
│  [bold]URL:[/]           http://us-wa.proxymesh.com:31280           │
│  [bold]Health:[/]        [green]● Healthy[/]                                  │
│                                                             │
│  [bold]Traffic:[/]       ↑ 1.2 GB sent  ↓ 3.4 GB received           │
│  [bold]Latency:[/]       [green]45ms[/] (avg)                                 │
│  [bold]Uptime:[/]        2d 3h 45m                                  │
│                                                             │
│  [bold]Firewall:[/]      [green]● Rules active[/]                             │
│  [bold]ipset:[/]         rust_proxy_targets (847 entries)           │
│  [bold]iptables:[/]      RUST_PROXY chain installed                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 5.7 `rust_proxy activate`

**Current Output:**
```
Activated proxy: mesh-us
```

**Rich Output:**
```
[bold green]✓[/] Activated proxy [bold cyan]mesh-us[/]

┌─ Proxy Configuration ───────────────────────────────────────┐
│ URL:      http://us-wa.proxymesh.com:31280                  │
│ Auth:     Credentials from environment                      │
│ Priority: 0                                                 │
└─────────────────────────────────────────────────────────────┘

[dim]Run 'sudo rust_proxy daemon' to start proxying traffic[/]
```

### 5.8 `rust_proxy diagnose`

**Current Output:**
```
iptables: ok
ipset: ok
dig: ok
...
```

**Rich Output:**
```
───────────────── System Diagnostics ─────────────────────────

┌─ Required Tools ────────────────────────────────────────────┐
│ ✓ iptables    /usr/sbin/iptables    1.8.9                   │
│ ✓ ipset       /usr/sbin/ipset       7.17                    │
│ ✓ dig         /usr/bin/dig          9.18.18                 │
└─────────────────────────────────────────────────────────────┘

┌─ Permissions ───────────────────────────────────────────────┐
│ ✓ Running as root (uid=0)                                   │
│ ✓ Can modify iptables                                       │
│ ✓ Can create ipset                                          │
└─────────────────────────────────────────────────────────────┘

┌─ Network ───────────────────────────────────────────────────┐
│ ✓ DNS resolution working                                    │
│ ✓ Can reach proxy (mesh-us)                                 │
│ ✓ Proxy authentication valid                                │
└─────────────────────────────────────────────────────────────┘

[bold green]All checks passed![/]
```

### 5.9 `rust_proxy check`

**Current Output:**
```
Config valid
2 warnings
```

**Rich Output:**
```
───────────────── Configuration Check ────────────────────────

[bold green]✓[/] Configuration is valid

┌─ Warnings ──────────────────────────────────────────────────┐
│ ⚠ Plaintext password in proxy 'backup-proxy'                │
│   [dim]Consider using --password-env instead[/]                     │
│                                                             │
│ ⚠ Provider mismatch: openai.com tagged as 'google'          │
│   [dim]Expected 'openai' based on domain[/]                         │
└─────────────────────────────────────────────────────────────┘

Proxies: 3   Targets: 127   Active: mesh-us
```

### 5.10 `rust_proxy test <url>`

**Current Output:**
```
example.com -> PROXY (matches target)
google.com -> DIRECT (no match)
```

**Rich Output:**
```
───────────────── Routing Decision ───────────────────────────

┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  [bold]URL:[/]      https://api.openai.com/v1/chat                  │
│  [bold]Domain:[/]   api.openai.com                                  │
│  [bold]Route:[/]    [bold green]PROXY[/] → mesh-us                              │
│                                                             │
│  [bold]Match:[/]    Exact domain match                              │
│  [bold]Provider:[/] OpenAI                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Daemon Output

### 6.1 Startup Sequence

**Current Output:**
```
Starting daemon...
Loading ipset...
Applying iptables rules...
Starting proxy on :12345...
```

**Rich Output:**
```
───────────────── rust_proxy Daemon ──────────────────────────

[bold cyan]Starting rust_proxy daemon...[/]

[dim]├[/] Loading configuration...                          [green]✓[/]
[dim]├[/] Resolving target domains (127 domains)...         [green]✓[/]
[dim]├[/] Fetching IP ranges...
[dim]│   ├[/] AWS ranges (4,821 CIDRs)                      [green]✓[/]
[dim]│   ├[/] Cloudflare ranges (15 CIDRs)                  [green]✓[/]
[dim]│   └[/] Google ranges (892 CIDRs)                     [green]✓[/]
[dim]├[/] Creating ipset 'rust_proxy_targets'...            [green]✓[/]
[dim]├[/] Applying iptables NAT rules...                    [green]✓[/]
[dim]└[/] Starting transparent proxy on :12345...           [green]✓[/]

┌─ Daemon Running ────────────────────────────────────────────┐
│                                                             │
│  [bold]Proxy:[/]     mesh-us (http://us-wa.proxymesh.com:31280)     │
│  [bold]Listen:[/]    127.0.0.1:12345                                │
│  [bold]Targets:[/]   127 domains + 5,728 IP ranges                  │
│  [bold]Health:[/]    Checking every 30s                             │
│                                                             │
│  [dim]Press Ctrl+C to stop[/]                                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Runtime Status Updates

Use tracing for daemon logs, but make them visually distinct:

```rust
// Custom tracing layer for rich output
fn format_log_event(event: &tracing::Event) -> String {
    let level = event.metadata().level();
    let (prefix, color) = match *level {
        Level::ERROR => ("ERR", "red"),
        Level::WARN  => ("WRN", "yellow"),
        Level::INFO  => ("INF", "cyan"),
        Level::DEBUG => ("DBG", "bright_black"),
        Level::TRACE => ("TRC", "bright_black"),
    };

    let timestamp = Utc::now().format("%H:%M:%S");
    format!("[{color}]{prefix}[/] [{timestamp}] {message}")
}
```

### 6.3 Periodic Status Line

For long-running daemon, show periodic summary:

```
[14:32:15] ↑ 45.2 MB ↓ 128.7 MB │ 847 targets │ [green]● Healthy[/] │ 45ms
```

### 6.4 Health Check Events

```
[14:35:00] [green]✓[/] Health check passed (mesh-us, 42ms)
[14:35:30] [yellow]⚠[/] Health check slow (mesh-us, 890ms)
[14:36:00] [red]✗[/] Health check failed (mesh-us, timeout)
[14:36:00] [yellow]→[/] Failing over to mesh-eu...
```

### 6.5 Failover Events

```
┌─ Failover Event ────────────────────────────────────────────┐
│                                                             │
│  [bold red]Primary proxy unhealthy:[/] mesh-us                          │
│  [bold]Reason:[/] 3 consecutive health check failures               │
│                                                             │
│  [bold green]Switching to:[/] mesh-eu                                     │
│  [bold]URL:[/] http://eu.proxymesh.com:31280                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.6 Shutdown Sequence

```
[bold]Shutting down rust_proxy daemon...[/]

[dim]├[/] Stopping proxy listener...                        [green]✓[/]
[dim]├[/] Removing iptables rules...                        [green]✓[/]
[dim]├[/] Destroying ipset...                               [green]✓[/]
[dim]└[/] Saving state...                                   [green]✓[/]

[bold green]Daemon stopped cleanly.[/]
```

---

## 7. Error & Warning Presentation

### 7.1 Error Panels

All errors should be displayed in consistent panels:

```rust
fn display_error(output: &OutputDispatcher, error: &anyhow::Error) {
    let panel = Panel::new(&error.to_string())
        .title("Error")
        .border_style(Style::new().color(theme().error))
        .title_align(JustifyMethod::Left);

    output.print_renderable(&panel);

    // Show chain of causes
    if let Some(cause) = error.source() {
        output.print_rich(&format!("\n[dim]Caused by: {}[/]", cause));
    }
}
```

**Example Error:**
```
┌─ Error ─────────────────────────────────────────────────────┐
│                                                             │
│ Proxy 'mesh-us' not found in configuration                  │
│                                                             │
│ Available proxies:                                          │
│   • mesh-eu                                                 │
│   • backup                                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Validation Warnings

```
┌─ Configuration Warnings ────────────────────────────────────┐
│                                                             │
│ [yellow]⚠[/] 2 issues found:                                         │
│                                                             │
│ 1. [bold]Insecure credentials[/]                                    │
│    Proxy 'backup' has plaintext password in config          │
│    [dim]Recommendation: Use --password-env instead[/]               │
│                                                             │
│ 2. [bold]Unreachable proxy[/]                                       │
│    Cannot connect to mesh-au (connection refused)           │
│    [dim]Check proxy URL and network connectivity[/]                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 7.3 Permission Errors

```
┌─ Permission Error ──────────────────────────────────────────┐
│                                                             │
│ This command requires root privileges                       │
│                                                             │
│ Run with sudo:                                              │
│   [dim]sudo rust_proxy daemon[/]                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 8. Progress & Status Indicators

### 8.1 DNS Resolution Progress

For large domain lists, show progress:

```rust
fn resolve_with_progress(output: &OutputDispatcher, domains: &[String]) {
    if output.mode == OutputMode::Human {
        output.print_rich(&format!(
            "[bold]Resolving {} domains...[/]",
            domains.len()
        ));

        // Show progress bar
        let bar = ProgressBar::new(domains.len() as u64)
            .description("Resolving")
            .bar_style(BarStyle::default()
                .filled_color(theme().primary)
                .empty_color(theme().muted));

        // Update as resolution progresses...
    }
}
```

### 8.2 IP Range Fetching

```
Fetching IP ranges...
  AWS         [████████████████████] 4,821 CIDRs
  Cloudflare  [████████████████████]    15 CIDRs
  Google      [████████████████████]   892 CIDRs
```

### 8.3 Connectivity Test Progress

```
Testing proxy connectivity...
  mesh-us     [████████████████████] 42ms ✓
  mesh-eu     [████████████████████] 156ms ✓
  mesh-au     [                    ] timeout ✗
```

### 8.4 Long-Running Operations

For operations that take time, use spinners:

```rust
fn with_spinner<T>(output: &OutputDispatcher, message: &str, f: impl FnOnce() -> T) -> T {
    if output.mode == OutputMode::Human {
        // Show spinner
        let spinner = Spinner::new("dots").text(message);
        output.print_renderable(&spinner);

        let result = f();

        // Replace with checkmark
        output.print_rich(&format!("[green]✓[/] {}", message));

        result
    } else {
        f()
    }
}
```

---

## 9. Implementation Order

### Phase 1: Foundation (Week 1)

1. **Add rich_rust dependency to Cargo.toml**
   ```toml
   [dependencies]
   rich_rust = { path = "../rich_rust" }  # or version once published
   ```

2. **Create output module structure**
   - `src/output/mod.rs` - OutputDispatcher, OutputMode
   - `src/output/theme.rs` - Theme, colors
   - `src/output/widgets.rs` - Reusable components
   - `src/output/formatters.rs` - Data formatters

3. **Implement OutputDispatcher with mode detection**

4. **Define color theme**

### Phase 2: Core Commands (Week 2)

5. **Update `init` command**
6. **Update `proxy add/remove/list` commands**
7. **Update `targets add/remove/list` commands**
8. **Update `activate/deactivate` commands**

### Phase 3: Stats & Status (Week 3)

9. **Update `list` (stats) command with rich table**
10. **Update `status` command with rich panel**
11. **Update `diagnose` command**
12. **Update `check` command**
13. **Update `test` command**

### Phase 4: Daemon (Week 4)

14. **Rich startup sequence**
15. **Runtime status formatting**
16. **Health check event formatting**
17. **Failover event panels**
18. **Graceful shutdown display**

### Phase 5: Polish (Week 5)

19. **Error presentation standardization**
20. **Warning presentation standardization**
21. **Progress indicators for long operations**
22. **Final theme tuning**
23. **Testing across terminal types**

---

## 10. Testing Strategy

### 10.1 Visual Testing

Create a visual test harness:

```bash
# examples/rich_demo.rs
cargo run --example rich_demo
```

This should display all widgets in all states for visual verification.

### 10.2 Agent Compatibility Testing

```bash
# Verify JSON output unchanged
rust_proxy list --json | jq .
rust_proxy status --json | jq .
rust_proxy targets list --json | jq .

# Verify piped output is plain
rust_proxy list | grep mesh-us

# Verify NO_COLOR respected
NO_COLOR=1 rust_proxy list
```

### 10.3 Terminal Compatibility

Test on:
- Modern terminals (iTerm2, Windows Terminal) - truecolor
- Standard terminals (xterm-256color) - 256 colors
- Basic terminals (linux console) - 16 colors
- No color (dumb terminal, CI) - plain text

### 10.4 Automated Testing

```rust
#[test]
fn test_json_output_unchanged() {
    let output = Command::new("cargo")
        .args(["run", "--", "list", "--json"])
        .output()
        .unwrap();

    // Should be valid JSON
    let _: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
}

#[test]
fn test_no_color_in_machine_mode() {
    let output = Command::new("cargo")
        .args(["run", "--", "list"])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("\x1b["), "Should not contain ANSI codes");
}
```

---

## Appendix A: Complete File List

New files to create:
```
src/output/mod.rs
src/output/theme.rs
src/output/widgets.rs
src/output/formatters.rs
examples/rich_demo.rs
```

Files to modify:
```
Cargo.toml              # Add rich_rust dependency
src/main.rs             # Integrate OutputDispatcher
src/config.rs           # No changes needed
src/state.rs            # No changes needed
src/proxy.rs            # Add rich startup/shutdown
src/iptables.rs         # Add progress indicators
src/dns.rs              # Add progress indicators
src/ip_ranges.rs        # Add progress indicators
src/validation.rs       # Rich warning/error output
```

---

## Appendix B: Markup Quick Reference

| Markup | Effect |
|--------|--------|
| `[bold]text[/]` | Bold |
| `[italic]text[/]` | Italic |
| `[underline]text[/]` | Underline |
| `[dim]text[/]` | Dimmed |
| `[red]text[/]` | Red foreground |
| `[on blue]text[/]` | Blue background |
| `[bold red on white]text[/]` | Combined |
| `[green]✓[/]` | Green checkmark |
| `[yellow]⚠[/]` | Yellow warning |
| `[red]✗[/]` | Red error |
| `[cyan]►[/]` | Cyan indicator |
| `[bright_black]dim text[/]` | Gray/muted |

---

## Appendix C: Box Drawing Characters

| Style | Characters |
|-------|------------|
| Rounded | ╭─╮│╰─╯ |
| Square | ┌─┐│└─┘ |
| Heavy | ┏━┓┃┗━┛ |
| Double | ╔═╗║╚═╝ |
| ASCII | +-+\|+-+ |

---

## Appendix D: Health Status Symbols

| Status | Symbol | Color |
|--------|--------|-------|
| Healthy | ● | green |
| Degraded | ◐ | yellow |
| Unhealthy | ○ | red |
| Unknown | ? | gray |

---

*End of Integration Plan*

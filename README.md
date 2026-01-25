# rust_proxy

<div align="center">
  <img src="rust_proxy.webp" alt="rust_proxy - Machine-wide targeted transparent proxy">
</div>

<div align="center">

[![CI](https://github.com/Dicklesworthstone/rust_proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/Dicklesworthstone/rust_proxy/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-2021-orange)
![Platform](https://img.shields.io/badge/platform-linux-blue)
![Routing](https://img.shields.io/badge/iptables-ipset-red)

Machine-wide, targeted transparent proxying for specific domains.
Pick an upstream HTTP proxy, activate it, and route only selected targets
(Anthropic/OpenAI/Google/AWS/Cloudflare/Vercel/Supabase or your own list).

<h3>Quick Install</h3>

```bash
curl -fsSL https://github.com/Dicklesworthstone/rust_proxy/archive/refs/heads/main.tar.gz | tar xz && cd rust_proxy-main && cargo install --path .
```

**Or build from source:**

```bash
cargo install --git https://github.com/Dicklesworthstone/rust_proxy.git
```

</div>

## TL;DR

**The Problem**: You want a proxy for specific domains (e.g., API providers) without forcing a global system proxy or browser extensions.

**The Solution**: `rust_proxy` installs no system-wide default proxy; it uses `iptables` + `ipset` to redirect only targeted IPv4 traffic into a local transparent proxy that tunnels through your chosen upstream HTTP proxy.

### Why Use rust_proxy?

| Feature | What It Does |
|---------|--------------|
| **Targeted routing** | Only routes domains you list; everything else stays direct. |
| **Machine-wide** | Works for CLI tools, SDKs, and apps without per-app config. |
| **Proxy stats** | Tracks bytes sent/received, activation age, and ping. |
| **Provider ranges** | Optionally adds AWS/Cloudflare/Google IPv4 ranges for wildcard domains. |
| **Safe defaults** | No permanent system proxy settings; rules are applied at runtime. |

### Quick Example

```bash
# Build
cargo build --release

# Initialize config
./target/release/rust_proxy init

# Add a proxy (plain credentials)
./target/release/rust_proxy proxy add mesh-us us-wa.proxymesh.com:31280 \
  --username YOUR_USER --password YOUR_PASS

# Activate + start daemon
./target/release/rust_proxy activate --select
sudo ./target/release/rust_proxy daemon

# Verify
./target/release/rust_proxy status
./target/release/rust_proxy list

# Deactivate (clears iptables/ipset if root)
sudo ./target/release/rust_proxy deactivate
```

## Design Philosophy

- **Targeted by default**: route only the domains you choose, not the whole machine.
- **Runtime state only**: no permanent system proxy settings or network config drift.
- **Observable behavior**: stats + clear CLI output make it obvious what is active.
- **Safe failure modes**: if the daemon stops, traffic returns to normal routing.

## How rust_proxy Compares

| Capability | rust_proxy | Global proxy env | Browser extension | proxychains |
|-----------|-----------|------------------|-------------------|-------------|
| Machine-wide | ✅ | ⚠️ Partial | ❌ | ✅ |
| Per-domain targeting | ✅ | ❌ | ✅ (browser only) | ⚠️ Manual |
| Works for SDKs/CLIs | ✅ | ⚠️ Partial | ❌ | ✅ |
| Requires app config | ❌ | ✅ | ✅ | ❌ |
| Uses iptables/ipset | ✅ | ❌ | ❌ | ❌ |

**When to use rust_proxy:**
- You need machine-wide routing for a small, controlled set of domains.
- You want zero per-app configuration and no global proxy defaults.

**When rust_proxy might not be ideal:**
- You need IPv6 or non-Linux environments.
- You want traffic inspection or MITM features (out of scope).

## Installation

### Quick Install (source tarball)

```bash
curl -fsSL https://github.com/Dicklesworthstone/rust_proxy/archive/refs/heads/main.tar.gz | tar xz
cd rust_proxy-main
cargo install --path .
```

### Cargo Install (Git)

```bash
cargo install --git https://github.com/Dicklesworthstone/rust_proxy.git
```

### From Source

```bash
git clone https://github.com/Dicklesworthstone/rust_proxy.git
cd rust_proxy
cargo build --release
sudo cp target/release/rust_proxy /usr/local/bin/
```

## Quick Start

1. Build or install `rust_proxy`.
2. Run `rust_proxy init` to create `~/.config/rust_proxy/config.toml`.
3. Add at least one proxy with `rust_proxy proxy add ...`.
4. Activate a proxy with `rust_proxy activate --select`.
5. Run `sudo rust_proxy daemon` to apply machine-wide routing.

## Commands

### `rust_proxy init`
Create a default config if missing.

```bash
rust_proxy init
rust_proxy init --force
```

### `rust_proxy proxy add`
Add an upstream proxy definition.

```bash
rust_proxy proxy add mesh-us us-wa.proxymesh.com:31280 \
  --username YOUR_USER --password YOUR_PASS

rust_proxy proxy add mesh-us us-wa.proxymesh.com:31280 \
  --username-env PROXY_USER --password-env PROXY_PASS
```

### `rust_proxy proxy remove`
Remove a proxy definition.

```bash
rust_proxy proxy remove mesh-us
```

### `rust_proxy proxy list`
List configured proxies (no stats).

```bash
rust_proxy proxy list
```

### `rust_proxy targets add`
Add a target domain with an optional provider hint.

```bash
rust_proxy targets add api.openai.com
rust_proxy targets add example.com --provider openai
```

### `rust_proxy targets remove`
Remove a target domain.

```bash
rust_proxy targets remove api.openai.com
```

### `rust_proxy targets list`
List target domains.

```bash
rust_proxy targets list
```

### `rust_proxy activate`
Set the active proxy.

```bash
rust_proxy activate mesh-us
rust_proxy activate --select
```

### `rust_proxy daemon`
Run the transparent proxy daemon (requires sudo).

```bash
sudo rust_proxy daemon
```

### `rust_proxy deactivate`
Disable routing (clears iptables/ipset when root).

```bash
sudo rust_proxy deactivate
sudo rust_proxy deactivate --keep-rules
```

### `rust_proxy list`
Show proxy stats table.

```bash
rust_proxy list
rust_proxy list --json
rust_proxy list --format toon
```

### `rust_proxy status`
Show active proxy + rule status.

```bash
rust_proxy status
rust_proxy status --json
rust_proxy status --format toon
```

### Output formats
Machine output supports JSON or TOON.

```bash
rust_proxy list --format json
rust_proxy list --format toon
RUST_PROXY_OUTPUT_FORMAT=toon rust_proxy status --json
TOON_DEFAULT_FORMAT=toon rust_proxy list --json
```

### `rust_proxy diagnose`
Check system dependencies.

```bash
rust_proxy diagnose
```

### `rust_proxy completions`
Generate shell completions for bash, zsh, fish, PowerShell, or elvish.

```bash
# Bash (add to ~/.bashrc)
rust_proxy completions bash >> ~/.bashrc
source ~/.bashrc

# Zsh (add to ~/.zshrc or use fpath)
rust_proxy completions zsh > ~/.zfunc/_rust_proxy
# Then add to ~/.zshrc: fpath=(~/.zfunc $fpath)

# Fish
rust_proxy completions fish > ~/.config/fish/completions/rust_proxy.fish

# PowerShell (add to profile)
rust_proxy completions powershell >> $PROFILE

# Elvish
rust_proxy completions elvish >> ~/.elvish/rc.elv
```

## Configuration

Config file location:
- `~/.config/rust_proxy/config.toml`

State file location:
- `~/.local/state/rust_proxy/state.json`

Example config (copy-paste ready):

```toml
# ~/.config/rust_proxy/config.toml
active_proxy = "mesh-us"

[[proxies]]
id = "mesh-us"
url = "http://us-wa.proxymesh.com:31280"
[proxies.auth]
username_env = "PROXY_USER"
password_env = "PROXY_PASS"

[[targets]]
domain = "api.openai.com"
provider = "openai"

[[targets]]
domain = "api.anthropic.com"
provider = "anthropic"

[[targets]]
domain = "console.cloud.google.com"
provider = "google"

[settings]
listen_port = 12345
# Refresh DNS + provider ranges every 5 minutes
dns_refresh_secs = 300
# Ping proxies every 60 seconds
ping_interval_secs = 60
# Proxy ping timeout (ms)
ping_timeout_ms = 1500
# ipset name used for targets
ipset_name = "rust_proxy_targets"
# iptables chain name
chain_name = "RUST_PROXY"
# Provider IPv4 ranges
include_aws_ip_ranges = true
include_cloudflare_ip_ranges = true
include_google_ip_ranges = true
# Connection retry settings (exponential backoff)
connect_max_retries = 3
connect_initial_backoff_ms = 100
connect_max_backoff_ms = 5000
```

## Running as a systemd Service

For production deployments, run rust_proxy as a systemd service for automatic startup and restart on failure.

### Installation

```bash
# Copy the service file
sudo cp rust_proxy.service /etc/systemd/system/

# (Optional) Set up proxy credentials
sudo cp rust_proxy.env.example /etc/rust_proxy.env
sudo chmod 600 /etc/rust_proxy.env
sudo nano /etc/rust_proxy.env  # Edit with your credentials

# Reload systemd and enable the service
sudo systemctl daemon-reload
sudo systemctl enable rust_proxy

# Start the service
sudo systemctl start rust_proxy
```

### Managing the Service

```bash
# Check status
sudo systemctl status rust_proxy

# View logs
sudo journalctl -u rust_proxy -f

# Restart after config changes
sudo systemctl restart rust_proxy

# Stop the service
sudo systemctl stop rust_proxy
```

### Configuration Notes

- The systemd service runs as root (required for iptables/ipset)
- Config is read from `/root/.config/rust_proxy/config.toml`
- State is stored in `/root/.local/state/rust_proxy/state.json`
- Proxy credentials can be set in `/etc/rust_proxy.env`
- The service restarts automatically on failure with exponential backoff

## Architecture

```
CLI
  │
  ▼
Config / State
  │
  ▼
Daemon
  │  ├─ DNS (targets) + Provider IP ranges
  │  ├─ ipset sync
  │  ├─ iptables NAT rules
  │  └─ Transparent proxy (CONNECT → upstream HTTP proxy)
  ▼
Upstream Proxy → Internet
```

## Troubleshooting

### "This command must be run as root (sudo)."

```bash
sudo rust_proxy daemon
sudo rust_proxy deactivate
```

### "iptables: missing" or "ipset: missing"

Install dependencies (Ubuntu/Debian):

```bash
sudo apt-get update
sudo apt-get install -y iptables ipset
```

### "No active proxy configured"

```bash
rust_proxy proxy add <id> <host:port>
rust_proxy activate --select
```

### "Proxy CONNECT failed"

Check proxy credentials and connectivity:

```bash
rust_proxy proxy list
# verify credentials and reachability
```

### "No targets configured"

```bash
rust_proxy targets add api.openai.com
```

## Limitations

### What rust_proxy Doesn't Do (Yet)

- **IPv6 support**: only IPv4 is supported today.
- **Non-Linux platforms**: uses `iptables` + `ipset` and is Linux-only.
- **TLS inspection**: no MITM or certificate injection.

## FAQ

### Why "rust_proxy"?
It is a Rust-based proxy selector with minimal system footprint.

### Does this change system proxy settings?
No. It only applies runtime `iptables` rules while the daemon is running.

### Is my traffic decrypted or inspected?
No. The proxy uses CONNECT and does not terminate TLS.

### Can I use environment variables for credentials?
Yes. Use `--username-env` and `--password-env` when adding a proxy.

### How do I reset all rules?

```bash
sudo rust_proxy deactivate
```

## About Contributions

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

License is not yet specified.

## Disclaimer

This tool modifies firewall rules. Use with care and ensure you can access your
machine via a local terminal if you are editing rules over SSH.

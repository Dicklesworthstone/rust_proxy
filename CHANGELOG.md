# Changelog

All notable changes to `rust_proxy` are documented in this file.

This project has no formal releases or tags yet (v0.1.0-dev). History is
reconstructed from the git log on `main`. Commit links point to
<https://github.com/Dicklesworthstone/rust_proxy>.

---

## [Unreleased] — 2026-01-17 to 2026-03-21

### Overview

`rust_proxy` is a machine-wide, targeted transparent proxy for Linux.
It uses `iptables` + `ipset` to redirect only selected domain traffic
(Anthropic, OpenAI, Google, AWS, Cloudflare, etc.) through a chosen
upstream HTTP proxy, without touching global system proxy settings.

The entire codebase was built in a single intensive sprint (Jan 17--25,
2026), with maintenance and dependency updates continuing through
February--March 2026.

---

### Core Proxy Engine

- **Transparent proxy daemon** (`rust_proxy daemon`): binds a local
  listener, intercepts redirected TCP traffic, and tunnels it via HTTP
  CONNECT to the configured upstream proxy.
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **Improved CONNECT response parsing**: proper status-code validation
  and trailer-data handling for faster connection setup.
  ([`b5780bb`](https://github.com/Dicklesworthstone/rust_proxy/commit/b5780bb4a846ef3e0a84abfe5bbfe36aa3fe0be5))
- **Connection retry with exponential backoff**: configurable
  `connect_max_retries` (default 3), `connect_initial_backoff_ms` (100),
  `connect_max_backoff_ms` (5000).
  ([`fd0978c`](https://github.com/Dicklesworthstone/rust_proxy/commit/fd0978ca21d341f7341c3b895848c8dbf75133a4))
- **Robust accept-loop error recovery**: transient OS errors (EMFILE,
  ENFILE, ECONNABORTED, ENOBUFS, ENOMEM, etc.) trigger exponential
  backoff instead of crashing the daemon.
  ([`0b8e7e6`](https://github.com/Dicklesworthstone/rust_proxy/commit/0b8e7e6d2a68532a948ba4ede64246565327327d))
- **File watcher for live config reload**: daemon automatically detects
  config changes and reloads without restart (`notify` crate).
  ([`89004ef`](https://github.com/Dicklesworthstone/rust_proxy/commit/89004ef017c7168c7cf587655c929c26e43232b3))
- **Proxy error logging and refresh detection** fix: surface
  `Ok(Err(e))` from join handles, compare ipset entries by content
  not count.
  ([`e510d8d`](https://github.com/Dicklesworthstone/rust_proxy/commit/e510d8df3b54e71f9886b5edf9f50536ceceec25))

### DNS and IP Range Resolution

- **Parallel DNS resolution** with semaphore-limited concurrency (max
  32): ~29x faster startup/refresh (4.35 s -> 150 ms for 87 domains).
  Includes retry logic for transient failures.
  ([`bb70d49`](https://github.com/Dicklesworthstone/rust_proxy/commit/bb70d4902fb36294a672fe39c298c8c55c4704b2))
- **Provider IP range fetching**: optional inclusion of AWS, Cloudflare,
  and Google IPv4 ranges for wildcard domain coverage.
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))

### Health Checks and Failover

- **Health check configuration and state management**: `HealthStatus`
  enum (Unknown/Healthy/Degraded/Unhealthy), consecutive-failure
  thresholds, per-proxy health tracking in state store.
  ([`d3a0563`](https://github.com/Dicklesworthstone/rust_proxy/commit/d3a05637b7eacc704972ba07cde22b6eae03d2e9))
- **Health check daemon integration**: background `health_check_loop()`
  with graceful shutdown; tests TCP connectivity and HTTP CONNECT.
  ([`d2224cd`](https://github.com/Dicklesworthstone/rust_proxy/commit/d2224cd414a9256a77aa0f096c9b3378e8647773))
- **Configurable health check methods**: support both
  `CONNECT host:port` and `GET url` targets, dispatched per proxy.
  ([`793f6c8`](https://github.com/Dicklesworthstone/rust_proxy/commit/793f6c80114faf0c1f747c47cbbc71298554c070),
   [`d112095`](https://github.com/Dicklesworthstone/rust_proxy/commit/d112095fa3bf62d4c31fd1bf7a7d075ac0245a3d))
- **Automatic failover/failback**: `RuntimeState` for dynamic proxy
  switching, priority-based `find_best_healthy_proxy()`, configurable
  failback delay.
  ([`9a01f36`](https://github.com/Dicklesworthstone/rust_proxy/commit/9a01f36f594f1048161bdae751663223b9d72e12))
- **`--test-connectivity` flag** on `check` command: parallel live
  connectivity tests with latency reporting, auth-required detection.
  ([`bde7f88`](https://github.com/Dicklesworthstone/rust_proxy/commit/bde7f88b71b438abfb601a0d47660915109e46d3))

### Degradation Policies

- **Degradation policy framework**: `FailClosed` (default), `TryAll`,
  `UseLast`, `Direct` — with `degradation_delay_secs` debounce and
  `allow_direct_fallback` safety gate.
  ([`328114f`](https://github.com/Dicklesworthstone/rust_proxy/commit/328114f703b627f2ebe041c4fefba574b750294b))
- **`UseLast` policy**: reconnect through the most recently healthy
  proxy; falls back to `TryAll` on failure.
  ([`e5795f2`](https://github.com/Dicklesworthstone/rust_proxy/commit/e5795f253cb34a1d667228417ae0928fc80fe36b))
- **`Direct` fallback policy**: bypass proxy entirely when all are
  unhealthy (requires explicit opt-in via config).
  ([`87267ca`](https://github.com/Dicklesworthstone/rust_proxy/commit/87267cac70ddcf47387d47516d6a13945611d7aa))
- **Unified degradation handler** integrated into connection flow with
  `is_degraded()` check and improved logging.
  ([`4e460ef`](https://github.com/Dicklesworthstone/rust_proxy/commit/4e460ef3096a698f9e3d03716b3f359292fe6452))

### Load Balancing

- **Load balancer module** (`src/load_balancer.rs`): strategies for
  distributing traffic across multiple backend proxies.
  ([`0370be8`](https://github.com/Dicklesworthstone/rust_proxy/commit/0370be8de0df58858effec5bbca6e74cebc94b07))
- **Extended load balancer configuration**: priority, weighting, and
  strategy options in config.
  ([`ee1e52c`](https://github.com/Dicklesworthstone/rust_proxy/commit/ee1e52c637f660aab2297a6997b92e4d45305b14))
- **Comprehensive load balancing logic**: single-priority, round-robin,
  and weighted distribution with health-aware proxy exclusion.
  ([`9766600`](https://github.com/Dicklesworthstone/rust_proxy/commit/97666009e89d9e4b47b7731ea0c06d7365be7425))
- **Enhanced load balancer and output widgets**: improved connection
  handling and TUI display feedback.
  ([`4614eb7`](https://github.com/Dicklesworthstone/rust_proxy/commit/4614eb72d06d1d473b24ff5bd1643a9397e695f0))

### Metrics and Observability

- **Prometheus metrics module** (`src/metrics.rs`): byte counters,
  connection tracking, proxy stats collection.
  ([`0370be8`](https://github.com/Dicklesworthstone/rust_proxy/commit/0370be8de0df58858effec5bbca6e74cebc94b07))
- **Metrics server** (`src/metrics_server.rs`): HTTP endpoints for
  metrics scraping.
  ([`0370be8`](https://github.com/Dicklesworthstone/rust_proxy/commit/0370be8de0df58858effec5bbca6e74cebc94b07),
   [`bb12079`](https://github.com/Dicklesworthstone/rust_proxy/commit/bb120793b59ad2d3ce61deb6b98cb8f54051b3c8))
- **Metrics tests and degradation tracking**: expanded test coverage for
  metrics collection and degradation state.
  ([`42f6a5c`](https://github.com/Dicklesworthstone/rust_proxy/commit/42f6a5c588a79447dddbc0874e98c04a6d7bf19f))

### CLI Commands

- **`rust_proxy init`**: create default config at
  `~/.config/rust_proxy/config.toml`.
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy proxy add/remove/list`**: manage upstream proxy
  definitions with plain or env-var credentials.
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy targets add/remove/list`**: manage target domain routing
  with optional provider hints.
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy activate/deactivate`**: set active proxy; clear iptables
  and ipset rules on deactivation.
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy status`**: show active proxy, rule status, and health
  information; supports `--json` and `--format toon`.
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449),
   [`9a01f36`](https://github.com/Dicklesworthstone/rust_proxy/commit/9a01f36f594f1048161bdae751663223b9d72e12))
- **`rust_proxy list`**: proxy stats table with JSON and TOON output.
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy check`**: pre-flight configuration validation (like
  `nginx -t`); validates proxies, targets, settings, active reference;
  `--strict`, `--quiet`, `--json` flags; exit codes 0/1/2/3.
  ([`dbd2af1`](https://github.com/Dicklesworthstone/rust_proxy/commit/dbd2af124df123b15d757b9dc2ab1a4e271449f6))
- **`rust_proxy test <url>`**: routing diagnosis showing DNS resolution,
  target match, provider range match, daemon status; `--json`, `-v`,
  `--no-dns` modes.
  ([`46c9a07`](https://github.com/Dicklesworthstone/rust_proxy/commit/46c9a070496b2341f5341ccef8095c363573b529))
- **`rust_proxy diagnose`**: check system dependencies (iptables, ipset).
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy completions <shell>`**: generate shell completions for
  bash, zsh, fish, PowerShell, elvish via `clap_complete`.
  ([`8fd8412`](https://github.com/Dicklesworthstone/rust_proxy/commit/8fd84126879ab7173f836ba937e556084eb3e99c),
   [`a8a8d26`](https://github.com/Dicklesworthstone/rust_proxy/commit/a8a8d26cdbb9d62fb1a68a5a010e50ba6696d7bf))

### Output and Theming

- **Comprehensive output system** (`src/output/`): formatters, themes,
  and reusable TUI widgets for styled CLI output.
  ([`c318245`](https://github.com/Dicklesworthstone/rust_proxy/commit/c31824547b5178a39c69b82a6487804cd0fe6671))
- **Output theming support**: consistent color schemes across all
  command output.
  ([`8ba9be8`](https://github.com/Dicklesworthstone/rust_proxy/commit/8ba9be82be0cd7e166b2096bfa2403f4f44829e3))
- **Rich terminal output with `rich_rust`/`charmed_rust`**: styled
  console output with structured tables and colors.
  ([`549d4e8`](https://github.com/Dicklesworthstone/rust_proxy/commit/549d4e8d4dec15c5b10377d6d5180207489de7a1))
- **JSON and TOON output formats**: machine-readable output on all
  commands via `--json` / `--format toon` / env vars.
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))

### Error Handling

- **Structured error module** (`src/error.rs`): 849-line error taxonomy
  covering config, proxy, DNS, iptables, health, and validation errors.
  ([`0370be8`](https://github.com/Dicklesworthstone/rust_proxy/commit/0370be8de0df58858effec5bbca6e74cebc94b07))

### Configuration and Validation

- **TOML config** at `~/.config/rust_proxy/config.toml` with proxy
  definitions, target domains, provider hints, and tunable settings.
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **Validation module** (`src/validation.rs`): proxy URL/auth/duplicate
  checks, domain format checks, settings range checks, strict mode.
  ([`dbd2af1`](https://github.com/Dicklesworthstone/rust_proxy/commit/dbd2af124df123b15d757b9dc2ab1a4e271449f6),
   [`328114f`](https://github.com/Dicklesworthstone/rust_proxy/commit/328114f703b627f2ebe041c4fefba574b750294b))
- **DryRun helper infrastructure**: `would_do()`, `execute_or_skip()`,
  `is_enabled()` for consistent dry-run behavior across commands.
  ([`f72a2d3`](https://github.com/Dicklesworthstone/rust_proxy/commit/f72a2d315b4d664c8e402c4b8de12dc3f5e806d0))
- **Extended config options**: proxy priority, health check URLs, load
  balancer strategy/weight, degradation policy.
  ([`eb94758`](https://github.com/Dicklesworthstone/rust_proxy/commit/eb947588de35d7efcf9e72df67f3bb7310d7aaab),
   [`df3da82`](https://github.com/Dicklesworthstone/rust_proxy/commit/df3da82c3a5eda7a04108a5475366c35a227c5b3),
   [`ee1e52c`](https://github.com/Dicklesworthstone/rust_proxy/commit/ee1e52c637f660aab2297a6997b92e4d45305b14))

### State Management

- **JSON state store** at `~/.local/state/rust_proxy/state.json`:
  per-proxy stats, health tracking, activation history.
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **Extended state tracking**: `record_health_check()`,
  `get_healthy_proxies()`, `get_last_healthy_proxy()`, network
  operation utilities.
  ([`d3a0563`](https://github.com/Dicklesworthstone/rust_proxy/commit/d3a05637b7eacc704972ba07cde22b6eae03d2e9),
   [`cc78da1`](https://github.com/Dicklesworthstone/rust_proxy/commit/cc78da1c2689feb91798695127e34dc0ef2db0b2))

### Deployment

- **systemd service file** (`rust_proxy.service`): automatic restart
  with exponential backoff, security hardening (ProtectSystem,
  PrivateTmp), journald logging, optional env file for credentials.
  ([`04889d3`](https://github.com/Dicklesworthstone/rust_proxy/commit/04889d32f124594cb66c033897d0756dc8dbbc17))

### Testing

- **35 unit tests** for `util.rs` and `config.rs`: `parse_proxy_url`,
  `format_bytes`, `format_duration`, `infer_provider`, `ProxyAuth`,
  `Settings` defaults.
  ([`4cf7097`](https://github.com/Dicklesworthstone/rust_proxy/commit/4cf7097f61368bb67aa6d953bfb56dbb4360ae0e))
- **E2E test infrastructure** (`tests/`): `TestHarness` with temp dirs,
  `MockProxy` server, configuration fixtures, domain-specific
  assertions.
  ([`33911e5`](https://github.com/Dicklesworthstone/rust_proxy/commit/33911e53431947a3fcdef66477f9c6f236e72658))
- **E2E load balancing tests**: single-priority, round-robin, weighted
  distribution, unhealthy-proxy exclusion, failover behavior.
  ([`5dccbd5`](https://github.com/Dicklesworthstone/rust_proxy/commit/5dccbd5f28a93ec3f56b42b2691a0597978e6197))
- **TOON list roundtrip test**: verify TOON serialization/deserialization
  of proxy list output.
  ([`f03fcca`](https://github.com/Dicklesworthstone/rust_proxy/commit/f03fccaf8e5cb971265a951f3c376a9efa39788e),
   [`5eb391e`](https://github.com/Dicklesworthstone/rust_proxy/commit/5eb391e9b3a3711f9c10e556210f5815305b5c8b))
- **Shell completion generation tests**: verify completions for all
  supported shells.
  ([`a8a8d26`](https://github.com/Dicklesworthstone/rust_proxy/commit/a8a8d26cdbb9d62fb1a68a5a010e50ba6696d7bf))

### CI/CD

- **GitHub Actions workflow** (`.github/workflows/ci.yml`): fmt, clippy,
  check, test steps; clones `rich_rust` and `toon_rust` path deps.
  ([`b5780bb`](https://github.com/Dicklesworthstone/rust_proxy/commit/b5780bb4a846ef3e0a84abfe5bbfe36aa3fe0be5),
   [`229d554`](https://github.com/Dicklesworthstone/rust_proxy/commit/229d554d7e42fdad6b76aed9eb989533db4d5885),
   [`03bc53a`](https://github.com/Dicklesworthstone/rust_proxy/commit/03bc53a744ab98fec11a92c73112d6601d212f84),
   [`dcb5c8f`](https://github.com/Dicklesworthstone/rust_proxy/commit/dcb5c8f587ff5afb2291063b387e96209f5bfc75))
- **Clippy warning fixes**: all warnings resolved for clean CI.
  ([`89e1403`](https://github.com/Dicklesworthstone/rust_proxy/commit/89e14032ae581ed43732e8fe85af8012dae0f936),
   [`ed5ecc1`](https://github.com/Dicklesworthstone/rust_proxy/commit/ed5ecc19063651238c99e7ef0338ecfad4f9a87e),
   [`aa614f1`](https://github.com/Dicklesworthstone/rust_proxy/commit/aa614f1aaf00563d0a1c3f5834515a7b1330f4cc))

### Dependencies

- **`rich_rust` migrated to crates.io v0.2.0** from pre-release/git ref.
  ([`fe1b803`](https://github.com/Dicklesworthstone/rust_proxy/commit/fe1b80364ebd53d54e8fdb7687e71154cba6f082))
- **Dependency updates**: 5 dependencies updated to latest stable
  versions (2026-01-18).
  ([`77076ba`](https://github.com/Dicklesworthstone/rust_proxy/commit/77076ba367f1623385a40b9732432e15e43ac780))
- **Cargo.lock refresh** (2026-01-25).
  ([`3973c93`](https://github.com/Dicklesworthstone/rust_proxy/commit/3973c935ce028236d8a639944a838e1442282b38))

### License

- **MIT License** added (2026-01-21).
  ([`eda22c2`](https://github.com/Dicklesworthstone/rust_proxy/commit/eda22c2a5f02d75e548fce955fab6a119096f663))
- **MIT + OpenAI/Anthropic Rider**: updated to restrict use by OpenAI,
  Anthropic, and affiliates without express permission (2026-02-21).
  ([`d2465b2`](https://github.com/Dicklesworthstone/rust_proxy/commit/d2465b2f8bf2b5c97cb4e5cfafedc267ba8fafaa))

### Documentation

- **README**: comprehensive docs covering installation, commands,
  configuration, architecture, troubleshooting, FAQ, comparison table.
  ([`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **Project illustration** and social preview image.
  ([`7bd8446`](https://github.com/Dicklesworthstone/rust_proxy/commit/7bd8446b2c5e07fafa7fd5c3e4be22d1adb7d85e),
   [`f3113b6`](https://github.com/Dicklesworthstone/rust_proxy/commit/f3113b6ba1ef7a6118f1e9ffca0a973ffa31a4bc))
- **rich_rust integration plan** documenting the output theming roadmap.
  ([`71c6459`](https://github.com/Dicklesworthstone/rust_proxy/commit/71c64592e6e5859024a7138cf557e70cde276200))

---

### Source Module Map (as of HEAD)

| Module | Lines | Purpose |
|--------|-------|---------|
| `src/main.rs` | ~101k | CLI entry point, daemon orchestration, command dispatch |
| `src/config.rs` | ~95k | TOML config parsing, proxy/target/settings structs |
| `src/proxy.rs` | ~52k | Transparent proxy, CONNECT tunneling, degradation |
| `src/util.rs` | ~51k | Helpers: DryRun, format_bytes, parse_proxy_url |
| `src/validation.rs` | ~33k | Config validation, check command logic |
| `src/output/widgets.rs` | ~36k | TUI widgets for styled output |
| `src/output/theme.rs` | ~32k | Color themes and styling |
| `src/output/mod.rs` | ~32k | Output system entry, format dispatch |
| `src/error.rs` | ~26k | Structured error types |
| `src/state.rs` | ~24k | JSON state store, health tracking |
| `src/load_balancer.rs` | ~22k | Multi-proxy load balancing strategies |
| `src/metrics.rs` | ~17k | Prometheus counters and gauges |
| `src/health.rs` | ~16k | Health check loop, failover/failback |
| `src/output/formatters.rs` | ~15k | Output formatting utilities |
| `src/dns.rs` | ~8k | Parallel DNS resolution with retry |
| `src/watcher.rs` | ~7k | Config file change watcher |
| `src/iptables.rs` | ~4k | iptables/ipset rule management |
| `src/metrics_server.rs` | ~4k | HTTP metrics endpoint |
| `src/ip_ranges.rs` | ~2k | AWS/Cloudflare/Google range fetching |

---

### Full Commit History (non-metadata)

Commits are listed newest-first. `bd sync` (beads state) and
`chore(beads)` commits are omitted for clarity.

| Date | Hash | Summary |
|------|------|---------|
| 2026-02-25 | [`557d029`](https://github.com/Dicklesworthstone/rust_proxy/commit/557d029f09bdf5e0e173998edbf8852b78c8121b) | docs(AGENTS.md): add cass tool reference |
| 2026-02-21 | [`d2465b2`](https://github.com/Dicklesworthstone/rust_proxy/commit/d2465b2f8bf2b5c97cb4e5cfafedc267ba8fafaa) | chore: update license to MIT with OpenAI/Anthropic Rider |
| 2026-02-21 | [`f3113b6`](https://github.com/Dicklesworthstone/rust_proxy/commit/f3113b6ba1ef7a6118f1e9ffca0a973ffa31a4bc) | chore: add GitHub social preview image |
| 2026-02-15 | [`fe1b803`](https://github.com/Dicklesworthstone/rust_proxy/commit/fe1b80364ebd53d54e8fdb7687e71154cba6f082) | Update rich_rust dep to crates.io v0.2.0 |
| 2026-02-14 | [`a800e62`](https://github.com/Dicklesworthstone/rust_proxy/commit/a800e6258fcdb41e6fa5df33e2a9c53baa34aace) | docs: update AGENTS.md |
| 2026-01-25 | [`3973c93`](https://github.com/Dicklesworthstone/rust_proxy/commit/3973c935ce028236d8a639944a838e1442282b38) | chore(deps): Update Cargo.lock |
| 2026-01-25 | [`dcb5c8f`](https://github.com/Dicklesworthstone/rust_proxy/commit/dcb5c8f587ff5afb2291063b387e96209f5bfc75) | fix(ci): clone toon_rust path dep for CI |
| 2026-01-25 | [`5eb391e`](https://github.com/Dicklesworthstone/rust_proxy/commit/5eb391e9b3a3711f9c10e556210f5815305b5c8b) | test: honor CARGO_BIN_EXE in harness |
| 2026-01-25 | [`f03fcca`](https://github.com/Dicklesworthstone/rust_proxy/commit/f03fccaf8e5cb971265a951f3c376a9efa39788e) | test: add TOON list roundtrip |
| 2026-01-25 | [`0ccd158`](https://github.com/Dicklesworthstone/rust_proxy/commit/0ccd158cb1feec34ce1f1443c2f4a0f0e01ac027) | Update from parallel agent work |
| 2026-01-25 | [`549d4e8`](https://github.com/Dicklesworthstone/rust_proxy/commit/549d4e8d4dec15c5b10377d6d5180207489de7a1) | Add rich terminal output with charmed_rust |
| 2026-01-24 | [`aa614f1`](https://github.com/Dicklesworthstone/rust_proxy/commit/aa614f1aaf00563d0a1c3f5834515a7b1330f4cc) | fix(tests): silence dead_code warnings |
| 2026-01-24 | [`ed5ecc1`](https://github.com/Dicklesworthstone/rust_proxy/commit/ed5ecc19063651238c99e7ef0338ecfad4f9a87e) | fix(ci): resolve all clippy warnings |
| 2026-01-24 | [`bea5cfb`](https://github.com/Dicklesworthstone/rust_proxy/commit/bea5cfbbc76f1f1b966a1bbca6e30716a2c0f1d1) | chore(gitignore): ephemeral file patterns |
| 2026-01-24 | [`89e1403`](https://github.com/Dicklesworthstone/rust_proxy/commit/89e14032ae581ed43732e8fe85af8012dae0f936) | fix: resolve clippy warnings for CI |
| 2026-01-24 | [`03bc53a`](https://github.com/Dicklesworthstone/rust_proxy/commit/03bc53a744ab98fec11a92c73112d6601d212f84) | fix(ci): clone rich_rust dep before cargo |
| 2026-01-23 | [`6ef3ac5`](https://github.com/Dicklesworthstone/rust_proxy/commit/6ef3ac5c89ef93815fe2e5ac83f3dd91297b3cd2) | Fix cargo fmt formatting |
| 2026-01-23 | [`4614eb7`](https://github.com/Dicklesworthstone/rust_proxy/commit/4614eb72d06d1d473b24ff5bd1643a9397e695f0) | feat(proxy): enhance load balancer and widgets |
| 2026-01-22 | [`9766600`](https://github.com/Dicklesworthstone/rust_proxy/commit/97666009e89d9e4b47b7731ea0c06d7365be7425) | feat(lb): comprehensive load balancing |
| 2026-01-22 | [`8ba9be8`](https://github.com/Dicklesworthstone/rust_proxy/commit/8ba9be82be0cd7e166b2096bfa2403f4f44829e3) | feat: Add output theming support |
| 2026-01-22 | [`cc78da1`](https://github.com/Dicklesworthstone/rust_proxy/commit/cc78da1c2689feb91798695127e34dc0ef2db0b2) | feat: Extend proxy state management |
| 2026-01-22 | [`4e460ef`](https://github.com/Dicklesworthstone/rust_proxy/commit/4e460ef3096a698f9e3d03716b3f359292fe6452) | Integrate degradation into connection flow |
| 2026-01-22 | [`87267ca`](https://github.com/Dicklesworthstone/rust_proxy/commit/87267cac70ddcf47387d47516d6a13945611d7aa) | Implement direct fallback degradation |
| 2026-01-22 | [`a8a8d26`](https://github.com/Dicklesworthstone/rust_proxy/commit/a8a8d26cdbb9d62fb1a68a5a010e50ba6696d7bf) | Add completions function and tests |
| 2026-01-22 | [`e5795f2`](https://github.com/Dicklesworthstone/rust_proxy/commit/e5795f253cb34a1d667228417ae0928fc80fe36b) | Implement use_last degradation policy |
| 2026-01-22 | [`9ec0733`](https://github.com/Dicklesworthstone/rust_proxy/commit/9ec07339254634e49203aa858a3bfb0a274040cc) | Update utility functions |
| 2026-01-21 | [`cf78d03`](https://github.com/Dicklesworthstone/rust_proxy/commit/cf78d031f77891d3f95edc598531f0f99bb04018) | Update proxy module |
| 2026-01-21 | [`5dccbd5`](https://github.com/Dicklesworthstone/rust_proxy/commit/5dccbd5f28a93ec3f56b42b2691a0597978e6197) | E2E tests for load balancing |
| 2026-01-21 | [`33911e5`](https://github.com/Dicklesworthstone/rust_proxy/commit/33911e53431947a3fcdef66477f9c6f236e72658) | E2E test infrastructure foundation |
| 2026-01-21 | [`42f6a5c`](https://github.com/Dicklesworthstone/rust_proxy/commit/42f6a5c588a79447dddbc0874e98c04a6d7bf19f) | Metrics tests + degradation tracking |
| 2026-01-21 | [`eda22c2`](https://github.com/Dicklesworthstone/rust_proxy/commit/eda22c2a5f02d75e548fce955fab6a119096f663) | Add MIT License |
| 2026-01-21 | [`d824094`](https://github.com/Dicklesworthstone/rust_proxy/commit/d824094f27fbf01551e420990594873fb39f8fb6) | Improve main and output modules |
| 2026-01-21 | [`89004ef`](https://github.com/Dicklesworthstone/rust_proxy/commit/89004ef017c7168c7cf587655c929c26e43232b3) | File watcher for config reload |
| 2026-01-21 | [`793f6c8`](https://github.com/Dicklesworthstone/rust_proxy/commit/793f6c80114faf0c1f747c47cbbc71298554c070) | Configurable health check methods |
| 2026-01-21 | [`d112095`](https://github.com/Dicklesworthstone/rust_proxy/commit/d112095fa3bf62d4c31fd1bf7a7d075ac0245a3d) | Health check target configuration |
| 2026-01-21 | [`f99f9d1`](https://github.com/Dicklesworthstone/rust_proxy/commit/f99f9d12b1d214e4e4e879343be86c57e604b33b) | Enhance config and utility functions |
| 2026-01-21 | [`3ffed02`](https://github.com/Dicklesworthstone/rust_proxy/commit/3ffed020919d5ab05b60850f454603a0576dd083) | Extend config and metrics |
| 2026-01-21 | [`ee1e52c`](https://github.com/Dicklesworthstone/rust_proxy/commit/ee1e52c637f660aab2297a6997b92e4d45305b14) | Enhance load balancer configuration |
| 2026-01-21 | [`df3da82`](https://github.com/Dicklesworthstone/rust_proxy/commit/df3da82c3a5eda7a04108a5475366c35a227c5b3) | Extend config handling |
| 2026-01-21 | [`eb94758`](https://github.com/Dicklesworthstone/rust_proxy/commit/eb947588de35d7efcf9e72df67f3bb7310d7aaab) | Enhance proxy config handling |
| 2026-01-21 | [`bb12079`](https://github.com/Dicklesworthstone/rust_proxy/commit/bb120793b59ad2d3ce61deb6b98cb8f54051b3c8) | Enhance metrics server endpoints |
| 2026-01-21 | [`0370be8`](https://github.com/Dicklesworthstone/rust_proxy/commit/0370be8de0df58858effec5bbca6e74cebc94b07) | Major proxy improvements (error, lb, metrics) |
| 2026-01-21 | [`c318245`](https://github.com/Dicklesworthstone/rust_proxy/commit/c31824547b5178a39c69b82a6487804cd0fe6671) | Comprehensive output system |
| 2026-01-19 | [`71c6459`](https://github.com/Dicklesworthstone/rust_proxy/commit/71c64592e6e5859024a7138cf557e70cde276200) | docs: rich_rust integration plan |
| 2026-01-18 | [`f070219`](https://github.com/Dicklesworthstone/rust_proxy/commit/f0702198eee98eebc90182dcaa785d1916db5087) | Update deps and add illustration |
| 2026-01-18 | [`f72a2d3`](https://github.com/Dicklesworthstone/rust_proxy/commit/f72a2d315b4d664c8e402c4b8de12dc3f5e806d0) | feat(util): DryRun helper infrastructure |
| 2026-01-18 | [`328114f`](https://github.com/Dicklesworthstone/rust_proxy/commit/328114f703b627f2ebe041c4fefba574b750294b) | feat(config): degradation policy options |
| 2026-01-18 | [`77076ba`](https://github.com/Dicklesworthstone/rust_proxy/commit/77076ba367f1623385a40b9732432e15e43ac780) | chore: update 5 dependencies |
| 2026-01-18 | [`bde7f88`](https://github.com/Dicklesworthstone/rust_proxy/commit/bde7f88b71b438abfb601a0d47660915109e46d3) | feat: --test-connectivity for check |
| 2026-01-18 | [`9a01f36`](https://github.com/Dicklesworthstone/rust_proxy/commit/9a01f36f594f1048161bdae751663223b9d72e12) | feat: failover/failback logic |
| 2026-01-18 | [`d2224cd`](https://github.com/Dicklesworthstone/rust_proxy/commit/d2224cd414a9256a77aa0f096c9b3378e8647773) | feat: health check daemon integration |
| 2026-01-18 | [`d3a0563`](https://github.com/Dicklesworthstone/rust_proxy/commit/d3a05637b7eacc704972ba07cde22b6eae03d2e9) | feat: health check config and state |
| 2026-01-18 | [`bb70d49`](https://github.com/Dicklesworthstone/rust_proxy/commit/bb70d4902fb36294a672fe39c298c8c55c4704b2) | perf: parallel DNS resolution |
| 2026-01-18 | [`46c9a07`](https://github.com/Dicklesworthstone/rust_proxy/commit/46c9a070496b2341f5341ccef8095c363573b529) | feat: `rust_proxy test <url>` command |
| 2026-01-18 | [`dbd2af1`](https://github.com/Dicklesworthstone/rust_proxy/commit/dbd2af124df123b15d757b9dc2ab1a4e271449f6) | feat: `rust_proxy check` command |
| 2026-01-18 | [`0b8e7e6`](https://github.com/Dicklesworthstone/rust_proxy/commit/0b8e7e6d2a68532a948ba4ede64246565327327d) | feat: robust accept loop recovery |
| 2026-01-18 | [`e510d8d`](https://github.com/Dicklesworthstone/rust_proxy/commit/e510d8df3b54e71f9886b5edf9f50536ceceec25) | fix: proxy error logging and refresh |
| 2026-01-18 | [`229d554`](https://github.com/Dicklesworthstone/rust_proxy/commit/229d554d7e42fdad6b76aed9eb989533db4d5885) | ci: add cargo test to workflow |
| 2026-01-18 | [`7bd8446`](https://github.com/Dicklesworthstone/rust_proxy/commit/7bd8446b2c5e07fafa7fd5c3e4be22d1adb7d85e) | docs: add README illustration |
| 2026-01-18 | [`fd0978c`](https://github.com/Dicklesworthstone/rust_proxy/commit/fd0978ca21d341f7341c3b895848c8dbf75133a4) | feat: connection retry with backoff |
| 2026-01-18 | [`8fd8412`](https://github.com/Dicklesworthstone/rust_proxy/commit/8fd84126879ab7173f836ba937e556084eb3e99c) | feat: shell completion generation |
| 2026-01-18 | [`04889d3`](https://github.com/Dicklesworthstone/rust_proxy/commit/04889d32f124594cb66c033897d0756dc8dbbc17) | feat: systemd service file |
| 2026-01-17 | [`4cf7097`](https://github.com/Dicklesworthstone/rust_proxy/commit/4cf7097f61368bb67aa6d953bfb56dbb4360ae0e) | test: 35 unit tests for util + config |
| 2026-01-17 | [`b5780bb`](https://github.com/Dicklesworthstone/rust_proxy/commit/b5780bb4a846ef3e0a84abfe5bbfe36aa3fe0be5) | feat: CI workflow + CONNECT improvements |
| 2026-01-17 | [`acaa94d`](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449) | chore: initialize repo and docs |

---

*This changelog was generated from 102 commits across 2 authors.*
*Repository: <https://github.com/Dicklesworthstone/rust_proxy>*
*Current version: 0.1.0 (no formal releases yet)*

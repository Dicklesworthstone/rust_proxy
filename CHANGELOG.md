# Changelog

All notable changes to **rust_proxy** are documented in this file.

There are no formal releases or tags yet; the project remains at `v0.1.0-dev`.
History is reconstructed exhaustively from the git log on `main`.
Commit links point to
[github.com/Dicklesworthstone/rust_proxy](https://github.com/Dicklesworthstone/rust_proxy).

---

## [Unreleased] -- 2026-01-17 through 2026-03-21

The entire functional codebase was built in a single intensive sprint
(2026-01-17 to 2026-01-25), with dependency updates, licensing, and
documentation continuing through February and March 2026.

---

### Transparent Proxy Engine

The core daemon intercepts traffic redirected by iptables/ipset and
tunnels it via HTTP CONNECT to the configured upstream proxy, without
touching global system proxy settings or requiring any per-app
configuration.

- **Transparent proxy daemon** (`rust_proxy daemon`): local TCP listener
  that accepts redirected connections and establishes CONNECT tunnels to
  the active upstream HTTP proxy. Requires root for iptables/ipset
  manipulation.
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **Improved CONNECT response parsing**: proper HTTP status-code
  validation and trailer-data handling after CONNECT headers, enabling
  faster connection setup.
  ([b5780bb](https://github.com/Dicklesworthstone/rust_proxy/commit/b5780bb4a846ef3e0a84abfe5bbfe36aa3fe0be5))
- **Connection retry with exponential backoff**: configurable
  `connect_max_retries` (default 3), `connect_initial_backoff_ms`
  (default 100), and `connect_max_backoff_ms` (default 5000) for
  resilient upstream connections.
  ([fd0978c](https://github.com/Dicklesworthstone/rust_proxy/commit/fd0978ca21d341f7341c3b895848c8dbf75133a4))
- **Robust accept-loop error recovery**: transient OS errors (EMFILE,
  ENFILE, ECONNABORTED, ENOBUFS, ENOMEM, ConnectionReset, Interrupted,
  WouldBlock) now trigger exponential backoff with a 5-second cap
  instead of crashing the daemon. Includes `AcceptBackoff` struct and 6
  unit tests for error classification.
  ([0b8e7e6](https://github.com/Dicklesworthstone/rust_proxy/commit/0b8e7e6d2a68532a948ba4ede64246565327327d))
- **Live config reload via file watcher**: the daemon monitors
  `config.toml` for changes using the `notify` crate and reloads
  without requiring a restart.
  ([89004ef](https://github.com/Dicklesworthstone/rust_proxy/commit/89004ef017c7168c7cf587655c929c26e43232b3))
- **Proxy error logging fix**: surface `Ok(Err(e))` from tokio join
  handles (not just `JoinError`); compare ipset entries by content
  rather than count for accurate refresh detection.
  ([e510d8d](https://github.com/Dicklesworthstone/rust_proxy/commit/e510d8df3b54e71f9886b5edf9f50536ceceec25))

### DNS and Provider IP Range Resolution

- **Parallel DNS resolution** with semaphore-limited concurrency (max 32
  concurrent lookups): approximately 29x faster startup and refresh
  times (4.35s down to ~150ms for 87 domains). Includes retry logic for
  transient DNS failures (SERVFAIL, timeout, connection refused) and a
  `DnsResolutionReport` struct for detailed statistics.
  ([bb70d49](https://github.com/Dicklesworthstone/rust_proxy/commit/bb70d4902fb36294a672fe39c298c8c55c4704b2))
- **Provider IP range fetching**: optional inclusion of AWS, Cloudflare,
  and Google IPv4 ranges for wildcard domain coverage, configurable via
  `include_aws_ip_ranges`, `include_cloudflare_ip_ranges`, and
  `include_google_ip_ranges` in settings.
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))

### Health Checks and Automatic Failover

- **Health check state management**: `HealthStatus` enum
  (Unknown / Healthy / Degraded / Unhealthy), consecutive-failure
  thresholds, per-proxy health tracking fields (`health_status`,
  `consecutive_failures`, `last_health_check`, `last_healthy`,
  `last_failure_reason`) in the state store with query methods
  (`record_health_check()`, `get_health_status()`,
  `get_healthy_proxies()`, `get_all_stats()`).
  ([d3a0563](https://github.com/Dicklesworthstone/rust_proxy/commit/d3a05637b7eacc704972ba07cde22b6eae03d2e9))
- **Health check daemon integration**: background `health_check_loop()`
  task tests TCP connectivity and HTTP CONNECT capability with graceful
  shutdown; only runs when `health_check_enabled = true`.
  ([d2224cd](https://github.com/Dicklesworthstone/rust_proxy/commit/d2224cd414a9256a77aa0f096c9b3378e8647773))
- **Configurable health check methods**: support both
  `CONNECT host:port` and `GET url` targets via a `HealthCheckTarget`
  parameter, dispatched per proxy.
  ([793f6c8](https://github.com/Dicklesworthstone/rust_proxy/commit/793f6c80114faf0c1f747c47cbbc71298554c070),
   [d112095](https://github.com/Dicklesworthstone/rust_proxy/commit/d112095fa3bf62d4c31fd1bf7a7d075ac0245a3d))
- **Automatic failover and failback**: `RuntimeState` for dynamic proxy
  switching, `check_and_perform_failover()`,
  `check_and_perform_failback()` with configurable delay,
  `find_best_healthy_proxy()` for priority-based selection, integrated
  into the health check loop.
  ([9a01f36](https://github.com/Dicklesworthstone/rust_proxy/commit/9a01f36f594f1048161bdae751663223b9d72e12))
- **`--test-connectivity` flag on `check` command**: parallel live
  connectivity tests showing latency, authentication status, and
  connection failure details in both human-readable and JSON output.
  ([bde7f88](https://github.com/Dicklesworthstone/rust_proxy/commit/bde7f88b71b438abfb601a0d47660915109e46d3))

### Degradation Policies

Controls behavior when all configured proxies are unhealthy.

- **Degradation policy framework** with four variants: `FailClosed`
  (default -- reject connections), `TryAll` (try each proxy in order),
  `UseLast` (reconnect through the most recently healthy proxy),
  `Direct` (bypass proxy entirely, requires opt-in). Includes
  `degradation_delay_secs` debounce and `allow_direct_fallback` safety
  gate, with validation that rejects `Direct` policy unless explicitly
  allowed.
  ([328114f](https://github.com/Dicklesworthstone/rust_proxy/commit/328114f703b627f2ebe041c4fefba574b750294b))
- **`UseLast` policy implementation**: `get_last_healthy_proxy()` finds
  the proxy with the most recent `last_healthy` timestamp; falls back to
  `TryAll` on failure.
  ([e5795f2](https://github.com/Dicklesworthstone/rust_proxy/commit/e5795f253cb34a1d667228417ae0928fc80fe36b))
- **`Direct` fallback policy**: `direct_connect()` bypasses all proxies
  and connects directly to the target; uses synthetic "direct" proxy ID
  for metrics; logs warnings about bypassing proxy security controls.
  ([87267ca](https://github.com/Dicklesworthstone/rust_proxy/commit/87267cac70ddcf47387d47516d6a13945611d7aa))
- **Unified degradation handler**: `handle_degradation()` function
  integrated into the connection flow with `is_degraded()` check,
  `RuntimeState` support for delay-period enforcement, and degradation
  config reflected in `status` command output.
  ([4e460ef](https://github.com/Dicklesworthstone/rust_proxy/commit/4e460ef3096a698f9e3d03716b3f359292fe6452))

### Load Balancing

- **Load balancer module** (`src/load_balancer.rs`): initial
  implementation with error types, metrics, health-aware proxy
  selection, and the metrics server for scraping.
  ([0370be8](https://github.com/Dicklesworthstone/rust_proxy/commit/0370be8de0df58858effec5bbca6e74cebc94b07))
- **Extended load balancer configuration**: priority, weighting, and
  strategy options exposed in TOML config.
  ([ee1e52c](https://github.com/Dicklesworthstone/rust_proxy/commit/ee1e52c637f660aab2297a6997b92e4d45305b14),
   [df3da82](https://github.com/Dicklesworthstone/rust_proxy/commit/df3da82c3a5eda7a04108a5475366c35a227c5b3),
   [eb94758](https://github.com/Dicklesworthstone/rust_proxy/commit/eb947588de35d7efcf9e72df67f3bb7310d7aaab))
- **Comprehensive load balancing logic**: single-priority selection,
  round-robin distribution, and weighted distribution with health-aware
  proxy exclusion (256 lines of core logic).
  ([9766600](https://github.com/Dicklesworthstone/rust_proxy/commit/97666009e89d9e4b47b7731ea0c06d7365be7425))
- **Enhanced load balancer with output widgets**: improved connection
  handling and TUI display feedback for load-balanced operations.
  ([4614eb7](https://github.com/Dicklesworthstone/rust_proxy/commit/4614eb72d06d1d473b24ff5bd1643a9397e695f0))

### Metrics and Observability

- **Prometheus metrics module** (`src/metrics.rs`): byte counters,
  connection tracking, and per-proxy statistics collection.
  ([0370be8](https://github.com/Dicklesworthstone/rust_proxy/commit/0370be8de0df58858effec5bbca6e74cebc94b07))
- **HTTP metrics server** (`src/metrics_server.rs`): endpoint for
  Prometheus scraping, with additional health and status endpoints.
  ([0370be8](https://github.com/Dicklesworthstone/rust_proxy/commit/0370be8de0df58858effec5bbca6e74cebc94b07),
   [bb12079](https://github.com/Dicklesworthstone/rust_proxy/commit/bb120793b59ad2d3ce61deb6b98cb8f54051b3c8))
- **Metrics tests and degradation tracking**: expanded test coverage for
  metrics collection and degradation state transitions.
  ([42f6a5c](https://github.com/Dicklesworthstone/rust_proxy/commit/42f6a5c588a79447dddbc0874e98c04a6d7bf19f))

### CLI Commands

All commands added in the initial commit unless otherwise noted.

- **`rust_proxy init [--force]`**: create default config at
  `~/.config/rust_proxy/config.toml`.
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy proxy add|remove|list`**: manage upstream proxy
  definitions with plain credentials (`--username`/`--password`) or
  environment variable references (`--username-env`/`--password-env`).
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy targets add|remove|list`**: manage target domain routing
  with optional `--provider` hints (openai, anthropic, google, aws,
  cloudflare, vercel, supabase).
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy activate [--select]`**: set the active proxy by name or
  via interactive selection.
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy deactivate [--keep-rules]`**: disable routing and clear
  iptables/ipset rules (unless `--keep-rules`).
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy daemon`**: run the transparent proxy daemon (requires
  sudo).
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy status [--json|--format toon]`**: show active proxy,
  iptables/ipset rule status, and health information.
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449),
   [9a01f36](https://github.com/Dicklesworthstone/rust_proxy/commit/9a01f36f594f1048161bdae751663223b9d72e12))
- **`rust_proxy list [--json|--format toon]`**: proxy stats table with
  bytes sent/received, activation age, and ping.
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy diagnose`**: check for system dependencies (iptables,
  ipset).
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **`rust_proxy check [--strict|--quiet|--json|--test-connectivity]`**:
  pre-flight configuration validation (analogous to `nginx -t`);
  validates proxy URLs, auth, duplicates, target domain formats, port
  ranges, interval/timeout values, backoff settings, and active proxy
  reference. Exit codes: 0 valid, 1 errors, 2 warnings (strict mode),
  3 unreadable config.
  ([dbd2af1](https://github.com/Dicklesworthstone/rust_proxy/commit/dbd2af124df123b15d757b9dc2ab1a4e271449f6),
   [bde7f88](https://github.com/Dicklesworthstone/rust_proxy/commit/bde7f88b71b438abfb601a0d47660915109e46d3))
- **`rust_proxy test <url> [--json|-v|--no-dns]`**: routing diagnosis
  command that resolves DNS, checks target list membership, matches
  against provider IP ranges, detects daemon status, and provides
  actionable suggestions.
  ([46c9a07](https://github.com/Dicklesworthstone/rust_proxy/commit/46c9a070496b2341f5341ccef8095c363573b529))
- **`rust_proxy completions <shell>`**: generate shell completions for
  bash, zsh, fish, PowerShell, and elvish via `clap_complete`.
  ([8fd8412](https://github.com/Dicklesworthstone/rust_proxy/commit/8fd84126879ab7173f836ba937e556084eb3e99c),
   [a8a8d26](https://github.com/Dicklesworthstone/rust_proxy/commit/a8a8d26cdbb9d62fb1a68a5a010e50ba6696d7bf))

### Output System and Terminal Theming

- **Comprehensive output module** (`src/output/`): four sub-modules
  providing formatters, color themes, and reusable TUI widgets for all
  CLI output.
  ([c318245](https://github.com/Dicklesworthstone/rust_proxy/commit/c31824547b5178a39c69b82a6487804cd0fe6671))
- **Output theming**: 580-line theme module with consistent color
  schemes across all command output.
  ([8ba9be8](https://github.com/Dicklesworthstone/rust_proxy/commit/8ba9be82be0cd7e166b2096bfa2403f4f44829e3))
- **Rich terminal output via `rich_rust` / `charmed_rust`**: styled
  console output with structured tables and colors; expanded environment
  configuration options.
  ([549d4e8](https://github.com/Dicklesworthstone/rust_proxy/commit/549d4e8d4dec15c5b10377d6d5180207489de7a1))
- **JSON and TOON output formats**: machine-readable output on `list`
  and `status` commands via `--json`, `--format toon`, or environment
  variables (`RUST_PROXY_OUTPUT_FORMAT`, `TOON_DEFAULT_FORMAT`).
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))

### Error Handling

- **Structured error module** (`src/error.rs`): 849-line error taxonomy
  with typed variants covering configuration, proxy, DNS, iptables,
  health check, and validation errors.
  ([0370be8](https://github.com/Dicklesworthstone/rust_proxy/commit/0370be8de0df58858effec5bbca6e74cebc94b07))

### Configuration and Validation

- **TOML config** at `~/.config/rust_proxy/config.toml`: proxy
  definitions with auth (plain or env-var), target domains with provider
  hints, and tunable settings (listen port, DNS refresh interval, ping
  interval/timeout, ipset/chain names, provider range toggles, retry
  settings).
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **Input validation module** (`src/validation.rs`): proxy URL and auth
  checks, duplicate detection, domain format validation, settings range
  enforcement, strict mode support.
  ([dbd2af1](https://github.com/Dicklesworthstone/rust_proxy/commit/dbd2af124df123b15d757b9dc2ab1a4e271449f6),
   [328114f](https://github.com/Dicklesworthstone/rust_proxy/commit/328114f703b627f2ebe041c4fefba574b750294b))
- **DryRun helper infrastructure**: `DryRun` struct with `would_do()`,
  `would_do_fmt()`, `execute_or_skip()`, and `is_enabled()` for
  consistent dry-run behavior across all commands.
  ([f72a2d3](https://github.com/Dicklesworthstone/rust_proxy/commit/f72a2d315b4d664c8e402c4b8de12dc3f5e806d0))
- **Extended config fields**: proxy priority, health check URLs, load
  balancer strategy/weight, degradation policy, and failover settings.
  ([eb94758](https://github.com/Dicklesworthstone/rust_proxy/commit/eb947588de35d7efcf9e72df67f3bb7310d7aaab),
   [df3da82](https://github.com/Dicklesworthstone/rust_proxy/commit/df3da82c3a5eda7a04108a5475366c35a227c5b3),
   [ee1e52c](https://github.com/Dicklesworthstone/rust_proxy/commit/ee1e52c637f660aab2297a6997b92e4d45305b14),
   [f99f9d1](https://github.com/Dicklesworthstone/rust_proxy/commit/f99f9d12b1d214e4e4e879343be86c57e604b33b))

### State Management

- **JSON state store** at `~/.local/state/rust_proxy/state.json`:
  per-proxy statistics, activation history, and byte counters.
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **Extended state tracking**: health check recording, healthy-proxy
  queries, last-healthy-proxy lookup, comprehensive network operation
  utilities and connection management tracking.
  ([d3a0563](https://github.com/Dicklesworthstone/rust_proxy/commit/d3a05637b7eacc704972ba07cde22b6eae03d2e9),
   [cc78da1](https://github.com/Dicklesworthstone/rust_proxy/commit/cc78da1c2689feb91798695127e34dc0ef2db0b2))

### Deployment

- **systemd service file** (`rust_proxy.service`): automatic restart on
  failure with exponential backoff, security hardening (ProtectSystem,
  PrivateTmp, NoNewPrivileges), journald logging, and optional
  environment file (`/etc/rust_proxy.env`) for proxy credentials.
  ([04889d3](https://github.com/Dicklesworthstone/rust_proxy/commit/04889d32f124594cb66c033897d0756dc8dbbc17))

### Testing

- **35 unit tests** for `util.rs` and `config.rs`: covering
  `parse_proxy_url`, `format_bytes`, `format_duration`,
  `format_timeout`, `infer_provider` (all providers), `ProxyAuth`,
  `Provider::as_str`, `TargetSpec` methods, and `Settings` defaults.
  ([4cf7097](https://github.com/Dicklesworthstone/rust_proxy/commit/4cf7097f61368bb67aa6d953bfb56dbb4360ae0e))
- **E2E test infrastructure** (`tests/`): `TestHarness` with temp
  directory management, `MockProxy` server with configurable behavior,
  configuration fixtures for various scenarios, domain-specific
  assertion helpers.
  ([33911e5](https://github.com/Dicklesworthstone/rust_proxy/commit/33911e53431947a3fcdef66477f9c6f236e72658))
- **E2E load balancing tests**: single-priority proxy selection,
  round-robin distribution, weighted routing, unhealthy-proxy exclusion,
  mock proxy request logging, and FailAfter behavior for failover.
  ([5dccbd5](https://github.com/Dicklesworthstone/rust_proxy/commit/5dccbd5f28a93ec3f56b42b2691a0597978e6197))
- **TOON list roundtrip test**: verify TOON serialization and
  deserialization of proxy list output.
  ([f03fcca](https://github.com/Dicklesworthstone/rust_proxy/commit/f03fccaf8e5cb971265a951f3c376a9efa39788e),
   [5eb391e](https://github.com/Dicklesworthstone/rust_proxy/commit/5eb391e9b3a3711f9c10e556210f5815305b5c8b))
- **Shell completion generation tests**: verify completion scripts for
  all five supported shells contain expected shell-specific content.
  ([a8a8d26](https://github.com/Dicklesworthstone/rust_proxy/commit/a8a8d26cdbb9d62fb1a68a5a010e50ba6696d7bf))

### CI/CD

- **GitHub Actions workflow** (`.github/workflows/ci.yml`): cargo fmt,
  clippy, check, and test steps; clones `rich_rust` and `toon_rust` path
  dependencies before cargo operations.
  ([b5780bb](https://github.com/Dicklesworthstone/rust_proxy/commit/b5780bb4a846ef3e0a84abfe5bbfe36aa3fe0be5),
   [229d554](https://github.com/Dicklesworthstone/rust_proxy/commit/229d554d7e42fdad6b76aed9eb989533db4d5885),
   [03bc53a](https://github.com/Dicklesworthstone/rust_proxy/commit/03bc53a744ab98fec11a92c73112d6601d212f84),
   [dcb5c8f](https://github.com/Dicklesworthstone/rust_proxy/commit/dcb5c8f587ff5afb2291063b387e96209f5bfc75))
- **Clippy and formatting fixes**: all warnings resolved across test
  harness and main codebase for clean CI.
  ([89e1403](https://github.com/Dicklesworthstone/rust_proxy/commit/89e14032ae581ed43732e8fe85af8012dae0f936),
   [ed5ecc1](https://github.com/Dicklesworthstone/rust_proxy/commit/ed5ecc19063651238c99e7ef0338ecfad4f9a87e),
   [aa614f1](https://github.com/Dicklesworthstone/rust_proxy/commit/aa614f1aaf00563d0a1c3f5834515a7b1330f4cc),
   [6ef3ac5](https://github.com/Dicklesworthstone/rust_proxy/commit/6ef3ac5c89ef93815fe2e5ac83f3dd91297b3cd2))

### Dependencies

- **`rich_rust` migrated to crates.io v0.2.0** from pre-release git ref,
  improving build reproducibility and eliminating git fetches during
  `cargo build` (2026-02-15).
  ([fe1b803](https://github.com/Dicklesworthstone/rust_proxy/commit/fe1b80364ebd53d54e8fdb7687e71154cba6f082))
- **5 dependencies updated** to latest stable versions (2026-01-18).
  ([77076ba](https://github.com/Dicklesworthstone/rust_proxy/commit/77076ba367f1623385a40b9732432e15e43ac780))
- **Cargo.lock refresh** (2026-01-25).
  ([3973c93](https://github.com/Dicklesworthstone/rust_proxy/commit/3973c935ce028236d8a639944a838e1442282b38))

### License

- **MIT License** added (2026-01-21).
  ([eda22c2](https://github.com/Dicklesworthstone/rust_proxy/commit/eda22c2a5f02d75e548fce955fab6a119096f663))
- **MIT + OpenAI/Anthropic Rider**: license updated to restrict use by
  OpenAI, Anthropic, and their affiliates without express written
  permission from Jeffrey Emanuel (2026-02-21).
  ([d2465b2](https://github.com/Dicklesworthstone/rust_proxy/commit/d2465b2f8bf2b5c97cb4e5cfafedc267ba8fafaa))

### Documentation

- **README**: comprehensive documentation covering installation (source
  tarball, cargo install, from source), commands, configuration example,
  architecture diagram, systemd deployment, troubleshooting,
  comparison table, FAQ, and contribution policy.
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449))
- **Project illustration** added to README.
  ([7bd8446](https://github.com/Dicklesworthstone/rust_proxy/commit/7bd8446b2c5e07fafa7fd5c3e4be22d1adb7d85e))
- **GitHub social preview image** (1280x640).
  ([f3113b6](https://github.com/Dicklesworthstone/rust_proxy/commit/f3113b6ba1ef7a6118f1e9ffca0a973ffa31a4bc))
- **rich_rust integration plan** documenting the output theming roadmap.
  ([71c6459](https://github.com/Dicklesworthstone/rust_proxy/commit/71c64592e6e5859024a7138cf557e70cde276200))
- **AGENTS.md**: multi-agent conventions and cass (Cross-Agent Session
  Search) tool reference for cross-session knowledge reuse.
  ([acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449),
   [a800e62](https://github.com/Dicklesworthstone/rust_proxy/commit/a800e6258fcdb41e6fa5df33e2a9c53baa34aace),
   [557d029](https://github.com/Dicklesworthstone/rust_proxy/commit/557d029f09bdf5e0e173998edbf8852b78c8121b))

---

### Source Module Map

| Module | Lines | Purpose |
|--------|------:|---------|
| `src/main.rs` | 3272 | CLI entry point, daemon orchestration, command dispatch |
| `src/config.rs` | 2782 | TOML config parsing, proxy/target/settings structs |
| `src/util.rs` | 1647 | Helpers: DryRun, format_bytes, parse_proxy_url, shell completions |
| `src/proxy.rs` | 1499 | Transparent proxy, CONNECT tunneling, degradation policies |
| `src/output/widgets.rs` | 1275 | Reusable TUI widgets for styled output |
| `src/validation.rs` | 1019 | Config validation and `check` command logic |
| `src/output/mod.rs` | 1010 | Output system entry point and format dispatch |
| `src/output/theme.rs` | 989 | Color themes and styling |
| `src/error.rs` | 849 | Structured error types |
| `src/state.rs` | 716 | JSON state store, health tracking |
| `src/load_balancer.rs` | 690 | Multi-proxy load balancing strategies |
| `src/metrics.rs` | 580 | Prometheus counters and gauges |
| `src/output/formatters.rs` | 550 | Output formatting utilities |
| `src/health.rs` | 477 | Health check loop, failover/failback |
| `src/dns.rs` | 256 | Parallel DNS resolution with retry |
| `src/watcher.rs` | 223 | Config file change watcher |
| `src/iptables.rs` | 166 | iptables/ipset rule management |
| `src/metrics_server.rs` | 119 | HTTP metrics endpoint |
| `src/ip_ranges.rs` | -- | AWS/Cloudflare/Google range fetching |
| **Total** | **17,353** | (library code, excluding tests) |

Test modules: `tests/common/` (1760 lines across 4 files) and
`tests/e2e/` (365 lines across 2 files) for a combined 2125 lines of
test code.

---

### Full Commit Log (non-metadata)

Commits listed newest-first. Beads state syncs (`bd sync`) and
`chore(beads)` commits are omitted for brevity.

| Date | Commit | Summary |
|------|--------|---------|
| 2026-02-25 | [557d029](https://github.com/Dicklesworthstone/rust_proxy/commit/557d029f09bdf5e0e173998edbf8852b78c8121b) | docs(AGENTS.md): add cass tool reference |
| 2026-02-21 | [d2465b2](https://github.com/Dicklesworthstone/rust_proxy/commit/d2465b2f8bf2b5c97cb4e5cfafedc267ba8fafaa) | chore: update license to MIT with OpenAI/Anthropic Rider |
| 2026-02-21 | [f3113b6](https://github.com/Dicklesworthstone/rust_proxy/commit/f3113b6ba1ef7a6118f1e9ffca0a973ffa31a4bc) | chore: add GitHub social preview image |
| 2026-02-15 | [fe1b803](https://github.com/Dicklesworthstone/rust_proxy/commit/fe1b80364ebd53d54e8fdb7687e71154cba6f082) | Update rich_rust dep to crates.io v0.2.0 |
| 2026-02-14 | [a800e62](https://github.com/Dicklesworthstone/rust_proxy/commit/a800e6258fcdb41e6fa5df33e2a9c53baa34aace) | docs: update AGENTS.md |
| 2026-01-25 | [3973c93](https://github.com/Dicklesworthstone/rust_proxy/commit/3973c935ce028236d8a639944a838e1442282b38) | chore(deps): Update Cargo.lock |
| 2026-01-25 | [dcb5c8f](https://github.com/Dicklesworthstone/rust_proxy/commit/dcb5c8f587ff5afb2291063b387e96209f5bfc75) | fix(ci): clone toon_rust path dep for CI |
| 2026-01-25 | [5eb391e](https://github.com/Dicklesworthstone/rust_proxy/commit/5eb391e9b3a3711f9c10e556210f5815305b5c8b) | test: honor CARGO_BIN_EXE in harness |
| 2026-01-25 | [f03fcca](https://github.com/Dicklesworthstone/rust_proxy/commit/f03fccaf8e5cb971265a951f3c376a9efa39788e) | test: add TOON list roundtrip |
| 2026-01-25 | [0ccd158](https://github.com/Dicklesworthstone/rust_proxy/commit/0ccd158cb1feec34ce1f1443c2f4a0f0e01ac027) | Update from parallel agent work |
| 2026-01-25 | [549d4e8](https://github.com/Dicklesworthstone/rust_proxy/commit/549d4e8d4dec15c5b10377d6d5180207489de7a1) | Add rich terminal output with charmed_rust |
| 2026-01-24 | [aa614f1](https://github.com/Dicklesworthstone/rust_proxy/commit/aa614f1aaf00563d0a1c3f5834515a7b1330f4cc) | fix(tests): silence dead_code warnings |
| 2026-01-24 | [ed5ecc1](https://github.com/Dicklesworthstone/rust_proxy/commit/ed5ecc19063651238c99e7ef0338ecfad4f9a87e) | fix(ci): resolve all clippy warnings |
| 2026-01-24 | [bea5cfb](https://github.com/Dicklesworthstone/rust_proxy/commit/bea5cfbbc76f1f1b966a1bbca6e30716a2c0f1d1) | chore(gitignore): ephemeral file patterns |
| 2026-01-24 | [89e1403](https://github.com/Dicklesworthstone/rust_proxy/commit/89e14032ae581ed43732e8fe85af8012dae0f936) | fix: resolve clippy warnings for CI |
| 2026-01-24 | [03bc53a](https://github.com/Dicklesworthstone/rust_proxy/commit/03bc53a744ab98fec11a92c73112d6601d212f84) | fix(ci): clone rich_rust dep before cargo |
| 2026-01-23 | [6ef3ac5](https://github.com/Dicklesworthstone/rust_proxy/commit/6ef3ac5c89ef93815fe2e5ac83f3dd91297b3cd2) | Fix cargo fmt formatting |
| 2026-01-23 | [4614eb7](https://github.com/Dicklesworthstone/rust_proxy/commit/4614eb72d06d1d473b24ff5bd1643a9397e695f0) | feat(proxy): enhance load balancer and widgets |
| 2026-01-22 | [9766600](https://github.com/Dicklesworthstone/rust_proxy/commit/97666009e89d9e4b47b7731ea0c06d7365be7425) | feat(lb): comprehensive load balancing |
| 2026-01-22 | [8ba9be8](https://github.com/Dicklesworthstone/rust_proxy/commit/8ba9be82be0cd7e166b2096bfa2403f4f44829e3) | feat: Add output theming support |
| 2026-01-22 | [cc78da1](https://github.com/Dicklesworthstone/rust_proxy/commit/cc78da1c2689feb91798695127e34dc0ef2db0b2) | feat: Extend proxy state management |
| 2026-01-22 | [4e460ef](https://github.com/Dicklesworthstone/rust_proxy/commit/4e460ef3096a698f9e3d03716b3f359292fe6452) | Integrate degradation into connection flow |
| 2026-01-22 | [87267ca](https://github.com/Dicklesworthstone/rust_proxy/commit/87267cac70ddcf47387d47516d6a13945611d7aa) | Implement direct fallback degradation |
| 2026-01-22 | [a8a8d26](https://github.com/Dicklesworthstone/rust_proxy/commit/a8a8d26cdbb9d62fb1a68a5a010e50ba6696d7bf) | Add completions function and tests |
| 2026-01-22 | [e5795f2](https://github.com/Dicklesworthstone/rust_proxy/commit/e5795f253cb34a1d667228417ae0928fc80fe36b) | Implement use_last degradation policy |
| 2026-01-22 | [9ec0733](https://github.com/Dicklesworthstone/rust_proxy/commit/9ec07339254634e49203aa858a3bfb0a274040cc) | Update utility functions |
| 2026-01-21 | [cf78d03](https://github.com/Dicklesworthstone/rust_proxy/commit/cf78d031f77891d3f95edc598531f0f99bb04018) | Update proxy module |
| 2026-01-21 | [5dccbd5](https://github.com/Dicklesworthstone/rust_proxy/commit/5dccbd5f28a93ec3f56b42b2691a0597978e6197) | E2E tests for load balancing |
| 2026-01-21 | [33911e5](https://github.com/Dicklesworthstone/rust_proxy/commit/33911e53431947a3fcdef66477f9c6f236e72658) | E2E test infrastructure foundation |
| 2026-01-21 | [42f6a5c](https://github.com/Dicklesworthstone/rust_proxy/commit/42f6a5c588a79447dddbc0874e98c04a6d7bf19f) | Metrics tests + degradation tracking |
| 2026-01-21 | [eda22c2](https://github.com/Dicklesworthstone/rust_proxy/commit/eda22c2a5f02d75e548fce955fab6a119096f663) | Add MIT License |
| 2026-01-21 | [d824094](https://github.com/Dicklesworthstone/rust_proxy/commit/d824094f27fbf01551e420990594873fb39f8fb6) | Improve main and output modules |
| 2026-01-21 | [89004ef](https://github.com/Dicklesworthstone/rust_proxy/commit/89004ef017c7168c7cf587655c929c26e43232b3) | File watcher for config reload |
| 2026-01-21 | [793f6c8](https://github.com/Dicklesworthstone/rust_proxy/commit/793f6c80114faf0c1f747c47cbbc71298554c070) | Configurable health check methods |
| 2026-01-21 | [d112095](https://github.com/Dicklesworthstone/rust_proxy/commit/d112095fa3bf62d4c31fd1bf7a7d075ac0245a3d) | Health check target configuration |
| 2026-01-21 | [2da1b13](https://github.com/Dicklesworthstone/rust_proxy/commit/2da1b13fece94873ac03ce3241665f2569efeb1e) | Update implementation |
| 2026-01-21 | [c8a652d](https://github.com/Dicklesworthstone/rust_proxy/commit/c8a652db75a13e463cfd0af1c4c960c362bde6be) | Update implementation |
| 2026-01-21 | [435b61d](https://github.com/Dicklesworthstone/rust_proxy/commit/435b61df20065baa32e852264b9a59a191c4998a) | Update implementation |
| 2026-01-21 | [3c4d66b](https://github.com/Dicklesworthstone/rust_proxy/commit/3c4d66bfdaa8bca8980499eaf61399c52dd5234a) | Update implementation and docs |
| 2026-01-21 | [f99f9d1](https://github.com/Dicklesworthstone/rust_proxy/commit/f99f9d12b1d214e4e4e879343be86c57e604b33b) | Enhance config and utility functions |
| 2026-01-21 | [3ffed02](https://github.com/Dicklesworthstone/rust_proxy/commit/3ffed020919d5ab05b60850f454603a0576dd083) | Extend config and metrics |
| 2026-01-21 | [ee1e52c](https://github.com/Dicklesworthstone/rust_proxy/commit/ee1e52c637f660aab2297a6997b92e4d45305b14) | Enhance load balancer configuration |
| 2026-01-21 | [df3da82](https://github.com/Dicklesworthstone/rust_proxy/commit/df3da82c3a5eda7a04108a5475366c35a227c5b3) | Extend config handling |
| 2026-01-21 | [bb12079](https://github.com/Dicklesworthstone/rust_proxy/commit/bb120793b59ad2d3ce61deb6b98cb8f54051b3c8) | Enhance metrics server endpoints |
| 2026-01-21 | [eb94758](https://github.com/Dicklesworthstone/rust_proxy/commit/eb947588de35d7efcf9e72df67f3bb7310d7aaab) | Enhance proxy config handling |
| 2026-01-21 | [0370be8](https://github.com/Dicklesworthstone/rust_proxy/commit/0370be8de0df58858effec5bbca6e74cebc94b07) | Major proxy improvements (error, lb, metrics) |
| 2026-01-21 | [c318245](https://github.com/Dicklesworthstone/rust_proxy/commit/c31824547b5178a39c69b82a6487804cd0fe6671) | Comprehensive output system |
| 2026-01-19 | [71c6459](https://github.com/Dicklesworthstone/rust_proxy/commit/71c64592e6e5859024a7138cf557e70cde276200) | docs: rich_rust integration plan |
| 2026-01-18 | [f070219](https://github.com/Dicklesworthstone/rust_proxy/commit/f0702198eee98eebc90182dcaa785d1916db5087) | Update deps and add illustration |
| 2026-01-18 | [f72a2d3](https://github.com/Dicklesworthstone/rust_proxy/commit/f72a2d315b4d664c8e402c4b8de12dc3f5e806d0) | feat(util): DryRun helper infrastructure |
| 2026-01-18 | [328114f](https://github.com/Dicklesworthstone/rust_proxy/commit/328114f703b627f2ebe041c4fefba574b750294b) | feat(config): degradation policy options |
| 2026-01-18 | [77076ba](https://github.com/Dicklesworthstone/rust_proxy/commit/77076ba367f1623385a40b9732432e15e43ac780) | chore: update 5 dependencies |
| 2026-01-18 | [bde7f88](https://github.com/Dicklesworthstone/rust_proxy/commit/bde7f88b71b438abfb601a0d47660915109e46d3) | feat: --test-connectivity for check |
| 2026-01-18 | [9a01f36](https://github.com/Dicklesworthstone/rust_proxy/commit/9a01f36f594f1048161bdae751663223b9d72e12) | feat: failover/failback logic |
| 2026-01-18 | [d2224cd](https://github.com/Dicklesworthstone/rust_proxy/commit/d2224cd414a9256a77aa0f096c9b3378e8647773) | feat: health check daemon integration |
| 2026-01-18 | [d3a0563](https://github.com/Dicklesworthstone/rust_proxy/commit/d3a05637b7eacc704972ba07cde22b6eae03d2e9) | feat: health check config and state |
| 2026-01-18 | [bb70d49](https://github.com/Dicklesworthstone/rust_proxy/commit/bb70d4902fb36294a672fe39c298c8c55c4704b2) | perf: parallel DNS resolution |
| 2026-01-18 | [46c9a07](https://github.com/Dicklesworthstone/rust_proxy/commit/46c9a070496b2341f5341ccef8095c363573b529) | feat: `rust_proxy test <url>` command |
| 2026-01-18 | [dbd2af1](https://github.com/Dicklesworthstone/rust_proxy/commit/dbd2af124df123b15d757b9dc2ab1a4e271449f6) | feat: `rust_proxy check` command |
| 2026-01-18 | [0b8e7e6](https://github.com/Dicklesworthstone/rust_proxy/commit/0b8e7e6d2a68532a948ba4ede64246565327327d) | feat: robust accept loop recovery |
| 2026-01-18 | [e510d8d](https://github.com/Dicklesworthstone/rust_proxy/commit/e510d8df3b54e71f9886b5edf9f50536ceceec25) | fix: proxy error logging and refresh |
| 2026-01-18 | [229d554](https://github.com/Dicklesworthstone/rust_proxy/commit/229d554d7e42fdad6b76aed9eb989533db4d5885) | ci: add cargo test to workflow |
| 2026-01-18 | [7bd8446](https://github.com/Dicklesworthstone/rust_proxy/commit/7bd8446b2c5e07fafa7fd5c3e4be22d1adb7d85e) | docs: add README illustration |
| 2026-01-18 | [fd0978c](https://github.com/Dicklesworthstone/rust_proxy/commit/fd0978ca21d341f7341c3b895848c8dbf75133a4) | feat: connection retry with backoff |
| 2026-01-18 | [8fd8412](https://github.com/Dicklesworthstone/rust_proxy/commit/8fd84126879ab7173f836ba937e556084eb3e99c) | feat: shell completion generation |
| 2026-01-18 | [04889d3](https://github.com/Dicklesworthstone/rust_proxy/commit/04889d32f124594cb66c033897d0756dc8dbbc17) | feat: systemd service file |
| 2026-01-17 | [4cf7097](https://github.com/Dicklesworthstone/rust_proxy/commit/4cf7097f61368bb67aa6d953bfb56dbb4360ae0e) | test: 35 unit tests for util + config |
| 2026-01-17 | [b5780bb](https://github.com/Dicklesworthstone/rust_proxy/commit/b5780bb4a846ef3e0a84abfe5bbfe36aa3fe0be5) | feat: CI workflow + CONNECT improvements |
| 2026-01-17 | [acaa94d](https://github.com/Dicklesworthstone/rust_proxy/commit/acaa94db1367cd6f0aca66e80df18a314c5ff449) | chore: initialize repo and docs |

---

*Reconstructed from 103 commits (67 substantive, 36 beads/metadata).*
*Repository: <https://github.com/Dicklesworthstone/rust_proxy>*
*Current version: 0.1.0 (no formal releases or tags yet)*

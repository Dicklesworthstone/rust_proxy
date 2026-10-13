# rust_proxy reality check and bridge plan

Audit date: 2026-10-13. Source baseline: `6113015f239072e23bcb5922824c5aa234f29c4f` on `main`.

The project has a substantial, connected implementation of transparent IPv4 TCP
proxying. It does not yet establish the README's stronger promises about precise
domain targeting, safe daemon failure, reliable live changes, or production
operability. Finishing the previous open backlog would improve the product but
would leave several important failures unaddressed.

This assessment separates source inspection, process tests, kernel networking
proof, and published releases. A successful Cargo suite does not prove iptables
redirection, recovery after a crash, or systemd deployment.

## Scope and evidence

Read the complete project `AGENTS.md` (723 lines), suite `/data/projects/AGENTS.md`
(539 lines), `README.md` (510 lines), and `RICH_INTEGRATION_PLAN.md` (1,213 lines).
Reviewed the changelog, upgrade history, manifest, toolchain, CI, service unit,
core implementations, test harnesses, and canonical Beads descriptions and
closure reasons. Keyword and AST scans found no `todo!` or `unimplemented!`
production placeholders. Unwired helpers and insufficient tests remain.

Initial canonical tracker: **179 issues: 117 closed, 58 open, 4 in progress**.
These counts describe task bookkeeping, not a percentage of product completion.
The schema-0 local database also contained 39 old `bd-*` aliases. All had
canonical `rust_proxy-*` counterparts, equivalent descriptions after ID
normalization, no comments or dirty issues, and no unmatched normalized
dependencies. The original database family and a complete `.beads` snapshot
were preserved in `/tmp/rust-proxy-reality-20261013-evEMzg`. The operational
database was rebuilt from the canonical JSONL using `br`, without importing
duplicate aliases or changing historical descriptions.

Fresh verification results and final tracker counts are recorded below after
the bridge graph is finalized. Initial RCH admission failed with exit 103
(`queue_timeout`); requesting worker `hz4` with the default estimated four cores
also refused because it has three slots. Neither refusal is a test failure or a
passing test. Smaller jobs were used for the actual checks.

GitHub reports the source baseline's CI run as successful:
[run 35760564547](https://github.com/Dicklesworthstone/rust_proxy/actions/runs/35760564547).
The GitHub releases endpoint returned an empty list, and the local repository
has no tags. Users install source from `main`; no formal release was verified.
No privileged daemon or live host firewall mutation was run for this audit.
An isolated user/network namespace probe (`unshare -Urn true`) failed with
`Operation not permitted`, so kernel-network qualification remains unproven.

## Vision checklist

`PARTIAL` means connected implementation with a concrete remaining defect.
`UNPROVEN` means source exists but the necessary product-level proof is missing.
`NOT_STARTED` refers to the named user-facing workflow, even when helpers exist.
Rows describe the inspected baseline; subsequent planning changes do not fix it.

| # | Testable goal and source | Baseline assessment | Evidence and coverage |
|---|---|---|---|
| V1 | Route selected domains machine-wide, leaving other traffic direct; README feature table and philosophy | PARTIAL / kernel path UNPROVEN | `main::refresh_target_entries`, `iptables::apply_rules`, `proxy::get_original_dst`. IP-level rules cannot distinguish domains sharing an IP; defaults merge entire AWS/Cloudflare/Google networks. No existing open bead owns a real kernel routing test or this semantic mismatch. |
| V2 | Relay transparent IPv4 TCP through upstream HTTP CONNECT without TLS interception; README architecture | Implemented / rootless process proof available | Real CONNECT, authentication header, early-byte relay, and bidirectional copy exist in `proxy.rs`; daemon seam tests explicitly replace SO_ORIGINAL_DST and skip firewall work. Parser and degradation proof beads remain open. |
| V3 | Configure, list, activate, and deactivate proxies and targets; README commands | PARTIAL | Real config mutations and activation exist. Live activation does not rebase runtime preference; cleanup discards errors. Custom-domain add requires an unrelated known-provider hint. Existing output beads covered presentation, not these semantics. |
| V4 | Inline/config/environment authentication; AGENTS design decisions and README credential examples | PARTIAL | Config/env Basic auth is implemented. URL userinfo is retained in the URL but ignored by `UpstreamProxy::from_config`; health CONNECT omits auth and accepts 407 as healthy. No existing open bead precisely covers credential agreement across paths. |
| V5 | Safe stop, crash recovery, and no persistent routing drift; README philosophy/FAQ/cleanup-stale | PARTIAL | SIGINT cleanup path and stale-state CLI exist. SIGTERM bypasses cleanup; startup has no rollback guard; cleanup ignores failures; pid ownership is a race. Previous closed crash-recovery acceptance was stronger than the evidence. |
| V6 | DNS/provider refresh stays correct through outages; README provider ranges and settings | PARTIAL | DNS concurrency limit 32, five-second lookup timeout, retries, and atomic ipset swap exist. DNS failures are collapsed; provider failures can remove prior ranges; startup target failure can yield an empty set. DNS proof bead reopened; feed retention was uncovered. |
| V7 | Reload valid changes without restarting, reject invalid ones; README reload and CHANGELOG | PARTIAL | Watcher proxy-set replacement and invalid-TOML retention have process tests. SIGHUP shuts down; activation, exclusions, restart fields, health scheduling, and retry settings are not coherently reconciled. Hot-reload bead reopened. |
| V8 | Health-based failover/failback, customizable checks, and four degradation policies; CHANGELOG/config | PARTIAL | Real loops and policy handlers exist. Probe semantics can report unauthenticated proxies healthy; per-proxy `health_check_url` is unused. Failure exclusion has a process test; restored traffic after failback remains unproven under open bead `9x6x`. |
| V9 | Single/round-robin/least-latency/weighted routing; CHANGELOG/config | PARTIAL | Selection is connected to production accepts. LeastLatency returns no proxy when every eligible proxy lacks a latency sample; weighted totals can overflow `u32`. Old load-balancing E2E tests mostly test fixtures/mocks. No open bead covers these edge failures. |
| V10 | Accurate bytes, ping, active state, and Prometheus observability; README stats, CHANGELOG | PARTIAL | Persistent traffic/health stats and `/metrics` + `/health` exist. Status reports configured preference, not effective failover proxy; several instruments have no production writers. Existing metrics completion and E2E beads cover much of this. |
| V11 | Install and run reliably as a systemd service; README service instructions | PARTIAL / deployment UNPROVEN | Static unit and `service generate` exist. Quick-start user config differs from root service config. Generated unit uses SIGTERM by default; static unit uses SIGINT. State/write paths and unit quoting need deployment proof; install helper is open. |
| V12 | Stable, parseable JSON/TOON and actionable diagnostic results; README output plus rich plan §§2,7 | PARTIAL | Dispatcher and JSON/TOON commands exist. Many handlers ignore dispatcher; `test --json -v` prints prose before its payload. A listening TCP port is treated as daemon identity. Existing machine-contract and diagnostic test beads need behavioral additions. |
| V13 | Rich output on every command, daemon events, progress, and terminal degradation; rich plan §§3–10 | PARTIAL | Theme, widgets, formatters, dispatcher, and rich init exist. Most command handlers use legacy tables/println; startup/runtime/health/failover/shutdown rich output and terminal tests remain open. Existing rich epic covers these goals. |
| V14 | Complete shell completion and dry-run/error workflows; README completions and Beads feature epics | PARTIAL | Completion generation works in source; install/uninstall helpers and DryRun exist but have no CLI dispatch. Service install, dry-run service behavior, and error suggestions remain open. These gaps already have beads. |
| V15 | Reliable persistent state and configuration during normal CLI/daemon use; README stats/config | PARTIAL | State uses temp+rename and corrupt-file quarantine. CLI activation and daemon flushing can overwrite each other's state updates; config mutations use direct read-modify-write. Atomic replacement alone does not preserve concurrent updates. No open bead covers shared-writer consistency. |
| V16 | Add an arbitrary valid domain from your own list with an optional provider hint; README introduction/targets add | PARTIAL | `targets_cmd` rejects unknown domains without a known provider; `TargetSpec::provider` defaults unknown Simple targets to Google. Installed-binary walkthrough reproduced the rejection. This gap had no dedicated existing bead. |

IPv6, non-Linux support, TLS inspection, gateway/PREROUTING traffic, and HTTP/3
UDP proxying are outside the current IPv4 TCP architecture. They are scope
limits to document, not features to smuggle into this bridge.

## Findings ordered by operator impact

### G1 — Daemon lifetime does not match its safety contract

`main.rs:3749` executes a single `tokio::select!`. The SIGHUP branch reloads and
then falls through into task abortion, firewall cleanup, state flush, and exit.
Only `ctrl_c()` is registered for orderly stop: SIGTERM retains its default
termination behavior. Proxy task errors are logged and ultimately return `Ok`,
so `Restart=on-failure` cannot reliably recover listener failure. Rules can be
installed before the asynchronous listener bind succeeds; subsequent startup
errors have no guaranteed cleanup. Startup bypasses `validate_config`; the
existing validator also omits health interval/timeout/threshold validation.
Rootless shutdown tests only check that the
process exited; they do not assert a normal exit or firewall teardown.

Bridge: supervise reload in a continuing event loop; handle SIGINT and SIGTERM;
validate the complete initial configuration; propagate fatal task outcomes;
bind before enabling REDIRECT; guard acquired
resources and join bounded shutdown work. Verify repeated reloads, continued
traffic, both stop signals, failed bind, and failure exit codes. Complexity: L.

### G2 — Firewall cleanup and ownership can give false assurance

`iptables.rs:252` calls `run_best_effort` for every removal and always returns
`Ok(())`. `deactivate` can print success while rules remain. `state.rs:577–614`
and daemon startup separately read, classify, and replace the pidfile: two
starters can both pass the check. Pid reuse is not process identity. Removing
rules while the refresh task remains running also needs a coordinated lifetime
policy; otherwise later refresh work can recreate partially removed state.
Permission/tool errors from the presence probes are also treated as absence;
the non-root command then reaches best-effort removal and prints success. This
counterexample reopens `rust_proxy-honest-deactivate-and-atomic-state-ifh`'s
original non-root CLI criterion while preserving its atomic-state proof.

Bridge: retain process-lifetime exclusive ownership; distinguish already-absent
objects from permission/tool/command failures; verify removal outcomes; coordinate
deactivation with the daemon; roll back only resources this instance acquired.
Also reconcile identifier limits: validation accepts 31-byte ipset names, but
the temporary name adds `_tmp`, exceeding the kernel's 32-byte buffer including
its terminator for otherwise accepted names longer than 27 bytes.
Original `rust_proxy-stale-rule-crash-recovery-iej` was reopened because its
simultaneous-start and proper-error-propagation requirements remain unmet.
Fault-injected command tests plus isolated concurrent-start/recovery tests are
required. Complexity: L. Depends on G1 for coordinated lifetime behavior.

### G3 — Config publication does not equal complete reload

`reload_config_once` publishes the entire new snapshot after merely warning on
restart-required fields. The refresh loop then uses new chain/ipset settings
while listener/cleanup retain old settings. RuntimeState is initialized only
once, so activating another retained healthy proxy leaves the original preferred
proxy in use. Upstream exclusions are resolved/applied only at startup; adding
or changing an upstream can therefore introduce a self-redirect loop. Health
tasks, their ticker, retry configuration, and metrics route/task lifetime also
have settings captured at startup.

Bridge: define applied-versus-pending settings explicitly; reconcile active
preference/failback origin, eligible health state, upstream exclusions, and
background scheduling as one validated transition; retain the last complete
configuration on failure. Keep socket/firewall identity fields pinned until a
controlled restart. Original `rust_proxy-wire-config-hot-reload-jmj` was reopened;
its target-edit-to-ipset criterion cannot be replaced with proxy-list swapping.
Complexity: L. Depends on G1/G2 and resolver preservation in G4.

### G4 — Resolution/feed failures can silently narrow routing

`dns::resolve_ipv4` always returns `Ok(report.ipv4_addresses())`. The refresh
guard only re-probes DNS when the combined set is empty and a previous set was
nonempty. A nonempty provider feed can mask total target-DNS failure. Successful
IPv6-only resolution is not a usable IPv4 route. Failed provider fetches add
nothing, then the reduced aggregate is swapped in. `ip_ranges.rs` uses unbounded
`reqwest::get`, does not call `error_for_status`, and does not validate CIDRs.

Bridge: carry per-source IPv4 outcomes through startup/refresh; keep last known
good values for failed sources while honoring deliberate target removal;
use bounded, status-checked, validated feed fetches. Expose stale/error outcomes.
Reopened `rust_proxy-dns-failure-fail-closed-semantics-qhi` retains its original
warning-plus-metric and controlled refresh-failure test requirements. Add a
separate feed-retention implementation/test pair. Complexity: M/L.

### G5 — Proxy transport/authentication and health checks disagree

URL parsing discards scheme/userinfo when constructing an upstream endpoint.
Validation accepts `https://`, but production opens an ordinary TCP stream and
sends plaintext CONNECT. Inline URL credentials do not become Basic auth.
Health CONNECT does not send configured credentials, reads only one buffer,
uses substring status checks, and accepts authentication rejection (407) as
healthy. HTTPS GET health checks return after CONNECT without performing the
requested GET, and `health_check_url` is never consumed. `list --json` serializes
configured auth fields, including plaintext credentials.

Bridge: one endpoint/auth contract across forwarding and probes; support the
promised HTTP proxy scope and explicitly reject unsupported TLS proxy transport
until implemented; resolve and redact credentials consistently; parse fragmented
responses and exact status codes; make health measure usable proxy service;
honor per-proxy targets and implement/document actual GET behavior. Authenticated
local-server and credential-rejection controls must prove the difference.
Existing customizable-health beads remain relevant. Complexity: M/L.

### G6 — Selected-proxy establishment has no finite overall deadline

`connect_with_retry` has bounded attempt count/backoff but no explicit TCP-connect
timeout. The main selected-proxy CONNECT read loop has no response deadline and
checks the 16 KiB cap only after looking for the header terminator. A peer can
hold each spawned connection task indefinitely or send an oversized final header
that bypasses that cap. Degradation attempts have outer timeouts, so paths differ.
The listener also binds `0.0.0.0`, despite the local OUTPUT-only routing scope
and the plan's loopback listener example.

Bridge: finite connect/CONNECT deadlines shared across selected/degradation
paths; enforce header size at its parsed boundary before accepting it; preserve
early bytes; classify timeout metrics and limit outstanding establishment work.
Reuse `rust_proxy-connect-handshake-parse-tests-y473` for fragmented, silent,
truncated, oversized, non-2xx, and trailer cases. Complexity: M.

### G7 — Load balancing has uncovered boundary failures

`select_least_latency` starts at `f64::MAX`, substitutes that same value for
unknown latency, and only chooses on strict `<`. Consequently every eligible
Unknown proxy can yield `None`. Weighted selection sums allowed `u32` weights
into a `u32` total and casts an atomic counter down to `u32`; overflow can panic
or invalidate selection. These are source-derived defects, not measured
performance regressions.

Bridge: deterministic eligible fallback when samples are absent; widened or
checked weight arithmetic; exact zero/maximum/counter-boundary semantics.
Companion tests must drive real daemon selections and identify the upstream
which received each tunnel, rather than merely validate fixture TOML. Complexity: M.

### G8 — Observability can report intent as live truth

`status` reloads config and persisted stats but has no daemon runtime snapshot.
It displays configured `active_proxy`, not the current failover target. Chain
existence alone becomes `rules_active`. `test` treats any successful connection
to the listen port as a running daemon and predicts routes from domain membership
and fresh feeds, not the live ipset. `test --json -v` mixes verbose prose into
stdout. DNS/retry/ipset/uptime instruments have no production writes, while
`PROXY_HEALTH` **is** written by `record_health_check` now: the older metric bead's
claim that all six instruments are dead is stale.

Bridge: expose a minimal identity-bound runtime snapshot with effective routing,
applied settings, reload outcome, readiness, and freshness; distinguish liveness
from usable forwarding; update existing metrics/diagnostic/machine-output beads.
Do not introduce a general administrative server just to report these facts.
Tests must include failover versus configured intent and an unrelated listener.
Complexity: M. Depends on G1/G3/G5.

### G9 — State/config persistence does not coordinate writers

Daemon StateStore retains an in-memory snapshot and periodically writes it.
CLI `activate` independently loads/modifies/saves the same state file. Either can
overwrite the other's counters or activation information. Config mutations also
perform unlocked read-modify-write and write directly to the live path.

Bridge: serialize mutations and preserve independent fields; make the daemon
authoritative for live state, or merge under a shared process lock; publish
configuration atomically. Test interleaved writers and interrupted publication.
Keep the existing corrupt-state quarantine behavior. Complexity: M.

### G10 — Precise domain targeting is stronger than IP-level routing can prove

The default settings enable all three provider range feeds. The daemon merges
each whole provider range regardless of the target's provider hint. Any other
domain using a matched IP is also redirected. Even with feeds disabled, domains
on the same IP share the same kernel rule. NAT matches TCP only; IPv6 and UDP
can remain direct. The rich plan's wildcard example has no generic wildcard-DNS
enumeration implementation.

Bridge: retain the documented useful IPv4 TCP architecture, but state its exact
scope before an operator activates it. Show provider-expanded versus directly
resolved entries and shared-IP ambiguity in diagnostics. Explicitly validate
wildcard support/refusal. Do not claim exact host isolation or silently replace
the transport architecture. Add independent targeted/untargeted/shared-IP/UDP/
IPv6 namespace controls to the final kernel qualification test. Complexity: M.

### G11 — Documentation and remaining product polish still need execution

README omits several implemented commands and settings, assumes user-generated
config works unchanged under sudo, and describes crash behavior too strongly.
CHANGELOG's old load-balancing E2E label exceeds what those tests exercise.
AGENTS says there are no tests, mentions pedantic/nursery enablement absent from
the manifest, and references two suite sections that are missing from the actual
suite file. The missing sections are a documentation finding, not permission to
invent their text. Preserve the concrete user-supplied rules.

Bridge: expand existing `rust_proxy-readme-sync-with-reality-7gze` to cover current
limits, root/config/state identity, diagnostics, restart/reload policy, deployment
validation, and actual proof classes. Existing service/completion/dry-run/error
and rich-output beads already cover most remaining workflows. Preserve them;
do not duplicate the entire rich integration plan. Complexity: M across existing
tasks. Docs should be updated with implemented results, not lowered promises
presented as functional progress.

### G12 — Custom-domain onboarding contradicts the own-list promise

The actual CLI walkthrough exposed another gap. `targets_cmd` (`main.rs:558`)
requires one of seven known providers when inference fails, so an arbitrary valid
domain cannot be added without an unrelated hint. `TargetSpec::provider`
(`config.rs:239`) additionally labels unknown Simple targets as Google. Manual
TOML can hold the domain, so this is a CLI/identity defect rather than missing
DNS forwarding machinery.

Bridge: represent unknown/custom provider identity truthfully; accept arbitrary
valid domains without a required provider; preserve explicit hints and known
inference; make canonical add/duplicate/remove/check/test behavior agree. Add a
complete custom-domain CLI walkthrough and controlled routing/untargeted proof.
The rich target command tasks alone did not cover this semantic requirement.
Complexity: M. New children `.18`/`.19` own implementation and verification.

## Bridge ordering and completion standard

1. G1/G2: establish bounded lifetime, ownership, accurate cleanup, and rollback.
2. G4/G5/G6/G7/G9/G12: repair resolver retention, usable authentication/health,
   connection bounds, selection boundaries, shared persistence, and custom targets.
3. G3/G8: reconcile live config and expose actual daemon state.
4. Finish existing metrics/CLI/service/completion/dry-run/rich-output tasks,
   with semantic and output-contract tests alongside each implementation.
5. Perform real kernel/systemd qualification in an isolated environment, then
   reconcile docs against verified behavior and review any release separately.

Every implementation has a companion verification bead or an explicitly reused
existing test bead. Unit tests pin edge/error behavior; process tests verify
traffic and exit/output contracts; isolated kernel tests prove NAT, SO_ORIGINAL_DST,
SO_MARK, stale-rule recovery, and targeted/direct control paths. All required
checks bind evidence to the source revision, and failed/incomplete checks remain
visible. No closed item was accepted merely because compilation succeeded.

## Plan refinement record

The skill's complete flow was applied to this one document and the existing
graph: vision → source/proof audit → bridge → Beads → ambition → Beads updates →
refinement → graph validation. Source repair implementation is subsequent work;
the plan itself does not change the baseline's behavior.

Two ambition passes developed (1) complete routing/lifetime/ownership transitions
and (2) independent process, kernel, and deployment controls. The skill's frozen
generation/refinement templates were applied verbatim; their execution copy is
preserved with the local audit evidence.

Refinement passes produced these outcomes:

1. Coverage: reused existing feature/test beads; added explicit inline auth,
   per-proxy health target, credential-redaction, live status, and targeting-scope
   criteria without duplicating the rich plan.
2. Transition failures: required startup validation, ownership-aware rollback,
   applied-versus-pending fields, bounded supervision, foreign-state preservation,
   and loopback listener scope.
3. Discriminative proof: required two retained proxies for live activation,
   actual authenticated forwarding/GET, forced persistence/ownership races,
   real refresh despite the seam's exclusions, and independent kernel controls.
4. Graph and boundaries: connected the initial 54 blocking dependencies; checked original
   acceptance and source ownership; caught missing health-settings validation and
   the accepted-name/temporary-ipset-length mismatch; added boundary controls.
5. Initial consistency: reread scopes/companions and vision mapping; no further
   static-analysis decomposition was needed at that point.
6. Executable feedback: installed-binary probes confirmed multiple findings and
   revealed G12. Added custom-target implementation/verification and linked the
   existing rich target tasks to the required semantics.
7. Final consistency: reviewed the added scopes and coverage again; the
   non-root permission-probe counterexample required reopening the original
   deactivate criterion and two more dependencies. The finished graph has 61
   added blocking links. Execution and targeting-policy decisions remain open;
   acceptance was not weakened.

## Verification results and graph handoff

Bridge epic: **`rust_proxy-reality-check-routing-bridge-4sic`**. Its 19 children
plus the epic are 20 new issues. Four existing issues were reopened with original
descriptions and acceptance preserved; no runtime task was closed in this audit.

| Child suffix | Scope | Companion or prerequisite |
|---|---|---|
| `.1` | Daemon lifetime/startup/signal supervision | `.2` |
| `.2` | Lifetime process and cleanup verification | `.1` |
| `.3` | Per-source DNS/feed retention | `.4`, reopened `qhi` |
| `.4` | Resolver/feed fault proof | `.3`, reopened `qhi` |
| `.5` | Endpoint/auth/usable-health agreement | `.6`, `.7` |
| `.6` | Authenticated probe/GET/traffic proof | `.5`, existing failback `9x6x` |
| `.7` | Finite establishment/parser/admission bounds | Existing parser test `y473` |
| `.8` | Load-balancing boundary correctness | `.9` |
| `.9` | Actual daemon strategy/distribution proof | `.8` |
| `.10` | Coordinated state/config writers | `.11` |
| `.11` | Forced persistence interleavings | `.10` |
| `.12` | Effective runtime state and honest diagnostics | Existing diagnostic test `2jn` |
| `.13` | Full live reload transition proof | Reopened `jmj`, `qhi` |
| `.14` | Ownership/cleanup/concurrent-start proof | Reopened `iej`, `ifh`, `.1` |
| `.15` | Exact-domain versus IP/provider scope decision | Independent shared-IP control |
| `.16` | Real kernel and systemd qualification | Repair/proof tasks plus existing metrics/diagnostic/service/degradation tests |
| `.17` | Complete README/rich-plan integration gate | `.16`, docs and existing feature/output epics |
| `.18` | Custom domains and truthful provider identity | `.19` |
| `.19` | Custom-domain onboarding/routing proof | `.18`, kernel qualification `.16` |

Existing reused implementation/proof work remains in place, including hot reload,
DNS failure handling, crash recovery, metrics instrumentation/E2E, parser tests,
failback restoration, diagnostic/CLI output tests, and all rich/completion/service/
dry-run/error workflows. Comments supply the new evidence and related scopes.

The bridge graph and separate dependency-maintenance follow-up have **200 issues:
113 closed, 83 open, 4 in progress**. The maintenance item is
`rust_proxy-dependency-future-compat-n8o3`: Cargo reported future incompatibility
in `proc-macro-error2 v2.0.1`. It is currently nonblocking and requires an
upstream diagnostic/minimal-fix investigation, not unrelated dependency upgrades.
`br dep cycles --include-closed --json` reports zero active or historical cycles.
Final triage places custom-target onboarding `.18`, lifetime `.1`, and transport
bounds `.7` among its top actionable choices. The source baseline remains unchanged. File ownership
still governs concurrent edits: independent graph tasks sharing `main.rs` must
reserve/coordinate their exact edit surface.

Completing the old open backlog would **not** close all twelve gap groups: it predominantly
covered presentation and omitted important runtime and proof gaps. Completing
the expanded graph would supply a coherent implementation and qualification
path, subject to the explicit shared-IP/hostname scope decision. Pure IP matching
cannot prove exact-domain isolation; no task may silently waive that limitation.

Installed-artifact probes used an immutable copy of the executable available at
`/home/ubuntu/.cargo/bin/rust_proxy` (mtime 2026-10-07, version 0.1.0, SHA-256
`93b0891ba0af267da3a873b3c88716a6cb64df95d1b9e6e440672e53061e51a4`).
Its source revision is unrecorded; these are **installed-artifact observations**,
not exact-SHA source qualification. Evidence:
`/tmp/rust-proxy-reality-20261013-evEMzg/installed-probes-final/probe-results.json`.

| Installed-artifact scenario | Observed outcome |
|---|---|
| Rootless CONNECT echo control | Exact payload relayed successfully |
| SIGHUP after successful traffic | Process exited 0 instead of staying alive |
| SIGTERM | Exit by signal (`-15`), no cleanup marker |
| Change active proxy while retaining both proxies | Watcher logged reload; next tunnel still reached old proxy (A:1, B:0) |
| LeastLatency with no samples | No upstream request; payload not relayed |
| URL userinfo | Tunnel succeeded against permissive endpoint; Basic auth header absent |
| `list --json` credential redaction | Artificial configured password appeared in stdout |
| `test --json -v --no-dns` | Exit 0 with stdout that did not parse as JSON |
| `targets list --json` | Flag rejected, exit 2 |
| Zero health-check interval validation | `check --json` accepted config, exit 0 |
| Permission-denied firewall tools (fault-injected CLI) | All six tool calls failed; command printed success and exited 0 |
| Fresh init/proxy/target/activate/status/list walkthrough | All steps except custom-domain add succeeded; custom add exited 1 |
| 407-only proxy health | `ping` reported success and one response |
| `trace` through local proxy | JSON and actual CONNECT observed |
| Completion generation / service generation | Nonempty completion payload; generated unit carried selected config and cleanup prestart |

Fresh exact-source verification at `6113015f239072e23bcb5922824c5aa234f29c4f`:

- `RCH_REQUIRE_REMOTE=1 rch exec --worker hz3 --base <SHA> --clean-overlay --no-overlay -- cargo test --workspace --locked -j 1`
  passed: **528 unit tests + 34 integration tests, zero failures/ignored tests**.
  RCH receipt tree `fa3b1868e94c6d8825c8cc935a70b3cc42aca2b8` matches the local
  Git tree for that source commit. Log is preserved in the audit evidence dir.
- The copied compiled binary SHA-256 is
  `d580c23c73242e4f945d2d5e4468ef34587d487d34f48852c287b3a6f795553d`.
  **All 15 process/CLI probe outcomes agree with the installed-artifact table**,
  including its failure cases. Exact-source probe evidence:
  `/tmp/rust-proxy-reality-20261013-evEMzg/compiled-probes/probe-results.json`.
- `cargo fmt --check` and `git diff --check` passed.
- Separate exact-source `cargo check --workspace --all-targets --locked -j 1`
  reached RCH's 1,800-second execution timeout. The helper verified its remote
  process group dead. This is **incomplete infrastructure-limited verification**,
  not a compiler diagnostic and not a passing check.
- Exact-source strict Clippy attempt:
  `cargo clippy --workspace --all-targets --locked -j 1 -- -D warnings` was
  refused by RCH admission with exit 103 / `RCH-I006` (`missing_runtime`) on the
  selected worker. **No fresh Clippy verdict was obtained.** The existing
  worker physically has the stable Clippy component; admission/probe consistency
  is an infrastructure limitation. A `+stable` retry also refused. The existing
  baseline CI run was successful, but it does not replace this missing current
  toolchain verification.
- Real kernel/network-namespace qualification remains unavailable on this host.
- `ubs --staged` inspected the three staged documentation/tracker paths and
  exited 3 because they contain no supported source language. **Nothing was
  scanned; this is not a UBS pass.** No `UBS_ALLOW_NO_SCAN` override was used.
  JSONL/graph preservation, parsing, cycle checks, and diff whitespace checks
  provide the appropriate verification for this metadata-only commit.

Earlier RCH slot/queue refusals and the cancelled disk-pressure run are not
source test verdicts. The full passing suite does not cover the behavioral
failures above and does not establish kernel/systemd readiness. No source code
was changed by this audit; all runtime repair/qualification criteria remain open.

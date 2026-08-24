use anyhow::{bail, Context, Result};
use std::cell::Cell;
use std::collections::HashSet;

pub fn require_root() -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        bail!("This command must be run as root (sudo).")
    }
    Ok(())
}

/// Seam for process spawning: `program` + `args`, an optional stdin payload,
/// returning trimmed stdout. Tests substitute a capturing implementation to
/// assert argv sequences and stdin payloads without root or a real binary.
type SpawnFn = fn(&str, &[&str], Option<&str>) -> Result<String>;

thread_local! {
    static SPAWN: Cell<SpawnFn> = const { Cell::new(real_spawn) };
}

fn dispatch(program: &str, args: &[&str], stdin_payload: Option<&str>) -> Result<String> {
    let spawn = SPAWN.with(Cell::get);
    spawn(program, args, stdin_payload)
}

fn real_spawn(program: &str, args: &[&str], stdin_payload: Option<&str>) -> Result<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut command = Command::new(program);
    command.args(args);
    if stdin_payload.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed running {} {:?}", program, args))?;
    if let Some(payload) = stdin_payload {
        let mut stdin = child.stdin.take().context("child stdin already closed")?;
        stdin
            .write_all(payload.as_bytes())
            .with_context(|| format!("Failed writing stdin to {} {:?}", program, args))?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Command failed: {} {:?}: {}", program, args, stderr.trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    dispatch(cmd, args, None)
}

/// Run `cmd`, feeding `payload` on stdin (used for the `ipset restore` batch).
fn run_with_stdin(cmd: &str, args: &[&str], payload: &str) -> Result<String> {
    dispatch(cmd, args, Some(payload))
}

fn run_best_effort(cmd: &str, args: &[&str]) {
    let _ = run(cmd, args);
}

pub fn ensure_ipset(ipset_name: &str) -> Result<()> {
    run(
        "ipset",
        &["create", ipset_name, "hash:net", "family", "inet", "-exist"],
    )?;
    Ok(())
}

pub fn sync_ipset(ipset_name: &str, ips: &HashSet<String>) -> Result<()> {
    // Atomically update the ipset by creating a temp set, swapping, and
    // destroying the old one. This prevents a window where the set is empty
    // (after flush) which would leak traffic.
    //
    // Short-circuit: when the live set already holds exactly `ips`, skip all
    // mutation work (one `ipset list` probe instead of thousands of forks).
    // Mirrors the refresh-detection semantics of e510d8d: compare actual
    // entries, not just counts.
    if let Ok(live) = current_ipset_members(ipset_name) {
        if live == *ips {
            return Ok(());
        }
    }

    // Entries are sorted lexicographically so the restore stream is
    // deterministic and stable across runs regardless of HashSet iteration
    // order; this keeps streams/logs diffable.
    let mut sorted: Vec<&String> = ips.iter().collect();
    sorted.sort();

    // A single `ipset restore` batch replaces the previous one-process-per-
    // entry population while preserving the create-tmp/populate/swap/destroy
    // atomic pattern.
    run_with_stdin(
        "ipset",
        &["restore"],
        &build_restore_stream(ipset_name, &sorted),
    )?;
    Ok(())
}

/// Render the `ipset restore` stdin script for the atomic
/// create-tmp/populate/swap/destroy sequence. Lines use standard ipset
/// restore syntax (`create`, `add`, `swap`, `destroy`); `-exist` keeps
/// re-runs idempotent if a stale tmp set survived a crash.
fn build_restore_stream(ipset_name: &str, sorted_ips: &[&String]) -> String {
    let temp_name = format!("{}_tmp", ipset_name);
    let mut stream = String::with_capacity(96 + sorted_ips.len() * 32);
    stream.push_str(&format!("create {temp_name} hash:net family inet -exist\n"));
    stream.push_str(&format!("flush {temp_name}\n"));
    for ip in sorted_ips {
        stream.push_str(&format!("add {temp_name} {ip} -exist\n"));
    }
    stream.push_str(&format!("swap {ipset_name} {temp_name}\n"));
    stream.push_str(&format!("destroy {temp_name}\n"));
    stream
}

/// Read the live member list of `ipset_name` from the `Members:` section of
/// `ipset list` (one CIDR per line). Fails if the set does not exist yet,
/// which the caller treats as "no short-circuit possible".
fn current_ipset_members(ipset_name: &str) -> Result<HashSet<String>> {
    let out = dispatch("ipset", &["list", ipset_name], None)?;
    let mut members = HashSet::new();
    let mut in_members = false;
    for line in out.lines() {
        match line.trim() {
            "Members:" => in_members = true,
            m if in_members && !m.is_empty() => {
                members.insert(m.to_string());
            }
            _ => {}
        }
    }
    Ok(members)
}

/// How the daemon exempts its own traffic from the REDIRECT rule.
///
/// Without an exemption, any connection the daemon itself opens toward an
/// ipset member (notably the Direct degradation policy's plain TCP connect)
/// is redirected back into our own listener and re-handled in a loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfExemption {
    /// Exempt sockets carrying this firewall mark via `-m mark`. The daemon
    /// sets SO_MARK only on its own direct-connect sockets, making the
    /// exemption precise regardless of daemon uid. Requires CAP_NET_ADMIN,
    /// which the daemon already needs for every other iptables/ipset write.
    ///
    /// A `-m owner` uid exemption was deliberately rejected: the daemon
    /// always runs as root (require_root), and exempting uid 0 would
    /// silently bypass the proxy for every root process on the machine.
    Mark(u32),
}

/// Firewall mark used for [`SelfExemption::Mark`]. Arbitrary non-zero value;
/// chosen to be unlikely to collide with unrelated policy marks.
pub const DIRECT_BYPASS_MARK: u32 = 0x5250_0001;

pub fn apply_rules(
    chain_name: &str,
    ipset_name: &str,
    listen_port: u16,
    self_exempt: Option<SelfExemption>,
    exclude_dests: &HashSet<String>,
) -> Result<()> {
    // Create chain if missing.
    run_best_effort("iptables", &["-t", "nat", "-N", chain_name]);
    // Flush chain.
    run("iptables", &["-t", "nat", "-F", chain_name])?;

    // Exclude local traffic.
    run(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            chain_name,
            "-d",
            "127.0.0.0/8",
            "-j",
            "RETURN",
        ],
    )?;

    if let Some(SelfExemption::Mark(mark)) = self_exempt {
        run(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                chain_name,
                "-m",
                "mark",
                "--mark",
                &mark.to_string(),
                "-j",
                "RETURN",
            ],
        )?;
    }

    for ip in exclude_dests {
        run(
            "iptables",
            &[
                "-t", "nat", "-A", chain_name, "-p", "tcp", "-d", ip, "-j", "RETURN",
            ],
        )?;
    }

    // Redirect matching destination IPs.
    run(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            chain_name,
            "-p",
            "tcp",
            "-m",
            "set",
            "--match-set",
            ipset_name,
            "dst",
            "-j",
            "REDIRECT",
            "--to-ports",
            &listen_port.to_string(),
        ],
    )?;

    // Ensure OUTPUT jumps to our chain (insert at top).
    run_best_effort("iptables", &["-t", "nat", "-D", "OUTPUT", "-j", chain_name]);
    run(
        "iptables",
        &["-t", "nat", "-I", "OUTPUT", "1", "-j", chain_name],
    )?;

    Ok(())
}

pub fn clear_rules(chain_name: &str, ipset_name: &str) -> Result<()> {
    run_best_effort("iptables", &["-t", "nat", "-D", "OUTPUT", "-j", chain_name]);
    run_best_effort("iptables", &["-t", "nat", "-F", chain_name]);
    run_best_effort("iptables", &["-t", "nat", "-X", chain_name]);
    run_best_effort("ipset", &["destroy", ipset_name]);
    Ok(())
}

pub fn chain_present(chain_name: &str) -> bool {
    dispatch("iptables", &["-t", "nat", "-S", chain_name], None).is_ok()
}

/// What `iptables -t nat -S <chain>` says about rules left by a previous run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSnapshot {
    /// The chain exists (was created by us or a predecessor).
    pub present: bool,
    /// REDIRECT `--to-ports` values found among the chain's rules.
    pub redirect_ports: Vec<u16>,
}

/// Parse the rule listing emitted by `iptables -t nat -S <chain>`.
/// Rule lines look like `-A CHAIN ... -j REDIRECT --to-ports 12345`;
/// declaration (`-N`) / builtin policy lines carry no `-A ` prefix.
pub fn parse_chain_rules(rules: &str) -> ChainSnapshot {
    let mut redirect_ports = Vec::new();
    for line in rules.lines() {
        let line = line.trim_start();
        if !line.starts_with("-A ") {
            continue;
        }
        if let Some(pos) = line.find("--to-ports ") {
            let port_str = line[pos + "--to-ports ".len()..]
                .split_whitespace()
                .next()
                .unwrap_or("");
            if let Ok(port) = port_str.parse::<u16>() {
                redirect_ports.push(port);
            }
        }
    }
    ChainSnapshot {
        present: !rules.trim().is_empty(),
        redirect_ports,
    }
}

/// Snapshot any chain remnants from a previous run. A missing chain is not
/// an error — it just means a clean slate.
pub fn chain_snapshot(chain_name: &str) -> Result<ChainSnapshot> {
    match dispatch("iptables", &["-t", "nat", "-S", chain_name], None) {
        Ok(out) => Ok(parse_chain_rules(&out)),
        Err(_) => Ok(ChainSnapshot {
            present: false,
            redirect_ports: Vec::new(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Captured spawn: (program, argv, stdin payload).
    type Call = (String, Vec<String>, Option<String>);

    thread_local! {
        static CALLS: RefCell<Vec<Call>> = const { RefCell::new(Vec::new()) };
        static LIVE_STDOUT: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    fn capturing_spawn(
        program: &str,
        args: &[&str],
        stdin_payload: Option<&str>,
    ) -> Result<String> {
        CALLS.with(|calls| {
            calls.borrow_mut().push((
                program.to_string(),
                args.iter().map(|a| (*a).to_string()).collect(),
                stdin_payload.map(str::to_string),
            ));
        });
        Ok(LIVE_STDOUT
            .with(|out| out.borrow().clone())
            .unwrap_or_default())
    }

    fn install_capturing_spawn(live_stdout: Option<&str>) {
        LIVE_STDOUT.with(|out| *out.borrow_mut() = live_stdout.map(str::to_string));
        SPAWN.with(|spawn| spawn.set(capturing_spawn));
    }

    fn calls() -> Vec<Call> {
        CALLS.with(|calls| calls.borrow().clone())
    }

    fn set_of(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn sync_batches_all_adds_into_a_single_restore_spawn() {
        install_capturing_spawn(Some("Name: t\nType: hash:net\nMembers:\n203.0.113.0/24\n"));
        let ips = set_of(&["8.8.8.8/32", "1.1.1.0/24", "2.2.2.0/24"]);
        sync_ipset("t", &ips).unwrap();

        let calls = calls();
        assert_eq!(
            calls.len(),
            2,
            "expected one `ipset list` probe plus ONE `ipset restore` batch carrying all adds"
        );
        assert_eq!(calls[0].0, "ipset");
        assert_eq!(calls[0].1, vec!["list", "t"]);
        assert_eq!(calls[0].2, None);

        assert_eq!(calls[1].0, "ipset");
        assert_eq!(calls[1].1, vec!["restore"]);
        let stdin: &str = calls[1]
            .2
            .as_deref()
            .expect("restore must carry stdin payload");
        assert_eq!(
            stdin,
            "create t_tmp hash:net family inet -exist\n\
             flush t_tmp\n\
             add t_tmp 1.1.1.0/24 -exist\n\
             add t_tmp 2.2.2.0/24 -exist\n\
             add t_tmp 8.8.8.8/32 -exist\n\
             swap t t_tmp\n\
             destroy t_tmp\n"
        );
    }

    #[test]
    fn sync_with_no_entries_swaps_via_a_single_add_free_batch() {
        install_capturing_spawn(Some("Name: t\nMembers:\n203.0.113.0/24\n"));
        sync_ipset("t", &HashSet::new()).unwrap();

        let calls = calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, "ipset");
        assert_eq!(calls[1].1, vec!["restore"]);
        let stdin: &str = calls[1].2.as_deref().unwrap();
        assert_eq!(
            stdin,
            "create t_tmp hash:net family inet -exist\n\
             flush t_tmp\n\
             swap t t_tmp\n\
             destroy t_tmp\n"
        );
    }

    #[test]
    fn sync_short_circuits_when_live_content_is_unchanged() {
        install_capturing_spawn(Some("Name: t\nMembers:\n1.1.1.0/24\n2.2.2.0/24\n"));
        let ips = set_of(&["2.2.2.0/24", "1.1.1.0/24"]);
        sync_ipset("t", &ips).unwrap();

        let calls = calls();
        assert_eq!(
            calls.len(),
            1,
            "unchanged content must skip all mutation work"
        );
        assert_eq!(calls[0].1, vec!["list", "t"]);
    }

    #[test]
    fn apply_rules_emits_pinned_rule_text_including_mark_return() {
        install_capturing_spawn(None);
        let dests = set_of(&["10.0.0.1"]);
        apply_rules(
            "RUST_PROXY_CHAIN",
            "rust_proxy_set",
            9090,
            Some(SelfExemption::Mark(DIRECT_BYPASS_MARK)),
            &dests,
        )
        .unwrap();

        let got: Vec<(String, Vec<String>)> = calls()
            .into_iter()
            .map(|(program, argv, _)| (program, argv))
            .collect();
        let v = |parts: &[&str]| parts.iter().map(|p| (*p).to_string()).collect::<Vec<_>>();
        let expected: Vec<(String, Vec<String>)> = vec![
            (
                "iptables".into(),
                v(&["-t", "nat", "-N", "RUST_PROXY_CHAIN"]),
            ),
            (
                "iptables".into(),
                v(&["-t", "nat", "-F", "RUST_PROXY_CHAIN"]),
            ),
            (
                "iptables".into(),
                v(&[
                    "-t",
                    "nat",
                    "-A",
                    "RUST_PROXY_CHAIN",
                    "-d",
                    "127.0.0.0/8",
                    "-j",
                    "RETURN",
                ]),
            ),
            ("iptables".into(), {
                let mut argv = v(&[
                    "-t",
                    "nat",
                    "-A",
                    "RUST_PROXY_CHAIN",
                    "-m",
                    "mark",
                    "--mark",
                ]);
                argv.push(DIRECT_BYPASS_MARK.to_string());
                argv.push("-j".to_string());
                argv.push("RETURN".to_string());
                argv
            }),
            (
                "iptables".into(),
                v(&[
                    "-t",
                    "nat",
                    "-A",
                    "RUST_PROXY_CHAIN",
                    "-p",
                    "tcp",
                    "-d",
                    "10.0.0.1",
                    "-j",
                    "RETURN",
                ]),
            ),
            (
                "iptables".into(),
                v(&[
                    "-t",
                    "nat",
                    "-A",
                    "RUST_PROXY_CHAIN",
                    "-p",
                    "tcp",
                    "-m",
                    "set",
                    "--match-set",
                    "rust_proxy_set",
                    "dst",
                    "-j",
                    "REDIRECT",
                    "--to-ports",
                    "9090",
                ]),
            ),
            (
                "iptables".into(),
                v(&["-t", "nat", "-D", "OUTPUT", "-j", "RUST_PROXY_CHAIN"]),
            ),
            (
                "iptables".into(),
                v(&["-t", "nat", "-I", "OUTPUT", "1", "-j", "RUST_PROXY_CHAIN"]),
            ),
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn apply_rules_without_exemption_omits_both_owner_and_mark_rules() {
        install_capturing_spawn(None);
        let dests = set_of(&[]);
        apply_rules("C", "S", 80, None, &dests).unwrap();

        let flat: Vec<String> = calls().into_iter().flat_map(|(_, argv, _)| argv).collect();
        assert!(!flat.contains(&"owner".to_string()));
        assert!(!flat.contains(&"--uid-owner".to_string()));
        assert!(!flat.contains(&"mark".to_string()));
    }

    #[test]
    fn parse_chain_rules_extracts_redirect_ports() {
        let rules = "-A RP -d 127.0.0.0/8 -j RETURN\n\
                     -A RP -p tcp -m set --match-set rp_set dst -j REDIRECT --to-ports 12345\n";
        let snap = parse_chain_rules(rules);
        assert!(snap.present);
        assert_eq!(snap.redirect_ports, vec![12345]);
    }

    #[test]
    fn parse_chain_rules_handles_empty_and_declaration_only_output() {
        // Missing chain: empty output.
        let snap = parse_chain_rules("");
        assert!(!snap.present);
        assert!(snap.redirect_ports.is_empty());

        // Chain created but flushed: only the declaration line.
        let snap = parse_chain_rules("-N RP\n");
        assert!(snap.present, "a declared-but-empty chain still exists");
        assert!(snap.redirect_ports.is_empty());
    }

    #[test]
    fn parse_chain_rules_ignores_non_rule_lines_and_bad_ports() {
        let rules = "-P INPUT ACCEPT\n\
                     garbage line\n\
                     -A RP -j REDIRECT --to-ports notaport\n";
        let snap = parse_chain_rules(rules);
        // The malformed-redirect rule line is still a rule (chain has rules),
        // but contributes no port.
        assert!(snap.present);
        assert!(snap.redirect_ports.is_empty());
    }
}

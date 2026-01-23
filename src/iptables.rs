use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::process::Command;

pub fn require_root() -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        bail!("This command must be run as root (sudo).")
    }
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("Failed running {} {:?}", cmd, args))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Command failed: {} {:?}: {}", cmd, args, stderr.trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_best_effort(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}

pub fn ensure_ipset(ipset_name: &str) -> Result<()> {
    run(
        "ipset",
        &["create", ipset_name, "hash:net", "family", "inet", "-exist"],
    )?;
    Ok(())
}

pub fn sync_ipset(ipset_name: &str, ips: &HashSet<String>) -> Result<()> {
    // Atomically update the ipset by creating a temp set, swapping, and destroying the old one.
    // This prevents a window where the set is empty (after flush) which would leak traffic.
    let temp_name = format!("{}_tmp", ipset_name);

    // 1. Create temporary set (must match the type of the main set)
    run(
        "ipset",
        &["create", &temp_name, "hash:net", "family", "inet", "-exist"],
    )?;

    // 2. Flush the temp set to ensure it's clean
    run("ipset", &["flush", &temp_name])?;

    // 3. Populate the temp set
    for ip in ips {
        run("ipset", &["add", &temp_name, ip, "-exist"])?;
    }

    // 4. Swap the main set with the temp set
    // This is atomic: the main set name now refers to the new content
    run("ipset", &["swap", ipset_name, &temp_name])?;

    // 5. Destroy the temporary set (which now holds the old content)
    run("ipset", &["destroy", &temp_name])?;

    Ok(())
}

pub fn apply_rules(
    chain_name: &str,
    ipset_name: &str,
    listen_port: u16,
    exclude_uid: Option<u32>,
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

    if let Some(uid) = exclude_uid {
        run(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                chain_name,
                "-m",
                "owner",
                "--uid-owner",
                &uid.to_string(),
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
    Command::new("iptables")
        .args(["-t", "nat", "-S", chain_name])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

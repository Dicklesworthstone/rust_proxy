//! Basic E2E tests for rust_proxy CLI operations.
//!
//! Tests the fundamental CLI commands without daemon functionality.

use crate::common::assertions::*;
use crate::common::fixtures;
use crate::common::mock_proxy::{MockBehavior, MockProxy};
use crate::common::TestHarness;
use anyhow::Context as _;

fn cli_8bnf_config(harness: &TestHarness) -> anyhow::Result<toml::Value> {
    let mut config: toml::Value = toml::from_str(&fixtures::single_proxy_config(
        harness.listen_port(),
        "http://127.0.0.1:12345",
    ))?;
    // Custom targets use the real Simple string variant. A detailed target
    // without a provider is valid TOML but not a valid AppConfig.
    config["targets"] = vec![toml::Value::String("example.invalid".into())].into();
    Ok(config)
}

fn cli_8bnf_run(
    harness: &TestHarness,
    args: &[&str],
    environment: &[(&str, &str)],
) -> anyhow::Result<std::process::Output> {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"));
    command
        .args(args)
        .env("RUST_PROXY_CONFIG", &harness.config_path)
        .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
        .env_remove("RUST_PROXY_OUTPUT_FORMAT")
        .env_remove("TOON_DEFAULT_FORMAT");
    for (key, value) in environment {
        command.env(key, value);
    }
    let output = command.output()?;
    // --nocapture retains the actual child streams in the invoking Cargo log;
    // capture does not turn missing/failed execution into a successful result.
    eprintln!(
        "CLI 8bnf {args:?}: status {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn cli_8bnf_clean_output(output: &std::process::Output) {
    for (name, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        assert!(!bytes.contains(&0x1b), "ANSI escape in {name}");
        let text = String::from_utf8_lossy(bytes);
        for markup in ["[bold", "[/bold", "[red]", "[/red]", "[green]", "[/green]"] {
            assert!(!text.contains(markup), "terminal markup in {name}");
        }
    }
}

fn cli_8bnf_machine(
    output: &std::process::Output,
    format: &str,
) -> anyhow::Result<serde_json::Value> {
    cli_8bnf_clean_output(output);
    if format == "toon" {
        return Ok(toon_rust::try_decode(std::str::from_utf8(&output.stdout)?, None)?.into());
    }
    let value = serde_json::from_slice(&output.stdout)?;
    // The original acceptance explicitly names jq as the downstream consumer.
    // Check the complete bytes with both parsers; no prefix/tail is discarded.
    let mut jq = std::process::Command::new("jq")
        .args(["-e", "."])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    {
        let mut stdin = jq
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("jq stdin missing"))?;
        std::io::Write::write_all(&mut stdin, &output.stdout)?;
    }
    let parsed = jq.wait_with_output()?;
    assert!(
        parsed.status.success(),
        "jq rejected CLI JSON: {}",
        String::from_utf8_lossy(&parsed.stderr)
    );
    Ok(value)
}

/// Offline validation/output contracts only; no daemon or kernel interception.
#[tokio::test]
async fn cli_8bnf_check_exact_exit_codes_and_json_payloads() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;
    let valid = cli_8bnf_config(&harness)?;
    std::fs::write(&harness.config_path, toml::to_string(&valid)?)?;
    let report = cli_8bnf_run(&harness, &["check", "--strict", "--json"], &[])?;
    assert_eq!(report.status.code(), Some(0));
    let payload = cli_8bnf_machine(&report, "json")?;
    assert_eq!(payload["valid"], true);
    assert_eq!(payload["summary"]["error_count"], 0);
    assert_eq!(payload["summary"]["warning_count"], 0);
    assert_eq!(payload["errors"], serde_json::json!([]));
    assert_eq!(payload["warnings"], serde_json::json!([]));

    let mut errors = valid.clone();
    errors["settings"]["listen_port"] = 0.into();
    std::fs::write(&harness.config_path, toml::to_string(&errors)?)?;
    let report = cli_8bnf_run(&harness, &["check", "--json"], &[])?;
    assert_eq!(report.status.code(), Some(1));
    let payload = cli_8bnf_machine(&report, "json")?;
    assert_eq!(payload["valid"], false);
    assert!(payload["errors"].as_array().unwrap().iter().any(|error| {
        error["category"] == "settings" && error["message"] == "listen_port cannot be 0"
    }));

    let mut warnings = valid.clone();
    warnings.as_table_mut().unwrap().remove("active_proxy");
    std::fs::write(&harness.config_path, toml::to_string(&warnings)?)?;
    for (args, expected) in [
        (vec!["check", "--json"], 0),
        (vec!["check", "--strict", "--json"], 2),
    ] {
        let report = cli_8bnf_run(&harness, &args, &[])?;
        assert_eq!(report.status.code(), Some(expected));
        let payload = cli_8bnf_machine(&report, "json")?;
        assert_eq!(payload["valid"], true);
        assert_eq!(payload["summary"]["error_count"], 0);
        assert_eq!(payload["summary"]["warning_count"], 1);
        assert_eq!(payload["warnings"][0]["category"], "active");
    }

    std::fs::write(&harness.config_path, "[[proxies]\n")?;
    let report = cli_8bnf_run(&harness, &["check", "--json"], &[])?;
    assert_eq!(report.status.code(), Some(3));
    let payload = cli_8bnf_machine(&report, "json")?;
    assert_eq!(payload["valid"], false);
    assert_eq!(payload["errors"][0]["category"], "file");
    assert_eq!(payload["warnings"], serde_json::json!([]));

    let missing = harness.temp_dir.path().join("never-created-config.toml");
    let report = cli_8bnf_run(
        &harness,
        &["check", "--json"],
        &[("RUST_PROXY_CONFIG", missing.to_str().unwrap())],
    )?;
    assert_eq!(report.status.code(), Some(3));
    let payload = cli_8bnf_machine(&report, "json")?;
    assert_eq!(payload["valid"], false);
    assert_eq!(payload["config_path"], missing.to_str().unwrap());
    Ok(())
}

#[tokio::test]
async fn cli_8bnf_check_format_and_environment_precedence() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;
    std::fs::write(
        &harness.config_path,
        toml::to_string(&cli_8bnf_config(&harness)?)?,
    )?;
    for (args, environment, format) in [
        (vec!["check", "--json"], vec![], "json"),
        (vec!["check", "--format", "json"], vec![], "json"),
        (vec!["check", "--format", "toon"], vec![], "toon"),
        (vec!["check", "--json", "--quiet"], vec![], "json"),
        (
            vec!["check", "--json"],
            vec![("RUST_PROXY_OUTPUT_FORMAT", "toon")],
            "toon",
        ),
        (
            vec!["check", "--json"],
            vec![("TOON_DEFAULT_FORMAT", "toon")],
            "toon",
        ),
        (
            vec!["check", "--json"],
            vec![
                ("RUST_PROXY_OUTPUT_FORMAT", "json"),
                ("TOON_DEFAULT_FORMAT", "toon"),
            ],
            "json",
        ),
        (
            vec!["check", "--format", "json"],
            vec![("RUST_PROXY_OUTPUT_FORMAT", "toon")],
            "json",
        ),
        (
            vec!["check", "--format", "toon"],
            vec![("RUST_PROXY_OUTPUT_FORMAT", "json")],
            "toon",
        ),
    ] {
        let output = cli_8bnf_run(&harness, &args, &environment)?;
        assert_eq!(output.status.code(), Some(0), "{args:?} {environment:?}");
        let payload = cli_8bnf_machine(&output, format)?;
        assert_eq!(payload["valid"], true);
        assert_eq!(payload["summary"]["error_count"].as_f64(), Some(0.0));
        assert_eq!(payload["summary"]["warning_count"].as_f64(), Some(0.0));
    }
    Ok(())
}

#[tokio::test]
async fn cli_8bnf_no_dns_target_hit_miss_and_removal_are_predictions() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;
    std::fs::write(
        &harness.config_path,
        toml::to_string(&cli_8bnf_config(&harness)?)?,
    )?;
    for (url, domain, expected) in [
        ("https://EXAMPLE.invalid/v1/chat", "example.invalid", true),
        ("HTTPS://EXAMPLE.invalid/v1/chat", "example.invalid", true),
        ("example.invalid", "example.invalid", true),
        ("example.invalid:443", "example.invalid", true),
        ("excluded.invalid", "excluded.invalid", false),
        (
            "unlisted.example.invalid",
            "unlisted.example.invalid",
            false,
        ),
    ] {
        let output = cli_8bnf_run(&harness, &["test", url, "--no-dns", "--json"], &[])?;
        assert_eq!(output.status.code(), Some(0));
        let prediction = cli_8bnf_machine(&output, "json")?;
        assert_eq!(prediction["domain"], domain);
        assert_eq!(prediction["would_proxy"], expected);
        assert_eq!(
            prediction["routing_decision"]["domain_in_targets"],
            expected
        );
        assert_eq!(prediction["resolved_ips"], serde_json::json!([]));
        assert!(prediction["dns_error"].is_null());
        assert_eq!(
            prediction["routing_decision"]["provider_range_matches"],
            serde_json::json!([])
        );
        assert_eq!(prediction["active_proxy"]["id"], "test-proxy");
        // daemon_running is deliberately not interpreted as proof of identity
        // or active firewall interception: this command predicts configuration.
    }
    let removed = cli_8bnf_run(&harness, &["targets", "remove", "example.invalid"], &[])?;
    assert_eq!(removed.status.code(), Some(0));
    let output = cli_8bnf_run(
        &harness,
        &["test", "example.invalid", "--no-dns", "--json"],
        &[],
    )?;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(cli_8bnf_machine(&output, "json")?["would_proxy"], false);
    Ok(())
}

#[tokio::test]
async fn cli_8bnf_verbose_machine_formats_and_environment_are_pure() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;
    std::fs::write(
        &harness.config_path,
        toml::to_string(&cli_8bnf_config(&harness)?)?,
    )?;
    for (flags, environment, format) in [
        (vec!["--json", "-v"], vec![], "json"),
        (vec!["--json", "--verbose"], vec![], "json"),
        (vec!["--format", "json", "-v"], vec![], "json"),
        (vec!["--format", "toon", "--verbose"], vec![], "toon"),
        (
            vec!["--json", "-v"],
            vec![("RUST_PROXY_OUTPUT_FORMAT", "toon")],
            "toon",
        ),
        (
            vec!["--json", "--verbose"],
            vec![("TOON_DEFAULT_FORMAT", "toon")],
            "toon",
        ),
        (
            vec!["--format", "json", "-v"],
            vec![("RUST_PROXY_OUTPUT_FORMAT", "toon")],
            "json",
        ),
    ] {
        for (domain, expected) in [("example.invalid", true), ("excluded.invalid", false)] {
            let mut args = vec!["test", domain, "--no-dns"];
            args.extend(flags.iter().copied());
            let output = cli_8bnf_run(&harness, &args, &environment)?;
            assert_eq!(output.status.code(), Some(0));
            let payload = cli_8bnf_machine(&output, format)?;
            assert_eq!(payload["domain"], domain);
            assert_eq!(payload["would_proxy"], expected);
            assert_eq!(payload["resolved_ips"], serde_json::json!([]));
        }
    }
    Ok(())
}

#[tokio::test]
async fn cli_8bnf_supported_quiet_preserves_exit_codes_and_plain_failures() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;
    let valid = cli_8bnf_config(&harness)?;
    std::fs::write(&harness.config_path, toml::to_string(&valid)?)?;
    let output = cli_8bnf_run(&harness, &["check", "--quiet"], &[])?;
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let mut warnings = valid.clone();
    warnings.as_table_mut().unwrap().remove("active_proxy");
    std::fs::write(&harness.config_path, toml::to_string(&warnings)?)?;
    let output = cli_8bnf_run(&harness, &["check", "--quiet"], &[])?;
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let output = cli_8bnf_run(&harness, &["check", "--strict", "--quiet"], &[])?;
    assert_eq!(output.status.code(), Some(2));
    cli_8bnf_clean_output(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("No active proxy configured"));
    let mut errors = valid;
    errors["settings"]["listen_port"] = 0.into();
    std::fs::write(&harness.config_path, toml::to_string(&errors)?)?;
    let output = cli_8bnf_run(&harness, &["check", "--quiet"], &[])?;
    assert_eq!(output.status.code(), Some(1));
    cli_8bnf_clean_output(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("listen_port cannot be 0"));
    std::fs::write(&harness.config_path, "[[proxies]\n")?;
    let output = cli_8bnf_run(&harness, &["check", "--quiet"], &[])?;
    assert_eq!(output.status.code(), Some(3));
    cli_8bnf_clean_output(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("Failed to load configuration"));
    Ok(())
}

#[tokio::test]
async fn cli_8bnf_invalid_arguments_and_target_errors_are_explicit() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;
    std::fs::write(
        &harness.config_path,
        toml::to_string(&cli_8bnf_config(&harness)?)?,
    )?;
    let valid = cli_8bnf_run(&harness, &["check", "--strict", "--json"], &[])?;
    assert_eq!(valid.status.code(), Some(0));
    assert_eq!(cli_8bnf_machine(&valid, "json")?["valid"], true);
    for args in [
        vec!["check", "--json", "--not-a-supported-option"],
        vec!["check", "--verbose"],
        vec!["test", "example.invalid", "--json", "--quiet", "--no-dns"],
        vec!["test", "example.invalid", "--format", "yaml", "--no-dns"],
        vec!["test", "--json"],
    ] {
        let output = cli_8bnf_run(&harness, &args, &[])?;
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        cli_8bnf_clean_output(&output);
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));
    }
    for target in [
        "",
        "bad..invalid",
        "https://[invalid-host",
        "ftp://public-user:public-password@example.invalid/path",
    ] {
        let output = cli_8bnf_run(&harness, &["test", target, "--json", "--no-dns"], &[])?;
        assert_eq!(output.status.code(), Some(1), "invalid target {target:?}");
        cli_8bnf_clean_output(&output);
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid target domain"));
        for secret in ["public-user", "public-password"] {
            assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
            assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
        }
    }
    Ok(())
}

#[tokio::test]
async fn cli_8bnf_config_credentials_never_enter_machine_reports() -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;
    let mut config = cli_8bnf_config(&harness)?;
    config["proxies"][0]["url"] =
        "http://inline-user-secret:inline-password-secret@127.0.0.1:12345".into();
    let mut auth = toml::Table::new();
    auth.insert("username".into(), "config-user-secret".into());
    auth.insert("password".into(), "config-password-secret".into());
    auth.insert("username_env".into(), "CLI_8BNF_USER".into());
    auth.insert("password_env".into(), "CLI_8BNF_PASSWORD".into());
    config["proxies"][0]
        .as_table_mut()
        .unwrap()
        .insert("auth".into(), auth.into());
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    let before = std::fs::read(&harness.config_path)?;
    let credentials = [
        ("CLI_8BNF_USER", "environment-user-secret"),
        ("CLI_8BNF_PASSWORD", "environment-password-secret"),
    ];
    for (args, format) in [
        (vec!["check", "--json"], "json"),
        (vec!["check", "--format", "toon"], "toon"),
        (
            vec!["test", "example.invalid", "--no-dns", "--json", "-v"],
            "json",
        ),
        (
            vec![
                "test",
                "example.invalid",
                "--no-dns",
                "--format",
                "toon",
                "--verbose",
            ],
            "toon",
        ),
    ] {
        let output = cli_8bnf_run(&harness, &args, &credentials)?;
        assert_eq!(output.status.code(), Some(0));
        cli_8bnf_machine(&output, format)?;
        for secret in [
            "inline-user-secret",
            "inline-password-secret",
            "config-user-secret",
            "config-password-secret",
            "environment-user-secret",
            "environment-password-secret",
        ] {
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains(secret),
                "stdout leaked {secret}"
            );
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains(secret),
                "stderr leaked {secret}"
            );
        }
        assert_eq!(std::fs::read(&harness.config_path)?, before);
    }
    config["proxies"][0]["url"] =
        "http://inline-user-secret:inline-password-secret@bad host:12345".into();
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    let output = cli_8bnf_run(&harness, &["check", "--json"], &credentials)?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(cli_8bnf_machine(&output, "json")?["valid"], false);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("inline-password-secret"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("inline-password-secret"));
    Ok(())
}

#[tokio::test]
async fn cli_8bnf_target_url_credentials_are_redacted_in_verbose_machine_output(
) -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;
    std::fs::write(
        &harness.config_path,
        toml::to_string(&cli_8bnf_config(&harness)?)?,
    )?;
    let target = "https://client-user-secret:client-password-secret@example.invalid/path";
    for (flags, format) in [
        (vec!["--json", "-v"], "json"),
        (vec!["--format", "toon", "--verbose"], "toon"),
    ] {
        let mut args = vec!["test", target, "--no-dns"];
        args.extend(flags);
        let output = cli_8bnf_run(&harness, &args, &[])?;
        assert_eq!(output.status.code(), Some(0));
        let payload = cli_8bnf_machine(&output, format)?;
        assert_eq!(payload["domain"], "example.invalid");
        assert_eq!(payload["would_proxy"], true);
        for secret in ["client-user-secret", "client-password-secret"] {
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains(secret),
                "stdout leaked {secret}"
            );
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains(secret),
                "stderr leaked {secret}"
            );
        }
        assert!(payload["input"]
            .as_str()
            .unwrap()
            .contains("example.invalid/path"));
    }
    Ok(())
}

const IPV6_UPSTREAM_TARGET: &str = "198.51.100.42:443";
const IPV6_UPSTREAM_USER: &str = "ipv6-client-user";

fn ipv6_upstream_password() -> anyhow::Result<String> {
    use std::io::Read as _;
    let mut bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[derive(Debug, serde::Serialize)]
struct Ipv6UpstreamReceipt {
    request_line: String,
    peer: std::net::SocketAddr,
    authorized: bool,
    body: Vec<u8>,
}

async fn ipv6_upstream_headers(stream: &mut tokio::net::TcpStream) -> anyhow::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        anyhow::ensure!(
            header.len() < 16 * 1024,
            "IPv6 CONNECT header exceeded bound"
        );
        header.push(stream.read_u8().await?);
    }
    Ok(header)
}

/// A real loopback IPv6 CONNECT endpoint. It validates the request and Basic
/// token before opening an echo tunnel; wrong credentials receive a real 407.
/// This is transport proof through a local endpoint, never target NAT proof.
async fn ipv6_upstream_endpoint(
    log_path: std::path::PathBuf,
    connections: usize,
    password: &str,
) -> anyhow::Result<(
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<Vec<Ipv6UpstreamReceipt>>>,
)> {
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    assert!(address.is_ipv6());
    let expected_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD
            .encode(format!("{IPV6_UPSTREAM_USER}:{password}"))
    );
    let task = tokio::spawn(async move {
        let mut receipts = Vec::new();
        for _ in 0..connections {
            let (mut stream, peer) = listener.accept().await?;
            assert_eq!(
                peer.ip(),
                std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            );
            let header = String::from_utf8(ipv6_upstream_headers(&mut stream).await?)?;
            let request_line = header
                .lines()
                .next()
                .context("missing CONNECT request")?
                .to_owned();
            let authorized =
                header
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .any(|(name, value)| {
                        name.eq_ignore_ascii_case("Proxy-Authorization")
                            && value.trim() == expected_auth
                    });
            let mut receipt = Ipv6UpstreamReceipt {
                request_line,
                peer,
                authorized,
                body: Vec::new(),
            };
            if authorized
                && receipt.request_line == format!("CONNECT {IPV6_UPSTREAM_TARGET} HTTP/1.1")
            {
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                let mut buffer = [0; 4096];
                loop {
                    let read = stream.read(&mut buffer).await?;
                    if read == 0 {
                        break;
                    }
                    receipt.body.extend_from_slice(&buffer[..read]);
                    stream.write_all(&buffer[..read]).await?;
                }
            } else {
                stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"ipv6-test\"\r\n\r\n").await?;
            }
            receipts.push(receipt);
            // Retain observations at the receiving endpoint, including any
            // successful direct control before a product assertion fails.
            std::fs::write(&log_path, serde_json::to_vec_pretty(&receipts)?)?;
        }
        Ok(receipts)
    });
    Ok((address, task))
}

fn ipv6_upstream_config(
    harness: &TestHarness,
    port: u16,
    password: &str,
) -> anyhow::Result<toml::Value> {
    let mut config = cli_8bnf_config(harness)?;
    config["proxies"][0]["url"] =
        format!("http://{IPV6_UPSTREAM_USER}:{password}@[::1]:{port}").into();
    config["settings"]
        .as_table_mut()
        .context("settings fixture")?
        .insert(
            "health_check_target".into(),
            format!("CONNECT {IPV6_UPSTREAM_TARGET}").into(),
        );
    Ok(config)
}

fn ipv6_upstream_cli(
    harness: &TestHarness,
    args: &[&str],
    password: &str,
) -> anyhow::Result<serde_json::Value> {
    use base64::Engine as _;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
        .args(args)
        .env("RUST_PROXY_CONFIG", &harness.config_path)
        .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
        .env_remove("RUST_PROXY_OUTPUT_FORMAT")
        .env_remove("TOON_DEFAULT_FORMAT")
        .output()?;
    eprintln!(
        "IPv6 upstream CLI {args:?}: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0));
    let token = base64::engine::general_purpose::STANDARD
        .encode(format!("{IPV6_UPSTREAM_USER}:{password}"));
    for bytes in [&output.stdout, &output.stderr] {
        for secret in [IPV6_UPSTREAM_USER, password, token.as_str()] {
            assert!(
                !String::from_utf8_lossy(bytes).contains(secret),
                "CLI leaked {secret}"
            );
        }
    }
    cli_8bnf_machine(&output, "json")
}

fn ipv6_upstream_assert_authority(value: &serde_json::Value, port: u16) -> anyhow::Result<()> {
    let text = value.as_str().context("redacted IPv6 upstream URL")?;
    assert_eq!(text, format!("http://[::1]:{port}"));
    let parsed = url::Url::parse(text)?;
    assert_eq!(
        parsed.host(),
        Some(url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST))
    );
    assert_eq!(parsed.port(), Some(port));
    assert!(parsed.username().is_empty());
    assert!(parsed.password().is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_upstream_cli_connectivity_and_redacted_authorities_are_real() -> anyhow::Result<()> {
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut harness = TestHarness::new().await?;
    harness.temp_dir.disable_cleanup(true);
    eprintln!("IPv6 CLI fixtures: {}", harness.temp_dir.path().display());
    let password = ipv6_upstream_password()?;
    let (address, endpoint) = ipv6_upstream_endpoint(
        harness.temp_dir.path().join("ipv6-cli-receipts.json"),
        4,
        &password,
    )
    .await?;
    let control_payload = b"independent-ipv6-connect-control";
    // Independent socket control discriminates an unavailable endpoint from
    // the product's bracketed-host lookup defect retained in the baseline log.
    let mut control = tokio::net::TcpStream::connect(address).await?;
    let token = base64::engine::general_purpose::STANDARD
        .encode(format!("{IPV6_UPSTREAM_USER}:{password}"));
    control.write_all(format!("CONNECT {IPV6_UPSTREAM_TARGET} HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n").as_bytes()).await?;
    assert!(ipv6_upstream_headers(&mut control)
        .await?
        .starts_with(b"HTTP/1.1 200 "));
    control.write_all(control_payload).await?;
    let mut echoed = vec![0; control_payload.len()];
    control.read_exact(&mut echoed).await?;
    assert_eq!(echoed, control_payload);
    control.shutdown().await?;
    drop(control);

    let mut config = ipv6_upstream_config(&harness, address.port(), &password)?;
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    let positive = ipv6_upstream_cli(
        &harness,
        &["check", "--test-connectivity", "--json"],
        &password,
    )?;
    assert_eq!(positive["valid"], true);
    assert_eq!(positive["connectivity"][0]["status"], "success");
    assert!(positive["connectivity"][0]["error"].is_null());
    assert!(positive["connectivity"][0]["latency_ms"].is_number());
    for args in [
        vec!["list", "--json"],
        vec!["test", "example.invalid", "--no-dns", "--json", "--verbose"],
    ] {
        let output = ipv6_upstream_cli(&harness, &args, &password)?;
        let redacted = if args[0] == "list" {
            &output["proxies"][0]["url"]
        } else {
            &output["active_proxy"]["url"]
        };
        ipv6_upstream_assert_authority(redacted, address.port())?;
    }
    config["proxies"][0]["url"] = format!(
        "http://{IPV6_UPSTREAM_USER}:{password}-wrong@[::1]:{}",
        address.port()
    )
    .into();
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    let denied = ipv6_upstream_cli(
        &harness,
        &["check", "--test-connectivity", "--json"],
        &password,
    )?;
    assert_eq!(denied["valid"], true);
    assert_eq!(denied["connectivity"][0]["status"], "auth_required");
    assert!(denied["connectivity"][0]["latency_ms"].is_null());
    std::fs::write(
        &harness.config_path,
        toml::to_string(&ipv6_upstream_config(&harness, address.port(), &password)?)?,
    )?;
    let recovered = ipv6_upstream_cli(
        &harness,
        &["check", "--test-connectivity", "--json"],
        &password,
    )?;
    assert_eq!(recovered["connectivity"][0]["status"], "success");
    let receipts = tokio::time::timeout(std::time::Duration::from_secs(5), endpoint).await???;
    assert_eq!(receipts.len(), 4);
    assert_eq!(receipts[0].body, control_payload);
    assert_eq!(
        receipts
            .iter()
            .map(|receipt| receipt.authorized)
            .collect::<Vec<_>>(),
        [true, true, false, true]
    );
    for receipt in &receipts {
        assert_eq!(
            receipt.request_line,
            format!("CONNECT {IPV6_UPSTREAM_TARGET} HTTP/1.1")
        );
    }
    assert!(receipts[1..].iter().all(|receipt| receipt.body.is_empty()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_upstream_daemon_relays_ipv4_destination_bytes_without_restart() -> anyhow::Result<()>
{
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    anyhow::ensure!(
        unsafe { libc::geteuid() } != 0,
        "IPv6 upstream daemon seam requires non-root"
    );
    let mut harness = TestHarness::new().await?;
    harness.temp_dir.disable_cleanup(true);
    eprintln!(
        "IPv6 daemon fixtures: {}",
        harness.temp_dir.path().display()
    );
    let password = ipv6_upstream_password()?;
    let (address, endpoint) = ipv6_upstream_endpoint(
        harness.temp_dir.path().join("ipv6-daemon-receipts.json"),
        3,
        &password,
    )
    .await?;
    let config = ipv6_upstream_config(&harness, address.port(), &password)?;
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    let stdout = harness.temp_dir.path().join("ipv6-daemon.stdout.log");
    let stderr = harness.temp_dir.path().join("ipv6-daemon.stderr.log");
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
        .arg("daemon")
        .env("RUST_PROXY_CONFIG", &harness.config_path)
        .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
        .env("RUST_PROXY_TEST_MODE", "1")
        .env("RUST_PROXY_TEST_ORIGINAL_DST", IPV6_UPSTREAM_TARGET)
        .env("RUST_LOG", "debug")
        .stdout(std::fs::File::create(&stdout)?)
        .stderr(std::fs::File::create(&stderr)?)
        .spawn()?;
    struct Ipv6OwnedDaemon(std::process::Child);
    impl Drop for Ipv6OwnedDaemon {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    let mut daemon = Ipv6OwnedDaemon(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        anyhow::ensure!(
            daemon.0.try_wait()?.is_none(),
            "IPv6 daemon exited before readiness"
        );
        let status = ipv6_upstream_cli(&harness, &["status", "--json"], &password)?;
        if status["daemon_running"] == true {
            assert_eq!(status["daemon"]["status"], "ready");
            assert_eq!(
                status["daemon"]["snapshot"]["identity"]["pid"],
                daemon.0.id()
            );
            assert_eq!(status["daemon"]["snapshot"]["test_mode"], true);
            assert_eq!(status["rules_active"], false);
            ipv6_upstream_assert_authority(
                &status["daemon"]["snapshot"]["applied"]["config"]["proxies"][0]["url"],
                address.port(),
            )?;
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "IPv6 daemon exceeded original 5s readiness bound"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let payloads: [&[u8]; 3] = [
        b"IPv6-upstream-relay-one",
        b"IPv6-upstream-relay-two",
        b"IPv6-upstream-relay-three",
    ];
    for payload in payloads {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut client =
                tokio::net::TcpStream::connect(("127.0.0.1", harness.listen_port())).await?;
            client.write_all(payload).await?;
            let mut echoed = vec![0; payload.len()];
            client.read_exact(&mut echoed).await?;
            assert_eq!(echoed, payload);
            client.shutdown().await?;
            let mut tail = Vec::new();
            client.read_to_end(&mut tail).await?;
            assert!(tail.is_empty());
            Ok::<(), anyhow::Error>(())
        })
        .await??;
    }
    let receipts = tokio::time::timeout(Duration::from_secs(5), endpoint).await???;
    assert_eq!(
        receipts.len(),
        3,
        "readiness and disabled health cannot inflate recipients"
    );
    for (receipt, payload) in receipts.iter().zip(payloads) {
        assert!(receipt.authorized);
        assert_eq!(
            receipt.request_line,
            format!("CONNECT {IPV6_UPSTREAM_TARGET} HTTP/1.1")
        );
        assert_eq!(receipt.body, payload);
    }
    let stopped = std::process::Command::new("kill")
        .args(["-TERM", &daemon.0.id().to_string()])
        .output()?;
    eprintln!(
        "IPv6 owned shutdown: {}\nstdout:{}\nstderr:{}",
        stopped.status,
        String::from_utf8_lossy(&stopped.stdout),
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(stopped.status.success());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = daemon.0.try_wait()? {
            assert!(status.success());
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "IPv6 daemon graceful shutdown exceeded 5s"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    for path in [stdout, stderr] {
        let output = std::fs::read_to_string(path)?;
        for secret in [IPV6_UPSTREAM_USER, password.as_str()] {
            assert!(!output.contains(secret), "daemon emitted a credential");
        }
    }
    Ok(())
}

#[tokio::test]
async fn daemon_final_flush_preserves_real_cli_activation_and_exact_traffic() -> anyhow::Result<()>
{
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    anyhow::ensure!(
        unsafe { libc::geteuid() } != 0,
        "persistence daemon seam requires non-root"
    );
    let harness = TestHarness::new().await?;
    let proxy = MockProxy::new(0, MockBehavior::TunnelEcho).await?;
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
    let mut proxies = Vec::new();
    for id in ["first", "second"] {
        let mut entry = toml::Table::new();
        entry.insert("id".into(), id.into());
        entry.insert("url".into(), proxy.url().into());
        proxies.push(toml::Value::Table(entry));
    }
    let root = config.as_table_mut().unwrap();
    root.insert("proxies".into(), proxies.into());
    root.insert("active_proxy".into(), "first".into());
    root.insert(
        "targets".into(),
        vec![toml::Value::String("persistence.target.invalid".into())].into(),
    );
    let settings = config["settings"].as_table_mut().unwrap();
    settings.insert("metrics_enabled".into(), false.into());
    settings.insert("health_check_enabled".into(), false.into());
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    assert!(harness.run_command(&["activate", "first"]).success);
    let work = tempfile::tempdir()?.keep();
    let log = work.join("daemon.stderr");
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
        .arg("daemon")
        .env("RUST_PROXY_CONFIG", &harness.config_path)
        .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
        .env("RUST_PROXY_TEST_MODE", "1")
        .env(
            "RUST_PROXY_TEST_ORIGINAL_DST",
            "persistence.target.invalid:443",
        )
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(&log)?)
        .spawn()?;
    struct OwnedDaemon(std::process::Child);
    impl Drop for OwnedDaemon {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    let mut daemon = OwnedDaemon(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::fs::read_to_string(&log)?.contains("transparent proxy listening") {
        anyhow::ensure!(
            daemon.0.try_wait()?.is_none(),
            "daemon exited before persistence proof"
        );
        anyhow::ensure!(
            Instant::now() < deadline,
            "persistence daemon startup exceeded budget"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let payload = b"persistence-counter-delta-payload";
    for _ in 0..3 {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut client =
                tokio::net::TcpStream::connect(("127.0.0.1", harness.listen_port())).await?;
            client.write_all(payload).await?;
            let mut echoed = vec![0; payload.len()];
            client.read_exact(&mut echoed).await?;
            anyhow::ensure!(echoed == payload, "persistence tunnel payload mismatch");
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    }
    assert!(harness.run_command(&["activate", "second"]).success);
    let path = harness.state_dir.join("state.json");
    let before: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let activation = before["proxies"]["second"]["activated_at"].clone();
    assert!(activation.is_string());
    assert_eq!(
        before["proxies"]["first"]["bytes_sent"], 0,
        "traffic must still be dirty in the daemon cache"
    );
    // SAFETY: positive PID of the live child owned by this test, ordinary SIGTERM.
    anyhow::ensure!(
        unsafe { libc::kill(daemon.0.id() as libc::pid_t, libc::SIGTERM) } == 0,
        "cannot terminate persistence daemon"
    );
    let shutdown = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = daemon.0.try_wait()? {
            assert!(status.success(), "daemon persistence exit failed");
            break;
        }
        anyhow::ensure!(
            Instant::now() < shutdown,
            "final persistence flush exceeded lifetime budget"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    assert_eq!(after["proxies"]["second"]["activated_at"], activation);
    assert_eq!(after["proxies"]["first"]["bytes_sent"], 3 * payload.len());
    assert_eq!(
        after["proxies"]["first"]["bytes_received"],
        3 * payload.len()
    );
    assert_eq!(
        proxy.request_count(),
        3,
        "readiness cannot inflate the traffic denominator"
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_config_mutations_wait_for_transaction_and_preserve_both_operations(
) -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;
    use std::time::Duration;
    let harness = TestHarness::new().await?;
    let original = std::fs::read(&harness.config_path)?;
    let directory = std::fs::File::open(harness.config_path.parent().unwrap())?;
    // SAFETY: live directory descriptor; the controller owns this exclusive gate.
    anyhow::ensure!(
        unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "cannot gate config transactions"
    );
    let launch = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
            .args(args)
            .env("RUST_PROXY_CONFIG", &harness.config_path)
            .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
    };
    let mut target = launch(&["targets", "add", "first.concurrent.invalid"])?;
    let mut proxy = launch(&[
        "proxy",
        "add",
        "second-concurrent",
        "http://127.0.0.1:12345",
    ])?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let both_waiting = target.try_wait()?.is_none() && proxy.try_wait()?.is_none();
    let unchanged = std::fs::read(&harness.config_path)? == original;
    drop(directory);
    let target = target.wait_with_output()?;
    let proxy = proxy.wait_with_output()?;
    assert!(
        both_waiting && unchanged,
        "mutations bypassed the exclusive transaction gate"
    );
    assert!(
        target.status.success(),
        "target command: {}",
        String::from_utf8_lossy(&target.stderr)
    );
    assert!(
        proxy.status.success(),
        "proxy command: {}",
        String::from_utf8_lossy(&proxy.stderr)
    );
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
    assert!(config["targets"]
        .as_array()
        .unwrap()
        .iter()
        .any(|target| target.as_str() == Some("first.concurrent.invalid")));
    assert!(config["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .any(|proxy| proxy["id"].as_str() == Some("second-concurrent")));
    Ok(())
}

#[tokio::test]
async fn busy_config_transaction_fails_without_changing_last_good_bytes() -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;
    let harness = TestHarness::new().await?;
    let original = std::fs::read(&harness.config_path)?;
    let directory = std::fs::File::open(harness.config_path.parent().unwrap())?;
    // SAFETY: live test-owned directory descriptor, released by File drop.
    anyhow::ensure!(
        unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "cannot hold busy transaction control"
    );
    // The controller NEVER releases the lock to produce success; the product
    // must emit its own bounded failure while the file remains unchanged.
    let started = std::time::Instant::now();
    let result = harness.run_command(&["targets", "add", "must-not-publish.invalid"]);
    drop(directory);
    assert!(!result.success);
    assert!(result
        .stderr
        .contains("Persistence transaction busy after two seconds"));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(std::fs::read(&harness.config_path)?, original);
    let recovered = harness.run_command(&["targets", "add", "must-not-publish.invalid"]);
    assert!(
        recovered.success,
        "lock remained stranded: {}",
        recovered.stderr
    );
    Ok(())
}

/// Child-only trust environment: never affect concurrent feed-client tests.
/// The trust FIFO has no writer or fixture timeout. Only the product's probe
/// deadline and bounded runtime shutdown can produce the asserted result.
#[tokio::test]
async fn stalled_native_trust_read_cannot_block_health_deadline() -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let harness = TestHarness::new().await?;
    let work = tempfile::tempdir()?.keep();
    let fifo = work.join("stalled-trust.pem");
    let path = std::ffi::CString::new(fifo.as_os_str().as_bytes())?;
    // SAFETY: live NUL-terminated test-owned pathname and ordinary mode bits.
    anyhow::ensure!(
        unsafe { libc::mkfifo(path.as_ptr(), 0o600) } == 0,
        "failed creating private trust FIFO"
    );
    let empty_roots = work.join("empty-trust-dir");
    std::fs::create_dir(&empty_roots)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    assert!(
        harness
            .run_command(&["proxy", "add", "trust-probe", &url])
            .success
    );
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
    let settings = config["settings"].as_table_mut().unwrap();
    settings.insert(
        "health_check_target".into(),
        "GET https://localhost/health".into(),
    );
    settings.insert("health_check_timeout_ms".into(), 200.into());
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    let endpoint = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).await?;
            request.push(byte[0]);
            anyhow::ensure!(
                request.len() <= 16 * 1024,
                "trust probe request exceeded fixture cap"
            );
        }
        anyhow::ensure!(
            request.starts_with(b"CONNECT localhost:443 HTTP/1.1\r\n"),
            "trust fixture did not receive CONNECT"
        );
        stream
            .write_all(b"HTTP/1.1 200 Established\r\n\r\n")
            .await?;
        Ok::<_, anyhow::Error>(())
    });
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
        .args(["check", "--json", "--test-connectivity"])
        .env("RUST_PROXY_CONFIG", &harness.config_path)
        .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
        .env("SSL_CERT_FILE", &fifo)
        .env("SSL_CERT_DIR", &empty_roots)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < Duration::from_secs(6) => {
                tokio::time::sleep(Duration::from_millis(25)).await
            }
            outcome => {
                let _ = child.kill();
                let output = child.wait_with_output()?;
                endpoint.abort();
                anyhow::bail!("trust probe exceeded product lifetime or failed polling: {outcome:?}; stderr: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
    }
    let output = child.wait_with_output()?;
    assert!(output.status.success(), "trust probe CLI failed");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["connectivity"][0]["status"], "timeout");
    assert_eq!(report["connectivity"][0]["error"], "Connection timeout");
    assert!(start.elapsed() < Duration::from_secs(6));
    tokio::time::timeout(Duration::from_secs(1), endpoint).await???;
    Ok(())
}

#[tokio::test]
async fn proxy_credentials_are_redacted_without_modifying_persisted_configuration(
) -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;
    assert!(
        harness
            .run_command(&["proxy", "add", "secret-test", "http://127.0.0.1:12345"])
            .success
    );
    let mut config: toml::Value = toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
    config["proxies"][0]["url"] =
        "http://distinct-url-user:distinct-url-password@127.0.0.1:12345".into();
    let mut auth = toml::Table::new();
    auth.insert("username".into(), "distinct-config-user".into());
    auth.insert("password".into(), "distinct-config-password".into());
    config["proxies"][0]["auth"] = auth.into();
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    let original = std::fs::read(&harness.config_path)?;
    for args in [
        vec!["proxy", "list"],
        vec!["list", "--json"],
        vec!["list", "--format", "toon"],
        vec!["list"],
        vec!["status", "--json"],
        vec!["check", "--json"],
        vec!["test", "example.invalid", "--json", "--verbose", "--no-dns"],
    ] {
        let result = harness.run_command(&args);
        assert!(result.success, "command failed: {args:?}");
        let output = format!("{}{}", result.stdout, result.stderr);
        for secret in [
            "distinct-url-user",
            "distinct-url-password",
            "distinct-config-user",
            "distinct-config-password",
        ] {
            assert!(
                !output.contains(secret),
                "command leaked a credential token: {args:?}"
            );
        }
    }
    assert_eq!(
        std::fs::read(&harness.config_path)?,
        original,
        "display redaction changed usable config"
    );
    // Even invalid URL/TOML errors must not echo the original credential line.
    config["proxies"][0]["url"] =
        "http://distinct-url-user:distinct-url-password@bad host:12345".into();
    std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
    let invalid = harness.run_command(&["check", "--json"]);
    assert!(!invalid.success);
    assert!(!format!("{}{}", invalid.stdout, invalid.stderr).contains("distinct-url-password"));
    std::fs::write(&harness.config_path, "[[proxies]]\nid = \"broken\"\nurl = \"http://distinct-url-user:distinct-url-password@broken\n")?;
    let invalid = harness.run_command(&["list", "--json"]);
    assert!(!invalid.success);
    assert!(!format!("{}{}", invalid.stdout, invalid.stderr).contains("distinct-url-password"));
    Ok(())
}

#[tokio::test]
async fn unsupported_proxy_transport_and_incomplete_auth_fail_before_listener_admission(
) -> anyhow::Result<()> {
    for (url, username) in [
        ("https://127.0.0.1:12345", None),
        ("http://127.0.0.1:12345", Some("partial-auth-user")),
    ] {
        let harness = TestHarness::new().await?;
        assert!(
            harness
                .run_command(&["proxy", "add", "rejected", url])
                .success
        );
        assert!(harness.run_command(&["activate", "rejected"]).success);
        let mut config: toml::Value =
            toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
        if let Some(username) = username {
            let mut auth = toml::Table::new();
            auth.insert("username".into(), username.into());
            config["proxies"][0]["auth"] = auth.into();
        }
        std::fs::write(&harness.config_path, toml::to_string(&config)?)?;
        let before = std::fs::read(&harness.config_path)?;
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
            .arg("daemon")
            .env("RUST_PROXY_CONFIG", &harness.config_path)
            .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
            .env("RUST_PROXY_TEST_MODE", "1")
            .output()?;
        assert!(!result.status.success());
        assert!(
            std::net::TcpStream::connect(("127.0.0.1", harness.listen_port())).is_err(),
            "rejected endpoint opened a listener"
        );
        assert_eq!(std::fs::read(&harness.config_path)?, before);
        let output = String::from_utf8(result.stderr)?;
        assert!(!output.contains("partial-auth-user"));
    }
    Ok(())
}

/// Test that the test harness can be created
#[tokio::test]
async fn test_harness_creation() {
    let harness = TestHarness::new().await;
    assert!(harness.is_ok(), "Failed to create test harness");
    let harness = harness.unwrap();
    assert!(harness.config_path.exists());
    assert!(harness.state_dir.exists());
    harness.cleanup().await;
}

/// Test that we can create a mock proxy server
#[tokio::test]
async fn test_mock_proxy_creation() {
    let mock = MockProxy::new(0, MockBehavior::Healthy { latency_ms: 0 }).await;
    assert!(mock.is_ok(), "Failed to create mock proxy");
    let mock = mock.unwrap();
    assert!(mock.port > 0);
    assert!(!mock.url().is_empty());
}

/// Test that config fixtures generate valid TOML
#[test]
fn test_fixtures_are_valid_toml() {
    let configs = [
        fixtures::minimal_config(12345),
        fixtures::single_proxy_config(12345, "http://localhost:8080"),
        fixtures::multi_proxy_config(12345, &["http://localhost:8080", "http://localhost:8081"]),
        fixtures::config_with_health_check(12345, "http://localhost:8080", 5, 3),
        fixtures::config_with_failover(12345, "http://localhost:8080", "http://localhost:8081", 30),
    ];

    for (i, config) in configs.iter().enumerate() {
        let result: Result<toml::Value, _> = toml::from_str(config);
        assert!(
            result.is_ok(),
            "Fixture {} failed to parse as TOML: {:?}",
            i,
            result.err()
        );
    }
}

/// Test the assertion helpers
#[test]
fn test_assertion_json_path() {
    let json: serde_json::Value = serde_json::json!({
        "name": "test",
        "nested": {
            "value": 42,
            "array": [1, 2, 3]
        }
    });

    assert_json_field_exists(&json, "name", "name should exist");
    assert_json_field_exists(&json, "nested.value", "nested.value should exist");
    assert_json_field_is_string(&json, "name", "name should be string");
    assert_json_field_is_array(&json, "nested.array", "nested.array should be array");
    assert_json_array_len(&json, "nested.array", 3, "array should have 3 elements");
}

/// Test TOON output round-trip for list output
#[tokio::test]
async fn test_list_toon_roundtrip() {
    let harness = TestHarness::new().await.expect("Failed to create harness");

    let json_result = harness.run_command(&["list", "--format", "json"]);
    assert!(
        json_result.success,
        "list --format json failed: {}",
        json_result.stderr
    );

    let toon_result = harness.run_command(&["list", "--format", "toon"]);
    assert!(
        toon_result.success,
        "list --format toon failed: {}",
        toon_result.stderr
    );

    let decoded =
        toon_rust::try_decode(&toon_result.stdout, None).expect("Failed to decode TOON output");
    let expected: serde_json::Value =
        serde_json::from_str(&json_result.stdout).expect("Failed to parse JSON output");
    assert_eq!(decoded, expected.into());

    harness.cleanup().await;
}

/// Different requested state directories must isolate actual CLI writes even
/// when both processes inherit the same HOME and XDG defaults.
#[tokio::test]
async fn explicit_state_directories_isolate_cli_activation_and_statistics() -> anyhow::Result<()> {
    let first = TestHarness::new().await?;
    let second = TestHarness::new().await?;
    for (harness, id) in [(&first, "isolated-first"), (&second, "isolated-second")] {
        for args in [
            vec!["proxy", "add", id, "http://127.0.0.1:12345"],
            vec!["activate", id],
        ] {
            let result = harness.run_command(&args);
            assert!(result.success, "{args:?}: {}", result.stderr);
        }
        assert!(harness.state_dir.join("state.json").is_file());
    }
    let first_stats = first.run_command(&["list", "--json"]).json()?["stats"].clone();
    let second_stats = second.run_command(&["list", "--json"]).json()?["stats"].clone();
    assert_eq!(first_stats["proxies"].as_object().unwrap().len(), 1);
    assert_eq!(second_stats["proxies"].as_object().unwrap().len(), 1);
    assert!(first_stats["proxies"]["isolated-first"]["activated_at"].is_string());
    assert!(first_stats["proxies"]["isolated-second"].is_null());
    assert!(second_stats["proxies"]["isolated-second"]["activated_at"].is_string());
    assert!(second_stats["proxies"]["isolated-first"].is_null());
    Ok(())
}

/// Real CLI mutations and diagnostics; the no-DNS path establishes config
/// identity only. Kernel interception is qualified separately.
#[tokio::test]
async fn custom_domain_onboarding_has_truthful_provider_and_canonical_identity(
) -> anyhow::Result<()> {
    let harness = TestHarness::new().await?;
    for args in [
        vec!["init"],
        vec!["proxy", "add", "customer-proxy", "http://127.0.0.1:12345"],
        vec!["targets", "add", "Customer.Example.Invalid."],
        vec!["activate", "customer-proxy"],
        vec![
            "targets",
            "add",
            "hinted.example.invalid",
            "--provider",
            "cloudflare",
        ],
        vec!["targets", "add", "API.OpenAI.com."],
    ] {
        let result = harness.run_command(&args);
        assert!(result.success, "{args:?}: {}", result.stderr);
    }
    let check = harness.run_command(&["check", "--json"]);
    assert!(check.success, "{} {}", check.stdout, check.stderr);
    check.json()?;

    let listed = harness.run_command(&["targets", "list", "--json"]);
    assert!(listed.success, "{}", listed.stderr);
    let targets = listed.json()?;
    assert_eq!(targets[0]["domain"], "customer.example.invalid");
    assert!(targets[0]["provider"].is_null());
    assert_eq!(targets[1]["provider"], "cloudflare");
    assert_eq!(targets[2]["provider"], "openai");

    let test = harness.run_command(&[
        "test",
        "Customer.Example.Invalid.",
        "--json",
        "--verbose",
        "--no-dns",
    ]);
    assert!(test.success, "{}", test.stderr);
    let decision = test.json()?;
    assert_eq!(decision["domain"], "customer.example.invalid");
    assert_eq!(decision["would_proxy"], true);
    assert!(decision["routing_decision"]["target_provider"].is_null());
    assert_eq!(decision["active_proxy"]["id"], "customer-proxy");

    let toon = harness.run_command(&["targets", "list", "--format", "toon"]);
    assert!(toon.success, "{}", toon.stderr);
    assert_eq!(toon_rust::try_decode(&toon.stdout, None)?, targets.into());

    let before = std::fs::read(&harness.config_path)?;
    for domain in [
        "CUSTOMER.EXAMPLE.INVALID",
        "https://bad.invalid",
        "bad.invalid:443",
        "bad..invalid",
        "*.bad.invalid",
        "bad.invalid/path",
    ] {
        let result = harness.run_command(&["targets", "add", domain]);
        assert!(!result.success, "accepted {domain}");
        assert_eq!(
            std::fs::read(&harness.config_path)?,
            before,
            "failed mutation changed config"
        );
    }
    let removed = harness.run_command(&["targets", "remove", "CUSTOMER.EXAMPLE.INVALID."]);
    assert!(removed.success, "{}", removed.stderr);
    let direct = harness.run_command(&["test", "customer.example.invalid", "--json", "--no-dns"]);
    assert_eq!(direct.json()?["would_proxy"], false);
    Ok(())
}

/// Fault-injected executables prove CLI error classification and config
/// preservation. They do not establish kernel rule removal.
#[tokio::test]
async fn deactivate_reports_permission_failure_and_accepts_confirmed_absence() -> anyhow::Result<()>
{
    use std::os::unix::fs::PermissionsExt;
    let harness = TestHarness::new().await?;
    let added = harness.run_command(&["proxy", "add", "upstream", "http://127.0.0.1:12345"]);
    assert!(added.success, "{}", added.stderr);
    let activated = harness.run_command(&["activate", "upstream"]);
    assert!(activated.success, "{}", activated.stderr);
    let before = std::fs::read(&harness.config_path)?;
    let bin_dir = harness.temp_dir.path().join("fault-tools");
    std::fs::create_dir(&bin_dir)?;
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_rust_proxy"))
            .arg("deactivate")
            .env("RUST_PROXY_CONFIG", &harness.config_path)
            .env("RUST_PROXY_STATE_DIR", &harness.state_dir)
            .env("PATH", &bin_dir)
            .output()
    };
    for (name, message, code) in [
        (
            "iptables",
            "Could not fetch rule set generation id: Permission denied",
            4,
        ),
        ("ipset", "Permission denied", 1),
    ] {
        let path = bin_dir.join(name);
        std::fs::write(
            &path,
            format!("#!/bin/sh\nprintf '%s\\n' '{message}' >&2\nexit {code}\n"),
        )?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    let denied = run()?;
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("Permission denied"));
    assert!(!String::from_utf8_lossy(&denied.stdout).contains("deactivated"));
    assert_eq!(std::fs::read(&harness.config_path)?, before);
    for (name, message) in [
        ("iptables", "No chain/target/match by that name."),
        ("ipset", "The set with the given name does not exist"),
    ] {
        std::fs::write(
            bin_dir.join(name),
            format!("#!/bin/sh\nprintf '%s\\n' '{message}' >&2\nexit 1\n"),
        )?;
    }
    let absent = run()?;
    assert!(
        absent.status.success(),
        "{}",
        String::from_utf8_lossy(&absent.stderr)
    );
    assert!(String::from_utf8_lossy(&absent.stdout).contains("deactivated"));
    let config: toml::Value = toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
    assert!(config.get("active_proxy").is_none());
    assert_eq!(config["settings"]["routing_enabled"].as_bool(), Some(false));
    assert!(harness.run_command(&["activate", "upstream"]).success);
    let reactivated: toml::Value = toml::from_str(&std::fs::read_to_string(&harness.config_path)?)?;
    assert_eq!(
        reactivated["settings"]["routing_enabled"].as_bool(),
        Some(true)
    );
    Ok(())
}

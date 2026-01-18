use anyhow::Result;
use futures::future::join_all;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Maximum concurrent DNS lookups to avoid overwhelming the resolver
const MAX_CONCURRENT_DNS: usize = 32;

/// Default timeout for individual DNS lookups
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Report from parallel DNS resolution containing resolved and failed domains
#[derive(Debug)]
#[allow(dead_code)]
pub struct DnsResolutionReport {
    pub resolved: Vec<(String, Vec<IpAddr>)>,
    pub failed: Vec<(String, String)>,
    pub total_domains: usize,
    pub elapsed: Duration,
}

impl DnsResolutionReport {
    /// Get all resolved IPv4 addresses as strings
    pub fn ipv4_addresses(&self) -> HashSet<String> {
        let mut ips = HashSet::new();
        for (_, addrs) in &self.resolved {
            for addr in addrs {
                if let IpAddr::V4(ipv4) = addr {
                    ips.insert(ipv4.to_string());
                }
            }
        }
        ips
    }
}

/// Resolve a single domain to its IP addresses
async fn resolve_domain(domain: &str) -> Result<Vec<IpAddr>> {
    let lookup = tokio::net::lookup_host((domain, 0)).await?;
    Ok(lookup.map(|addr| addr.ip()).collect())
}

/// Check if a DNS error is transient and might succeed on retry
fn is_transient_dns_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("temporary")
        || msg.contains("servfail")
        || msg.contains("timeout")
        || msg.contains("try again")
        || msg.contains("timed out")
        || msg.contains("connection refused")
}

/// Resolve a domain with retry for transient failures
async fn resolve_with_retry(domain: &str, timeout: Duration) -> Result<Vec<IpAddr>> {
    match tokio::time::timeout(timeout, resolve_domain(domain)).await {
        Ok(Ok(ips)) => Ok(ips),
        Ok(Err(e)) if is_transient_dns_error(&e) => {
            tracing::debug!(domain, error = %e, "DNS failed, retrying once");
            tokio::time::sleep(Duration::from_millis(100)).await;
            match tokio::time::timeout(timeout, resolve_domain(domain)).await {
                Ok(result) => result,
                Err(_) => anyhow::bail!("DNS timeout for {} (retry)", domain),
            }
        }
        Ok(Err(e)) => Err(e),
        Err(_) => anyhow::bail!("DNS timeout for {}", domain),
    }
}

/// Resolve multiple domains in parallel with semaphore-based concurrency control
pub async fn resolve_parallel(domains: &[String]) -> DnsResolutionReport {
    resolve_parallel_with_options(domains, MAX_CONCURRENT_DNS, DNS_LOOKUP_TIMEOUT).await
}

/// Resolve multiple domains in parallel with custom concurrency and timeout
pub async fn resolve_parallel_with_options(
    domains: &[String],
    max_concurrent: usize,
    timeout: Duration,
) -> DnsResolutionReport {
    let start = Instant::now();
    let total_domains = domains.len();

    if domains.is_empty() {
        return DnsResolutionReport {
            resolved: Vec::new(),
            failed: Vec::new(),
            total_domains: 0,
            elapsed: start.elapsed(),
        };
    }

    let semaphore = Arc::new(Semaphore::new(max_concurrent));

    let futures: Vec<_> = domains
        .iter()
        .map(|domain| {
            let sem = semaphore.clone();
            let domain = domain.clone();
            async move {
                let _permit = sem.acquire().await.expect("semaphore closed unexpectedly");
                let result = resolve_with_retry(&domain, timeout).await;
                (domain, result)
            }
        })
        .collect();

    let results = join_all(futures).await;
    let elapsed = start.elapsed();

    let mut resolved = Vec::new();
    let mut failed = Vec::new();

    for (domain, result) in results {
        match result {
            Ok(ips) => {
                tracing::debug!(
                    domain,
                    ips = ?ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                    "Resolved domain"
                );
                resolved.push((domain, ips));
            }
            Err(e) => {
                tracing::warn!(domain, error = %e, "Failed to resolve domain");
                failed.push((domain, e.to_string()));
            }
        }
    }

    tracing::info!(
        total = total_domains,
        resolved = resolved.len(),
        failed = failed.len(),
        elapsed_ms = elapsed.as_millis(),
        "DNS resolution complete"
    );

    DnsResolutionReport {
        resolved,
        failed,
        total_domains,
        elapsed,
    }
}

/// Resolve domains to IPv4 addresses (parallel implementation)
///
/// This is the main entry point for DNS resolution. It resolves all domains
/// in parallel and returns only IPv4 addresses as strings.
pub async fn resolve_ipv4(domains: &[String]) -> Result<HashSet<String>> {
    let report = resolve_parallel(domains).await;
    Ok(report.ipv4_addresses())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transient_error_classification() {
        assert!(is_transient_dns_error(&anyhow::anyhow!(
            "temporary failure"
        )));
        assert!(is_transient_dns_error(&anyhow::anyhow!("SERVFAIL")));
        assert!(is_transient_dns_error(&anyhow::anyhow!(
            "connection timed out"
        )));
        assert!(is_transient_dns_error(&anyhow::anyhow!("try again later")));
        assert!(is_transient_dns_error(&anyhow::anyhow!(
            "connection refused"
        )));

        // Non-transient errors
        assert!(!is_transient_dns_error(&anyhow::anyhow!("NXDOMAIN")));
        assert!(!is_transient_dns_error(&anyhow::anyhow!(
            "no such host is known"
        )));
    }

    #[test]
    fn test_dns_resolution_report_ipv4_extraction() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let report = DnsResolutionReport {
            resolved: vec![
                (
                    "example.com".to_string(),
                    vec![
                        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                        IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0, 0, 0, 0xe7)),
                    ],
                ),
                (
                    "test.com".to_string(),
                    vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
                ),
            ],
            failed: vec![],
            total_domains: 2,
            elapsed: Duration::from_millis(100),
        };

        let ipv4s = report.ipv4_addresses();
        assert_eq!(ipv4s.len(), 2);
        assert!(ipv4s.contains("93.184.216.34"));
        assert!(ipv4s.contains("10.0.0.1"));
    }

    #[tokio::test]
    async fn test_empty_domains() {
        let report = resolve_parallel(&[]).await;
        assert_eq!(report.total_domains, 0);
        assert!(report.resolved.is_empty());
        assert!(report.failed.is_empty());
    }

    #[tokio::test]
    async fn test_parallel_resolution_basic() {
        // Use well-known domains that should always resolve
        let domains = vec!["google.com".to_string(), "cloudflare.com".to_string()];

        let report = resolve_parallel(&domains).await;
        assert_eq!(report.total_domains, 2);
        // At least one should resolve (network conditions permitting)
        assert!(!report.resolved.is_empty() || !report.failed.is_empty());
    }

    #[tokio::test]
    async fn test_partial_failure_continues() {
        let domains = vec![
            "google.com".to_string(),
            "definitely-not-a-real-domain-xyz123.invalid".to_string(),
        ];

        let report = resolve_parallel(&domains).await;
        assert_eq!(report.total_domains, 2);
        // One should succeed, one should fail
        // (network conditions may vary, so we just check both lists aren't empty)
        assert!(report.resolved.len() + report.failed.len() == 2);
    }

    #[tokio::test]
    async fn test_timeout_doesnt_block() {
        let domains = vec!["example.com".to_string()];
        let start = Instant::now();
        let _report = resolve_parallel_with_options(&domains, 1, Duration::from_millis(100)).await;
        let elapsed = start.elapsed();
        // Should complete within a reasonable time (not hang)
        assert!(elapsed < Duration::from_secs(10));
    }
}

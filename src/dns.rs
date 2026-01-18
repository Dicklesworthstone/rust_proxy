use anyhow::Result;
use std::collections::HashSet;
use std::net::IpAddr;

pub async fn resolve_ipv4(domains: &[String]) -> Result<HashSet<String>> {
    let mut ips = HashSet::new();
    for domain in domains {
        let lookup = tokio::net::lookup_host((domain.as_str(), 0)).await;
        match lookup {
            Ok(results) => {
                for addr in results {
                    if let IpAddr::V4(ipv4) = addr.ip() {
                        ips.insert(ipv4.to_string());
                    }
                }
            }
            Err(err) => {
                tracing::warn!("DNS lookup failed for {}: {}", domain, err);
            }
        }
    }
    Ok(ips)
}

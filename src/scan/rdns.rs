//! Reverse DNS (PTR) via the system resolver.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::task::spawn_blocking;
use tokio::time::timeout;

/// PTR lookup with a hard timeout. Results that merely echo the IP are dropped.
pub async fn lookup(ip: Ipv4Addr) -> Option<String> {
    let t = spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok());
    let name = timeout(Duration::from_millis(1500), t).await.ok()?.ok()??;
    let name = name.trim_end_matches('.');
    let name = name
        .strip_suffix(".local")
        .or_else(|| name.strip_suffix(".lan"))
        .unwrap_or(name);
    (!name.is_empty() && name.parse::<IpAddr>().is_err() && !name.starts_with(&ip.to_string()))
        .then(|| name.to_string())
}

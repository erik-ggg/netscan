use super::model::NetworkInfo;
use anyhow::{Context, Result, anyhow};
use std::net::Ipv4Addr;
use std::process::Command;

/// Largest subnet we are willing to sweep (a /24 around the local IP).
const MAX_SCAN_PREFIX: u8 = 24;

pub fn mask_from_prefix(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) }
}

pub fn fmt_mac(bytes: [u8; 6]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

pub fn detect() -> Result<NetworkInfo> {
    let iface = netdev::get_default_interface().map_err(|e| anyhow!("default interface: {e}"))?;
    let v4 = iface.ipv4.first().context("default interface has no IPv4 address")?;
    let local_ip = v4.addr();
    let prefix = v4.prefix_len();
    let gw = iface.gateway.as_ref();
    let mut gateway_ip = gw.and_then(|g| g.ipv4.first().copied());
    if gateway_ip.is_none() {
        gateway_ip = gateway_from_route();
    }
    Ok(build(
        iface.name.clone(),
        local_ip,
        prefix,
        iface.mac_addr.map(|m| fmt_mac(m.octets())),
        gateway_ip,
        gw.map(|g| fmt_mac(g.mac_addr.octets())).filter(|m| m != "00:00:00:00:00:00"),
    ))
}

fn gateway_from_route() -> Option<Ipv4Addr> {
    let out = Command::new("route").args(["-n", "get", "default"]).output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("gateway:").and_then(|v| v.trim().parse().ok()))
}

fn build(
    interface: String,
    local_ip: Ipv4Addr,
    prefix: u8,
    local_mac: Option<String>,
    gateway_ip: Option<Ipv4Addr>,
    gateway_mac: Option<String>,
) -> NetworkInfo {
    let scan_prefix = prefix.max(MAX_SCAN_PREFIX);
    let base = u32::from(local_ip) & mask_from_prefix(scan_prefix);
    NetworkInfo {
        interface,
        local_ip: local_ip.to_string(),
        local_mac,
        prefix,
        netmask: Ipv4Addr::from(mask_from_prefix(prefix)).to_string(),
        gateway_ip: gateway_ip.map(|g| g.to_string()),
        gateway_mac,
        subnet_cidr: format!("{}/{}", Ipv4Addr::from(base), scan_prefix),
    }
}

/// All usable host addresses of the (capped) scan subnet.
pub fn scan_hosts(info: &NetworkInfo) -> Vec<Ipv4Addr> {
    let Some((base, p)) = info.subnet_cidr.split_once('/') else { return vec![] };
    let (Ok(base), Ok(p)) = (base.parse::<Ipv4Addr>(), p.parse::<u8>()) else { return vec![] };
    let base = u32::from(base);
    let size = 1u64 << (32 - p as u32);
    if size < 4 {
        return vec![];
    }
    (1..size as u32 - 1).map(|i| Ipv4Addr::from(base + i)).collect()
}

pub fn in_subnet(info: &NetworkInfo, ip: Ipv4Addr) -> bool {
    let Some((base, p)) = info.subnet_cidr.split_once('/') else { return false };
    let (Ok(base), Ok(p)) = (base.parse::<Ipv4Addr>(), p.parse::<u8>()) else { return false };
    u32::from(ip) & mask_from_prefix(p) == u32::from(base)
}

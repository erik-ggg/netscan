//! Network scan pipeline: net -> ping -> arp -> merge.

pub mod arp;
pub mod classify;
pub mod inet;
pub mod mdns;
pub mod model;
pub mod net;
pub mod oui;
pub mod ping;
pub mod rdns;
pub mod vendor;

use anyhow::Result;
use model::*;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::timeout;

pub async fn scan(progress: impl Fn(ScanProgress) + Send + Sync + 'static) -> Result<ScanResult> {
    let phase = |name: &str, pct: u8| progress(ScanProgress::Phase { name: name.into(), pct });
    let log = |m: String| progress(ScanProgress::Log(m));

    phase("Detecting network", 0);
    let mut network = net::detect()?;
    log(format!(
        "IF {} // {} // GW {}",
        network.interface,
        network.local_ip,
        network.gateway_ip.as_deref().unwrap_or("NONE")
    ));
    log(format!("SUBNET {}", network.subnet_cidr));

    // mDNS and public-IP lookups are independent of the sweep: start them now.
    let mdns_task = tokio::spawn(timeout(Duration::from_secs(9), mdns::discover(Duration::from_millis(4500))));
    let inet_task = tokio::spawn(timeout(Duration::from_secs(6), inet::fetch()));

    let hosts = net::scan_hosts(&network);
    log(format!("PROBING {} TARGETS // ICMP + TCP + UDP", hosts.len()));
    let alive = ping::sweep(hosts, |pct| phase("Sweeping subnet", 5 + (pct as u32 * 35 / 100) as u8)).await;
    log(format!("{} HOSTS RESPONDED", alive.len()));

    phase("Reading ARP table", 40);
    let arp = timeout(Duration::from_secs(5), arp::table(&network.interface)).await.unwrap_or_default();
    let arp: BTreeMap<Ipv4Addr, String> =
        arp.into_iter().filter(|(ip, _)| net::in_subnet(&network, *ip)).collect();
    log(format!("ARP CACHE // {} ENTRIES", arp.len()));

    let local_ip: Ipv4Addr = network.local_ip.parse()?;
    let gateway_ip: Option<Ipv4Addr> = network.gateway_ip.as_ref().and_then(|g| g.parse().ok());
    if network.gateway_mac.is_none() {
        network.gateway_mac = gateway_ip.and_then(|g| arp.get(&g).cloned());
    }

    let mut ips: Vec<Ipv4Addr> = alive.into_iter().chain(arp.keys().copied()).collect();
    ips.push(local_ip);
    ips.extend(gateway_ip);
    ips.sort();
    ips.dedup();

    let mut devices: Vec<Device> = ips
        .iter()
        .map(|&ip| {
            let is_self = ip == local_ip;
            let mac = if is_self { network.local_mac.clone() } else { arp.get(&ip).cloned() };
            Device {
                ip: ip.to_string(),
                mac_randomized: mac.as_deref().is_some_and(arp::is_randomized),
                vendor: mac.as_deref().and_then(oui::lookup),
                mac,
                is_self,
                is_gateway: Some(ip) == gateway_ip,
                hostname: None,
                model: None,
                services: vec![],
                kind: DeviceKind::Unknown,
            }
        })
        .collect();

    phase("Enriching (mDNS, DNS, Internet)", 45);
    let rdns = async {
        let rs = futures::future::join_all(ips.iter().map(|&ip| async move { (ip, rdns::lookup(ip).await) })).await;
        rs.into_iter().filter_map(|(ip, n)| Some((ip, n?))).collect::<BTreeMap<_, _>>()
    };
    let (found, rdns, inet) = tokio::join!(
        async { mdns_task.await.ok().and_then(Result::ok).unwrap_or_default() },
        async { timeout(Duration::from_secs(4), rdns).await.unwrap_or_default() },
        async { inet_task.await.ok().and_then(Result::ok).unwrap_or_default() },
    );
    phase("Classifying", 90);
    log(format!("MDNS {} HOSTS // RDNS {} NAMES", found.len(), rdns.len()));
    log(format!("WAN {}", inet.public_ip.as_deref().unwrap_or("OFFLINE")));

    for ip in found.keys() {
        if !net::in_subnet(&network, *ip) || ip.octets()[3] == 255 || ip.octets()[3] == 0 {
            continue;
        }
        if !ips.contains(ip) {
            devices.push(Device {
                ip: ip.to_string(),
                mac: None,
                is_self: false,
                is_gateway: false,
                hostname: None,
                vendor: None,
                model: None,
                services: vec![],
                kind: DeviceKind::Unknown,
                mac_randomized: false,
            });
        }
    }
    devices.sort_by_key(|d| d.ip.parse::<Ipv4Addr>().ok());
    for d in &mut devices {
        let Ok(ip) = d.ip.parse::<Ipv4Addr>() else { continue };
        let f = found.get(&ip);
        d.hostname = f
            .and_then(|f| f.name.clone())
            .or_else(|| rdns.get(&ip).cloned())
            .or_else(|| f.and_then(|f| f.host.clone()));
        if let Some(f) = f {
            d.services = f.services.iter().cloned().collect();
            d.model = f.model.clone();
        }
        d.kind = classify::classify(d);
    }

    phase("Done", 100);
    Ok(ScanResult { network, public_ip: inet.public_ip, isp: inet.isp, devices })
}

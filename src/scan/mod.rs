//! Network scan pipeline: net -> ping -> arp -> merge.

pub mod arp;
pub mod beacon;
pub mod classify;
pub mod inet;
pub mod intel;
pub mod mdns;
pub mod model;
pub mod net;
pub mod os;
pub mod oui;
pub mod ping;
pub mod rdns;
pub mod ssdp;
pub mod textutil;
pub mod vendor;

use anyhow::Result;
use model::*;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::timeout;

pub async fn scan(progress: impl Fn(ScanProgress) + Send + Sync + 'static) -> Result<ScanResult> {
    let phase = |name: &str, pct: u8| {
        progress(ScanProgress::Phase {
            name: name.into(),
            pct,
        })
    };
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
    let mdns_task = tokio::spawn(timeout(
        Duration::from_secs(9),
        mdns::discover(Duration::from_millis(4500)),
    ));
    let ssdp_task = tokio::spawn(timeout(
        Duration::from_secs(4),
        ssdp::discover(Duration::from_millis(2500)),
    ));
    let inet_task = tokio::spawn(timeout(Duration::from_secs(6), inet::fetch()));

    let hosts = net::scan_hosts(&network);
    log(format!(
        "PROBING {} TARGETS // ICMP + TCP + UDP",
        hosts.len()
    ));
    let alive = ping::sweep(hosts, |pct| {
        phase("Sweeping subnet", 5 + (pct as u32 * 35 / 100) as u8)
    })
    .await;
    log(format!("{} HOSTS RESPONDED", alive.len()));

    phase("Reading ARP table", 40);
    let arp = timeout(Duration::from_secs(5), arp::table(&network.interface))
        .await
        .unwrap_or_default();
    let arp: BTreeMap<Ipv4Addr, String> = arp
        .into_iter()
        .filter(|(ip, _)| net::in_subnet(&network, *ip))
        .collect();
    log(format!("ARP CACHE // {} ENTRIES", arp.len()));

    let local_ip: Ipv4Addr = network.local_ip.parse()?;
    let gateway_ip: Option<Ipv4Addr> = network.gateway_ip.as_ref().and_then(|g| g.parse().ok());
    if network.gateway_mac.is_none() {
        network.gateway_mac = gateway_ip.and_then(|g| arp.get(&g).cloned());
    }

    // BEACON: TV-port probes overlap the mDNS wait, so they add no wall time.
    let cands = beacon::candidates(&alive, &arp, local_ip, gateway_ip);
    let n_cands = cands.len();
    let beacon_task = tokio::spawn(timeout(
        Duration::from_millis(1800),
        beacon::probe_all(cands, Duration::from_millis(1700)),
    ));

    let mut ips: Vec<Ipv4Addr> = alive.keys().copied().chain(arp.keys().copied()).collect();
    ips.push(local_ip);
    ips.extend(gateway_ip);
    ips.sort();
    ips.dedup();

    let mut devices: Vec<Device> = ips
        .iter()
        .map(|&ip| {
            let is_self = ip == local_ip;
            let mac = if is_self {
                network.local_mac.clone()
            } else {
                arp.get(&ip).cloned()
            };
            Device {
                ip: ip.to_string(),
                mac_randomized: mac.as_deref().is_some_and(arp::is_randomized),
                vendor: mac.as_deref().and_then(oui::lookup),
                mac,
                is_self,
                is_gateway: Some(ip) == gateway_ip,
                rtt_ms: alive
                    .get(&ip)
                    .and_then(|p| p.rtt)
                    .map(|d| d.as_secs_f32() * 1000.0),
                ttl: alive.get(&ip).and_then(|p| p.ttl),
                ..Default::default()
            }
        })
        .collect();

    phase("Enriching (mDNS, DNS, Internet)", 45);
    let rdns = async {
        let rs = futures::future::join_all(
            ips.iter()
                .map(|&ip| async move { (ip, rdns::lookup(ip).await) }),
        )
        .await;
        rs.into_iter()
            .filter_map(|(ip, n)| Some((ip, n?)))
            .collect::<BTreeMap<_, _>>()
    };
    let ssdp_hits = async {
        let hits = ssdp_task
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(800))
            .timeout(Duration::from_millis(1500))
            .build()
            .ok();
        let hits: BTreeMap<Ipv4Addr, ssdp::SsdpHit> = hits
            .into_iter()
            .filter(|(ip, _)| net::in_subnet(&network, *ip))
            .collect();
        let mut desc: BTreeMap<Ipv4Addr, UpnpInfo> = BTreeMap::new();
        if let Some(client) = client {
            let fetch = futures::future::join_all(hits.iter().filter_map(|(ip, h)| {
                let loc = h.location.clone()?;
                let client = client.clone();
                let ip = *ip;
                Some(async move { (ip, ssdp::fetch_description(&client, ip, &loc).await) })
            }));
            if let Ok(rs) = timeout(Duration::from_millis(2500), fetch).await {
                desc = rs
                    .into_iter()
                    .filter_map(|(ip, u)| Some((ip, u?)))
                    .collect();
            }
        }
        (hits, desc)
    };
    let (found, rdns, inet, (ssdp_found, mut upnp), beacons) = tokio::join!(
        async {
            mdns_task
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default()
        },
        async {
            timeout(Duration::from_secs(4), rdns)
                .await
                .unwrap_or_default()
        },
        async {
            inet_task
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default()
        },
        ssdp_hits,
        async {
            beacon_task
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default()
        },
    );
    let beacon::BeaconResult {
        mut beacons,
        upnp: mut dial_upnp,
    } = beacons;
    log(format!(
        "BEACON {n_cands} HOSTS // {} TV PORTS // {} IDENTS",
        beacons.values().map(|b| b.open.len()).sum::<usize>(),
        beacons.values().map(|b| b.idents.len()).sum::<usize>()
    ));
    for (ip, h) in &ssdp_found {
        if let Some(u) = upnp.get_mut(ip) {
            u.server = h.server.clone();
        }
    }
    log(format!(
        "SSDP {} DEVICES // UPNP {} DESCRIPTORS",
        ssdp_found.len(),
        upnp.len()
    ));
    phase("Classifying", 90);
    log(format!(
        "MDNS {} HOSTS // RDNS {} NAMES",
        found.len(),
        rdns.len()
    ));
    log(format!(
        "WAN {}",
        inet.public_ip.as_deref().unwrap_or("OFFLINE")
    ));

    for ip in found.keys() {
        if !net::in_subnet(&network, *ip) || ip.octets()[3] == 255 || ip.octets()[3] == 0 {
            continue;
        }
        if !ips.contains(ip) {
            devices.push(Device {
                ip: ip.to_string(),
                ..Default::default()
            });
        }
    }
    devices.sort_by_key(|d| d.ip.parse::<Ipv4Addr>().ok());
    for d in &mut devices {
        let Ok(ip) = d.ip.parse::<Ipv4Addr>() else {
            continue;
        };
        let f = found.get(&ip);
        d.hostname = f
            .and_then(|f| f.name.clone())
            .or_else(|| rdns.get(&ip).cloned())
            .or_else(|| f.and_then(|f| f.host.clone()));
        if let Some(f) = f {
            d.services = f.services.iter().cloned().collect();
            d.model = f.model.clone();
            d.txt = f.txt.clone();
            d.svc_ports = f.ports.clone();
        }
        d.upnp = upnp.remove(&ip).or_else(|| dial_upnp.remove(&ip));
        d.beacon = beacons.remove(&ip);
        let c = classify::assess(d, None);
        d.kind = c.kind;
        d.class = Some(c);
    }

    phase("Done", 100);
    Ok(ScanResult {
        network,
        public_ip: inet.public_ip,
        isp: inet.isp,
        devices,
    })
}

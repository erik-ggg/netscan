//! BEACON: cheap TV/streamer probes on candidate hosts. TCP connects to the
//! well-known smart-TV control ports, then the public, unauthenticated identity
//! endpoints of whatever answered (Cast eureka_info, Roku ECP, Samsung, Philips)
//! plus a unicast DIAL M-SEARCH. Read-only: no pairing, no writes.

use super::model::{Beacon, Ident, UpnpInfo};
use super::ping::HostProbe;
use super::{ssdp, textutil::clean};
use futures::StreamExt;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant as TInstant, timeout, timeout_at};

pub const TV_PORTS: [u16; 16] = [
    5555, 6466, 6467, 8008, 8009, 8443, 3000, 3001, 8001, 8002, 7000, 8060, 1925, 1926, 9922, 55000,
];
const MAX_HOSTS: usize = 48;
const HOST_CONCURRENCY: usize = 12;
const CONNECT_MS: u64 = 450;
const BODY_CAP: usize = 32 * 1024;
const DIAL_ST: &str = "urn:dial-multiscreen-org:service:dial:1";

/// What to GET once a port is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetch {
    /// Connect only.
    None,
    Eureka {
        tls: bool,
    },
    Roku,
    Samsung {
        tls: bool,
    },
    Philips {
        tls: bool,
    },
}

/// The port table: every TV port, with its identity fetch (if any).
pub fn plan() -> Vec<(u16, Fetch)> {
    TV_PORTS
        .iter()
        .map(|&p| {
            let f = match p {
                8008 => Fetch::Eureka { tls: false },
                8443 => Fetch::Eureka { tls: true },
                8060 => Fetch::Roku,
                8001 => Fetch::Samsung { tls: false },
                8002 => Fetch::Samsung { tls: true },
                1925 => Fetch::Philips { tls: false },
                1926 => Fetch::Philips { tls: true },
                _ => Fetch::None,
            };
            (p, f)
        })
        .collect()
}

#[derive(Debug, Default)]
pub struct BeaconResult {
    pub beacons: BTreeMap<Ipv4Addr, Beacon>,
    /// UPnP descriptors learned from DIAL replies.
    pub upnp: BTreeMap<Ipv4Addr, UpnpInfo>,
}

/// Hosts worth probing: every ARP/alive IP except self and the gateway whose
/// TTL is 64 or unknown (TVs/boxes are Linux-like; 255 = RTOS, 128 = Windows).
pub fn candidates(
    alive: &HashMap<Ipv4Addr, HostProbe>,
    arp: &BTreeMap<Ipv4Addr, String>,
    local: Ipv4Addr,
    gw: Option<Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    let mut v: Vec<Ipv4Addr> = alive
        .keys()
        .chain(arp.keys())
        .copied()
        .filter(|&ip| ip != local && Some(ip) != gw)
        .filter(|ip| matches!(alive.get(ip).and_then(|p| p.ttl), None | Some(64)))
        .collect();
    v.sort();
    v.dedup();
    v.truncate(MAX_HOSTS);
    v
}

/// Probe all hosts and send DIAL searches, within `cap`. Partial results are kept.
pub async fn probe_all(hosts: Vec<Ipv4Addr>, cap: Duration) -> BeaconResult {
    let deadline = TInstant::now() + cap;
    let Ok(client) = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // only ever used for 8443/8002/1926
        .danger_accept_invalid_hostnames(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(500))
        .timeout(Duration::from_millis(900))
        .build()
    else {
        return BeaconResult::default();
    };
    let table = plan();
    let tcp = async {
        let mut out: BTreeMap<Ipv4Addr, Beacon> = BTreeMap::new();
        let mut s = futures::stream::iter(hosts.clone())
            .map(|ip| {
                let (c, t) = (client.clone(), table.clone());
                async move { (ip, probe_host_ports(&c, ip, &t).await) }
            })
            .buffer_unordered(HOST_CONCURRENCY);
        while let Ok(Some((ip, b))) = timeout_at(deadline, s.next()).await {
            if !b.open.is_empty() || !b.idents.is_empty() {
                out.insert(ip, b);
            }
        }
        out
    };
    let (mut beacons, dial) = tokio::join!(tcp, dial_unicast(&client, &hosts, deadline));
    let mut upnp = BTreeMap::new();
    for (ip, (ident, info)) in dial {
        let b = beacons.entry(ip).or_default();
        b.idents.push(ident);
        upnp.insert(ip, info);
    }
    BeaconResult { beacons, upnp }
}

/// Connect to every port in `plan` concurrently, then run the identity fetches
/// of the open ones. One ident per source (first in table order wins).
pub async fn probe_host_ports(
    client: &reqwest::Client,
    ip: Ipv4Addr,
    plan: &[(u16, Fetch)],
) -> Beacon {
    let t0 = Instant::now();
    let checks = plan.iter().map(|&(port, fetch)| async move {
        let ok = matches!(
            timeout(
                Duration::from_millis(CONNECT_MS),
                TcpStream::connect(SocketAddr::new(IpAddr::V4(ip), port)),
            )
            .await,
            Ok(Ok(_))
        );
        (port, fetch, ok)
    });
    let open: Vec<(u16, Fetch)> = futures::future::join_all(checks)
        .await
        .into_iter()
        .filter(|r| r.2)
        .map(|r| (r.0, r.1))
        .collect();
    let fetches = open
        .iter()
        .filter(|(_, f)| *f != Fetch::None)
        .map(|&(port, f)| fetch_ident(client, ip, port, f));
    let mut idents: Vec<Ident> = Vec::new();
    for i in futures::future::join_all(fetches)
        .await
        .into_iter()
        .flatten()
    {
        if !idents.iter().any(|e| e.source == i.source) {
            idents.push(i);
        }
    }
    let mut open: Vec<u16> = open.into_iter().map(|(p, _)| p).collect();
    open.sort_unstable();
    Beacon {
        open,
        idents,
        elapsed_ms: t0.elapsed().as_millis() as u32,
    }
}

async fn fetch_ident(client: &reqwest::Client, ip: Ipv4Addr, port: u16, f: Fetch) -> Option<Ident> {
    let s = |tls: bool| if tls { "https" } else { "http" };
    match f {
        Fetch::None => None,
        Fetch::Eureka { tls } => {
            let u = format!(
                "{}://{ip}:{port}/setup/eureka_info?params=name,device_info",
                s(tls)
            );
            parse_eureka(&get_body(client, &u).await?)
        }
        Fetch::Roku => {
            parse_roku(&get_body(client, &format!("http://{ip}:{port}/query/device-info")).await?)
        }
        Fetch::Samsung { tls } => {
            parse_samsung(&get_body(client, &format!("{}://{ip}:{port}/api/v2/", s(tls))).await?)
        }
        Fetch::Philips { tls } => {
            parse_philips(&get_body(client, &format!("{}://{ip}:{port}/6/system", s(tls))).await?)
        }
    }
}

/// GET with a 32 KiB body cap; `None` unless 2xx. Redirects are disabled on the client.
async fn get_body(client: &reqwest::Client, url: &str) -> Option<String> {
    let mut resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let mut body = Vec::new();
    while let Ok(Some(c)) = resp.chunk().await {
        body.extend_from_slice(&c);
        if body.len() > BODY_CAP {
            body.truncate(BODY_CAP);
            break;
        }
    }
    Some(String::from_utf8_lossy(&body).into_owned())
}

fn jstr(v: &serde_json::Value, key: &str) -> Option<String> {
    let s = clean(v.get(key)?.as_str()?);
    (!s.is_empty()).then_some(s)
}

/// Cast `eureka_info`: `{"name", "device_info": {"model_name", "manufacturer"}}`,
/// older firmware puts model/manufacturer at the top level.
pub fn parse_eureka(json: &str) -> Option<Ident> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let di = v.get("device_info").unwrap_or(&v);
    let name = jstr(&v, "name");
    let model = jstr(di, "model_name").or_else(|| jstr(&v, "model_name"));
    let maker = jstr(di, "manufacturer").or_else(|| jstr(&v, "manufacturer"));
    if name.is_none() && model.is_none() && maker.is_none() {
        return None;
    }
    Some(Ident {
        source: "CAST".into(),
        name,
        model,
        maker,
        ..Default::default()
    })
}

/// Roku ECP `device-info` XML.
pub fn parse_roku(xml: &str) -> Option<Ident> {
    use super::textutil::xml_tag;
    let model = xml_tag(xml, "model-name");
    let name = xml_tag(xml, "user-device-name").or_else(|| xml_tag(xml, "friendly-device-name"));
    let is_tv = xml_tag(xml, "is-tv").map(|s| s.eq_ignore_ascii_case("true"));
    if model.is_none() && name.is_none() && is_tv.is_none() {
        return None;
    }
    Some(Ident {
        source: "ROKU-ECP".into(),
        name,
        model,
        maker: xml_tag(xml, "vendor-name"),
        os: None,
        is_tv,
    })
}

/// Samsung `/api/v2/`: `{"device": {"name", "modelName", "OS", "type"}}` or top-level fields.
pub fn parse_samsung(json: &str) -> Option<Ident> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let d = v.get("device").unwrap_or(&v);
    let name = jstr(d, "name").or_else(|| jstr(&v, "name"));
    let model = jstr(d, "modelName");
    let os = jstr(d, "OS");
    let ty = jstr(d, "type").or_else(|| jstr(&v, "type"));
    if name.is_none() && model.is_none() && ty.is_none() && os.is_none() {
        return None;
    }
    Some(Ident {
        source: "SAMSUNG-API".into(),
        name,
        model,
        maker: Some("Samsung".into()),
        os,
        is_tv: ty
            .as_deref()
            .map(|t| t.to_ascii_lowercase().contains("smarttv"))
            .filter(|&b| b),
    })
}

/// Philips JointSpace `/6/system`.
pub fn parse_philips(json: &str) -> Option<Ident> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let name = jstr(&v, "name");
    let model = jstr(&v, "model");
    if name.is_none()
        && model.is_none()
        && v.get("api_version").is_none()
        && v.get("softwareversion").is_none()
    {
        return None;
    }
    Some(Ident {
        source: "PHILIPS-JS".into(),
        name,
        model,
        maker: Some("Philips".into()),
        ..Default::default()
    })
}

/// Unicast DIAL M-SEARCH to each host on port 1900. Only replies from the
/// searched IP whose LOCATION host equals that IP are followed.
pub async fn dial_unicast(
    client: &reqwest::Client,
    hosts: &[Ipv4Addr],
    deadline: TInstant,
) -> BTreeMap<Ipv4Addr, (Ident, UpnpInfo)> {
    let mut out = BTreeMap::new();
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        return out;
    };
    for &ip in hosts {
        let _ = ssdp::unicast_search(&sock, ip, DIAL_ST, 1).await;
    }
    let window = (TInstant::now() + Duration::from_millis(800)).min(deadline);
    let mut hits: BTreeMap<Ipv4Addr, ssdp::SsdpHit> = BTreeMap::new();
    let mut buf = [0u8; 2048];
    while let Ok(Ok((n, from))) = timeout_at(window, sock.recv_from(&mut buf)).await {
        let IpAddr::V4(ip) = from.ip() else { continue };
        if !hosts.contains(&ip) || hits.contains_key(&ip) {
            continue;
        }
        if let Some(h) = ssdp::parse_response(&String::from_utf8_lossy(&buf[..n]))
            && h.location.is_some()
        {
            hits.insert(ip, h);
        }
    }
    let fetch = futures::future::join_all(hits.into_iter().map(|(ip, h)| async move {
        let loc = h.location.clone()?;
        let mut info = ssdp::fetch_description(client, ip, &loc).await?;
        info.server = h.server;
        Some((ip, info))
    }));
    if let Ok(rs) = timeout_at(deadline, fetch).await {
        for (ip, info) in rs.into_iter().flatten() {
            let ident = Ident {
                source: "DIAL".into(),
                name: info.friendly_name.clone(),
                model: info.model_name.clone(),
                maker: info.manufacturer.clone(),
                ..Default::default()
            };
            out.insert(ip, (ident, info));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn eureka_new_and_old() {
        let new = r#"{"name":"Living Room TV","device_info":{"model_name":"TCL Google TV","manufacturer":"TCL"}}"#;
        let i = parse_eureka(new).unwrap();
        assert_eq!(i.source, "CAST");
        assert_eq!(i.name.as_deref(), Some("Living Room TV"));
        assert_eq!(i.model.as_deref(), Some("TCL Google TV"));
        assert_eq!(i.maker.as_deref(), Some("TCL"));
        let old = r#"{"name":"Kitchen","model_name":"Chromecast","manufacturer":"Google Inc."}"#;
        let i = parse_eureka(old).unwrap();
        assert_eq!(i.model.as_deref(), Some("Chromecast"));
        assert_eq!(i.maker.as_deref(), Some("Google Inc."));
        assert!(parse_eureka("{}").is_none());
        assert!(parse_eureka("<html>").is_none());
    }

    #[test]
    fn roku_xml() {
        let x = "<device-info><vendor-name>TCL</vendor-name><model-name>6-Series</model-name><user-device-name>Den</user-device-name><is-tv>true</is-tv></device-info>";
        let i = parse_roku(x).unwrap();
        assert_eq!(i.source, "ROKU-ECP");
        assert_eq!(i.model.as_deref(), Some("6-Series"));
        assert_eq!(i.maker.as_deref(), Some("TCL"));
        assert_eq!(i.name.as_deref(), Some("Den"));
        assert_eq!(i.is_tv, Some(true));
        assert_eq!(
            parse_roku(
                "<device-info><model-name>Ultra</model-name><is-tv>false</is-tv></device-info>"
            )
            .unwrap()
            .is_tv,
            Some(false)
        );
        assert!(parse_roku("nope").is_none());
    }

    #[test]
    fn samsung_json() {
        let j = r#"{"device":{"name":"[TV] Samsung 7 Series","modelName":"UE55NU7400","OS":"Tizen","type":"Samsung SmartTV"},"id":"uuid:1","name":"[TV] Samsung 7 Series"}"#;
        let i = parse_samsung(j).unwrap();
        assert_eq!(i.source, "SAMSUNG-API");
        assert_eq!(i.model.as_deref(), Some("UE55NU7400"));
        assert_eq!(i.os.as_deref(), Some("Tizen"));
        assert_eq!(i.is_tv, Some(true));
        assert!(parse_samsung("[]").is_none());
    }

    #[test]
    fn philips_json() {
        let i = parse_philips(r#"{"name":"55PUS7304","model":"TPM191E_R.101.001","country":"Spain","api_version":{"Major":6}}"#).unwrap();
        assert_eq!(i.source, "PHILIPS-JS");
        assert_eq!(i.name.as_deref(), Some("55PUS7304"));
        assert!(parse_philips(r#"{"softwareversion":"1.2"}"#).is_some());
        assert!(parse_philips(r#"{"x":1}"#).is_none());
    }

    #[test]
    fn candidates_filter() {
        let ip = |n| Ipv4Addr::new(192, 168, 1, n);
        let mut alive = HashMap::new();
        let p = |ttl| HostProbe { rtt: None, ttl };
        alive.insert(ip(2), p(Some(64)));
        alive.insert(ip(3), p(Some(255)));
        alive.insert(ip(4), p(Some(128)));
        alive.insert(ip(5), p(None));
        alive.insert(ip(1), p(Some(64))); // gateway
        alive.insert(ip(10), p(Some(64))); // self
        let mut arp = BTreeMap::new();
        arp.insert(ip(6), "aa:bb:cc:dd:ee:ff".to_string()); // ARP only: TTL unknown
        arp.insert(ip(2), "aa:bb:cc:dd:ee:01".to_string());
        let c = candidates(&alive, &arp, ip(10), Some(ip(1)));
        assert_eq!(c, vec![ip(2), ip(5), ip(6)]);
        let many: BTreeMap<Ipv4Addr, String> = (1..=200u8)
            .map(|n| (Ipv4Addr::new(10, 0, 0, n), String::new()))
            .collect();
        assert_eq!(
            candidates(&HashMap::new(), &many, Ipv4Addr::new(10, 0, 0, 250), None).len(),
            MAX_HOSTS
        );
    }

    #[tokio::test]
    async fn loopback_eureka_and_fallback_dedupe() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b).await;
                let body = r#"{"name":"Den","device_info":{"model_name":"Chromecast","manufacturer":"Google Inc."}}"#;
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });
        let c = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        // A closed port next to the open one, plus a second Cast entry that dedupes.
        let closed = {
            let t = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            t.local_addr().unwrap().port()
        };
        let b = probe_host_ports(
            &c,
            Ipv4Addr::LOCALHOST,
            &[
                (closed, Fetch::None),
                (port, Fetch::Eureka { tls: false }),
                (port, Fetch::Eureka { tls: false }),
            ],
        )
        .await;
        assert_eq!(b.open, vec![port, port]);
        assert_eq!(b.idents.len(), 1);
        assert_eq!(b.idents[0].model.as_deref(), Some("Chromecast"));
    }

    #[test]
    fn plan_covers_tv_ports() {
        let p = plan();
        assert_eq!(p.len(), TV_PORTS.len());
        assert!(p.contains(&(8060, Fetch::Roku)));
    }
}

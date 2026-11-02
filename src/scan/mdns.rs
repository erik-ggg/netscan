//! mDNS / Bonjour discovery: service types, friendly names and hardware models.

use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::timeout;

const META: &str = "_services._dns-sd._udp.local.";
const TYPES: &[&str] = &[
    "_airplay._tcp",
    "_raop._tcp",
    "_googlecast._tcp",
    "_hap._tcp",
    "_homekit._tcp",
    "_ipp._tcp",
    "_ipps._tcp",
    "_printer._tcp",
    "_pdl-datastream._tcp",
    "_companion-link._tcp",
    "_device-info._tcp",
    "_spotify-connect._tcp",
    "_sonos._tcp",
    "_smb._tcp",
    "_afpovertcp._tcp",
    "_ssh._tcp",
    "_sftp-ssh._tcp",
    "_rdlink._tcp",
    "_workstation._tcp",
    "_http._tcp",
    "_amzn-wplay._tcp",
    "_matter._tcp",
    "_matterc._udp",
    "_meshcop._udp",
    "_hue._tcp",
    "_androidtvremote2._tcp",
    "_nvstream._tcp",
    "_mqtt._tcp",
    "_display._tcp",
    "_adb-tls-connect._tcp",
    "_adb-tls-pairing._tcp",
    "_androidtvremote._tcp",
    "_amzn-alexa._tcp",
];
/// Types whose instance name is usually the user-facing device name, best first.
const NAME_TYPES: &[&str] = &[
    "_companion-link",
    "_airplay",
    "_raop",
    "_googlecast",
    "_sonos",
    "_hap",
    "_ipp",
    "_printer",
];

#[derive(Debug, Default, Clone)]
pub struct Found {
    pub services: BTreeSet<String>,
    pub name: Option<String>,
    pub host: Option<String>,
    pub model: Option<String>,
    /// Selected TXT keys (`md`, `fn`, ...), cleaned and capped.
    pub txt: BTreeMap<String, String>,
    /// Service short type (`_adb-tls-connect`) -> port.
    pub ports: BTreeMap<String, u16>,
}

/// TXT keys worth keeping.
const TXT_KEYS: &[&str] = &[
    "md",
    "fn",
    "model",
    "am",
    "rpMd",
    "manufacturer",
    "ty",
    "usb_MDL",
    "ca",
];

/// Pure helper: pull the interesting TXT keys through `get`, cleaned and capped at 80 chars.
fn capture_txt(get: impl Fn(&str) -> Option<String>) -> BTreeMap<String, String> {
    TXT_KEYS
        .iter()
        .filter_map(|k| {
            let v = crate::scan::textutil::clean(&get(k)?);
            let v: String = v.chars().take(80).collect();
            (!v.is_empty()).then(|| (k.to_string(), v))
        })
        .collect()
}

/// Type without the `._tcp` / `._udp` transport suffix.
fn bare_type(ty: &str) -> &str {
    ty.strip_suffix("._tcp")
        .or_else(|| ty.strip_suffix("._udp"))
        .unwrap_or(ty)
}

fn short_type(ty: &str) -> String {
    ty.trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}

/// Browse for `dur` and return what was found per IPv4 address.
pub async fn discover(dur: Duration) -> BTreeMap<Ipv4Addr, Found> {
    let out: Arc<Mutex<BTreeMap<Ipv4Addr, (Found, usize)>>> = Default::default();
    let Ok(daemon) = ServiceDaemon::new() else {
        return BTreeMap::new();
    };
    let known: Arc<Mutex<BTreeSet<String>>> = Default::default();

    let mut tasks = Vec::new();
    let start = |ty: String, tasks: &mut Vec<_>| {
        if !known.lock().unwrap().insert(ty.clone()) {
            return;
        }
        let Ok(rx) = daemon.browse(&ty) else { return };
        let (out, known, d, is_meta) = (out.clone(), known.clone(), daemon.clone(), ty == META);
        tasks.push(tokio::spawn(async move {
            while let Ok(ev) = rx.recv_async().await {
                match ev {
                    ServiceEvent::ServiceFound(_, name) if is_meta => {
                        // Meta-query answers carry the discovered type as the "instance".
                        if known.lock().unwrap().insert(name.clone()) {
                            // Receiver is drained by a nested task below.
                            if let Ok(rx2) = d.browse(&name) {
                                let out = out.clone();
                                tokio::spawn(async move {
                                    while let Ok(ev) = rx2.recv_async().await {
                                        record(&out, ev);
                                    }
                                });
                            }
                        }
                    }
                    ev => record(&out, ev),
                }
            }
        }));
    };
    start(META.into(), &mut tasks);
    for t in TYPES {
        start(format!("{t}.local."), &mut tasks);
    }
    tokio::time::sleep(dur).await;
    // Shutdown closes the channels so the tasks end.
    let _ = daemon.shutdown();
    let _ = timeout(Duration::from_millis(500), futures::future::join_all(tasks)).await;
    let m = out.lock().unwrap();
    m.iter().map(|(ip, (f, _))| (*ip, f.clone())).collect()
}

fn record(out: &Mutex<BTreeMap<Ipv4Addr, (Found, usize)>>, ev: ServiceEvent) {
    let ServiceEvent::ServiceResolved(info) = ev else {
        return;
    };
    let ty = short_type(&info.ty_domain);
    let instance = info
        .fullname
        .strip_suffix(&format!(".{}", info.ty_domain))
        .unwrap_or(&info.fullname)
        .to_string();
    let host = info
        .host
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string();
    let prop = |k: &str| {
        info.txt_properties
            .get_property_val_str(k)
            .filter(|v| !v.is_empty())
            .map(String::from)
    };
    let model = prop("model")
        .or_else(|| prop("md"))
        .or_else(|| prop("am"))
        .or_else(|| prop("rpMd"));
    // Cast devices expose their user-facing name in TXT `fn`.
    let name = prop("fn").unwrap_or(instance);
    let prio = NAME_TYPES
        .iter()
        .position(|t| ty.starts_with(&format!("{t}.")))
        .unwrap_or(NAME_TYPES.len());
    let good_name = !name.contains('[') && !name.is_empty() && !ty.starts_with("_adb-tls");
    let txt = capture_txt(|k| {
        info.txt_properties
            .get_property_val_str(k)
            .map(String::from)
    });

    let mut m = out.lock().unwrap();
    for ip in info.addresses.iter().filter_map(|a| match a.to_ip_addr() {
        std::net::IpAddr::V4(v) if !v.is_link_local() => Some(v),
        _ => None,
    }) {
        let (f, best) = m
            .entry(ip)
            .or_insert_with(|| (Found::default(), usize::MAX));
        f.services.insert(ty.clone());
        f.ports.insert(bare_type(&ty).to_string(), info.port);
        for (k, v) in &txt {
            // Cast TXT is the most reliable source for md/fn.
            if ty.starts_with("_googlecast") || !f.txt.contains_key(k) {
                f.txt.insert(k.clone(), v.clone());
            }
        }
        f.host.get_or_insert_with(|| host.clone());
        if good_name && prio < *best {
            *best = prio;
            f.name = Some(name.clone());
        }
        if f.model.is_none() || ty.starts_with("_device-info") || ty.starts_with("_companion-link")
        {
            f.model = model.clone().or(f.model.take());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_capture_filters_cleans_and_caps() {
        let long = "x".repeat(200);
        let t = capture_txt(|k| match k {
            "md" => Some("  Chromecast \n Ultra ".into()),
            "fn" => Some(long.clone()),
            "ca" => Some(String::new()),
            "other" => Some("nope".into()),
            _ => None,
        });
        assert_eq!(t.get("md").unwrap(), "Chromecast Ultra");
        assert_eq!(t.get("fn").unwrap().len(), 80);
        assert!(!t.contains_key("ca") && !t.contains_key("other"));
    }

    #[test]
    fn bare_type_strips_transport() {
        assert_eq!(bare_type("_adb-tls-connect._tcp"), "_adb-tls-connect");
        assert_eq!(bare_type("_matterc._udp"), "_matterc");
        assert_eq!(bare_type("_x"), "_x");
    }
}

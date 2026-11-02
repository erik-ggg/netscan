use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use tokio::task::spawn_blocking;

/// Run `arp -an` and return IP -> MAC for the given interface.
pub async fn table(interface: &str) -> HashMap<Ipv4Addr, String> {
    let iface = interface.to_string();
    spawn_blocking(move || {
        Command::new("arp")
            .arg("-an")
            .output()
            .map(|o| parse(&String::from_utf8_lossy(&o.stdout), &iface))
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

/// Lines look like: `? (192.168.1.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]`
pub fn parse(output: &str, interface: &str) -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    for line in output.lines() {
        if line.contains("(incomplete)") {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        let (Some(ip), Some(at), Some(on)) = (
            toks.get(1)
                .and_then(|t| t.trim_matches(['(', ')']).parse::<Ipv4Addr>().ok()),
            toks.iter()
                .position(|t| *t == "at")
                .and_then(|i| toks.get(i + 1)),
            toks.iter()
                .position(|t| *t == "on")
                .and_then(|i| toks.get(i + 1)),
        ) else {
            continue;
        };
        if *on != interface {
            continue;
        }
        if let Some(mac) = normalize_mac(at) {
            // Skip broadcast and multicast entries.
            if mac != "ff:ff:ff:ff:ff:ff" && !is_multicast(&mac) {
                map.insert(ip, mac);
            }
        }
    }
    map
}

pub fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let bytes: Option<Vec<u8>> = parts
        .iter()
        .map(|p| u8::from_str_radix(p, 16).ok())
        .collect();
    Some(super::net::fmt_mac(bytes?.try_into().ok()?))
}

fn is_multicast(mac: &str) -> bool {
    u8::from_str_radix(&mac[..2], 16).is_ok_and(|b| b & 1 == 1)
}

/// Locally-administered bit set => randomized/private MAC.
pub fn is_randomized(mac: &str) -> bool {
    u8::from_str_radix(&mac[..2], 16).is_ok_and(|b| b & 2 == 2)
}

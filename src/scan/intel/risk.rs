//! Factual exposure notes derived from what the probes found.

use crate::scan::model::*;

fn next(r: Risk) -> Risk {
    match r {
        Risk::Info => Risk::Low,
        Risk::Low => Risk::Medium,
        Risk::Medium | Risk::High => Risk::High,
    }
}

/// `Name/1.2.3`-style version disclosure.
fn discloses_version(server: &str) -> bool {
    server.split_whitespace().any(|t| {
        t.split_once('/')
            .is_some_and(|(_, v)| v.starts_with(|c: char| c.is_ascii_digit()))
    })
}

pub fn assess(d: &Device, i: &DeviceIntel) -> (Vec<Note>, Risk) {
    let mut notes: Vec<Note> = vec![];
    for p in i
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open && p.risk >= Risk::Medium)
    {
        notes.push(Note {
            risk: p.risk,
            text: format!(
                "{}/TCP {} EXPOSED // {}",
                p.port,
                p.service,
                p.meaning.to_uppercase()
            ),
        });
    }
    for h in i.http.iter().filter(|h| !h.tls) {
        let t = format!(
            "{} {}",
            h.title.as_deref().unwrap_or(""),
            h.auth_realm.as_deref().unwrap_or("")
        )
        .to_lowercase();
        if [
            "login",
            "admin",
            "router",
            "password",
            "sign in",
            "management",
        ]
        .iter()
        .any(|k| t.contains(k))
            || h.auth_realm.is_some()
        {
            notes.push(Note {
                risk: Risk::Low,
                text: format!("{}/TCP LOGIN/ADMIN PAGE OVER PLAIN HTTP", h.port),
            });
        }
    }
    let up = d.upnp.as_ref().or(i.upnp.as_ref());
    if up
        .and_then(|u| u.device_type.as_deref())
        .is_some_and(|t| t.contains("InternetGatewayDevice"))
    {
        notes.push(Note {
            risk: Risk::Low,
            text: "UPNP GATEWAY ACCEPTS PORT-FORWARD REQUESTS".into(),
        });
    }
    for h in &i.http {
        if let Some(s) = h.server.as_deref().filter(|s| discloses_version(s)) {
            notes.push(Note {
                risk: Risk::Low,
                text: format!("{}/TCP SERVER HEADER DISCLOSES VERSION: {s}", h.port),
            });
        }
    }
    if notes.is_empty() {
        notes.push(Note {
            risk: Risk::Info,
            text: "NO EXPOSED SERVICES IN PROBE SET".into(),
        });
    }
    let max = notes.iter().map(|n| n.risk).max().unwrap_or(Risk::Info);
    let mediums = notes.iter().filter(|n| n.risk == Risk::Medium).count();
    let exposure = if mediums >= 3 { next(max) } else { max };
    (notes, exposure)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(port: u16) -> PortInfo {
        super::super::ports::info(port, PortState::Open)
    }

    #[test]
    fn telnet_is_high() {
        let i = DeviceIntel {
            ports: vec![open(23), open(80)],
            ..Default::default()
        };
        let (n, r) = assess(&Device::default(), &i);
        assert_eq!(r, Risk::High);
        assert!(n.iter().any(|n| n.text.contains("23/TCP")));
    }

    #[test]
    fn clean_host_and_bump() {
        let (n, r) = assess(&Device::default(), &DeviceIntel::default());
        assert_eq!(r, Risk::Info);
        assert!(n[0].text.contains("NO EXPOSED"));
        let i = DeviceIntel {
            ports: vec![open(21), open(445), open(554)],
            ..Default::default()
        };
        assert_eq!(assess(&Device::default(), &i).1, Risk::High);
    }

    #[test]
    fn version_header() {
        assert!(discloses_version("lighttpd/1.4.55"));
        assert!(!discloses_version("nginx"));
    }
}

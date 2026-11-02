//! Dioxus UI: Arasaka-style HUD with a loading screen and a topology map.

pub mod app;
pub mod icons;
pub mod layout;
pub mod loading;
pub mod network_map;

use std::sync::OnceLock;

const MAIN_CSS: &str = include_str!("../../assets/main.css");
const RAJDHANI: &[u8] = include_bytes!("../../assets/fonts/Rajdhani-SemiBold.ttf");
const SHARE_MONO: &[u8] = include_bytes!("../../assets/fonts/ShareTechMono-Regular.ttf");

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Full stylesheet with the fonts inlined as data URIs (no network, no asset bundling).
pub fn css() -> &'static str {
    static CSS: OnceLock<String> = OnceLock::new();
    CSS.get_or_init(|| {
        format!(
            "@font-face{{font-family:'Rajdhani';font-weight:600;src:url(data:font/ttf;base64,{}) format('truetype');}}\
             @font-face{{font-family:'Share Tech Mono';src:url(data:font/ttf;base64,{}) format('truetype');}}\n{}",
            base64(RAJDHANI),
            base64(SHARE_MONO),
            MAIN_CSS
        )
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_ok() {
        assert_eq!(super::base64(b"Man"), "TWFu");
        assert_eq!(super::base64(b"Ma"), "TWE=");
        assert_eq!(super::base64(b"M"), "TQ==");
    }
}

/// Dev aid: `PREVIEW_DIR=/some/dir cargo test dump_preview` writes static HTML snapshots.
#[cfg(test)]
mod preview {
    use super::{loading::Loading, network_map::NetworkMap};
    use crate::scan::model::*;
    use dioxus::prelude::*;

    fn fake(n: usize) -> ScanResult {
        let kinds = [
            DeviceKind::Mobile, DeviceKind::Iot, DeviceKind::Unknown, DeviceKind::Computer,
            DeviceKind::Tv, DeviceKind::Car, DeviceKind::Printer, DeviceKind::Console, DeviceKind::Media, DeviceKind::Tablet,
        ];
        let mut devices = vec![Device {
            ip: "192.168.1.1".into(), mac: Some("AA:BB:CC:00:11:22".into()), is_self: false, is_gateway: true,
            hostname: Some("starlink.router".into()), vendor: Some("Starlink".into()), model: None,
            services: vec![], kind: DeviceKind::Router, mac_randomized: false,
        }];
        for i in 0..n {
            devices.push(Device {
                ip: format!("192.168.1.{}", i + 20), mac: Some("DA:11:22:33:44:55".into()), is_self: i == 3,
                hostname: (i % 2 == 0).then(|| format!("device-{i}")), vendor: (i % 3 != 0).then(|| "TP-Link".into()),
                model: None, services: vec!["_airplay._tcp".into()], is_gateway: false,
                kind: kinds[i % kinds.len()], mac_randomized: i % 4 == 0,
            });
        }
        ScanResult {
            network: NetworkInfo {
                interface: "en0".into(), local_ip: "192.168.1.23".into(), local_mac: None, prefix: 24,
                netmask: "255.255.255.0".into(), gateway_ip: Some("192.168.1.1".into()), gateway_mac: None,
                subnet_cidr: "192.168.1.0/24".into(),
            },
            public_ip: Some("186.12.34.56".into()),
            isp: Some("Starlink".into()),
            devices,
        }
    }

    fn page(body: String) -> String {
        format!("<!doctype html><html><head><meta charset=utf-8><style>{}</style><style>.map-screen,.node-body,.loading,.log-line,.readout{{animation:none!important;opacity:1!important;filter:none!important}}</style></head><body><div id=main><div class=app><div class=bg-grid></div>{body}<div class=scanlines></div><div class=vignette></div></div></div></body></html>", super::css())
    }

    #[test]
    fn dump_preview() {
        let Ok(dir) = std::env::var("PREVIEW_DIR") else { return };
        if let Ok(f) = std::env::var("PREVIEW_JSON") {
            let r: ScanResult = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
            for (name, hov) in [("real", None), ("real_hover", Some(4usize))] {
                let mut vd = VirtualDom::new_with_props(
                    move |r: ScanResult| rsx! { NetworkMap { result: r, hovered: use_signal(move || hov) } },
                    r.clone(),
                );
                vd.rebuild_in_place();
                std::fs::write(format!("{dir}/{name}.html"), page(dioxus_ssr::render(&vd))).unwrap();
            }
        }
        for n in [14usize, 40] {
            let mut vd = VirtualDom::new_with_props(
                |n: usize| rsx! { NetworkMap { result: fake(n), hovered: use_signal(|| if n == 14 { Some(4usize) } else { None }) } },
                n,
            );
            vd.rebuild_in_place();
            std::fs::write(format!("{dir}/map{n}.html"), page(dioxus_ssr::render(&vd))).unwrap();
        }
        let mut vd = VirtualDom::new(|| rsx! {
            Loading { phase: "Sweeping subnet", pct: 52u8, exiting: false,
                logs: vec!["IF en0 // 192.168.1.23 // GW 192.168.1.1".to_string(), "SUBNET 192.168.1.0/24".into(), "PROBING 254 TARGETS // ICMP + TCP + UDP".into(), "13 HOSTS RESPONDED".into()] }
        });
        vd.rebuild_in_place();
        std::fs::write(format!("{dir}/load.html"), page(dioxus_ssr::render(&vd))).unwrap();
    }
}

//! Dioxus UI: Arasaka-style HUD with a loading screen and a topology map.

pub mod app;
pub mod dossier;
pub mod icons;
pub mod intrusion;
pub mod layout;
pub mod loading;
pub mod network_map;
pub mod session;
pub mod sfx;

use std::sync::OnceLock;

const MAIN_CSS: &str = include_str!("../../assets/main.css");
const RAJDHANI: &[u8] = include_bytes!("../../assets/fonts/Rajdhani-SemiBold.ttf");
const SHARE_MONO: &[u8] = include_bytes!("../../assets/fonts/ShareTechMono-Regular.ttf");

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
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
    use super::{
        dossier::Dossier,
        intrusion::{Intrusion, Stamp},
        loading::Loading,
        network_map::NetworkMap,
        session::IntelSession,
    };
    use crate::scan::model::*;
    use dioxus::prelude::*;
    use std::collections::HashMap;

    fn fake(n: usize) -> ScanResult {
        let kinds = [
            DeviceKind::Mobile,
            DeviceKind::Iot,
            DeviceKind::Unknown,
            DeviceKind::Computer,
            DeviceKind::Tv,
            DeviceKind::Car,
            DeviceKind::Printer,
            DeviceKind::Console,
            DeviceKind::Media,
            DeviceKind::Tablet,
        ];
        let mut devices = vec![Device {
            ip: "192.168.1.1".into(),
            mac: Some("AA:BB:CC:00:11:22".into()),
            is_self: false,
            is_gateway: true,
            hostname: Some("starlink.router".into()),
            vendor: Some("Starlink".into()),
            model: None,
            services: vec![],
            kind: DeviceKind::Router,
            mac_randomized: false,
            rtt_ms: Some(1.8),
            ttl: Some(64),
            ..Default::default()
        }];
        for i in 0..n {
            devices.push(Device {
                ip: format!("192.168.1.{}", i + 20),
                mac: Some("DA:11:22:33:44:55".into()),
                is_self: i == 3,
                hostname: (i % 2 == 0).then(|| format!("device-{i}")),
                vendor: (i % 3 != 0).then(|| "TP-Link".into()),
                model: None,
                services: vec!["_airplay._tcp".into()],
                is_gateway: false,
                kind: kinds[i % kinds.len()],
                mac_randomized: i % 4 == 0,
                rtt_ms: (i % 3 != 2).then_some(2.0 + i as f32 * 3.7),
                ttl: (i % 3 != 2).then_some([64u8, 128, 255][i % 3]),
                ..Default::default()
            });
        }
        ScanResult {
            network: NetworkInfo {
                interface: "en0".into(),
                local_ip: "192.168.1.23".into(),
                local_mac: None,
                prefix: 24,
                netmask: "255.255.255.0".into(),
                gateway_ip: Some("192.168.1.1".into()),
                gateway_mac: None,
                subnet_cidr: "192.168.1.0/24".into(),
            },
            public_ip: Some("186.12.34.56".into()),
            isp: Some("Starlink".into()),
            devices,
        }
    }

    fn page(body: String) -> String {
        format!(
            "<!doctype html><html><head><meta charset=utf-8><style>{}</style><style>.map-screen,.node-body,.loading,.log-line,.readout,.dz-wrap,.dossier,.dz-sec,.c,.ret-in,.reclass,.ix-p,.ix-top,.ix-bar,.cs-col,.cs-band,.tl,.stamp,.stamp-wrap,.ice-ring,.tw,.dz-top,.dz-id{{animation:none!important;opacity:1!important;filter:none!important}}.st-main::before,.st-main::after,.ice-arc,.ice-spin{{animation:none!important}}.burst,.ix-sweep{{display:none!important}}</style></head><body><div id=main><div class=app><div class=bg-grid></div>{body}<div class=scanlines></div><div class=vignette></div></div></div></body></html>",
            super::css()
        )
    }

    /// Replays a finished `DeviceIntel` through `IntelSession::apply`, like the live event pump.
    fn replay(i: &DeviceIntel, upto_ports: usize, finish: bool) -> IntelSession {
        let mut s = IntelSession::new(&i.ip, 1);
        s.apply(IntelEvent::Stage {
            stage: IntelStage::Echo,
            pct: 0,
        });
        if let Some(p) = &i.ping {
            for (n, r) in p.samples.iter().enumerate() {
                s.apply(IntelEvent::Echo {
                    seq: n as u8,
                    rtt_ms: *r,
                    ttl: p.ttl,
                });
            }
        }
        s.apply(IntelEvent::Stage {
            stage: IntelStage::Lattice,
            pct: 15,
        });
        for p in i.ports.iter().take(upto_ports) {
            s.apply(IntelEvent::Port {
                port: p.port,
                state: p.state,
            });
        }
        if finish {
            s.apply(IntelEvent::Stage {
                stage: IntelStage::Assemble,
                pct: 100,
            });
            s.apply(IntelEvent::Done(Box::new(i.clone())));
        } else {
            s.apply(IntelEvent::Stage {
                stage: IntelStage::Lattice,
                pct: 15 + upto_ports as u8,
            });
        }
        s
    }

    type SceneProps = (
        ScanResult,
        Option<usize>,
        HashMap<String, IntelSession>,
        Option<(Device, IntelSession)>,
    );

    fn scene(
        r: ScanResult,
        focus: Option<usize>,
        sessions: HashMap<String, IntelSession>,
        dz: Option<(usize, IntelSession)>,
    ) -> String {
        let d = dz.as_ref().map(|(i, s)| (r.devices[*i].clone(), s.clone()));
        let mut vd = VirtualDom::new_with_props(
            move |(r, focus, sessions, d): SceneProps| {
                rsx! {
                    NetworkMap { result: r, hovered: use_signal(|| None::<usize>), focus, intel: use_signal(move || sessions.clone()), on_target: |_| {} }
                    if let Some((device, session)) = d {
                        Dossier { device, session, closing: false, on_close: |_| {}, on_rescan: |_| {} }
                    }
                }
            },
            (r, focus, sessions, d),
        );
        vd.rebuild_in_place();
        page(dioxus_ssr::render(&vd))
    }

    type BreachProps = (
        ScanResult,
        usize,
        HashMap<String, IntelSession>,
        Device,
        IntelSession,
        u32,
        Option<(bool, bool, bool)>,
    );

    /// Breach (`stamp == None`) or stamp overlay over the zoomed map.
    fn breach_scene(
        r: ScanResult,
        idx: usize,
        session: IntelSession,
        elapsed: u32,
        stamp: Option<(bool, bool, bool)>,
    ) -> String {
        let device = r.devices[idx].clone();
        let mut sessions = HashMap::new();
        sessions.insert(device.ip.clone(), session.clone());
        let mut vd = VirtualDom::new_with_props(
            move |(r, idx, sessions, device, session, elapsed, stamp): BreachProps| {
                let sub = format!(
                    "{} // {} OPEN // {} PORTS PROBED",
                    device.ip,
                    session.open_count(),
                    session.ports.len()
                );
                rsx! {
                    NetworkMap { result: r, hovered: use_signal(|| None::<usize>), focus: Some(idx), intel: use_signal(move || sessions.clone()), on_target: |_| {}, breach: true }
                    match stamp {
                        None => rsx! { Intrusion { device, session, elapsed_ms: elapsed, on_abort: |_| {} } },
                        Some((denied, partial, relink)) => rsx! { Stamp { denied, partial, relink, sub } },
                    }
                }
            },
            (r, idx, sessions, device, session, elapsed, stamp),
        );
        vd.rebuild_in_place();
        page(dioxus_ssr::render(&vd))
    }

    fn load_intel(dir: &str, f: &str) -> Option<DeviceIntel> {
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{f}")).ok()?).ok()
    }

    #[test]
    fn dump_dossier_preview() {
        let (Ok(dir), Ok(json)) = (std::env::var("PREVIEW_DIR"), std::env::var("PREVIEW_JSON"))
        else {
            return;
        };
        let r: ScanResult = serde_json::from_str(&std::fs::read_to_string(json).unwrap()).unwrap();
        let ri = super::layout::router_index(&r.devices).unwrap();
        let (Some(i1), Some(i194)) = (
            load_intel(&dir, "intel_1.json"),
            load_intel(&dir, "intel_194.json"),
        ) else {
            return;
        };
        let ip194 = r
            .devices
            .iter()
            .position(|d| d.ip == "192.168.1.194")
            .unwrap();
        let full = replay(&i1, 36, true);
        let s194 = replay(&i194, 36, true);
        let s194_done = s194.clone();

        // Dark phone: everything filtered, no echo.
        let ph = r.devices.iter().position(|d| d.mac_randomized).unwrap();
        let dark_i = DeviceIntel {
            ip: r.devices[ph].ip.clone(),
            complete: true,
            elapsed_ms: 1650,
            ping: Some(PingStats {
                sent: 4,
                recv: 0,
                samples: vec![None; 4],
                ..Default::default()
            }),
            ports: i1
                .ports
                .iter()
                .map(|p| PortInfo {
                    state: PortState::Filtered,
                    ..p.clone()
                })
                .collect(),
            os: OsGuess {
                label: "MOBILE (IOS/ANDROID)".into(),
                short: "MOB".into(),
                confidence: 40,
                evidence: vec!["TTL 64".into(), "PRIVATE MAC".into()],
                ..Default::default()
            },
            notes: vec![Note {
                risk: Risk::Info,
                text: "NO EXPOSED SERVICES IN PROBE SET".into(),
            }],
            ..Default::default()
        };
        let dark = replay(&dark_i, 36, true);
        let dark_done = dark.clone();
        let pend = replay(&i1, 22, false);

        let mut all: HashMap<String, IntelSession> = HashMap::new();
        all.insert(r.devices[ri].ip.clone(), full.clone());
        all.insert(r.devices[ip194].ip.clone(), s194.clone());
        all.insert(r.devices[ph].ip.clone(), dark.clone());
        let w = |n: &str, h: String| std::fs::write(format!("{dir}/{n}.html"), h).unwrap();
        w("map_chips", scene(r.clone(), None, all.clone(), None));
        w(
            "map_locked",
            scene(r.clone(), Some(ip194), all.clone(), None),
        );
        w(
            "dossier_full",
            scene(r.clone(), Some(ri), all.clone(), Some((ri, full))),
        );
        w(
            "dossier_ssh",
            scene(r.clone(), Some(ip194), all.clone(), Some((ip194, s194))),
        );
        w(
            "dossier_dark",
            scene(r.clone(), Some(ph), all.clone(), Some((ph, dark))),
        );
        let tv = r
            .devices
            .iter()
            .position(|d| d.ip == "192.168.1.194")
            .unwrap_or(ri);
        let w2 = |n: &str, h: String| std::fs::write(format!("{dir}/{n}.html"), h).unwrap();
        // ~25% overall: echoes done, lattice sweeping.
        let mut b25 = replay(&i194, 12, false);
        b25.apply(IntelEvent::Stage {
            stage: IntelStage::Lattice,
            pct: 25,
        });
        w2("breach_25", breach_scene(r.clone(), tv, b25, 1100, None));
        // ~70%: fingerprinting, lattice finished.
        let mut b70 = replay(&i194, 36, false);
        b70.apply(IntelEvent::Log("LATTICE // 3 OPEN".into()));
        b70.apply(IntelEvent::Log("FINGERPRINT // SERVICES".into()));
        b70.apply(IntelEvent::Stage {
            stage: IntelStage::Fingerprint,
            pct: 70,
        });
        w2("breach_70", breach_scene(r.clone(), tv, b70, 2300, None));
        w2(
            "stamp",
            breach_scene(
                r.clone(),
                tv,
                s194_done.clone(),
                3000,
                Some((false, false, false)),
            ),
        );
        w2(
            "stamp_denied",
            breach_scene(
                r.clone(),
                ph,
                dark_done.clone(),
                3000,
                Some((true, false, false)),
            ),
        );
        let mut pm = HashMap::new();
        pm.insert(r.devices[ri].ip.clone(), pend.clone());
        w(
            "dossier_pending",
            scene(r.clone(), Some(ri), pm, Some((ri, pend))),
        );
    }

    #[test]
    fn dump_preview() {
        let Ok(dir) = std::env::var("PREVIEW_DIR") else {
            return;
        };
        if let Ok(f) = std::env::var("PREVIEW_JSON") {
            let r: ScanResult = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
            for (name, hov) in [("real", None), ("real_hover", Some(4usize))] {
                let mut vd = VirtualDom::new_with_props(
                    move |r: ScanResult| rsx! { NetworkMap { result: r, hovered: use_signal(move || hov), focus: None, intel: use_signal(HashMap::new), on_target: |_| {} } },
                    r.clone(),
                );
                vd.rebuild_in_place();
                std::fs::write(format!("{dir}/{name}.html"), page(dioxus_ssr::render(&vd)))
                    .unwrap();
            }
        }
        for n in [14usize, 40] {
            let mut vd = VirtualDom::new_with_props(
                |n: usize| rsx! { NetworkMap { result: fake(n), hovered: use_signal(|| if n == 14 { Some(4usize) } else { None }), focus: None, intel: use_signal(HashMap::new), on_target: |_| {} } },
                n,
            );
            vd.rebuild_in_place();
            std::fs::write(format!("{dir}/map{n}.html"), page(dioxus_ssr::render(&vd))).unwrap();
        }
        let mut vd = VirtualDom::new(|| {
            rsx! {
                Loading { phase: "Sweeping subnet", pct: 52u8, exiting: false,
                    logs: vec!["IF en0 // 192.168.1.23 // GW 192.168.1.1".to_string(), "SUBNET 192.168.1.0/24".into(), "PROBING 254 TARGETS // ICMP + TCP + UDP".into(), "13 HOSTS RESPONDED".into()] }
            }
        });
        vd.rebuild_in_place();
        std::fs::write(format!("{dir}/load.html"), page(dioxus_ssr::render(&vd))).unwrap();
    }
}

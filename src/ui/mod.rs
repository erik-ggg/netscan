//! Dioxus UI: Arasaka-style HUD with a loading screen and a topology map.

pub mod app;
pub mod dossier;
pub mod icons;
pub mod intrusion;
pub mod layout;
pub mod link;
pub mod loading;
pub mod network_map;
pub mod session;
pub mod sfx;
pub mod xterm;

use std::sync::OnceLock;

const MAIN_CSS: &str = include_str!("../../assets/main.css");
const RAJDHANI: &[u8] = include_bytes!("../../assets/fonts/Rajdhani-SemiBold.ttf");
const SHARE_MONO: &[u8] = include_bytes!("../../assets/fonts/ShareTechMono-Regular.ttf");

pub(crate) fn base64(data: &[u8]) -> String {
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
             @font-face{{font-family:'Share Tech Mono';src:url(data:font/ttf;base64,{}) format('truetype');}}\n{}\n{}",
            base64(RAJDHANI),
            base64(SHARE_MONO),
            MAIN_CSS,
            xterm::XTERM_CSS
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
        page_x(body, "")
    }

    fn page_x(body: String, extra: &str) -> String {
        format!(
            "<!doctype html><html><head><meta charset=utf-8><style>{}</style><style>.map-screen,.node-body,.loading,.log-line,.readout,.dz-wrap,.dossier,.dz-sec,.c,.ret-in,.reclass,.ix-p,.ix-top,.ix-bar,.cs-col,.cs-band,.tl,.stamp,.stamp-wrap,.ice-ring,.tw,.dz-top,.dz-id,.nl,.nl-wrap,.lc,.nl-modal,.nl-modal-wrap,.nl-chip,.nl-pip,.nl-pip .bx,.dz-chip .dot,.nl-mock .cur,.hs-line,.hs-pk,.nl-term{{animation:none!important;opacity:1!important;filter:none!important}}.nl-hs{{display:none!important}}.nl-term{{background:#060405}}.st-main::before,.st-main::after,.ice-arc,.ice-spin{{animation:none!important}}.burst,.ix-sweep{{display:none!important}}</style><style>{}</style></head><body><div id=main><div class=app><div class=bg-grid></div>{body}<div class=scanlines></div><div class=vignette></div></div></div></body></html>",
            super::css(),
            extra
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
                        Dossier { device, session, closing: false, on_close: |_| {}, on_rescan: |_| {}, network: NetworkInfo { interface: "en0".into(), local_ip: "192.168.1.23".into(), local_mac: None, prefix: 24, netmask: "255.255.255.0".into(), gateway_ip: Some("192.168.1.1".into()), gateway_mac: None, subnet_cidr: "192.168.1.0/24".into() }, tools: crate::link::tools::Tools::default(), cfg_open: false, on_cfg: |_| {}, on_connect: |_| {}, on_recheck: |_| {} }
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

    /// Fixture LG TV with a full evidence trail, shown in the dossier.
    #[test]
    fn dump_class_preview() {
        let Ok(dir) = std::env::var("PREVIEW_DIR") else {
            return;
        };
        let ev = |kind, weight, source, text: &str| Evidence {
            kind,
            weight,
            source,
            text: text.into(),
        };
        let class = Classification {
            kind: DeviceKind::Tv,
            confidence: 92,
            label: Some("WEBOS TV".into()),
            reason: "MODEL 55NANO796NE \u{25B8} LG TV LINE".into(),
            evidence: vec![
                ev(
                    DeviceKind::Tv,
                    87,
                    EvSource::Model,
                    "MODEL 55NANO796NE \u{25B8} LG TV LINE",
                ),
                ev(
                    DeviceKind::Tv,
                    70,
                    EvSource::Name,
                    "NAME \"LG WEBOS TV 2272\" \u{25B8} WEBOS TV",
                ),
                ev(
                    DeviceKind::Tv,
                    60,
                    EvSource::Mdns,
                    "MDNS _DISPLAY \u{25B8} DISPLAY SINK",
                ),
                ev(
                    DeviceKind::Tv,
                    55,
                    EvSource::Probe,
                    "PROBE :3000 \u{25B8} WEBOS REMOTE API",
                ),
                ev(
                    DeviceKind::Tv,
                    40,
                    EvSource::Vendor,
                    "VENDOR LG ELECTRONICS \u{25B8} TV/APPLIANCE",
                ),
                ev(
                    DeviceKind::Media,
                    30,
                    EvSource::Mdns,
                    "MDNS _AIRPLAY \u{25B8} AIRPLAY TARGET",
                ),
                ev(
                    DeviceKind::Iot,
                    25,
                    EvSource::Mdns,
                    "MDNS _HAP \u{25B8} HOMEKIT ACCESSORY",
                ),
            ],
            alt: vec![(DeviceKind::Media, 30), (DeviceKind::Iot, 25)],
        };
        let tv = Device {
            ip: "192.168.1.32".into(),
            mac: Some("A8:23:FE:12:34:56".into()),
            hostname: Some("LG webOS TV 2272".into()),
            vendor: Some("LG Electronics".into()),
            model: Some("55NANO796NE".into()),
            services: vec![
                "_airplay._tcp".into(),
                "_display._tcp".into(),
                "_hap._tcp".into(),
            ],
            kind: DeviceKind::Tv,
            rtt_ms: Some(6.2),
            ttl: Some(64),
            class: Some(class),
            ..Default::default()
        };
        let mut r = fake(10);
        r.devices.push(tv.clone());
        // An uncertain neighbour for the "?" marker.
        r.devices[2].class = Some(Classification {
            kind: DeviceKind::Iot,
            confidence: 44,
            reason: "VENDOR BILIAN \u{25B8} WI-FI MODULE".into(),
            evidence: vec![ev(
                DeviceKind::Iot,
                45,
                EvSource::Vendor,
                "VENDOR BILIAN \u{25B8} WI-FI MODULE",
            )],
            alt: vec![(DeviceKind::Tv, 15)],
            ..Default::default()
        });
        r.devices[2].kind = DeviceKind::Iot;
        let idx = r.devices.len() - 1;
        let s = IntelSession::new(&tv.ip, 1);
        let mut m = HashMap::new();
        m.insert(tv.ip.clone(), s.clone());
        std::fs::write(
            format!("{dir}/dossier_class.html"),
            scene(r, Some(idx), m, Some((idx, s))),
        )
        .unwrap();
    }

    /// Neural link: config drawer (.194 ssh, no-adb TV) and console (mock lines, purge, handshake).
    #[test]
    fn dump_link_preview() {
        use crate::link::{LinkRequest, Proto, tools::Tools};
        let Ok(dir) = std::env::var("PREVIEW_DIR") else {
            return;
        };
        let ev = |kind, weight, source, text: &str| Evidence {
            kind,
            weight,
            source,
            text: text.into(),
        };
        let wb_class = Classification {
            kind: DeviceKind::Car,
            confidence: 63,
            label: Some("EV CHARGER".into()),
            reason: "NAME WB277129 \u{25B8} WALLBOX-STYLE NAME".into(),
            evidence: vec![ev(
                DeviceKind::Car,
                70,
                EvSource::Name,
                "NAME WB277129 \u{25B8} WALLBOX-STYLE NAME",
            )],
            alt: vec![(DeviceKind::Computer, 45)],
        };
        let wb = Device {
            ip: "192.168.1.194".into(),
            mac: Some("F8:F0:05:12:34:56".into()),
            hostname: Some("WB277129".into()),
            vendor: Some("Newport Media".into()),
            services: vec!["_ssh._tcp".into(), "_sftp-ssh._tcp".into()],
            kind: DeviceKind::Car,
            ttl: Some(64),
            rtt_ms: Some(4.1),
            class: Some(wb_class),
            ..Default::default()
        };
        let tv_class = Classification {
            kind: DeviceKind::Tv,
            confidence: 88,
            label: Some("GOOGLE TV".into()),
            reason: "CAST MODEL TCL GOOGLE TV".into(),
            evidence: vec![ev(
                DeviceKind::Tv,
                90,
                EvSource::Probe,
                "CAST MODEL TCL GOOGLE TV",
            )],
            alt: vec![],
        };
        let tv = Device {
            ip: "192.168.1.47".into(),
            mac: Some("84:D1:5A:AA:BB:CC".into()),
            hostname: Some("Sabrina".into()),
            vendor: Some("TCL".into()),
            services: vec!["_googlecast._tcp".into(), "_androidtvremote2._tcp".into()],
            kind: DeviceKind::Tv,
            ttl: Some(64),
            beacon: Some(Beacon {
                open: vec![5555, 6466, 8008, 8009],
                ..Default::default()
            }),
            class: Some(tv_class),
            ..Default::default()
        };
        let mut r = fake(10);
        r.devices.push(wb.clone());
        r.devices.push(tv.clone());
        let iw = r.devices.len() - 2;
        let it = r.devices.len() - 1;
        let tools_none = Tools {
            ssh: Some("/usr/bin/ssh".into()),
            shell: "/bin/zsh".into(),
            ..Default::default()
        };

        let drawer = |idx: usize, tab: usize, tools: Tools| {
            let d = r.devices[idx].clone();
            let s = IntelSession::new(&d.ip, 1);
            let mut m = HashMap::new();
            m.insert(d.ip.clone(), s.clone());
            let rr = r.clone();
            let mut vd = VirtualDom::new_with_props(
                move |(rr, d, s, m, tools, tab, idx): (
                    ScanResult,
                    Device,
                    IntelSession,
                    HashMap<String, IntelSession>,
                    Tools,
                    usize,
                    usize,
                )| {
                    let n = rr.network.clone();
                    let _ = tab;
                    rsx! {
                        NetworkMap { result: rr.clone(), hovered: use_signal(|| None::<usize>), focus: Some(idx), intel: use_signal(move || m.clone()), on_target: |_| {} }
                        Dossier { device: d.clone(), session: s, closing: false, on_close: |_| {}, on_rescan: |_| {}, network: n.clone(), tools: tools.clone(), cfg_open: true, on_cfg: |_| {}, on_connect: |_| {}, on_recheck: |_| {} }
                    }
                },
                (rr, d, s, m, tools, tab, idx),
            );
            vd.rebuild_in_place();
            page(dioxus_ssr::render(&vd))
        };
        let w = |n: &str, h: String| std::fs::write(format!("{dir}/{n}.html"), h).unwrap();
        w("link_config_ssh", drawer(iw, 0, tools_none.clone()));
        w("link_config_noadb", drawer(it, 0, tools_none.clone()));

        let lines: Vec<String> = [
            "$ adb connect 192.168.1.47:5555 && adb -s 192.168.1.47:5555 shell",
            "already connected to 192.168.1.47:5555",
            "sabrina:/ $ getprop ro.product.model",
            "55C745",
            "sabrina:/ $ pm list packages | wc -l",
            "214",
            "sabrina:/ $ pm list packages | grep -i tcl",
            "package:com.tcl.tv",
            "package:com.tcl.ui.dsp",
            "package:com.tcl.tvweishi",
            "package:com.tcl.android.launcher",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let console = |purge: bool, extra: &str| {
            let mut req = LinkRequest::new("192.168.1.47".parse().unwrap(), Proto::Adb);
            req.adb_port = 5555;
            let tvc = tv.clone();
            let lines = lines.clone();
            let mut vd = VirtualDom::new_with_props(
                move |(tvc, req, lines, purge, idx, rr): (
                    Device,
                    LinkRequest,
                    Vec<String>,
                    bool,
                    usize,
                    ScanResult,
                )| {
                    rsx! {
                        NetworkMap { result: rr, hovered: use_signal(|| None::<usize>), focus: Some(idx), intel: use_signal(HashMap::new), on_target: |_| {} }
                        super::link::NeuralLink { device: tvc, req, run: 1, on_sever: |_| {}, mock: Some(lines), tools: Tools { adb: Some("/opt/homebrew/bin/adb".into()), ..Default::default() } }
                        if purge { super::link::ConfirmPurge { ip: "192.168.1.47".to_string(), on_abort: |_| {}, on_type: |_| {}, checked: true } }
                    }
                },
                (tvc, req, lines, purge, it, r.clone()),
            );
            vd.rebuild_in_place();
            page_x(
                dioxus_ssr::render(&vd).replace("class=\"app\"", "class=\"app linked\""),
                extra,
            )
        };
        w("link_console", console(false, ""));
        w("link_purge", console(true, ""));
        // Handshake frozen mid-flight.
        w(
            "link_handshake",
            console(
                false,
                ".nl-hs{display:flex!important;animation:none!important;opacity:1!important}.hs-line.f{animation:none!important;stroke-dashoffset:0!important}.hs-pk{animation:none!important;opacity:1!important}.hs-pk.b{transform:translateX(120px)}.hs-pk.c{transform:translateX(230px)}",
            ),
        );
    }

    #[test]
    fn dump_preview() {
        let Ok(dir) = std::env::var("PREVIEW_DIR") else {
            return;
        };
        if let Ok(f) = std::env::var("PREVIEW_JSON") {
            let mut r: ScanResult =
                serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
            // Older scans predate the classifier: score them now.
            for d in r.devices.iter_mut().filter(|d| d.class.is_none()) {
                d.class = Some(crate::scan::classify::assess(d, None));
            }
            let hi = r
                .devices
                .iter()
                .position(|d| {
                    d.class
                        .as_ref()
                        .is_some_and(|c| c.label.is_some() && !d.is_self)
                })
                .unwrap_or(4);
            for (name, hov) in [("real", None), ("real_hover", Some(hi))] {
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

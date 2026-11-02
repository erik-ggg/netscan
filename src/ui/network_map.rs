use super::icons;
use super::layout::{self, CX, CY, H, NET_POS, W};
use super::loading::Emblem;
use super::session::IntelSession;
use crate::scan::model::*;
use crate::scan::os;
use dioxus::prelude::*;
use std::collections::HashMap;

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

/// SMIL pulses travelling both ways along an edge.
fn pulses(a: (f64, f64), b: (f64, f64), seed: usize, rtt_ms: Option<f32>) -> String {
    let dur = match rtt_ms {
        Some(r) => (1.4 + r as f64 / 20.0).clamp(1.4, 4.5),
        None => 2.2 + (seed % 5) as f64 * 0.37,
    };
    let off = (seed % 7) as f64 * 0.43;
    let fwd = format!("M{:.1} {:.1} L{:.1} {:.1}", a.0, a.1, b.0, b.1);
    let back = format!("M{:.1} {:.1} L{:.1} {:.1}", b.0, b.1, a.0, a.1);
    format!(
        r##"<circle r="2.6" class="pulse"><animateMotion path="{fwd}" dur="{dur:.2}s" begin="-{off:.2}s" repeatCount="indefinite"/></circle>
<circle r="1.6" class="pulse dim"><animateMotion path="{back}" dur="{d2:.2}s" begin="-{o2:.2}s" repeatCount="indefinite"/></circle>"##,
        d2 = dur * 1.7,
        o2 = off + 0.9
    )
}

/// Below this confidence a node is drawn as "uncertain".
pub const UNCERTAIN: u8 = 50;

/// Scored classification to show: the deep-scan one when present, else the sweep one.
pub fn eff_class<'a>(d: &'a Device, intel: Option<&'a DeviceIntel>) -> Option<&'a Classification> {
    intel.and_then(|i| i.class.as_ref()).or(d.class.as_ref())
}

/// Camera zoom on the targeted node.
const ZOOM: f64 = 1.55;
/// Max empty scene space the zoomed camera may reveal past the map bounds.
const SLACK: f64 = 120.0;

/// Camera translation that centres `p` at scale `s`, clamped so little empty space shows.
pub fn camera_for(p: (f64, f64), s: f64) -> (f64, f64) {
    let clamp = |t: f64, size: f64| t.clamp(size - (size + SLACK) * s, SLACK * s);
    (clamp(CX - p.0 * s, W), clamp(392.0 - p.1 * s, H))
}

const OCT: &str = "-12,-31 12,-31 31,-12 31,12 12,31 -12,31 -31,12 -31,-12";

#[component]
fn Icon(kind: DeviceKind, scale: f64) -> Element {
    rsx! {
        g { class: "icon", transform: "scale({scale})",
            for d in icons::paths(kind) { path { d: "{d}" } }
        }
    }
}

const OCT2: &str = "-9,-24 9,-24 24,-9 24,9 9,24 -9,24 -24,9 -24,-9";

fn scanned_open(sessions: &HashMap<String, IntelSession>, ip: &str) -> Option<usize> {
    sessions
        .get(ip)
        .filter(|s| s.intel.is_some())
        .map(|s| s.open_count())
}

/// Corner chip on a scanned node: rotated square holding the open-port count.
#[component]
fn Chip(n: usize, x: f64, y: f64) -> Element {
    let cls = if n > 0 { "chip open" } else { "chip" };
    rsx! {
        g { class: "{cls}", transform: "translate({x} {y})",
            polygon { points: "0,-10 10,0 0,10 -10,0" }
            text { y: "4", "{n}" }
        }
    }
}

const ICE_R: [f64; 4] = [66.0, 78.0, 90.0, 102.0];
const ICE_NAMES: [&str; 4] = [
    "ICE-1 ▸ ECHO",
    "ICE-2 ▸ LATTICE",
    "ICE-3 ▸ PRINT",
    "ICE-4 ▸ CORE",
];

/// Four concentric ICE rings around the target; arc length = that stage's progress.
#[component]
fn Ice(x: f64, y: f64, prog: [u8; 4]) -> Element {
    rsx! {
        g { class: "ice", transform: "translate({x:.1} {y:.1})",
            for (i, r) in ICE_R.iter().enumerate() {
                {
                    let p = prog[i];
                    let cracked = p >= 100;
                    let dir = if i % 2 == 0 { "ice-spin" } else { "ice-spin rev" };
                    rsx! {
                        g { key: "{i}", class: "ice-ring", style: "--d:{i}",
                            circle { class: "ice-bg", r: "{r}" }
                            g { class: "{dir}", style: "animation-duration:{7 + i * 5}s",
                                if cracked {
                                    circle { key: "c{i}", class: "ice-arc cracked", r: "{r}", path_length: "100", stroke_dasharray: "11 5.67" }
                                } else if p > 0 {
                                    circle { class: "ice-arc", r: "{r}", path_length: "100", stroke_dasharray: "{p} 100" }
                                }
                            }
                                            if p > 0 && !cracked { text { class: "ice-t", y: "{-r - 3.0}", "{ICE_NAMES[i]}" } }
                        }
                    }
                }
            }
        }
    }
}

/// Lock-on reticle drawn in scene space at the target.
#[component]
fn Reticle(x: f64, y: f64, #[props(default = false)] breach: bool) -> Element {
    let label = format!("X{:04.0} Y{:04.0}", x, y);
    rsx! {
        g { class: if breach { "reticle breach" } else { "reticle" }, transform: "translate({x:.1} {y:.1})",
            g { class: "ret-in",
                line { class: "xh", x1: "-600", y1: "0", x2: "-64", y2: "0" }
                line { class: "xh", x1: "64", y1: "0", x2: "600", y2: "0" }
                line { class: "xh", x1: "0", y1: "-600", x2: "0", y2: "-64" }
                line { class: "xh", x1: "0", y1: "92", x2: "0", y2: "600" }
                circle { class: "ret-ring", r: "58" }
                path { class: "ret-br", d: "M-46 -30 V-46 H-30 M30 -46 H46 V-30 M46 30 V46 H30 M-30 46 H-46 V30" }
                text { class: "ret-t", x: "66", y: "-6", "LOCK ", tspan { class: "jp", "標的捕捉" } }
                text { class: "ret-c", x: "66", y: "16", "{label}" }
            }
        }
    }
}

#[component]
pub fn NetworkMap(
    result: ScanResult,
    hovered: Signal<Option<usize>>,
    focus: Option<usize>,
    intel: Signal<HashMap<String, IntelSession>>,
    on_target: EventHandler<usize>,
    #[props(default = false)] breach: bool,
    #[props(default = false)] muted: bool,
) -> Element {
    let mut hovered = hovered;
    let net = &result.network;
    let devs = &result.devices;
    let placed = layout::layout(devs);
    let router = layout::router_index(devs);
    let sc = layout::node_scale(placed.len());
    let net_id = devs.len(); // pseudo index for the internet node
    let router_id = router.unwrap_or(devs.len() + 1);
    let hot = hovered();
    let is_inet = hot == Some(net_id);
    let sessions = intel.read();

    // Camera / target.
    let target_pos = focus.and_then(|f| {
        if Some(f) == router {
            Some((CX, CY))
        } else {
            placed.iter().find(|p| p.idx == f).map(|p| (p.x, p.y))
        }
    });
    let (cam_s, cam_t) = match target_pos {
        Some(p) => (ZOOM, camera_for(p, ZOOM)),
        None => (1.0, (0.0, 0.0)),
    };
    let tp = target_pos.unwrap_or((CX, CY));
    let focused = target_pos.is_some();
    let ice_prog = focus
        .and_then(|f| devs.get(f))
        .and_then(|d| sessions.get(&d.ip))
        .map(super::intrusion::ice_progress)
        .unwrap_or([0; 4]);
    let target_is_router = focus.is_some() && focus == router;

    let mut counts: Vec<(DeviceKind, usize)> = vec![];
    for p in &placed {
        let k = devs[p.idx].kind;
        match counts.iter_mut().find(|(c, _)| *c == k) {
            Some(e) => e.1 += 1,
            None => counts.push((k, 1)),
        }
    }

    let edges_svg: String = {
        let mut s = pulses(NET_POS, (CX, CY), 0, None);
        for (i, p) in placed.iter().enumerate() {
            s += &pulses((CX, CY), (p.x, p.y), i + 1, devs[p.idx].rtt_ms);
        }
        s
    };

    let router_dev = router.map(|i| &devs[i]);
    let router_name = router_dev
        .map(|d| trunc(&d.label(), 20))
        .unwrap_or_else(|| "GATEWAY".into());
    let router_ip = router_dev
        .map(|d| d.ip.clone())
        .or(net.gateway_ip.clone())
        .unwrap_or_default();
    let public_ip = result.public_ip.clone().unwrap_or_else(|| "OFFLINE".into());
    let isp = result
        .isp
        .clone()
        .map(|s| trunc(&s, 34))
        .unwrap_or_else(|| "UPLINK UNKNOWN".into());

    // Detail panel content.
    let detail = hot.map(|h| {
        if h == net_id {
            let rows = vec![
                ("PUBLIC IP", public_ip.clone()),
                ("OPERATOR", result.isp.clone().unwrap_or_else(|| "—".into())),
            ];
            (
                "INTERNET".to_string(),
                (
                    icons::code(DeviceKind::Internet).0.to_string(),
                    icons::code(DeviceKind::Internet).1,
                ),
                rows,
                Vec::new(),
                false,
            )
        } else {
            let d = &devs[h.min(devs.len() - 1)];
            let mac = match (&d.mac, d.mac_randomized) {
                (Some(m), true) => format!("{m}  (private)"),
                (Some(m), false) => m.clone(),
                _ => "—".into(),
            };
            let os = os::guess(d, None);
            let intel_h = sessions.get(&d.ip).and_then(|s| s.intel.as_ref());
            let cl = eff_class(d, intel_h);
            let kind_h = intel_h.and_then(|i| i.kind).unwrap_or(d.kind);
            let code = icons::code(kind_h);
            let mut code_s = code.0.to_string();
            let mut cls_rows: Vec<(&'static str, String)> = Vec::new();
            if let Some(c) = cl {
                if c.confidence < UNCERTAIN {
                    code_s.push_str(" ·?");
                }
                let name = match &c.label {
                    Some(l) => format!("{} // {}", c.kind.name(), l),
                    None => c.kind.name().to_string(),
                };
                cls_rows.push(("CLASS", format!("{name} {}%", c.confidence)));
                if !c.reason.is_empty() {
                    cls_rows.push(("WHY", trunc(&c.reason, 48)));
                }
            }
            let rows = vec![
                ("IP", d.ip.clone()),
                (
                    "RTT",
                    d.rtt_ms
                        .map(|r| format!("{r:.1}ms"))
                        .unwrap_or_else(|| "—".into()),
                ),
                (
                    "TTL",
                    d.ttl.map(|t| t.to_string()).unwrap_or_else(|| "—".into()),
                ),
                (
                    "OS",
                    if os.confidence > 0 {
                        format!("{} {}%", os.label, os.confidence)
                    } else {
                        "—".into()
                    },
                ),
                ("MAC", mac),
                ("VENDOR", d.vendor.clone().unwrap_or_else(|| "—".into())),
                ("MODEL", d.model.clone().unwrap_or_else(|| "—".into())),
                (
                    "SERVICES",
                    if d.services.is_empty() {
                        "—".into()
                    } else {
                        d.services
                            .iter()
                            .map(|s| s.split('.').next().unwrap_or(s).trim_start_matches('_'))
                            .collect::<Vec<_>>()
                            .join(" ")
                    },
                ),
            ];
            (d.label(), (code_s, code.1), rows, cls_rows, d.is_self)
        }
    });

    rsx! {
        div { class: "map-screen",
            header { class: "hud",
                div { class: "brand",
                    Emblem { size: 40 }
                    div { class: "brand-text",
                        div { class: "brand-name", "NETSCAN" }
                        div { class: "brand-sub", span { class: "jp", "荒坂" }, " SEC-OPS // ", span { class: "jp", "ネットワーク" } }
                    }
                }
                div { class: "hud-cells",
                    div { class: "cell", span { class: "k", "INTERFACE" } span { class: "v", "{net.interface}" } }
                    div { class: "cell", span { class: "k", "SUBNET" } span { class: "v", "{net.subnet_cidr}" } }
                    div { class: "cell", span { class: "k", "LOCAL IP" } span { class: "v", "{net.local_ip}" } }
                    div { class: "cell", span { class: "k", "GATEWAY" } span { class: "v", "{net.gateway_ip.clone().unwrap_or_else(|| \"—\".into())}" } }
                    div { class: "cell count", span { class: "k", span { class: "jp", "端末 " } "NODES" } span { class: "v big", "{devs.len()}" } }
                }
            }

            div { class: "map-stage",
                svg { class: if breach { "map focused breach" } else if focused { "map focused" } else { "map" }, view_box: "0 0 {W} {H}", preserve_aspect_ratio: "xMidYMid meet",
                    defs {
                        mask { id: "dim-mask", mask_units: "userSpaceOnUse", x: "-1500", y: "-1500", width: "4500", height: "4000",
                            rect { x: "-1500", y: "-1500", width: "4500", height: "4000", fill: "#fff" }
                            rect { x: "{tp.0 - 66.0}", y: "{tp.1 - 66.0}", width: "132", height: "152", rx: "34", fill: "#000" }
                        }
                    }
                    g { class: "camera", style: "transform: translate({cam_t.0:.1}px, {cam_t.1:.1}px) scale({cam_s})",
                    // range rings
                    g { class: "rings",
                        circle { cx: "{CX}", cy: "{CY}", r: "120" }
                        circle { cx: "{CX}", cy: "{CY}", r: "250" }
                        circle { cx: "{CX}", cy: "{CY}", r: "380" }
                        line { x1: "{CX}", y1: "40", x2: "{CX}", y2: "{H - 20.0}" }
                        line { x1: "20", y1: "{CY}", x2: "{W - 20.0}", y2: "{CY}" }
                    }
                    // links
                    g { class: "edges",
                        line { class: if target_is_router { "edge net trace" } else if hot == Some(net_id) { "edge net hot" } else { "edge net" },
                            x1: "{NET_POS.0}", y1: "{NET_POS.1}", x2: "{CX}", y2: "{CY}" }
                        for p in placed.iter() {
                            line { class: if focus == Some(p.idx) { "edge trace" } else if hot == Some(p.idx) { "edge hot" } else { "edge" },
                                x1: "{CX}", y1: "{CY}", x2: "{p.x}", y2: "{p.y}" }
                        }
                    }
                    g { class: "pulses", dangerous_inner_html: "{edges_svg}" }

                    // internet node
                    g { transform: "translate({NET_POS.0} {NET_POS.1})",
                        onmouseenter: move |_| hovered.set(Some(net_id)),
                        onmouseleave: move |_| hovered.set(None),
                        g { class: "node-body net", style: "--i:0",
                            circle { class: "hit", r: "44" }
                            polygon { class: "frame", points: "{OCT}" }
                            Icon { kind: DeviceKind::Internet, scale: 0.85 }
                            text { class: "lbl-kind", x: "52", y: "-6", text_anchor: "start", "INTERNET  外部" }
                            text { class: "lbl-name", x: "52", y: "10", text_anchor: "start", "{public_ip}" }
                            text { class: "lbl-sub", x: "52", y: "24", text_anchor: "start", "{isp}" }
                        }
                    }

                    // router
                    g { transform: "translate({CX} {CY})",
                        onmouseenter: move |_| hovered.set(Some(router_id)),
                        onmouseleave: move |_| hovered.set(None),
                        onclick: move |_| { if let Some(r) = router { on_target.call(r) } },
                        g { class: "node-body router", style: "--i:1",
                            circle { class: "hit", r: "58" }
                            circle { class: "halo h1", r: "54" }
                            circle { class: "halo h2", r: "66" }
                            polygon { class: "frame", points: "{OCT}", transform: "scale(1.5)" }
                            Icon { kind: DeviceKind::Router, scale: 1.15 }
                            if let Some(n) = router.and_then(|r| scanned_open(&sessions, &devs[r].ip)) {
                                Chip { n, x: 40.0, y: -40.0 }
                            }
                            text { class: "lbl-kind", y: "76", "GATEWAY  中枢" }
                            text { class: "lbl-name", y: "92", "{router_name}" }
                            text { class: "lbl-sub", y: "106", "{router_ip}" }
                        }
                    }

                    // devices
                    for (k, p) in placed.iter().enumerate() {
                        {
                            let d = &devs[p.idx];
                            let idx = p.idx;
                            let name = trunc(&d.label(), 15);
                            let sess = sessions.get(&d.ip).filter(|s| s.intel.is_some());
                            let og = match sess.and_then(|s| s.intel.as_ref()) {
                                Some(i) if i.os.confidence > 0 => i.os.clone(),
                                _ => os::guess(d, None),
                            };
                            let kind = sess.and_then(|s| s.intel.as_ref()).and_then(|i| i.kind).unwrap_or(d.kind);
                            let reclass = kind != d.kind;
                            let ncl = eff_class(d, sess.and_then(|s| s.intel.as_ref()));
                            let unsure = ncl.is_some_and(|c| c.confidence < UNCERTAIN);
                            let chip_n = sess.map(|s| s.open_count());
                            let os_tag = (og.confidence >= 40 && og.short != "---").then(|| og.short.clone());
                            let cls = match (d.is_self, hot == Some(idx), unsure) {
                                (true, true, _) => "node-body me on",
                                (true, false, _) => "node-body me",
                                (false, true, true) => "node-body on uncertain",
                                (false, true, false) => "node-body on",
                                (false, false, true) => "node-body uncertain",
                                _ => "node-body",
                            };
                            rsx! {
                                g { key: "{d.ip}", transform: "translate({p.x:.1} {p.y:.1}) scale({sc})",
                                    onmouseenter: move |_| hovered.set(Some(idx)),
                                    onmouseleave: move |_| hovered.set(None),
                                    onclick: move |_| on_target.call(idx),
                                    g { class: "{cls}", style: "--i:{(k + 2).min(14)}",
                                        circle { class: "hit", r: "40" }
                                        if d.is_self {
                                            g { class: "me-brackets",
                                                path { d: "M-40 -22 V-40 H-22 M22 -40 H40 V-22 M40 22 V40 H22 M-22 40 H-40 V22" }
                                            }
                                        }
                                        polygon { class: "frame", points: "{OCT}" }
                                        if chip_n.is_some() { polygon { class: "frame2", points: "{OCT2}" } }
                                        g { key: "{kind:?}", class: if reclass { "reclass" } else { "" },
                                            Icon { kind, scale: 0.72 }
                                        }
                                        if let Some(n) = chip_n { Chip { n, x: 22.0, y: -22.0 } }
                                        if unsure && !d.is_self { text { class: "unsure", x: "19", y: "26", "?" } }
                                        if d.is_self {
                                            g { class: "you", transform: "translate(0 -52)",
                                                polygon { points: "-34,-9 30,-9 36,-3 36,9 -30,9 -36,3" }
                                                text { y: "4", text_anchor: "middle", "YOU 本機" }
                                            }
                                        }
                                        text { class: "lbl-name", y: "50", "{name}" }
                                        text { class: "lbl-sub", y: "63",
                                            if let Some(t) = os_tag { tspan { class: "os", "{t} · " } }
                                            "{d.ip}"
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // targeting
                    rect { class: if focused { "dimmask on" } else { "dimmask" }, x: "-1500", y: "-1500", width: "4500", height: "4000", mask: "url(#dim-mask)" }
                    if let Some(f) = focus {
                        if focused {
                            Reticle { key: "{f}", x: tp.0, y: tp.1, breach }
                            if breach {
                                Ice { x: tp.0, y: tp.1, prog: ice_prog }
                            }
                        }
                    }
                    }
                }
            }

            footer { class: if focused { "legend off" } else { "legend" },
                span { class: "status", span { class: "dot" } "LINK SECURE  " span { class: "jp", "接続" } }
                if let Some((title, (code, jp), rows, cls_rows, is_self)) = detail {
                    div { class: "readout",
                        div { class: "ro-head",
                            span { class: "ro-code", "{code}", span { class: "jp", " {jp}" } }
                            span { class: "ro-title", "{title}" }
                            if is_self { span { class: "d-you", "YOU 本機" } }
                            if !is_inet { span { class: "ro-hint", "CLICK ▸ BREACH ", span { class: "jp", "侵入" } } }
                        }
                        if !cls_rows.is_empty() {
                            div { class: "ro-rows cls",
                                for (k, v) in cls_rows.into_iter() {
                                    span { class: "ro-cell {k.to_lowercase()}", span { class: "k", "{k}" } span { class: "v", "{v}" } }
                                }
                            }
                        }
                        div { class: "ro-rows",
                            for (k, v) in rows.into_iter().filter(|r| r.1 != "—") {
                                span { class: "ro-cell", span { class: "k", "{k}" } span { class: "v", "{v}" } }
                            }
                        }
                    }
                } else {
                    div { class: "legend-items",
                        for (kind, n) in counts {
                            span { class: "lg",
                                svg { width: "18", height: "18", view_box: "-24 -24 48 48",
                                    g { class: "icon", for d in icons::paths(kind) { path { d: "{d}" } } }
                                }
                                "{icons::code(kind).0}"
                                b { " ×{n}" }
                            }
                        }
                    }
                }
                span { class: "status dim audio", "M ▸ AUDIO " b { if muted { "OFF" } else { "ON" } } }
                span { class: "status dim", "SCAN COMPLETE" span { class: "cursor" } }
            }
        }
    }
}

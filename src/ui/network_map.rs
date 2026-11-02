use super::icons;
use super::layout::{self, CX, CY, H, NET_POS, W};
use super::loading::Emblem;
use crate::scan::model::*;
use dioxus::prelude::*;

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() } else { format!("{}…", s.chars().take(n - 1).collect::<String>()) }
}

/// SMIL pulses travelling both ways along an edge.
fn pulses(a: (f64, f64), b: (f64, f64), seed: usize) -> String {
    let dur = 2.2 + (seed % 5) as f64 * 0.37;
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

const OCT: &str = "-12,-31 12,-31 31,-12 31,12 12,31 -12,31 -31,12 -31,-12";

#[component]
fn Icon(kind: DeviceKind, scale: f64) -> Element {
    rsx! {
        g { class: "icon", transform: "scale({scale})",
            for d in icons::paths(kind) { path { d: "{d}" } }
        }
    }
}

#[component]
pub fn NetworkMap(result: ScanResult, hovered: Signal<Option<usize>>) -> Element {
    let mut hovered = hovered;
    let net = &result.network;
    let devs = &result.devices;
    let placed = layout::layout(devs);
    let router = layout::router_index(devs);
    let sc = layout::node_scale(placed.len());
    let net_id = devs.len(); // pseudo index for the internet node
    let router_id = router.unwrap_or(devs.len() + 1);
    let hot = hovered();

    let mut counts: Vec<(DeviceKind, usize)> = vec![];
    for p in &placed {
        let k = devs[p.idx].kind;
        match counts.iter_mut().find(|(c, _)| *c == k) {
            Some(e) => e.1 += 1,
            None => counts.push((k, 1)),
        }
    }

    let edges_svg: String = {
        let mut s = pulses(NET_POS, (CX, CY), 0);
        for (i, p) in placed.iter().enumerate() {
            s += &pulses((CX, CY), (p.x, p.y), i + 1);
        }
        s
    };

    let router_dev = router.map(|i| &devs[i]);
    let router_name = router_dev.map(|d| trunc(&d.label(), 20)).unwrap_or_else(|| "GATEWAY".into());
    let router_ip = router_dev.map(|d| d.ip.clone()).or(net.gateway_ip.clone()).unwrap_or_default();
    let public_ip = result.public_ip.clone().unwrap_or_else(|| "OFFLINE".into());
    let isp = result.isp.clone().map(|s| trunc(&s, 34)).unwrap_or_else(|| "UPLINK UNKNOWN".into());

    // Detail panel content.
    let detail = hot.map(|h| {
        if h == net_id {
            let rows = vec![
                ("PUBLIC IP", public_ip.clone()),
                ("OPERATOR", result.isp.clone().unwrap_or_else(|| "—".into())),
            ];
            ("INTERNET".to_string(), icons::code(DeviceKind::Internet), rows, false)
        } else {
            let d = &devs[h.min(devs.len() - 1)];
            let mac = match (&d.mac, d.mac_randomized) {
                (Some(m), true) => format!("{m}  (private)"),
                (Some(m), false) => m.clone(),
                _ => "—".into(),
            };
            let rows = vec![
                ("IP", d.ip.clone()),
                ("MAC", mac),
                ("VENDOR", d.vendor.clone().unwrap_or_else(|| "—".into())),
                ("MODEL", d.model.clone().unwrap_or_else(|| "—".into())),
                ("SERVICES", if d.services.is_empty() { "—".into() } else { d.services.iter().map(|s| s.split('.').next().unwrap_or(s).trim_start_matches('_')).collect::<Vec<_>>().join(" ") }),
            ];
            (d.label(), icons::code(d.kind), rows, d.is_self)
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
                svg { class: "map", view_box: "0 0 {W} {H}", preserve_aspect_ratio: "xMidYMid meet",
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
                        line { class: if hot == Some(net_id) { "edge net hot" } else { "edge net" },
                            x1: "{NET_POS.0}", y1: "{NET_POS.1}", x2: "{CX}", y2: "{CY}" }
                        for p in placed.iter() {
                            line { class: if hot == Some(p.idx) { "edge hot" } else { "edge" },
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
                        g { class: "node-body router", style: "--i:1",
                            circle { class: "hit", r: "58" }
                            circle { class: "halo h1", r: "54" }
                            circle { class: "halo h2", r: "66" }
                            polygon { class: "frame", points: "{OCT}", transform: "scale(1.5)" }
                            Icon { kind: DeviceKind::Router, scale: 1.15 }
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
                            let cls = match (d.is_self, hot == Some(idx)) {
                                (true, true) => "node-body me on",
                                (true, false) => "node-body me",
                                (false, true) => "node-body on",
                                _ => "node-body",
                            };
                            rsx! {
                                g { key: "{d.ip}", transform: "translate({p.x:.1} {p.y:.1}) scale({sc})",
                                    onmouseenter: move |_| hovered.set(Some(idx)),
                                    onmouseleave: move |_| hovered.set(None),
                                    g { class: "{cls}", style: "--i:{(k + 2).min(14)}",
                                        circle { class: "hit", r: "40" }
                                        if d.is_self {
                                            g { class: "me-brackets",
                                                path { d: "M-40 -22 V-40 H-22 M22 -40 H40 V-22 M40 22 V40 H22 M-22 40 H-40 V22" }
                                            }
                                        }
                                        polygon { class: "frame", points: "{OCT}" }
                                        Icon { kind: d.kind, scale: 0.72 }
                                        if d.is_self {
                                            g { class: "you", transform: "translate(0 -52)",
                                                polygon { points: "-34,-9 30,-9 36,-3 36,9 -30,9 -36,3" }
                                                text { y: "4", text_anchor: "middle", "YOU 本機" }
                                            }
                                        }
                                        text { class: "lbl-name", y: "50", "{name}" }
                                        text { class: "lbl-sub", y: "63", "{d.ip}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            footer { class: "legend",
                span { class: "status", span { class: "dot" } "LINK SECURE  " span { class: "jp", "接続" } }
                if let Some((title, (code, jp), rows, is_self)) = detail {
                    div { class: "readout",
                        div { class: "ro-head",
                            span { class: "ro-code", "{code}", span { class: "jp", " {jp}" } }
                            span { class: "ro-title", "{title}" }
                            if is_self { span { class: "d-you", "YOU 本機" } }
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
                span { class: "status dim", "SCAN COMPLETE" span { class: "cursor" } }
            }
        }
    }
}

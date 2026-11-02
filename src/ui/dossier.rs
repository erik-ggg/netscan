//! "TARGET PROFILE // 標的記録": modal dossier that fills live from an `IntelSession`.

use super::icons;
use super::intrusion::{DecodeText, seed_for};
use super::link::{LinkConfig, proto_name};
use super::session::IntelSession;
use crate::link::{self, LinkRequest, plan::Readiness, tools::Tools};
use crate::scan::intel::ports::{self, PORTS};
use crate::scan::model::*;
use crate::scan::os;
use dioxus::prelude::*;

fn risk_level(r: Risk) -> usize {
    match r {
        Risk::Info => 1,
        Risk::Low => 2,
        Risk::Medium => 3,
        Risk::High => 4,
    }
}

fn risk_name(r: Risk) -> &'static str {
    match r {
        Risk::Info => "INFO",
        Risk::Low => "LOW",
        Risk::Medium => "MEDIUM",
        Risk::High => "HIGH",
    }
}

fn risk_cls(r: Risk) -> &'static str {
    match r {
        Risk::Info => "r-info",
        Risk::Low => "r-low",
        Risk::Medium => "r-med",
        Risk::High => "r-high",
    }
}

fn dash(o: &Option<String>) -> String {
    o.clone().unwrap_or_else(|| "---".into())
}

/// One labelled value line; the value ellipsizes.
#[component]
fn Row(k: &'static str, v: String, #[props(default = false)] dim: bool) -> Element {
    let cls = if dim || v == "---" {
        "dz-v dim"
    } else {
        "dz-v"
    };
    let n = v.chars().count().clamp(1, 60);
    rsx! { div { class: "dz-row", span { class: "dz-k", "{k}" } span { class: "{cls} tw", style: "--n:{n}", title: "{v}", "{v}" } } }
}

/// Framed section. `pending` swaps the body for the decrypting shimmer; `empty` for the no-signal state.
#[component]
fn Section(
    n: &'static str,
    title: &'static str,
    jp: &'static str,
    #[props(default = String::new())] tag: String,
    pending: bool,
    #[props(default = false)] empty: bool,
    #[props(default = "NO SIGNAL")] empty_text: &'static str,
    #[props(default = "無信号")] empty_jp: &'static str,
    #[props(default = "")] class: &'static str,
    children: Element,
) -> Element {
    let state = if pending {
        "pending"
    } else if empty {
        "empty"
    } else {
        "ready"
    };
    rsx! {
        section { class: "dz-sec {state} {class}", style: "--s:{n.trim_start_matches('0')}",
            div { class: "dz-sh",
                span { class: "dz-n", "{n}" }
                span { class: "dz-st", "{title} " span { class: "jp", "{jp}" } }
                if !tag.is_empty() { span { class: "dz-tag", "{tag}" } }
            }
            div { class: "dz-body",
                if pending {
                    div { class: "dz-pend", span { class: "shim" } "DECRYPTING… " span { class: "jp", "復号中" } }
                } else if empty {
                    div { class: "dz-empty", "{empty_text} // " span { class: "jp", "{empty_jp}" } }
                } else {
                    {children}
                }
            }
        }
    }
}

fn fmt_ms(v: f32) -> String {
    format!("{v:.1}")
}

/// `+87 TEXT` evidence line; the winner's lines are bright, the rest dim with a kind tag.
fn ev_line(e: &Evidence, win: DeviceKind) -> Element {
    let own = e.kind == win;
    let tag = if own {
        String::new()
    } else {
        format!("[{}] ", icons::code(e.kind).0)
    };
    rsx! {
        div { class: if own { "ev cls win" } else { "ev cls" }, title: "{e.text}",
            b { "+{e.weight}" } " {tag}{e.text}"
        }
    }
}

fn conf_bar(c: u8) -> Element {
    let on = (c as usize).div_ceil(20).min(5);
    rsx! {
        span { class: "conf",
            for i in 0..5 { i { class: if i < on { "on" } else { "" } } }
        }
    }
}

/// Hex dump of the target's own facts (address, names, banners, open ports, timing), padded with
/// a deterministic keystream so the panel always reads as a full capture. Decorative.
fn hexdump(d: &Device, session: &IntelSession, rows: usize) -> String {
    let mut b: Vec<u8> = vec![];
    b.extend(d.ip.split('.').filter_map(|o| o.parse::<u8>().ok()));
    if let Some(m) = &d.mac {
        b.extend(m.split(':').filter_map(|h| u8::from_str_radix(h, 16).ok()));
    }
    for t in [&d.hostname, &d.vendor, &d.model].into_iter().flatten() {
        b.extend(t.bytes());
        b.push(0);
    }
    if let Some(i) = &session.intel {
        for h in &i.http {
            b.extend(h.port.to_be_bytes());
            b.extend(
                h.server
                    .iter()
                    .chain(h.title.iter())
                    .flat_map(|t| t.bytes()),
            );
            b.push(0);
        }
        for bn in &i.banners {
            b.extend(bn.text.bytes());
            b.push(0);
        }
    }
    for (p, st) in &session.ports {
        if *st == PortState::Open {
            b.extend(p.to_be_bytes());
        }
    }
    let mut x = seed_for(d);
    let mut out = String::new();
    for r in 0..rows {
        let mut row = [0u8; 16];
        for (k, c) in row.iter_mut().enumerate() {
            *c = match b.get(r * 16 + k) {
                Some(v) => *v,
                None => {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                }
            };
        }
        out += &format!("{:04X}  ", r * 16);
        for (k, c) in row.iter().enumerate() {
            out += &format!("{c:02X}");
            out.push(if k % 2 == 1 { ' ' } else { '\u{0}' });
        }
        out = out.replace('\u{0}', "");
        out.push(' ');
        out.extend(row.iter().map(|&c| {
            if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                '.'
            }
        }));
        out.push('\n');
    }
    out
}

/// Decorative carrier waveform: seeded noise whose amplitude follows the measured latency.
fn carrier(d: &Device, avg_ms: f32) -> String {
    let mut x = seed_for(d);
    let amp = (6.0 + avg_ms.min(40.0) * 0.6) as f64;
    let mut path = String::from("M0 30");
    let mut v = 0.0f64;
    for i in 1..=100 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let n = (x % 2000) as f64 / 1000.0 - 1.0;
        v = v * 0.55 + n * amp * 0.9;
        let env = ((i as f64 / 100.0) * std::f64::consts::PI).sin().max(0.25);
        path += &format!(" L{} {:.1}", i * 2, 30.0 + v * env);
    }
    path
}

#[component]
pub fn Dossier(
    device: Device,
    session: IntelSession,
    closing: bool,
    on_close: EventHandler<()>,
    on_rescan: EventHandler<()>,
    network: NetworkInfo,
    tools: Tools,
    cfg_open: bool,
    on_cfg: EventHandler<bool>,
    on_connect: EventHandler<(LinkRequest, Option<String>)>,
    on_recheck: EventHandler<()>,
) -> Element {
    let intel = session.intel.as_ref();
    let lplans = link::plan::plans(&device, intel, &tools);
    let top_plan = lplans.first().cloned();
    let link_ready = top_plan
        .as_ref()
        .is_some_and(|p| p.readiness == Readiness::Ready && p.proto != link::Proto::Local);
    let link_label = top_plan
        .as_ref()
        .map(|p| proto_name(p.proto))
        .unwrap_or("LOCAL");
    let done = session.done;
    let dark = session.is_dark();
    let cls = super::network_map::eff_class(&device, intel).cloned();
    let kind = intel.and_then(|i| i.kind).unwrap_or(device.kind);
    let (kcode, kjp) = icons::code(kind);
    let og = match intel {
        Some(i) if i.os.confidence > 0 => i.os.clone(),
        _ => os::guess(&device, None),
    };
    let fp_ready = session.fingerprinted();
    let lat_ready = !session.ports.is_empty() || done;

    // --- header facts
    let name = device.label();
    let mac = match (&device.mac, device.mac_randomized) {
        (Some(m), true) => format!("{m} (private)"),
        (Some(m), false) => m.clone(),
        _ => "---".into(),
    };
    let ping = intel.and_then(|i| i.ping.as_ref());
    let rtt_line = match ping {
        Some(p) if p.recv > 0 => format!(
            "{}/{}/{} ms",
            fmt_ms(p.min_ms),
            fmt_ms(p.avg_ms),
            fmt_ms(p.max_ms)
        ),
        // Deep echoes all lost: the sweep RTT is the only number; say where it came from.
        Some(_) => device
            .rtt_ms
            .map(|r| format!("{} ms (SWEEP)", fmt_ms(r)))
            .unwrap_or_else(|| "---".into()),
        None => device
            .rtt_ms
            .map(|r| format!("{} ms", fmt_ms(r)))
            .unwrap_or_else(|| "---".into()),
    };
    let ttl = ping
        .and_then(|p| p.ttl)
        .or(device.ttl)
        .map(|t| t.to_string())
        .unwrap_or_else(|| "---".into());
    let secs = intel
        .map(|i| format!("{:.2}s", i.elapsed_ms as f32 / 1000.0))
        .unwrap_or_else(|| "…".into());
    let (status_cls, status_txt, status_jp) = if dark {
        ("dark", "TARGET DARK".to_string(), "無応答")
    } else if done {
        ("ok", "SCAN COMPLETE".to_string(), "完了")
    } else {
        ("live", format!("LIVE SCAN {}%", session.pct), "走査中")
    };
    let expo = intel.filter(|_| done).map(|i| i.exposure);

    // --- signal
    let samples: Vec<Option<f32>> = match ping {
        Some(p) if !p.samples.is_empty() => p.samples.clone(),
        _ => session.echoes.clone(),
    };
    let max_s = samples.iter().flatten().cloned().fold(0.1f32, f32::max);
    let recv = samples.iter().flatten().count();
    let avg = if recv > 0 {
        samples.iter().flatten().sum::<f32>() / recv as f32
    } else {
        0.0
    };
    let ttl_hint = match ttl.parse::<u8>().ok() {
        Some(t) if t <= 64 => "UNIX-LIKE STACK",
        Some(t) if t <= 128 => "WINDOWS-LIKE STACK",
        Some(_) => "NETWORK / RTOS STACK",
        None => "",
    };
    let svc_list: Vec<String> = device
        .services
        .iter()
        .map(|s| {
            s.split('.')
                .next()
                .unwrap_or(s)
                .trim_start_matches('_')
                .to_uppercase()
        })
        .collect();

    // --- lattice
    let cell = |port: u16| -> &'static str {
        let st = intel
            .and_then(|i| i.ports.iter().find(|p| p.port == port).map(|p| p.state))
            .or_else(|| session.ports.iter().find(|p| p.0 == port).map(|p| p.1));
        match st {
            Some(PortState::Open) => "c open",
            Some(PortState::Closed) => "c closed",
            Some(PortState::Filtered) => "c filt",
            None => "c wait",
        }
    };
    let open_ports: Vec<PortInfo> = {
        let mut v: Vec<PortInfo> = match intel {
            Some(i) if !i.ports.is_empty() => i
                .ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .cloned()
                .collect(),
            _ => session
                .ports
                .iter()
                .filter(|p| p.1 == PortState::Open)
                .map(|p| ports::info(p.0, p.1))
                .collect(),
        };
        v.sort_by_key(|p| p.port);
        v
    };
    let scanned = session
        .ports
        .len()
        .max(intel.map(|i| i.ports.len()).unwrap_or(0));
    let open_n = open_ports.len();

    // --- web + banners
    let http: Vec<HttpFingerprint> = intel.map(|i| i.http.clone()).unwrap_or_default();
    let banners: Vec<Banner> = intel.map(|i| i.banners.clone()).unwrap_or_default();
    let up = intel.and_then(|i| i.upnp.clone()).or(device.upnp.clone());
    let nb = intel.and_then(|i| i.netbios.clone());
    let notes: Vec<Note> = intel.map(|i| i.notes.clone()).unwrap_or_default();
    let probes = http.len() + banners.len();
    let reclass_txt = intel.and_then(|i| i.kind_reason.clone());
    let reclassified = intel.is_some_and(|i| i.kind.is_some_and(|k| k != device.kind));
    let tip = cls
        .as_ref()
        .map(|c| {
            c.evidence
                .iter()
                .map(|e| format!("+{} {}", e.weight, e.text))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let hex_rows = 40;
    let logtxt = session
        .log
        .iter()
        .filter(|l| !l.contains("CLOSED") && !l.contains("FILTERED"))
        .enumerate()
        .map(|(i, l)| format!("{:03} {l}", i))
        .collect::<Vec<_>>()
        .join("\n");
    let wave = carrier(&device, avg);
    let hex = hexdump(&device, &session, hex_rows);
    let wrap = if closing {
        "dz-wrap closing"
    } else {
        "dz-wrap"
    };

    rsx! {
        div { class: "{wrap}", onclick: move |_| on_close.call(()),
            if !closing { div { class: "ix-sweep" } }
            div { class: "dossier", onclick: move |e| e.stop_propagation(),
                div { class: "dz-top",
                    span { class: "dz-title", DecodeText { text: "TARGET PROFILE".to_string(), ms: 480 } " " span { class: "jp", "標的記録" } }
                    span { class: "dz-ip", "{device.ip}" }
                    span { class: "dz-scan", "SCAN {secs}" }
                    if link_ready { button { class: "dz-chip", onclick: move |_| on_cfg.call(true), span { class: "dot" } "LINK READY \u{25B8} {link_label}" } }
                    span { class: "dz-status {status_cls}", span { class: "dot" } "{status_txt} " span { class: "jp", "{status_jp}" } }
                    button { class: "dz-close", onclick: move |_| on_close.call(()), "[ESC] DISCONNECT " span { class: "jp", "切断" } }
                }
                div { class: "dz-id",
                    div { class: "dz-icon",
                        svg { view_box: "-26 -26 52 52",
                            g { key: "{kind:?}", class: if reclassified { "icon reclass" } else { "icon" },
                                for d in icons::paths(kind) { path { d: "{d}" } }
                            }
                        }
                    }
                    div { class: "dz-who",
                        h2 { class: "dz-name", DecodeText { text: name.clone(), ms: 640 } }
                        div { class: "dz-line",
                            span { "{device.ip}" }
                            span { "{mac}" }
                            if let Some(v) = &device.vendor { span { "{v}" } }
                        }
                        div { class: "dz-line facts",
                            span { class: "f", span { class: "dz-k", "OS" } b { "{og.label}" } {conf_bar(og.confidence)} span { class: "dim", if done { "{og.confidence}%" } else { "{og.confidence}% PRELIM" } } }
                            span { class: "f", span { class: "dz-k", "RTT" } b { "{rtt_line}" } }
                            span { class: "f", span { class: "dz-k", "TTL" } b { "{ttl}" } }
                        }
                    }
                    div { class: "dz-kind",
                        div { class: "dz-kcode", "{kcode} " span { class: "jp", "{kjp}" } }
                        if let Some(c) = &cls {
                            if let Some(l) = &c.label { div { class: "dz-klabel", "{l}" } }
                            div { class: if c.confidence < super::network_map::UNCERTAIN { "dz-kconf unsure" } else { "dz-kconf" },
                                {conf_bar(c.confidence)} b { "{c.confidence}%" }
                                if c.confidence < super::network_map::UNCERTAIN { span { class: "q", "?" } }
                            }
                            div { class: "dz-reclass", title: "{tip}",
                                if reclassified { "◂ " }
                                "{c.reason}"
                            }
                        } else if reclassified {
                            div { class: "dz-reclass", "◂ RECLASSIFIED " if let Some(r) = &reclass_txt { span { "({r})" } } }
                        }
                    }
                    div { class: "dz-expo",
                        span { class: "dz-k", "EXPOSURE " span { class: "jp", "露出" } }
                        if let Some(r) = expo {
                            div { class: "meter4 {risk_cls(r)}",
                                for i in 0..4 { i { class: if i < risk_level(r) { "on" } else { "" } } }
                            }
                            span { class: "dz-elabel {risk_cls(r)}", "{risk_name(r)}" }
                        } else {
                            div { class: "meter4", for _ in 0..4 { i {} } }
                            span { class: "dz-elabel dim", "PENDING" }
                        }
                    }
                }

                if dark {
                    div { class: "dz-dark", span { class: "x", "▲" } "TARGET DARK " span { class: "jp", "無応答" } span { class: "m", "NO ANSWER TO ECHO OR PORT PROBES // SHOWING SWEEP FACTS ONLY" } }
                }
                div { class: "dz-cols",
                    // ---- column 1
                    div { class: "dz-col",
                        Section { n: "01", title: "IDENTITY", jp: "識別", pending: false,
                            Row { k: "NAME", v: name.clone() }
                            Row { k: "HOST", v: dash(&device.hostname) }
                            Row { k: "MAKER", v: dash(&device.vendor) }
                            Row { k: "MODEL", v: dash(&device.model) }
                            Row { k: "MAC", v: mac.clone() }
                            Row { k: "KIND", v: format!("{kcode} {kjp}") }
                            Row { k: "ROLE", v: if device.is_self { "THIS MACHINE 本機".to_string() } else if device.is_gateway { "GATEWAY 中枢".into() } else { "LAN HOST".into() } }
                            if !svc_list.is_empty() { Row { k: "ADVERT", v: svc_list.join(" ") } }
                            if fp_ready { Row { k: "NETBIOS", v: nb.as_ref().map(|n| match &n.group { Some(g) => format!("{} / {g}", n.name), None => n.name.clone() }).unwrap_or_else(|| "---".into()) } }
                        }
                        Section { n: "02", title: "SIGNAL", jp: "信号", pending: samples.is_empty() && !done, empty: recv == 0, tag: format!("{recv}/{} ECHO", samples.len().max(4)),
                            div { class: "spark",
                                for s in samples.iter() {
                                    match s {
                                        Some(v) => rsx! { i { style: "height:{(v / max_s * 100.0).max(12.0):.0}%" } },
                                        None => rsx! { i { class: "lost", style: "height:8%" } },
                                    }
                                }
                            }
                            Row { k: "AVG", v: if recv > 0 { format!("{avg:.1} ms") } else { "---".to_string() } }
                            Row { k: "TTL", v: if ttl_hint.is_empty() { ttl.clone() } else { format!("{ttl} → {ttl_hint}") } }
                        }
                        Section { n: "08", title: "SCAN LOG", jp: "記録", pending: false, class: "grow hex", tag: format!("{} EVT", session.log.len()),
                            pre { class: "hexd logv", "{logtxt}" }
                        }
                    }
                    // ---- column 2
                    div { class: "dz-col",
                        Section { n: "03", title: "PORT LATTICE", jp: "港湾", pending: !lat_ready, class: "lat", tag: format!("{open_n}/{} OPEN", PORTS.len()),
                            div { class: "lattice",
                                for (i, p) in PORTS.iter().enumerate() {
                                    div { key: "{p.port}", class: "{cell(p.port)}", style: "--i:{(i / 6) + (i % 6)}", title: "{p.port} {p.service}", "{p.port}" }
                                }
                            }
                            div { class: "plist",
                                for p in open_ports.iter() {
                                    div { key: "{p.port}", class: "pl {risk_cls(p.risk)}",
                                        b { "{p.port}" } span { class: "svc", "{p.service}" } span { class: "mean", "{p.meaning}" }
                                    }
                                }
                                if open_ports.is_empty() && done { div { class: "pl none", "NO OPEN PORTS IN PROBE SET // ", span { class: "jp", "閉鎖" } } }
                                if scanned < PORTS.len() && !done { div { class: "pl none", "SWEEPING {scanned}/{PORTS.len()}…" } }
                            }
                        }
                        Section { n: "04", title: "PROFILE", jp: "基盤", pending: false, tag: if done { String::new() } else { "PRELIMINARY".into() },
                            div { class: "os-main", span { class: "dz-k", "OS" } b { "{og.label}" } {conf_bar(og.confidence)} span { class: "dim", "{og.confidence}%" } }
                            if og.evidence.is_empty() { div { class: "dz-empty", "NO EVIDENCE // ", span { class: "jp", "無" } } }
                            for e in og.evidence.iter().take(if cls.is_some() { 2 } else { 6 }) { div { class: "ev", "· {e}" } }
                            if let Some(c) = &cls {
                                div { class: "os-main cl", span { class: "dz-k", "CLASS" }
                                    b { { match &c.label { Some(l) => format!("{} // {l}", c.kind.name()), None => c.kind.name().to_string() } } }
                                    {conf_bar(c.confidence)} span { class: "dim", "{c.confidence}%" } }
                                for e in c.evidence.iter().take(6) { {ev_line(e, c.kind)} }
                                if !c.alt.is_empty() {
                                    div { class: "ev alt", "ALT ▸ "
                                        { c.alt.iter().map(|(k, p)| format!("{} {p}%", k.name())).collect::<Vec<_>>().join("  ") } }
                                }
                            }
                        }
                        Section { n: "09", title: "PACKET TRACE", jp: "痕跡", pending: false, class: "grow hex", tag: format!("{} B", hex_rows * 16),
                            pre { class: "hexd", "{hex}" }
                        }
                    }
                    // ---- column 3
                    div { class: "dz-col",
                        Section { n: "05", title: "WEB SURFACE", jp: "表層", pending: !fp_ready, empty: http.is_empty() && banners.is_empty(), empty_text: "NO WEB SURFACE", empty_jp: "無", tag: format!("{probes} PROBES"),
                            for h in http.iter() {
                                div { key: "{h.port}", class: "web",
                                    div { class: "web-h", b { ":{h.port}" } span { if h.tls { "HTTPS" } else { "HTTP" } } span { class: "st", "{h.status}" }
                                        if let Some(t) = &h.title { span { class: "ttl", "\"{t}\"" } } }
                                    if let Some(s) = &h.server { div { class: "web-r", "SERVER " b { "{s}" } } }
                                    if let Some(s) = &h.powered_by { div { class: "web-r", "X-POWERED-BY " b { "{s}" } } }
                                    if let Some(s) = &h.auth_realm { div { class: "web-r", "AUTH REALM " b { "{s}" } } }
                                    if let Some(s) = &h.redirect { div { class: "web-r", "REDIRECT " b { "{s}" } } }
                                }
                            }
                            for b in banners.iter() {
                                div { key: "{b.port}{b.proto}", class: "web",
                                    div { class: "web-h", b { ":{b.port}" } span { "{b.proto}" } span { class: "ttl", "{b.text}" } }
                                }
                            }
                        }
                        Section { n: "06", title: "UPNP DESCRIPTOR", jp: "機器記述", pending: !fp_ready, empty: up.is_none(),
                            if let Some(u) = &up {
                                Row { k: "TYPE", v: dash(&u.device_type.as_ref().map(|t| t.rsplit(':').nth(1).unwrap_or(t).to_string())) }
                                Row { k: "NAME", v: dash(&u.friendly_name) }
                                Row { k: "MAKER", v: dash(&u.manufacturer) }
                                Row { k: "MODEL", v: dash(&u.model_name) }
                                Row { k: "SERVER", v: dash(&u.server) }
                            }
                        }
                        Section { n: "07", title: "EXPOSURE NOTES", jp: "脆弱性", pending: !done, empty: notes.is_empty(), empty_text: "NOTHING FLAGGED", empty_jp: "無",
                            for (i, n) in notes.iter().enumerate() {
                                div { key: "{i}", class: "note {risk_cls(n.risk)}",
                                    span { class: "nr", match n.risk { Risk::High => "▲▲ HIGH", Risk::Medium => "▲ MED", Risk::Low => "● LOW", Risk::Info => "● INFO" } }
                                    span { class: "nt", "{n.text}" }
                                }
                            }
                        }
                        Section { n: "10", title: "CARRIER TRACE", jp: "搬送波", pending: false, class: "grow scope", tag: if done { "LOCKED".to_string() } else { "ACQUIRING".to_string() },
                            svg { class: "scope-svg", view_box: "0 0 200 60", preserve_aspect_ratio: "none",
                                path { class: "sc-grid", d: "M0 15H200M0 30H200M0 45H200M50 0V60M100 0V60M150 0V60" }
                                path { class: "sc-wave", d: "{wave}" }
                            }
                        }
                    }
                }
                div { class: "dz-foot",
                    span { class: "sum", "{scanned} PORTS · {samples.len()} ECHOES · {probes} PROBES" }
                    span { class: "keys",
                        if done { button { class: "dz-btn", onclick: move |_| on_rescan.call(()), "[R] RE-SCAN " span { class: "jp", "再走査" } } }
                        button { class: if cfg_open { "dz-btn link on" } else if link_ready { "dz-btn link ready" } else { "dz-btn link" }, onclick: move |_| on_cfg.call(!cfg_open),
                            "[C] CONNECT " span { class: "jp", "接続" } " \u{25B8} {link_label}" }
                        span { "[ESC] DISCONNECT " span { class: "jp", "切断" } }
                    }
                    span { class: "sig", "0xA5C0 // ", span { class: "jp", "荒坂" }, " SEC-OPS" }
                }
                if cfg_open {
                    LinkConfig {
                        device: device.clone(),
                        intel: intel.cloned(),
                        network: network.clone(),
                        tools: tools.clone(),
                        on_connect: move |a| on_connect.call(a),
                        on_cancel: move |_| on_cfg.call(false),
                        on_recheck: move |_| on_recheck.call(()),
                    }
                }
            }
        }
    }
}

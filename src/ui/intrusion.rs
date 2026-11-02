//! "INTRUSION // 侵入": purely visual breach overlay driven by a live `IntelSession`.
//! Decorative and non-interactive: every number on screen comes from real scan events or is
//! derived from the target's own address data.

use super::session::IntelSession;
use crate::scan::intel::ports::PORTS;
use crate::scan::model::*;
use dioxus::prelude::*;
use std::time::Duration;

/// Shortest breach, so a fast scan still plays the full sequence.
pub const MIN_BREACH_MS: u32 = 2600;
/// Hard cap; past it the dossier opens with whatever has landed ("PARTIAL ACCESS").
pub const MAX_BREACH_MS: u32 = 8000;
pub const LOCK_NEW: Duration = Duration::from_millis(450);
pub const LOCK_CACHED: Duration = Duration::from_millis(300);
pub const GRANTED_HOLD: Duration = Duration::from_millis(900);
pub const RELINK_HOLD: Duration = Duration::from_millis(500);
/// Pause after each Log/Port event so the terminal drips instead of dumping.
pub const DRIP: Duration = Duration::from_millis(40);

/// When may the breach end? `Some(partial)` once it may, `None` to keep waiting.
pub fn breach_exit(done: bool, elapsed_ms: u32) -> Option<bool> {
    if done && elapsed_ms >= MIN_BREACH_MS {
        Some(false)
    } else if elapsed_ms >= MAX_BREACH_MS {
        Some(!done)
    } else {
        None
    }
}

/// Stamp flavour for a session at the end of the breach: `(denied, partial)`.
pub fn stamp_flags(s: &IntelSession) -> (bool, bool) {
    (s.is_dark(), !s.done)
}

pub fn stage_index(s: IntelStage) -> usize {
    match s {
        IntelStage::Echo => 0,
        IntelStage::Lattice => 1,
        IntelStage::Fingerprint => 2,
        IntelStage::Assemble => 3,
    }
}

const STAGE_RANGE: [(u32, u32); 4] = [(0, 15), (15, 55), (55, 90), (90, 100)];

/// Per-stage progress 0..=100 for the four ICE rings / daemons, from overall pct.
pub fn ice_progress(s: &IntelSession) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (i, (a, b)) in STAGE_RANGE.iter().enumerate() {
        out[i] = if s.done || i < stage_index(s.stage) {
            100
        } else {
            let p = (s.pct as u32).clamp(*a, *b) - a;
            (p * 100 / (b - a)) as u8
        };
    }
    out
}

fn xorshift(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

/// Deterministic seed from IP + MAC (FNV-1a).
pub fn seed_for(d: &Device) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in
        d.ip.bytes()
            .chain(d.mac.clone().unwrap_or_default().bytes())
    {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h | 1
}

/// Four real bytes per stage, shown in the sequence bands once that stage completes.
pub fn locks(d: &Device, s: &IntelSession) -> [Option<[u8; 4]>; 4] {
    let p = ice_progress(s);
    let intel = s.intel.as_ref();
    let mac: Vec<u8> = d
        .mac
        .as_deref()
        .map(|m| {
            m.split(':')
                .filter_map(|h| u8::from_str_radix(h, 16).ok())
                .collect()
        })
        .unwrap_or_default();
    let ip: Vec<u8> = d.ip.split('.').filter_map(|o| o.parse().ok()).collect();
    let b0 = if mac.len() >= 4 {
        [mac[0], mac[1], mac[2], mac[3]]
    } else if ip.len() == 4 {
        [ip[0], ip[1], ip[2], ip[3]]
    } else {
        [0xA5, 0xC0, 0x00, 0x01]
    };
    let rtt = s
        .echoes
        .iter()
        .flatten()
        .cloned()
        .fold(0.0f32, f32::max)
        .max(d.rtt_ms.unwrap_or(0.0));
    let rtt_u = (rtt * 100.0) as u16;
    let ttl = intel
        .and_then(|i| i.ping.as_ref().and_then(|p| p.ttl))
        .or(d.ttl)
        .unwrap_or(0);
    let b1 = [(rtt_u >> 8) as u8, rtt_u as u8, ttl, s.echoes.len() as u8];
    let open = s.open_count() as u8;
    let b2 = [
        open,
        s.ports.len() as u8,
        0x36,
        (s.ports.len() as u8) ^ open,
    ];
    let probes = intel.map_or(0, |i| i.http.len() + i.banners.len()) as u8;
    let conf = intel.map_or(0, |i| i.os.confidence);
    let b3 = [probes, conf, intel.map_or(0, |i| i.notes.len() as u8), 0xFF];
    [
        (p[0] == 100).then_some(b0),
        (p[1] == 100).then_some(b1),
        (p[2] == 100).then_some(b2),
        (p[3] == 100).then_some(b3),
    ]
}

/// Scrambled text settling left to right. `frame` 0..=FRAMES.
const FRAMES: u32 = 16;
const SCRAMBLE: &[char] = &[
    'A', 'B', 'C', 'D', 'E', 'F', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'ア', 'イ',
    'ウ', 'エ', 'オ', '#', '%',
];

pub fn decode_frame(text: &str, frame: u32) -> String {
    let n = text.chars().count();
    let settled = n * frame.min(FRAMES) as usize / FRAMES as usize;
    let mut x = 0x9E3779B97F4A7C15u64 ^ (frame as u64 + 1).wrapping_mul(0x2545F4914F6CDD1D);
    text.chars()
        .enumerate()
        .map(|(i, c)| {
            if i < settled || c == ' ' {
                c
            } else {
                SCRAMBLE[(xorshift(&mut x) % SCRAMBLE.len() as u64) as usize]
            }
        })
        .collect()
}

/// Text that decodes from noise. The timer lives in this component only.
#[component]
pub fn DecodeText(text: String, ms: u32) -> Element {
    let mut frame = use_signal(|| {
        if cfg!(test) || super::sfx::reduced_motion() {
            FRAMES
        } else {
            0
        }
    });
    use_hook(|| {
        spawn(async move {
            let step = Duration::from_millis((ms / FRAMES).max(10) as u64);
            while *frame.peek() < FRAMES {
                tokio::time::sleep(step).await;
                frame += 1;
            }
        })
    });
    let shown = decode_frame(&text, frame());
    rsx! { span { class: "decode", "{shown}" } }
}

/// Columns of hex that drift upward. Text blocks, 8 transforms in total.
#[component]
pub fn CodeStream(seed: u64, locks: [Option<[u8; 4]>; 4]) -> Element {
    let mut x = seed;
    let cols: Vec<(String, u32)> = (0..8)
        .map(|_| {
            let one: Vec<String> = (0..22)
                .map(|_| {
                    let v = xorshift(&mut x);
                    format!("{:02X} {:02X}", v as u8, (v >> 8) as u8)
                })
                .collect();
            let block = one.join("\n");
            let dur = 6 + (xorshift(&mut x) % 9) as u32;
            (format!("{block}\n{block}"), dur)
        })
        .collect();
    let names = ["ECHO", "SWEEP", "PRINT", "ASM"];
    let lefts = [4u32, 38, 14, 44];
    rsx! {
        div { class: "cs",
            for (i, (text, dur)) in cols.iter().enumerate() {
                div { key: "{i}", class: "cs-col", style: "animation-duration:{dur}s;animation-delay:-{i}s", "{text}" }
            }
            for (i, l) in locks.iter().enumerate() {
                div { key: "b{i}", class: if l.is_some() { "cs-band lock" } else { "cs-band" }, style: "top:{10 + i * 23}%;left:{lefts[i]}%",
                    span { class: "bn", "{names[i]}" }
                    {l.map_or_else(|| "-- -- -- --".to_string(), |b| format!("{:02X} {:02X} {:02X} {:02X}", b[0], b[1], b[2], b[3]))}
                }
            }
        }
    }
}

const DAEMONS: [(&str, &str); 4] = [
    ("SPIKE.ECHO", "針"),
    ("LATTICE.SWEEP", "格子"),
    ("MIRROR.PRINT", "鏡"),
    ("DOSSIER.ASM", "記録"),
];
const STAGE_NAMES: [(&str, &str); 4] = [
    ("ECHO PROBE", "反響"),
    ("LATTICE SWEEP", "ポート走査"),
    ("FINGERPRINT", "指紋"),
    ("ASSEMBLE", "組立"),
];

fn line_class(l: &str) -> &'static str {
    if l.contains("······· OPEN") {
        "tl open"
    } else if l.contains("······· CLOSED") {
        "tl closed"
    } else if l.contains("······· FILTERED") || l.contains("LOST") {
        "tl filt"
    } else {
        "tl"
    }
}

/// Breach overlay: code stream, daemons, trace terminal, port lattice, progress bar.
#[component]
pub fn Intrusion(
    device: Device,
    session: IntelSession,
    elapsed_ms: u32,
    on_abort: EventHandler<()>,
) -> Element {
    let prog = ice_progress(&session);
    let si = stage_index(session.stage).min(3);
    let (sn, sjp) = STAGE_NAMES[si];
    let stage_no = si + 1;
    let open_n = session.open_count();
    // New key = new burst: one per OPEN port and per stage change.
    let burst = open_n + si * 100 + usize::from(session.done) * 1000;
    let lk = locks(&device, &session);
    let seed = seed_for(&device);
    let name = device.label();
    let start = session.log.len().saturating_sub(14);
    let t = elapsed_ms as f32 / 1000.0;
    let cell = |port: u16| -> &'static str {
        match session.ports.iter().find(|p| p.0 == port).map(|p| p.1) {
            Some(PortState::Open) => "c open",
            Some(PortState::Closed) => "c closed",
            Some(PortState::Filtered) => "c filt",
            None => "c wait",
        }
    };
    let pct = session.pct;
    rsx! {
        div { class: "ix",
            div { class: "ix-sweep" }
            for b in [burst] { div { key: "{b}", class: "burst" } }
            div { class: "ix-top",
                span { class: "ix-t1", "INTRUSION " span { class: "jp", "侵入" } }
                span { class: "ix-t2", "TARGET " b { "{device.ip}" } }
                span { class: "ix-t3", DecodeText { text: name.to_uppercase(), ms: 520 } }
                span { class: "ix-time", "T+{t:05.2}s" }
                button { class: "dz-close", onclick: move |_| on_abort.call(()), "[ESC] ABORT " span { class: "jp", "中止" } }
            }
            div { class: "ix-left",
                div { class: "ix-p", style: "--p:0",
                    div { class: "ix-ph", "CODE STREAM " span { class: "jp", "符号" } }
                    CodeStream { seed, locks: lk }
                }
                div { class: "ix-p dm", style: "--p:1",
                    div { class: "ix-ph", "DAEMONS " span { class: "jp", "常駐" } }
                    for (i, (nm, jp)) in DAEMONS.iter().enumerate() {
                        {
                            let p = prog[i];
                            let on = (p as usize * 12 / 100).min(12);
                            let running = p > 0 && p < 100;
                            let stat = if p >= 100 { "EXECUTED".to_string() } else if p > 0 { format!("{p}%") } else { "QUEUED".to_string() };
                            rsx! {
                                div { key: "{i}", class: "dm-row",
                                    span { class: "dm-n", "{nm} " span { class: "jp", "{jp}" } }
                                    span { class: "dm-segs",
                                        for j in 0..12 { i { key: "{j}", class: if j < on { if running && j + 1 == on { "on lead" } else { "on" } } else { "" } } }
                                    }
                                    span { class: if p >= 100 { "dm-s done" } else if p > 0 { "dm-s run" } else { "dm-s" }, "{stat}" }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "ix-right",
                div { class: "ix-p term", style: "--p:1",
                    div { class: "ix-ph", "TRACE " span { class: "jp", "追跡" } span { class: "ix-tag", "{session.log.len()} EVT" } }
                    div { class: "term-b",
                        for (k, l) in session.log[start..].iter().enumerate() {
                            div { key: "{start + k}", class: "{line_class(l)}", span { class: "chev", ">" } "{l}" }
                        }
                        span { class: "cursor" }
                    }
                }
                div { class: "ix-p lat", style: "--p:2",
                    div { class: "ix-ph", "PORT LATTICE " span { class: "jp", "港湾" } span { class: "ix-tag", "{open_n} OPEN" } }
                    div { class: "lattice mini",
                        for p in PORTS.iter() {
                            div { key: "{p.port}", class: "{cell(p.port)}", "{p.port}" }
                        }
                    }
                }
            }
            div { class: "ix-bar", style: "--p:3",
                span { class: "bb-l", "BREACH " span { class: "jp", "侵入" } }
                div { class: "bb-track", div { class: "bb-fill", style: "transform:scaleX({pct as f32 / 100.0})" } }
                span { class: "bb-pct", "{pct}%" }
                span { class: "bb-stage", "STAGE 0{stage_no}/04 ▸ {sn} " span { class: "jp", "{sjp}" } }
            }
        }
    }
}

/// ACCESS GRANTED / DENIED slam. `relink` is the short cached-target variant.
#[component]
pub fn Stamp(
    denied: bool,
    partial: bool,
    #[props(default = false)] relink: bool,
    #[props(default = String::new())] sub: String,
) -> Element {
    let (main, jp) = if denied {
        ("ACCESS DENIED", "拒否")
    } else if relink {
        ("RE-LINK", "再接続")
    } else if partial {
        ("PARTIAL ACCESS", "部分")
    } else {
        ("ACCESS GRANTED", "アクセス許可")
    };
    let cls = if denied { "stamp denied" } else { "stamp" };
    rsx! {
        div { class: "stamp-wrap",
            div { class: "ix-sweep" }
            div { class: "{cls}",
                div { class: "st-main", "data-text": "{main}", "{main}" }
                div { class: "st-jp", "// " span { class: "jp", "{jp}" } " //" }
                if !sub.is_empty() { div { class: "st-sub", "{sub}" } }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sess(stage: IntelStage, pct: u8, done: bool) -> IntelSession {
        let mut s = IntelSession::new("1.1.1.1", 1);
        s.stage = stage;
        s.pct = pct;
        s.done = done;
        s
    }

    #[test]
    fn exit_rules() {
        assert_eq!(breach_exit(true, 1000), None);
        assert_eq!(breach_exit(false, 5000), None);
        assert_eq!(breach_exit(true, 2600), Some(false));
        assert_eq!(breach_exit(false, 8000), Some(true));
        assert_eq!(breach_exit(true, 9000), Some(false));
    }

    #[test]
    fn ice_progress_follows_stage() {
        assert_eq!(
            ice_progress(&sess(IntelStage::Echo, 0, false)),
            [0, 0, 0, 0]
        );
        assert_eq!(
            ice_progress(&sess(IntelStage::Lattice, 35, false)),
            [100, 50, 0, 0]
        );
        assert_eq!(
            ice_progress(&sess(IntelStage::Fingerprint, 55, false)),
            [100, 100, 0, 0]
        );
        assert_eq!(
            ice_progress(&sess(IntelStage::Assemble, 100, true)),
            [100; 4]
        );
    }

    #[test]
    fn decode_settles() {
        assert_eq!(decode_frame("LG TV", FRAMES), "LG TV");
        let mid = decode_frame("ABCDEFGH", FRAMES / 2);
        assert_eq!(mid.chars().count(), 8);
        assert!(mid.starts_with("ABCD"));
        assert_eq!(decode_frame("A B", 0).chars().nth(1), Some(' '));
    }

    #[test]
    fn locks_appear_with_stages() {
        let d = Device {
            ip: "10.0.0.2".into(),
            mac: Some("AA:BB:CC:DD:EE:FF".into()),
            ..Default::default()
        };
        let l = locks(&d, &sess(IntelStage::Lattice, 20, false));
        assert_eq!(l[0], Some([0xAA, 0xBB, 0xCC, 0xDD]));
        assert!(l[1].is_none());
        assert!(locks(&d, &sess(IntelStage::Assemble, 100, true))[3].is_some());
        assert_eq!(seed_for(&d), seed_for(&d));
    }

    #[test]
    fn stamp_flags_dark_and_partial() {
        let s = sess(IntelStage::Lattice, 30, false);
        assert_eq!(stamp_flags(&s), (false, true));
        let mut d = IntelSession::new("1.1.1.1", 1);
        d.apply(IntelEvent::Done(Box::new(DeviceIntel {
            ping: Some(PingStats::default()),
            ..Default::default()
        })));
        assert_eq!(stamp_flags(&d), (true, false));
    }
}

use dioxus::prelude::*;

#[component]
pub fn Emblem(#[props(default = 120)] size: u32) -> Element {
    // Original mark: a broken ring around two opposed blades and a core.
    rsx! {
        svg { class: "emblem", width: "{size}", height: "{size}", view_box: "-50 -50 100 100",
            path { class: "em-ring", d: "M0 -44 A44 44 0 1 1 -38 22" }
            path { class: "em-ring thin", d: "M-42 12 A44 44 0 0 1 -14 -42" }
            path { class: "em-blade", d: "M0 -30 L9 4 L0 30 L-9 4 Z" }
            path { class: "em-blade alt", d: "M-30 0 L-4 -7 L30 0 L-4 7 Z" }
            circle { class: "em-core", r: "5" }
        }
    }
}

#[component]
pub fn Loading(phase: String, pct: u8, logs: Vec<String>, exiting: bool) -> Element {
    const SEGS: usize = 48;
    let lit = pct as usize * SEGS / 100;
    let start = logs.len().saturating_sub(8);
    let shown: Vec<String> = logs[start..].to_vec();
    let n = shown.len();
    let step = match pct {
        0..=4 => 1,
        5..=39 => 2,
        40..=44 => 3,
        45..=89 => 4,
        90..=99 => 5,
        _ => 6,
    };
    rsx! {
        div { class: if exiting { "loading exiting" } else { "loading" },
            div { class: "brackets" }
            div { class: "side-code left", "SEC-OPS / 7734-A" }
            div { class: "side-code right", "ARK-NET UPLINK // 暗号化" }
            div { class: "load-core",
                div { class: "emblem-wrap",
                    div { class: "orbit o1" }
                    div { class: "orbit o2" }
                    Emblem { size: 132 }
                }
                h1 { class: "glitch", "data-text": "NETSCAN", "NETSCAN" }
                div { class: "subtitle", span { class: "jp", "荒坂" }, " SEC-OPS // ", span { class: "jp", "ネットワーク偵察" } }

                div { class: "meter",
                    div { class: "meter-head",
                        span { class: "phase", "{phase}", span { class: "cursor" } }
                        span { class: "pct", "{pct:>3}", span { class: "unit", "%" } }
                    }
                    div { class: "segs",
                        for i in 0..SEGS {
                            span { class: if i < lit { "seg on" } else if i == lit { "seg lead" } else { "seg" } }
                        }
                    }
                    div { class: "meter-foot",
                        span { "PHASE 0{step} / 06" }
                        span { class: "jp", "接続中" }
                    }
                }

                div { class: "log",
                    for (i, l) in shown.iter().enumerate() {
                        div { class: if i + 1 == n { "log-line last" } else { "log-line" }, key: "{start + i}",
                            span { class: "chev", ">" }
                            "{l}"
                        }
                    }
                }
            }
        }
    }
}

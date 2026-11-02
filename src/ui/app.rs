use super::intrusion::{self, Intrusion, Stamp};
use super::{
    css, dossier::Dossier, link::NeuralLink, loading::Loading, network_map::NetworkMap,
    session::IntelSession, sfx,
};
use crate::link::{self, LinkRequest, tools::Tools};
use crate::scan::{self, model::*};
use dioxus::prelude::*;
use futures::StreamExt;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MIN_LOADING: Duration = Duration::from_millis(1500);

#[derive(Clone, PartialEq)]
enum Stage {
    Loading,
    Exiting,
    Map,
    Failed(String),
}

/// Targeting flow: Lock -> Breach -> Granted -> Dossier (cached: Lock -> Granted(re-link) ->
/// Dossier). The rest of the UI (camera, reticle, modal) keys off `Focus::idx()`.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Focus {
    None,
    Lock {
        idx: usize,
    },
    Breach {
        idx: usize,
    },
    Granted {
        idx: usize,
        denied: bool,
        partial: bool,
    },
    Dossier {
        idx: usize,
    },
    Closing {
        idx: usize,
    },
    /// Neural link console (modal): the map stays focused underneath.
    Link {
        idx: usize,
    },
}

impl Focus {
    pub fn idx(self) -> Option<usize> {
        match self {
            Focus::None => None,
            Focus::Lock { idx }
            | Focus::Breach { idx }
            | Focus::Granted { idx, .. }
            | Focus::Dossier { idx }
            | Focus::Closing { idx }
            | Focus::Link { idx } => Some(idx),
        }
    }
}

const CLOSE_MS: Duration = Duration::from_millis(350);

#[component]
pub fn App() -> Element {
    let mut stage = use_signal(|| Stage::Loading);
    let mut phase = use_signal(|| ("Initialising".to_string(), 0u8));
    let mut logs = use_signal(Vec::<String>::new);
    let mut result = use_signal(|| None::<ScanResult>);

    use_hook(sfx::install);
    use_hook(|| {
        spawn(async move {
            let started = Instant::now();
            let (tx, mut rx) = futures::channel::mpsc::unbounded::<ScanProgress>();
            let handle = tokio::spawn(scan::scan(move |p| {
                let _ = tx.unbounded_send(p);
            }));
            while let Some(p) = rx.next().await {
                match p {
                    ScanProgress::Phase { name, pct } => phase.set((name, pct)),
                    ScanProgress::Log(l) => logs.with_mut(|v| v.push(l)),
                }
            }
            let outcome = match handle.await {
                Ok(r) => r.map_err(|e| format!("{e:#}")),
                Err(e) => Err(e.to_string()),
            };
            match outcome {
                Ok(r) => {
                    let name = phase.read().0.clone();
                    phase.set((name, 100));
                    let left = MIN_LOADING.saturating_sub(started.elapsed());
                    tokio::time::sleep(left.max(Duration::from_millis(450))).await;
                    result.set(Some(r));
                    stage.set(Stage::Exiting);
                    tokio::time::sleep(Duration::from_millis(650)).await;
                    stage.set(Stage::Map);
                }
                Err(e) => {
                    tokio::time::sleep(MIN_LOADING.saturating_sub(started.elapsed())).await;
                    stage.set(Stage::Failed(e));
                }
            }
        })
    });

    let hovered = use_signal(|| None::<usize>);
    let mut focus = use_signal(|| Focus::None);
    let mut sessions = use_signal(HashMap::<String, IntelSession>::new);
    let mut runs = use_signal(|| 0u32);
    let mut elapsed = use_signal(|| 0u32);
    let mut relink = use_signal(|| false);
    let mut muted = use_signal(sfx::muted);
    let mut link_cfg = use_signal(|| false);
    let mut link_req = use_signal(|| None::<LinkRequest>);
    let mut link_pre = use_signal(|| None::<String>);
    let mut link_run = use_signal(|| 0u32);
    let mut tools = use_signal(Tools::default);
    // `detect` may block ~1 s (xcode-select probe): keep it off the UI thread.
    let refresh_tools = move || {
        spawn(async move {
            if let Ok(t) = tokio::task::spawn_blocking(link::tools::detect).await {
                tools.set(t);
            }
        });
    };
    use_hook(refresh_tools);

    // Breach hum follows focus: on while in Breach, off on any other state.
    use_effect(move || {
        sfx::play(if matches!(focus(), Focus::Breach { .. }) {
            "hum_on"
        } else {
            "hum_off"
        });
    });

    // Deep scan: tokio does the network work; this local task folds events into the session.
    let mut start_scan = move |idx: usize| {
        let Some(r) = result.peek().clone() else {
            return;
        };
        let Some(device) = r.devices.get(idx).cloned() else {
            return;
        };
        let ip = device.ip.clone();
        let run = {
            runs += 1;
            *runs.peek()
        };
        sessions
            .write()
            .insert(ip.clone(), IntelSession::new(&ip, run));
        spawn(async move {
            let (tx, mut rx) = futures::channel::mpsc::unbounded::<IntelEvent>();
            let target = scan::intel::Target {
                device,
                network: r.network.clone(),
            };
            tokio::spawn(async move {
                scan::intel::deep_scan(target, move |ev| {
                    let _ = tx.unbounded_send(ev);
                })
                .await
            });
            while let Some(ev) = rx.next().await {
                if matches!(
                    ev,
                    IntelEvent::Port {
                        state: PortState::Open,
                        ..
                    }
                ) {
                    sfx::play("tick");
                }
                let drip = matches!(ev, IntelEvent::Log(_) | IntelEvent::Port { .. });
                {
                    let mut w = sessions.write();
                    match w.get_mut(&ip) {
                        Some(s) if s.run == run => s.apply(ev),
                        _ => break, // superseded by a re-scan
                    }
                }
                if drip {
                    tokio::time::sleep(intrusion::DRIP).await;
                }
            }
        });
    };

    // Breach -> Granted -> Dossier. The 100 ms tick feeds `elapsed` and ends itself as soon as
    // focus leaves `Breach` (ESC), so nothing keeps ticking afterwards.
    let mut begin_breach = move |idx: usize| {
        focus.set(Focus::Breach { idx });
        elapsed.set(0);
        spawn(async move {
            let started = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if *focus.peek() != (Focus::Breach { idx }) {
                    return;
                }
                let ms = started.elapsed().as_millis() as u32;
                elapsed.set(ms);
                let Some(s) = result
                    .peek()
                    .as_ref()
                    .and_then(|r| r.devices.get(idx))
                    .and_then(|d| sessions.peek().get(&d.ip).cloned())
                else {
                    return;
                };
                if let Some(partial) = intrusion::breach_exit(s.done, ms) {
                    let (denied, _) = intrusion::stamp_flags(&s);
                    relink.set(false);
                    sfx::play(if denied && !partial {
                        "denied"
                    } else {
                        "granted"
                    });
                    focus.set(Focus::Granted {
                        idx,
                        denied: denied && !partial,
                        partial,
                    });
                    tokio::time::sleep(intrusion::GRANTED_HOLD).await;
                    if matches!(*focus.peek(), Focus::Granted { idx: i, .. } if i == idx) {
                        focus.set(Focus::Dossier { idx });
                    }
                    return;
                }
            }
        });
    };

    let open_target = move |idx: usize| {
        if focus.peek().idx().is_some() {
            return; // modal: one target at a time
        }
        let Some(ip) = result
            .peek()
            .as_ref()
            .and_then(|r| r.devices.get(idx).map(|d| d.ip.clone()))
        else {
            return;
        };
        let cached = sessions.peek().contains_key(&ip);
        if !cached {
            start_scan(idx);
        }
        focus.set(Focus::Lock { idx });
        sfx::play("lock");
        spawn(async move {
            tokio::time::sleep(if cached {
                intrusion::LOCK_CACHED
            } else {
                intrusion::LOCK_NEW
            })
            .await;
            if *focus.peek() != (Focus::Lock { idx }) {
                return;
            }
            if cached {
                relink.set(true);
                sfx::play("relink");
                focus.set(Focus::Granted {
                    idx,
                    denied: false,
                    partial: false,
                });
                tokio::time::sleep(intrusion::RELINK_HOLD).await;
                if matches!(*focus.peek(), Focus::Granted { idx: i, .. } if i == idx) {
                    focus.set(Focus::Dossier { idx });
                }
            } else {
                begin_breach(idx);
            }
        });
    };

    let engage = move |(req, pre): (LinkRequest, Option<String>)| {
        let cur = *focus.peek();
        let Focus::Dossier { idx } = cur else {
            return;
        };
        link_req.set(Some(req));
        link_pre.set(pre);
        link_run += 1;
        link_cfg.set(false);
        sfx::play("link");
        focus.set(Focus::Link { idx });
    };

    let mut close = move || {
        let cur = *focus.peek();
        let cfg = *link_cfg.peek();
        if cfg && matches!(cur, Focus::Dossier { .. }) {
            link_cfg.set(false); // ESC closes the drawer first
            return;
        }
        match cur {
            Focus::Dossier { idx } => {
                link_cfg.set(false);
                focus.set(Focus::Closing { idx });
                sfx::play("close");
                spawn(async move {
                    tokio::time::sleep(CLOSE_MS).await;
                    if *focus.peek() == (Focus::Closing { idx }) {
                        focus.set(Focus::None);
                    }
                });
            }
            Focus::Lock { .. } | Focus::Breach { .. } | Focus::Granted { .. } => {
                sfx::play("abort");
                focus.set(Focus::None)
            }
            _ => {} // Closing / Link: the console owns ESC (it goes to the terminal)
        }
    };

    let st = stage();
    let linked = matches!(focus(), Focus::Link { .. });
    rsx! {
        style { "{css()}" }
        div { class: if linked { "app linked" } else { "app" }, tabindex: "-1",
            onmounted: move |e| async move { let _ = e.set_focus(true).await; },
            onkeydown: move |e| {
                // Keys typed in the terminal must never trigger app actions.
                let cur = *focus.peek();
                if matches!(cur, Focus::Link { .. }) {
                    return;
                }
                let cfg = *link_cfg.peek();
                match e.key() {
                Key::Escape => close(),
                Key::Character(c) if c.eq_ignore_ascii_case("m") => {
                    muted.set(sfx::toggle_mute());
                }
                Key::Character(c) if c.eq_ignore_ascii_case("c") => {
                    let cmd = e.modifiers().intersects(Modifiers::META | Modifiers::CONTROL);
                    if !cmd && matches!(cur, Focus::Dossier { .. }) {
                        link_cfg.set(!cfg);
                    }
                }
                Key::Character(c) if c.eq_ignore_ascii_case("r") && !cfg => {
                    // Copy out first: an `if let` keeps the peek guard alive for the whole
                    // body, and `begin_breach` writes `focus` -> AlreadyBorrowed panic.
                    if let Focus::Dossier { idx } = cur {
                        let done = result.peek().as_ref().and_then(|r| r.devices.get(idx)).and_then(|d| sessions.peek().get(&d.ip).map(|s| s.done));
                        if done == Some(true) {
                            start_scan(idx);
                            begin_breach(idx);
                        }
                    }
                }
                _ => {}
                }
            },
            div { class: "bg-grid" }
            match st {
                Stage::Loading | Stage::Exiting => rsx! {
                    Loading {
                        phase: phase().0,
                        pct: phase().1,
                        logs: logs(),
                        exiting: st == Stage::Exiting,
                    }
                },
                Stage::Failed(msg) => rsx! { Failure { msg } },
                Stage::Map => rsx! {
                    if let Some(r) = result() {
                        NetworkMap {
                            result: r.clone(),
                            hovered,
                            focus: focus().idx(),
                            muted: muted(),
                            intel: sessions,
                            on_target: open_target,
                            breach: matches!(focus(), Focus::Breach { .. } | Focus::Granted { .. }),
                        }
                        if let Focus::Breach { idx } = focus() {
                            if let Some(d) = r.devices.get(idx).cloned() {
                                if let Some(s) = sessions().get(&d.ip).cloned() {
                                    Intrusion { device: d, session: s, elapsed_ms: elapsed(), on_abort: move |_| close() }
                                }
                            }
                        }
                        if let Focus::Granted { idx, denied, partial } = focus() {
                            if let Some(d) = r.devices.get(idx).cloned() {
                                Stamp {
                                    key: "{idx}{denied}{partial}",
                                    denied,
                                    partial,
                                    relink: relink(),
                                    sub: stamp_sub(&d, sessions().get(&d.ip)),
                                }
                            }
                        }
                        if let Focus::Dossier { idx } | Focus::Closing { idx } = focus() {
                            if let Some(d) = r.devices.get(idx).cloned() {
                                if let Some(s) = sessions().get(&d.ip).cloned() {
                                    Dossier {
                                        device: d,
                                        session: s,
                                        closing: matches!(focus(), Focus::Closing { .. }),
                                        on_close: move |_| close(),
                                        on_rescan: move |_| {
                                            start_scan(idx);
                                            begin_breach(idx);
                                        },
                                        network: r.network.clone(),
                                        tools: tools(),
                                        cfg_open: link_cfg(),
                                        on_cfg: move |open: bool| link_cfg.set(open),
                                        on_connect: engage,
                                        on_recheck: move |_| refresh_tools(),
                                    }
                                }
                            }
                        }
                        if let Focus::Link { idx } = focus() {
                            if let (Some(d), Some(req)) = (r.devices.get(idx).cloned(), link_req()) {
                                NeuralLink {
                                    key: "{link_run()}",
                                    device: d,
                                    req,
                                    run: link_run(),
                                    tools: tools(),
                                    pretype: link_pre(),
                                    on_reengage: move |_| {
                                        link_pre.set(None);
                                        link_run += 1;
                                    },
                                    on_sever: move |_| {
                                        let cur = *focus.peek();
                                        if let Focus::Link { idx } = cur {
                                            focus.set(Focus::Dossier { idx });
                                        }
                                        link_req.set(None);
                                        // The console owned the keyboard focus: give it back to the app.
                                        let _ = document::eval("var a=document.querySelector('.app');if(a)a.focus();");
                                    },
                                }
                            }
                        }
                    }
                },
            }
            div { class: "scanlines" }
            div { class: "vignette" }
        }
    }
}

/// One-line summary under the stamp, from the finished session.
fn stamp_sub(d: &Device, s: Option<&IntelSession>) -> String {
    match s {
        Some(s) if s.is_dark() => format!("{} // NO ANSWER // SWEEP FACTS ONLY", d.ip),
        Some(s) => format!(
            "{} // {} OPEN // {} PORTS PROBED",
            d.ip,
            s.open_count(),
            s.ports.len()
        ),
        None => d.ip.clone(),
    }
}

#[component]
fn Failure(msg: String) -> Element {
    rsx! {
        div { class: "loading failure",
            div { class: "brackets" }
            div { class: "fail-code", "ERR // 0xA5C0 // 接続失敗" }
            h1 { class: "fail-title", "SCAN ABORTED" }
            p { class: "fail-msg", "{msg}" }
            p { class: "fail-hint", "Check that this machine is connected to a local network, then restart netscan." }
        }
    }
}

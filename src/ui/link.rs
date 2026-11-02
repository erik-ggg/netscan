//! "NEURAL LINK // 神経接続": the link config drawer, the live terminal console, the payload
//! drawer (cleanyourtv presets, typed never executed) and the PURGE confirmation.
//!
//! Bridge: one long-lived `document::eval` per mount drives xterm.js; a tokio-backed PTY runs the
//! user's own shell. Everything the user types goes to the PTY; the app only prepares commands.

use super::icons;
use super::intrusion::DecodeText;
use super::sfx;
use super::xterm::{self, FromJs, ToJs};
use crate::link::{
    self, LinkRequest, Proto,
    payload::{self, Preset},
    plan::{self, LinkPlan, Readiness},
    pty::{PtyEvent, PtyHandle},
    status::{LinkStatus, Watcher},
    tools::Tools,
};
use crate::scan::model::*;
use dioxus::document::{self, Eval};
use dioxus::prelude::*;
use futures::StreamExt;
use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

const CLOSE_MS: Duration = Duration::from_millis(350);
/// Flow control: stop reading the PTY while this many bytes are unacknowledged by xterm.
const MAX_INFLIGHT: usize = 1 << 20;

pub fn proto_name(p: Proto) -> &'static str {
    match p {
        Proto::Adb => "ADB",
        Proto::AdbPair => "PAIR",
        Proto::Ssh => "SSH",
        Proto::Local => "LOCAL",
    }
}

fn ready_glyph(r: &Readiness) -> &'static str {
    match r {
        Readiness::Ready => "\u{25CF}",
        Readiness::NeedsTool { .. } => "\u{2715}",
        Readiness::NeedsDeviceSetup { .. } => "\u{25D0}",
        Readiness::Unlikely => "\u{25CB}",
    }
}

fn ready_cls(r: &Readiness) -> &'static str {
    match r {
        Readiness::Ready => "ok",
        Readiness::NeedsTool { .. } => "no",
        Readiness::NeedsDeviceSetup { .. } => "setup",
        Readiness::Unlikely => "unl",
    }
}

fn proto_line(r: &LinkRequest) -> String {
    match r.proto {
        Proto::Adb => format!("ADB {}", r.adb_port),
        Proto::AdbPair => format!("ADB PAIR {}", r.adb_port),
        Proto::Ssh => format!("SSH {}", r.ssh_port),
        Proto::Local => "LOCAL".into(),
    }
}

// ---------------------------------------------------------------------------------------------
// LINK CONFIG drawer
// ---------------------------------------------------------------------------------------------

#[derive(Clone, PartialEq, Default)]
struct Fields {
    user: String,
    port: String,
    legacy: bool,
    pair_port: String,
    code: String,
    connect_port: String,
}

fn fields_for(p: &LinkPlan) -> Fields {
    let mut f = Fields {
        port: p.port.map(|v| v.to_string()).unwrap_or_default(),
        ..Default::default()
    };
    match p.proto {
        Proto::Ssh => {
            f.user = p.user.unwrap_or("").to_string();
            f.legacy = p.legacy_rsa;
        }
        Proto::AdbPair => {
            f.connect_port = f.port.clone();
            f.pair_port = p.pair_port.map(|v| v.to_string()).unwrap_or_default();
        }
        _ => {}
    }
    f
}

fn request_from(ip: Ipv4Addr, proto: Proto, f: &Fields) -> LinkRequest {
    let num = |s: &str| s.trim().parse::<u16>().unwrap_or(0);
    let mut r = LinkRequest::new(ip, proto);
    match proto {
        Proto::Ssh => {
            r.ssh_port = num(&f.port);
            let u = f.user.trim();
            r.ssh_user = (!u.is_empty()).then(|| u.to_string());
            r.legacy_rsa = f.legacy;
        }
        Proto::Adb => r.adb_port = num(&f.port),
        Proto::AdbPair => {
            r.adb_port = num(&f.connect_port);
            r.pair = Some((num(&f.pair_port), f.code.trim().to_string()));
        }
        Proto::Local => {}
    }
    r
}

/// Right-hand drawer in the dossier: choose a way in, review the exact command, ENGAGE.
#[component]
pub fn LinkConfig(
    device: Device,
    intel: Option<DeviceIntel>,
    network: NetworkInfo,
    tools: Tools,
    on_connect: EventHandler<(LinkRequest, Option<String>)>,
    on_cancel: EventHandler<()>,
    on_recheck: EventHandler<()>,
    /// Preview only: start on this plan tab.
    #[props(default = 0)]
    start_tab: usize,
) -> Element {
    let plans = plan::plans(&device, intel.as_ref(), &tools);
    let first = plans.first().map(fields_for).unwrap_or_default();
    let mut sel = use_signal(move || start_tab);
    let mut f = use_signal(move || first.clone());
    let n = plans.len().max(1);
    let si = sel().min(n - 1);
    let Some(p) = plans.get(si).cloned() else {
        return rsx! {};
    };
    let fv = f();
    let ip: Ipv4Addr = device.ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
    let built = request_from(ip, p.proto, &fv);
    let (ok_req, err) = match link::validate(built, &network) {
        Ok(r) => (Some(r), None),
        Err(e) => (None, Some(format!("{e}").to_uppercase())),
    };
    let cmd = ok_req.as_ref().map(|r| {
        link::typed_line(r)
            .unwrap_or_else(|| format!("# netscan link // target {ip} // $TV_HOST $NETSCAN_DATA"))
    });
    let tool_missing = match &p.readiness {
        Readiness::NeedsTool { tool, install } => Some((*tool, *install)),
        _ => None,
    };
    let setup: Vec<&'static str> = match &p.readiness {
        Readiness::NeedsDeviceSetup { steps } => steps.clone(),
        _ => vec![],
    };
    let can = ok_req.is_some() && tool_missing.is_none();
    let engage_req = ok_req.clone();
    let name = proto_name(p.proto);
    let port_label = if p.proto == Proto::Ssh {
        "PORT"
    } else {
        "ADB PORT"
    };

    rsx! {
        div { class: "lc",
            onclick: move |e| e.stop_propagation(),
            onkeydown: move |e| {
                e.stop_propagation();
                if e.key() == Key::Escape { on_cancel.call(()); }
            },
            div { class: "lc-top",
                span { class: "lc-title", "LINK CONFIG " span { class: "jp", "接続設定" } }
                button { class: "lc-x", title: "Close", onclick: move |_| on_cancel.call(()), "\u{2715}" }
            }
            div { class: "lc-body",
                div { class: "lc-k", "PROTOCOL " span { class: "jp", "経路" } }
                div { class: "lc-tabs",
                    for (i, t) in plans.iter().enumerate() {
                        button {
                            key: "{i}",
                            class: if i == si { "lc-tab sel {ready_cls(&t.readiness)}" } else { "lc-tab {ready_cls(&t.readiness)}" },
                            onclick: {
                                let t = t.clone();
                                move |_| { sel.set(i); f.set(fields_for(&t)); }
                            },
                            span { class: "g", "{ready_glyph(&t.readiness)}" }
                            "{proto_name(t.proto)}"
                            if let Some(pt) = t.port { span { class: "pt", "{pt}" } }
                        }
                    }
                }
                div { class: "lc-why {ready_cls(&p.readiness)}",
                    b { "{name}" } if let Some(pt) = p.port { " // {pt}" } " " span { class: "m", "{p.why}" }
                }

                match p.proto {
                    Proto::Ssh => rsx! {
                        div { class: "lc-row",
                            label { class: "lc-f", span { class: "lc-k", "USER" }
                                input { class: "nl-in", r#type: "text", value: "{fv.user}", spellcheck: "false", autocomplete: "off", maxlength: "32",
                                    oninput: move |e| f.with_mut(|x| x.user = e.value()) } }
                            label { class: "lc-f narrow", span { class: "lc-k", "{port_label}" }
                                input { class: "nl-in", r#type: "text", value: "{fv.port}", inputmode: "numeric", maxlength: "5", spellcheck: "false",
                                    oninput: move |e| f.with_mut(|x| x.port = e.value()) } }
                        }
                        button { class: if fv.legacy { "lc-check on" } else { "lc-check" },
                            onclick: move |_| f.with_mut(|x| x.legacy = !x.legacy),
                            i { class: "bx", if fv.legacy { "\u{25A0}" } else { "" } }
                            "LEGACY RSA KEYS " span { class: "m", "ssh-rsa // OLD DROPBEAR / EMBEDDED BOXES" }
                        }
                    },
                    Proto::Adb => rsx! {
                        div { class: "lc-row",
                            label { class: "lc-f narrow", span { class: "lc-k", "{port_label}" }
                                input { class: "nl-in", r#type: "text", value: "{fv.port}", inputmode: "numeric", maxlength: "5", spellcheck: "false",
                                    oninput: move |e| f.with_mut(|x| x.port = e.value()) } }
                        }
                    },
                    Proto::AdbPair => rsx! {
                        div { class: "lc-row",
                            label { class: "lc-f narrow", span { class: "lc-k", "PAIR PORT" }
                                input { class: "nl-in", r#type: "text", value: "{fv.pair_port}", inputmode: "numeric", maxlength: "5", spellcheck: "false", placeholder: "from TV",
                                    oninput: move |e| f.with_mut(|x| x.pair_port = e.value()) } }
                            label { class: "lc-f narrow", span { class: "lc-k", "CODE" }
                                input { class: "nl-in", r#type: "text", value: "{fv.code}", inputmode: "numeric", maxlength: "6", spellcheck: "false", placeholder: "000000",
                                    oninput: move |e| f.with_mut(|x| x.code = e.value()) } }
                            label { class: "lc-f narrow", span { class: "lc-k", "CONNECT" }
                                input { class: "nl-in", r#type: "text", value: "{fv.connect_port}", inputmode: "numeric", maxlength: "5", spellcheck: "false",
                                    oninput: move |e| f.with_mut(|x| x.connect_port = e.value()) } }
                        }
                    },
                    Proto::Local => rsx! {
                        div { class: "lc-note", "NO REMOTE HOP. YOUR OWN SHELL OPENS WITH "
                            b { "$TV_HOST" } " = {ip}, " b { "$NETSCAN_TARGET" } " AND " b { "$NETSCAN_DATA" } " SET." }
                    },
                }

                div { class: "lc-k", "COMMAND " span { class: "jp", "命令" } span { class: "m", " // TYPED INTO YOUR SHELL, VISIBLE" } }
                div { class: if err.is_some() { "lc-cmd bad" } else { "lc-cmd" },
                    if let Some(c) = &cmd { span { class: "ps", "$ " } "{c}" }
                    else if let Some(e) = &err { span { class: "ps", "\u{25B2} " } "{e}" }
                }

                if let Some((tool, install)) = tool_missing {
                    div { class: "lc-tool",
                        div { class: "lc-tool-h", b { "{tool}" } " \u{2715} NOT INSTALLED " span { class: "jp", "未導入" } }
                        div { class: "lc-cmd", span { class: "ps", "$ " } "{install}" }
                        div { class: "lc-tool-b",
                            button { class: "dz-btn",
                                onclick: {
                                    let req = LinkRequest::new(ip, Proto::Local);
                                    let txt = install.to_string();
                                    let req = link::validate(req, &network).ok();
                                    move |_| { if let Some(r) = req.clone() { on_connect.call((r, Some(txt.clone()))); } }
                                },
                                "TYPE IN LOCAL SHELL " span { class: "jp", "入力" } }
                            button { class: "dz-btn", onclick: move |_| on_recheck.call(()), "RE-CHECK " span { class: "jp", "再確認" } }
                        }
                    }
                }
                if !setup.is_empty() {
                    div { class: "lc-setup",
                        div { class: "lc-k", "DEVICE SETUP " span { class: "jp", "端末設定" } }
                        for (i, s) in setup.iter().enumerate() {
                            div { key: "{i}", class: "lc-step", b { "{i + 1}" } span { "{s}" } }
                        }
                    }
                }
                if p.proto == Proto::Ssh && p.port == Some(9922) {
                    div { class: "lc-note", "\u{24D8} KEY: DEV MODE APP \u{25B8} KEY SERVER. NO PASSWORD IS TYPED FOR YOU." }
                }
                if matches!(p.proto, Proto::Adb | Proto::AdbPair) {
                    div { class: "lc-note", "\u{24D8} STOCK ADB AND CLEANYOURTV KEEP SEPARATE KEYS: THE TV MAY ASK TO AUTHORIZE TWICE." }
                }
            }
            div { class: "lc-foot",
                div { class: "lc-scope", span { class: "x", "\u{25B2}" }
                    span { "TARGET LOCKED " b { "{ip}" } " // IN-SUBNET ONLY // NO CREDENTIALS STORED" } }
                button { class: if can { "lc-engage" } else { "lc-engage off" }, disabled: !can,
                    onclick: move |_| { if let Some(r) = engage_req.clone() { on_connect.call((r, None)); } },
                    "ENGAGE " span { class: "jp", "接続" } " \u{25B8}" }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// PURGE confirm
// ---------------------------------------------------------------------------------------------

/// Centered modal. Nothing runs on confirm: the command is only typed into the terminal.
#[component]
pub fn ConfirmPurge(
    ip: String,
    on_abort: EventHandler<()>,
    on_type: EventHandler<()>,
    #[props(default = false)] checked: bool,
) -> Element {
    let mut backup = use_signal(move || checked);
    let ok = backup();
    rsx! {
        div { class: "nl-modal-wrap",
            onclick: move |e| e.stop_propagation(),
            onkeydown: move |e| {
                e.stop_propagation();
                if e.key() == Key::Escape { on_abort.call(()); }
            },
            div { class: "nl-modal",
                div { class: "nm-hazard" }
                div { class: "nm-top", "CONFIRM PURGE " span { class: "jp", "除去確認" } }
                div { class: "nm-body",
                    div { class: "nm-l1", "DISABLE PACKAGES ON " b { "{ip}" } " FOR USER 0" }
                    div { class: "nm-l2", "NOTHING IS UNINSTALLED. UNDO WITH " b { "07 RESTORE" } " (SAME LIST)." }
                    button { class: if ok { "lc-check on" } else { "lc-check" }, onclick: move |_| backup.set(!ok),
                        i { class: "bx", if ok { "\u{25A0}" } else { "" } }
                        "BACKUP TAKEN " span { class: "m", "(STEP 04)" } }
                    div { class: "nm-l3", "THE COMMAND IS TYPED, NOT RUN. REVIEW IT, THEN PRESS \u{23CE}." }
                }
                div { class: "nm-act",
                    button { class: "dz-btn abort",
                        onmounted: move |e| async move { let _ = e.set_focus(true).await; },
                        onclick: move |_| on_abort.call(()),
                        "ABORT " span { class: "jp", "中止" } }
                    button { class: if ok { "dz-btn danger" } else { "dz-btn danger off" }, disabled: !ok,
                        onclick: move |_| { if ok { on_type.call(()); } },
                        "TYPE COMMAND " span { class: "jp", "入力" } " \u{25B8}" }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// PAYLOAD drawer (cleanyourtv)
// ---------------------------------------------------------------------------------------------

fn cyt_root() -> PathBuf {
    link::data_dir().join("cleanyourtv")
}

/// First unmet requirement of a step, as a short hint.
fn unmet(needs: &[&str], tools: &Tools) -> Option<&'static str> {
    let root = cyt_root();
    for n in needs {
        let bad = match *n {
            "git" => (tools.git.is_none() || tools.clt_stub)
                .then_some("NEEDS GIT \u{25B8} XCODE-SELECT --INSTALL"),
            "python3" => (tools.python3.is_none() || tools.clt_stub)
                .then_some("NEEDS PYTHON3 \u{25B8} XCODE-SELECT --INSTALL"),
            "repo" => (!root.join("tools").is_dir()).then_some("RUN 01 ACQUIRE FIRST"),
            "venv" => (!root.join("tools/venv").is_dir()).then_some("RUN 02 ARM FIRST"),
            _ => None,
        };
        if bad.is_some() {
            return bad;
        }
    }
    None
}

fn payload_applies(d: &Device, req: &LinkRequest) -> bool {
    if req.proto == Proto::Ssh || d.is_self {
        return false;
    }
    let class = d.class.as_ref();
    let kind = class.map(|c| c.kind).unwrap_or(d.kind);
    if !matches!(kind, DeviceKind::Tv | DeviceKind::Media) {
        return false;
    }
    let label = class
        .and_then(|c| c.label.as_deref())
        .unwrap_or("")
        .to_uppercase();
    let android = ["ANDROID", "GOOGLE", "FIRE"]
        .iter()
        .any(|k| label.contains(k));
    let open = d
        .beacon
        .as_ref()
        .is_some_and(|b| b.open.iter().any(|p| matches!(p, 5555 | 6466)));
    android || open || matches!(req.proto, Proto::Adb | Proto::AdbPair)
}

#[component]
fn Payload(
    device: Device,
    tools: Tools,
    ready_all: bool,
    on_type: EventHandler<String>,
    on_purge: EventHandler<String>,
) -> Element {
    let mut tick = use_signal(|| 0u32);
    use_hook(|| {
        spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                tick += 1;
            }
        })
    });
    let _ = tick();
    let slug = device.vendor.as_deref().and_then(payload::brand_slug);
    let presets: Vec<Preset> = payload::presets(slug);
    rsx! {
        div { class: "nl-sec pay",
            div { class: "nl-sh", span { "PAYLOAD " span { class: "jp", "浄化" } } span { class: "tg", "CLEANYOURTV" } }
            div { class: "pay-warn", "AUTHORIZE THE NEW KEY ON THE TV: tv.py USES ITS OWN ADB KEY." }
            div { class: "pay-list",
                for p in presets.iter() {
                    {
                        let hint = if ready_all { None } else { unmet(p.needs, &tools) };
                        let text = p.text.clone();
                        let destructive = p.destructive;
                        rsx! {
                            div { key: "{p.id}", class: if hint.is_some() { "pay-row off" } else if destructive { "pay-row hot" } else { "pay-row" },
                                span { class: "n", "{p.step}" }
                                span { class: "t", "{p.title} " span { class: "jp", "{p.jp}" }
                                    if destructive { span { class: "w", " \u{25B2}" } }
                                    if let Some(h) = hint { span { class: "h", "{h}" } } }
                                button { class: "pay-btn", disabled: hint.is_some(),
                                    onclick: move |_| { if destructive { on_purge.call(text.clone()) } else { on_type.call(text.clone()) } },
                                    if destructive { "ARM\u{2026}" } else { "TYPE \u{25B8}" } }
                            }
                        }
                    }
                }
            }
            div { class: "pay-foot", "TYPED ONLY \u{25B8} YOU PRESS \u{23CE}" }
            div { class: "pay-credit", "LAUNCHER BUILD (JDK 17\u{2013}22 + SDK 34) \u{25B8} SEE REPO README" br {} "github.com/Gathin23/cleanyourtv \u{00B7} MIT" }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// NEURAL LINK console
// ---------------------------------------------------------------------------------------------

/// Everything that must be torn down when the link ends. Lives in an `Rc`, not a signal: the
/// `use_drop` hook may run after the component's signals are gone.
#[derive(Default)]
struct Cleanup {
    handle: Option<PtyHandle>,
    ev: Option<Eval>,
    adb: Option<(PathBuf, String)>,
}

impl Cleanup {
    /// Kills the child (SIGKILL via the supervisor) and, for ADB links, drops the TCP connection.
    fn kill_pty(&mut self) {
        if let Some(h) = self.handle.take() {
            h.kill();
        }
        if let Some((adb, target)) = self.adb.take() {
            std::thread::spawn(move || {
                let _ = std::process::Command::new(adb)
                    .args(["disconnect", &target])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            });
        }
    }

    fn shutdown(&mut self) {
        self.kill_pty();
        if let Some(ev) = self.ev.take() {
            let _ = ev.send(ToJs::End);
        }
    }

    /// Types text into the terminal without a newline (the user presses Enter).
    fn type_text(&self, t: String) {
        if let Some(ev) = self.ev {
            let _ = ev.send(ToJs::Type { d: t });
        }
    }
}

#[derive(Clone)]
struct Bridge {
    sid: u32,
    spec: link::SpawnSpec,
    local: bool,
    pretype: Option<String>,
    cl: Rc<RefCell<Cleanup>>,
    stage: Signal<u8>,
    status: Signal<Option<LinkStatus>>,
    size: Signal<(u16, u16)>,
    pid: Signal<Option<u32>>,
    on_close: Callback<()>,
}

async fn run_bridge(b: Bridge) {
    let Bridge {
        sid,
        spec,
        local,
        pretype,
        cl,
        mut stage,
        mut status,
        mut size,
        mut pid,
        on_close,
    } = b;
    if !xterm::ensure_loaded().await {
        status.set(Some(LinkStatus::Failed));
        return;
    }
    let ev = document::eval(&xterm::bridge_js(sid));
    cl.borrow_mut().ev = Some(ev);
    let mut evr = ev; // `Eval` is Copy: one copy receives, one sends
    let (cols, rows) = loop {
        match evr.recv::<FromJs>().await {
            Ok(FromJs::Ready { cols, rows }) => break (cols.max(20), rows.max(5)),
            Ok(FromJs::Close) => {
                on_close.call(());
                return;
            }
            Ok(_) => {}
            Err(_) => {
                status.set(Some(LinkStatus::Failed));
                return;
            }
        }
    };
    size.set((cols, rows));
    stage.set(2);
    let (h, mut out, mut out_open) = match link::pty::spawn(spec, cols, rows).await {
        Ok((h, out)) => {
            stage.set(3);
            pid.set(h.pid);
            cl.borrow_mut().handle = Some(h.clone());
            (Some(h), out, true)
        }
        Err(e) => {
            status.set(Some(LinkStatus::Failed));
            let msg = format!("\r\n\x1b[31m// SPAWN FAILED: {e:#}\x1b[0m\r\n");
            let _ = ev.send(ToJs::Out {
                d: super::base64(msg.as_bytes()),
            });
            (
                None,
                futures::channel::mpsc::unbounded::<PtyEvent>().1,
                false,
            )
        }
    };
    let mut inflight = 0usize;
    let mut first = true;
    let mut watcher = Watcher::new();
    let mut pre = pretype;
    loop {
        tokio::select! {
            m = evr.recv::<FromJs>() => match m {
                Ok(FromJs::Close) => {
                    on_close.call(());
                    break;
                }
                Ok(FromJs::Resize { cols, rows }) => {
                    size.set((cols, rows));
                    if let Some(h) = &h { h.resize(cols, rows); }
                }
                Ok(FromJs::Ack { n }) => inflight = inflight.saturating_sub(n),
                Ok(FromJs::Ready { .. }) => {}
                Ok(msg) => {
                    if let (Some(h), Some(bytes)) = (&h, msg.bytes()) {
                        h.input(bytes);
                    }
                }
                Err(_) => break,
            },
            o = out.next(), if out_open && inflight < MAX_INFLIGHT => match o {
                Some(PtyEvent::Output(mut buf)) => {
                    let mut exit = None;
                    while buf.len() < 64 * 1024 {
                        match out.try_recv() {
                            Ok(PtyEvent::Output(more)) => buf.extend(more),
                            Ok(e) => { exit = Some(e); break; }
                            Err(_) => break,
                        }
                    }
                    if first {
                        first = false;
                        stage.set(4);
                        if local {
                            status.set(Some(LinkStatus::Linked));
                        }
                        if let Some(t) = pre.take() {
                            // Typed, never run: let the prompt settle, then paste without Enter.
                            dioxus::prelude::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(900)).await;
                                let _ = ev.send(ToJs::Type { d: t });
                            });
                        }
                    }
                    if let Some(s) = watcher.feed(&buf) {
                        status.set(Some(s));
                    }
                    inflight += buf.len();
                    let _ = ev.send(ToJs::Out { d: super::base64(&buf) });
                    if let Some(PtyEvent::Exited(c)) = exit {
                        status.set(Some(LinkStatus::Dropped(c)));
                        let _ = ev.send(ToJs::Exit { code: c });
                    }
                }
                Some(PtyEvent::Exited(c)) => {
                    status.set(Some(LinkStatus::Dropped(c)));
                    let _ = ev.send(ToJs::Exit { code: c });
                }
                None => out_open = false,
            },
        }
    }
}

/// (css class, glyph, text, jp, hint)
fn chip(
    s: Option<LinkStatus>,
) -> (
    &'static str,
    &'static str,
    String,
    &'static str,
    &'static str,
) {
    match s {
        None => ("wait", "\u{25D0}", "HANDSHAKE".into(), "交渉中", ""),
        Some(LinkStatus::Linked) => ("ok", "\u{25C9}", "LINKED".into(), "接続中", ""),
        Some(LinkStatus::Paired) => ("ok", "\u{25C9}", "PAIRED".into(), "対合", "NOW CONNECTING"),
        Some(LinkStatus::AwaitingAuth) => (
            "auth",
            "\u{25D0}",
            "AWAITING AUTH".into(),
            "承認待ち",
            "ACCEPT THE PROMPT ON THE TARGET",
        ),
        Some(LinkStatus::AwaitingSecret) => (
            "auth",
            "\u{25D0}",
            "SECRET REQUESTED".into(),
            "認証",
            "TYPE IT IN THE TERMINAL // NEVER STORED",
        ),
        Some(LinkStatus::HostKeyPrompt) => (
            "auth",
            "\u{25D0}",
            "HOST KEY PROMPT".into(),
            "鍵確認",
            "ANSWER yes OR no IN THE TERMINAL",
        ),
        Some(LinkStatus::KeyIssue) => (
            "bad",
            "\u{25B2}",
            "KEY MISMATCH".into(),
            "鍵不一致",
            "TRY LEGACY RSA KEYS IN LINK CONFIG",
        ),
        Some(LinkStatus::Failed) => (
            "bad",
            "\u{2715}",
            "LINK FAILED".into(),
            "失敗",
            "CHECK TARGET / PORT",
        ),
        Some(LinkStatus::Dropped(c)) => (
            "bad",
            "\u{2715}",
            format!(
                "LINK DROPPED // EXIT {}",
                c.map(|v| v.to_string()).unwrap_or_else(|| "?".into())
            ),
            "切断",
            "",
        ),
    }
}

/// Full-screen console. Mount it keyed by `run`: one bridge (one `eval`) per mount.
#[component]
pub fn NeuralLink(
    device: Device,
    req: LinkRequest,
    run: u32,
    on_sever: EventHandler<()>,
    /// Preview only: static screen lines instead of a live terminal.
    #[props(default)]
    mock: Option<Vec<String>>,
    #[props(default)] tools: Tools,
    /// Text pasted (never executed) after the first prompt.
    #[props(default)]
    pretype: Option<String>,
    #[props(default)] on_reengage: Option<EventHandler<()>>,
) -> Element {
    let is_mock = mock.is_some();
    let stage = use_signal(move || if is_mock { 4u8 } else { 1 });
    let status = use_signal(move || is_mock.then_some(LinkStatus::Linked));
    let size = use_signal(move || if is_mock { (118u16, 34u16) } else { (0, 0) });
    let pid = use_signal(|| None::<u32>);
    let mut closing = use_signal(|| false);
    let mut secs = use_signal(move || if is_mock { 42u32 } else { 0 });
    let mut purge = use_signal(|| None::<String>);

    let adb = matches!(req.proto, Proto::Adb | Proto::AdbPair)
        .then(|| {
            tools
                .adb
                .clone()
                .map(|a| (a, format!("{}:{}", req.ip, req.adb_port)))
        })
        .flatten();
    let cl = use_hook(move || {
        Rc::new(RefCell::new(Cleanup {
            adb,
            ..Default::default()
        }))
    });
    {
        let cl = cl.clone();
        use_drop(move || cl.borrow_mut().shutdown());
    }
    // T+ counter; stops counting once the link dropped.
    use_hook(move || {
        spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let dropped = matches!(*status.peek(), Some(LinkStatus::Dropped(_)));
                if !dropped {
                    secs += 1;
                }
            }
        })
    });

    let sever = {
        let cl = cl.clone();
        use_callback(move |_: ()| {
            let already = *closing.peek();
            if already {
                return;
            }
            closing.set(true);
            cl.borrow_mut().kill_pty();
            sfx::play("close");
            let cl = cl.clone();
            spawn(async move {
                tokio::time::sleep(CLOSE_MS).await;
                cl.borrow_mut().shutdown();
                on_sever.call(());
            });
        })
    };

    let spec = link::bootstrap(&req, &tools);
    let bridge = Bridge {
        sid: run,
        spec,
        local: req.proto == Proto::Local,
        pretype,
        cl: cl.clone(),
        stage,
        status,
        size,
        pid,
        on_close: sever,
    };
    let type_text = {
        let cl = cl.clone();
        move |t: String| cl.borrow().type_text(t)
    };

    let st = stage();
    let stat = status();
    let (ccls, cglyph, ctext, cjp, chint) = chip(stat);
    let dropped = matches!(stat, Some(LinkStatus::Dropped(_)));
    let (cols, rows) = size();
    let t = secs();
    let tstr = format!("T+{:02}:{:02}", t / 60, t % 60);
    let cls = device.class.as_ref();
    let kind = cls.map(|c| c.kind).unwrap_or(device.kind);
    let (kcode, kjp) = icons::code(kind);
    let label = cls
        .and_then(|c| c.label.clone())
        .unwrap_or_else(|| kcode.to_string());
    let name = device.label();
    let pl = proto_line(&req);
    let pips = [
        ("LOCK", "捕捉"),
        ("ROUTE", "経路"),
        (proto_name(req.proto), "接続"),
        ("PTY", "端末"),
    ];
    let show_pay = payload_applies(&device, &req);
    let wrap = if closing() {
        "nl-wrap closing"
    } else {
        "nl-wrap"
    };
    let ip = device.ip.clone();
    let purge_ip = ip.clone();
    let host_id = format!("nl-term-{run}");
    let env_adb = format!("{}:{}", req.ip, req.adb_port);
    let me_kind = DeviceKind::Computer;

    rsx! {
        div { class: "{wrap}",
            onkeydown: move |e| {
                e.stop_propagation();
                if e.modifiers().contains(Modifiers::CONTROL) && e.key() == Key::Character("]".into()) {
                    sever.call(());
                }
            },
            div { class: "nl",
                div { class: "nl-top",
                    span { class: "nl-title", "NEURAL LINK " span { class: "jp", "神経接続" } }
                    span { class: "nl-tgt", "\u{25B8} {ip} \u{25B8} {label} \u{25B8} {pl}" }
                    span { class: "nl-chip {ccls}", span { class: "led" } "{cglyph} {ctext} " span { class: "jp", "{cjp}" } }
                    if !chint.is_empty() { span { class: "nl-hint", "{chint}" } }
                    span { class: "nl-t", "{tstr}" }
                    if dropped {
                        if let Some(re) = on_reengage {
                            button { class: "dz-btn", onclick: move |_| re.call(()), "RE-ENGAGE " span { class: "jp", "再接続" } }
                        }
                    }
                    button { class: "dz-close nl-sever", onclick: move |_| sever.call(()), "\u{23CF} SEVER " span { class: "jp", "切断" } }
                }
                div { class: "nl-main",
                    div { class: "nl-left",
                        div { class: "nl-steps",
                            for (i, (n, jp)) in pips.iter().enumerate() {
                                div { key: "{i}", class: if (st as usize) > i { "nl-pip done" } else if (st as usize) == i { "nl-pip cur" } else { "nl-pip" },
                                    i { class: "bx" } span { class: "pn", "{n}" } span { class: "jp pj", "{jp}" }
                                }
                                if i < 3 { div { class: if (st as usize) > i + 1 { "nl-seg on" } else { "nl-seg" } } }
                            }
                        }
                        div { class: "nl-termwrap",
                            onclick: {
                                let cl = cl.clone();
                                move |_| {
                                    let ev = cl.borrow().ev;
                                    if let Some(ev) = ev { let _ = ev.send(ToJs::Focus); }
                                }
                            },
                            if let Some(lines) = &mock {
                                div { class: "nl-mock",
                                    for (i, l) in lines.iter().enumerate() {
                                        {
                                            let at = l.find(" $ ").map(|p| p + 3).unwrap_or(0);
                                            let (pre, post) = l.split_at(at);
                                            rsx! { div { key: "{i}", span { class: "ps", "{pre}" } "{post}" } }
                                        }
                                    }
                                    div { span { class: "ps", "sabrina:/ $ " } span { class: "cur" } }
                                }
                            } else {
                                div {
                                    id: "{host_id}",
                                    class: "nl-term",
                                    onkeydown: move |e| e.stop_propagation(),
                                    onmounted: move |_| {
                                        let b = bridge.clone();
                                        spawn(run_bridge(b));
                                    },
                                }
                            }
                            div { class: "nl-hs",
                                    div { class: "ix-sweep" }
                                    div { class: "hs-core",
                                        svg { class: "hs-svg", view_box: "0 0 520 120",
                                            g { transform: "translate(60 60)", class: "hs-node",
                                                for d in icons::paths(me_kind) { path { d: "{d}" } }
                                            }
                                            g { transform: "translate(460 60)", class: "hs-node",
                                                for d in icons::paths(kind) { path { d: "{d}" } }
                                            }
                                            path { class: "hs-line", d: "M104 60 H416" }
                                            path { class: "hs-line f", d: "M104 60 H416" }
                                            rect { class: "hs-pk a", x: "104", y: "57", width: "14", height: "6" }
                                            rect { class: "hs-pk b", x: "104", y: "57", width: "14", height: "6" }
                                            rect { class: "hs-pk c", x: "104", y: "57", width: "14", height: "6" }
                                        }
                                        div { class: "hs-t", DecodeText { text: "NEURAL LINK".to_string(), ms: 700 } " " span { class: "jp", "神経接続" } }
                                        div { class: "hs-s", "{ip} \u{25B8} {pl} \u{25B8} {name}" }
                                    }
                            }
                        }
                    }
                    div { class: "nl-side",
                        div { class: "nl-sec tgt",
                            div { class: "nl-sh", span { "TARGET " span { class: "jp", "標的" } } span { class: "tg", "{kcode}" } }
                            div { class: "tg-id",
                                div { class: "tg-ic", svg { view_box: "-26 -26 52 52", g { class: "icon", for d in icons::paths(kind) { path { d: "{d}" } } } } }
                                div { class: "tg-tx",
                                    div { class: "tg-n", "{name}" }
                                    div { class: "tg-l", "{label} " span { class: "jp", "{kjp}" }
                                        if let Some(c) = cls { span { class: "dim", " {c.confidence}%" } } }
                                }
                            }
                            div { class: "tg-r", span { class: "dz-k", "ADDR" } b { "{ip}" } }
                            div { class: "tg-r", span { class: "dz-k", "PROTO" } b { "{pl}" } }
                            div { class: "tg-r", span { class: "dz-k", "PTY" } b { if cols > 0 { "{cols}\u{00D7}{rows}" } else { "---" } } }
                            if let Some(p) = pid() { div { class: "tg-r", span { class: "dz-k", "PID" } b { "{p}" } } }
                            div { class: "tg-r", span { class: "dz-k", "ENV" } b { "TV_HOST={ip}" } }
                            if matches!(req.proto, Proto::Adb | Proto::AdbPair) {
                                div { class: "tg-r", span { class: "dz-k", "" } b { "ANDROID_SERIAL={env_adb}" } }
                            }
                        }
                        if show_pay {
                            Payload {
                                device: device.clone(),
                                tools: tools.clone(),
                                ready_all: is_mock,
                                on_type: move |t: String| type_text(t),
                                on_purge: move |t: String| purge.set(Some(t)),
                            }
                        } else {
                            div { class: "nl-sec notes",
                                div { class: "nl-sh", span { "SESSION " span { class: "jp", "記録" } } }
                                if req.proto == Proto::Local {
                                    div { class: "nt", "YOUR OWN SHELL, PREPARED FOR THIS TARGET." }
                                } else {
                                    div { class: "nt", "REMOTE SESSION: THE PROMPT BELONGS TO THE TARGET ONCE CONNECTED. WHEN IT ENDS THE LINK DROPS." }
                                }
                                div { class: "nt", b { "$TV_HOST" } " AND " b { "$NETSCAN_TARGET" } " HOLD THE ADDRESS." }
                                div { class: "nt", b { "$NETSCAN_DATA" } " IS A SCRATCH DIRECTORY." }
                                div { class: "nt dim", "PASSWORDS AND HOST KEY PROMPTS ARE ANSWERED IN THE TERMINAL. NOTHING IS STORED." }
                            }
                        }
                    }
                }
                div { class: "nl-foot",
                    span { "CTRL+] SEVER \u{00B7} \u{2318}C/\u{2318}V COPY/PASTE \u{00B7} ESC \u{2192} TERMINAL" }
                    span { class: "sig", "0xA5C0 // " span { class: "jp", "荒坂" } " NEURAL-OPS" }
                }
            }
            if let Some(text) = purge() {
                ConfirmPurge {
                    ip: purge_ip.clone(),
                    on_abort: {
                        let cl = cl.clone();
                        move |_| {
                            purge.set(None);
                            let ev = cl.borrow().ev;
                            if let Some(ev) = ev { let _ = ev.send(ToJs::Focus); }
                        }
                    },
                    on_type: {
                        let cl = cl.clone();
                        move |_| { cl.borrow().type_text(text.clone()); purge.set(None); }
                    },
                }
            }
        }
    }
}

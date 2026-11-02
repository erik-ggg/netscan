//! xterm.js assets (vendored offline) and the Rust <-> JS bridge script.
//!
//! Vendored files live in `assets/vendor/xterm/` (see SOURCES.md there):
//!   xterm.js      @xterm/xterm 6.0.0      sha256 14903579ff54664cd72f8e8699e6961a6272c21863ec1c3b118cdc8af5d4a972
//!   xterm.css     @xterm/xterm 6.0.0      sha256 854a7c0fb70e8b1a083c16797ab827299fb18744f5ad34f227b48337e33293c6
//!   addon-fit.js  @xterm/addon-fit 0.11.0 sha256 ba3ea256ce0620a0992a197d6c9baea64823fc93d8da07a9e366ca9943c18527

use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};

pub const XTERM_JS: &str = include_str!("../../assets/vendor/xterm/xterm.js");
pub const FIT_JS: &str = include_str!("../../assets/vendor/xterm/addon-fit.js");
pub const XTERM_CSS: &str = include_str!("../../assets/vendor/xterm/xterm.css");

/// xterm `Terminal` options (Arasaka palette).
pub const THEME_JSON: &str = r##"{
"cursorBlink":true,"scrollback":5000,"fontSize":14,"lineHeight":1.1,"allowProposedApi":false,
"fontFamily":"'Share Tech Mono', Menlo, monospace",
"theme":{
"background":"#060405","foreground":"#f3ebe8","cursor":"#ff1a2d","cursorAccent":"#060405",
"selectionBackground":"rgba(255,26,45,.35)",
"black":"#1d0709","red":"#ff1a2d","green":"#8fd4a8","yellow":"#e8c070",
"blue":"#7aa2d6","magenta":"#d06aa8","cyan":"#6fc9c9","white":"#c9bdba",
"brightBlack":"#4a0e15","brightRed":"#ff4a58","brightGreen":"#b5f0c8","brightYellow":"#ffe0a0",
"brightBlue":"#a8c6f0","brightMagenta":"#f08ac8","brightCyan":"#9ff0f0","brightWhite":"#ffffff"}}"##;

/// JS -> Rust messages (`dioxus.send`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum FromJs {
    Ready {
        cols: u16,
        rows: u16,
    },
    /// `onData`: UTF-16 string, written to the PTY as UTF-8.
    In {
        d: String,
    },
    /// `onBinary`: binary string, one byte per char.
    Bin {
        d: String,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    /// Ctrl+].
    Close,
    /// Bytes written to xterm have been rendered (flow control).
    Ack {
        n: usize,
    },
}

/// Rust -> JS messages (`Eval::send`).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum ToJs {
    /// Base64 of raw PTY bytes.
    Out {
        d: String,
    },
    /// `term.paste`: types text without a newline.
    Type {
        d: String,
    },
    #[allow(dead_code)] // reserved: the JS side ignores unknown messages
    Status {
        s: String,
    },
    Exit {
        code: Option<i32>,
    },
    Focus,
    End,
}

impl FromJs {
    /// Bytes to write to the PTY for an input message.
    pub fn bytes(&self) -> Option<Vec<u8>> {
        match self {
            FromJs::In { d } => Some(d.clone().into_bytes()),
            FromJs::Bin { d } => Some(d.chars().map(|c| c as u32 as u8).collect()),
            _ => None,
        }
    }
}

/// Base64 of xterm.js + the fit addon: avoids the literal ESC/NBSP bytes in the
/// bundle and any quote-escaping hazard when passed through `eval`.
static B64: LazyLock<String> =
    LazyLock::new(|| super::base64(format!("{XTERM_JS}\n{FIT_JS}").as_bytes()));
static LOADED: AtomicBool = AtomicBool::new(false);

/// Loads xterm + fit addon into the webview (once). True when both are defined.
pub async fn ensure_loaded() -> bool {
    if LOADED.load(Ordering::Relaxed) {
        return true;
    }
    let js = format!(
        "if(!window.Terminal){{const b=atob('{}');const u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);(0,eval)(new TextDecoder().decode(u));}} return typeof window.Terminal==='function' && !!window.FitAddon;",
        *B64
    );
    let ok = dioxus::document::eval(&js)
        .join::<bool>()
        .await
        .unwrap_or(false);
    if ok {
        LOADED.store(true, Ordering::Relaxed);
    }
    ok
}

/// Long-lived bidirectional bridge for session `sid`. The promise stays pending
/// (`while(true){ await dioxus.recv() }`) until the Rust side sends `end`.
/// Written without JS template literals so nothing needs escaping.
pub fn bridge_js(sid: u32) -> String {
    const TEMPLATE: &str = r#"
const host = document.getElementById('nl-term-__SID__');
if (!host) { dioxus.send({t:'close'}); return false; }
try { await document.fonts.load("14px 'Share Tech Mono'"); } catch (_) {}
const term = new Terminal(__OPTS__);
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
term.open(host);
try { fit.fit(); } catch (_) {}
term.focus();
const dec = s => { const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
term.attachCustomKeyEventHandler(e => {
  if (e.type === 'keydown' && e.ctrlKey && (e.key === ']' || e.code === 'BracketRight')) { dioxus.send({t:'close'}); return false; }
  return true;
});
term.onData(d => dioxus.send({t:'in', d: d}));
term.onBinary(d => dioxus.send({t:'bin', d: d}));
term.onResize(r => dioxus.send({t:'resize', cols: r.cols, rows: r.rows}));
const ro = new ResizeObserver(() => { try { fit.fit(); } catch (_) {} });
ro.observe(host);
dioxus.send({t:'ready', cols: term.cols, rows: term.rows});
let pend = 0;
while (true) {
  const m = await dioxus.recv();
  if (m.t === 'out') {
    const u = dec(m.d); pend += u.length;
    term.write(u, () => { const n = u.length; pend -= n; dioxus.send({t:'ack', n: n}); });
  } else if (m.t === 'type') { term.paste(m.d); term.focus(); }
  else if (m.t === 'exit') { term.write('\r\n\x1b[31m// LINK DROPPED · EXIT ' + (m.code == null ? '?' : m.code) + ' // 切断\x1b[0m\r\n'); }
  else if (m.t === 'focus') { term.focus(); }
  else if (m.t === 'end') { ro.disconnect(); term.dispose(); return true; }
}
"#;
    TEMPLATE
        .replace("__SID__", &sid.to_string())
        .replace("__OPTS__", THEME_JSON)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assets_are_real() {
        assert!(XTERM_JS.len() > 400_000 && XTERM_JS.contains("Terminal"));
        assert!(FIT_JS.contains("FitAddon"));
        assert!(XTERM_CSS.contains(".xterm"));
    }

    #[test]
    fn b64_roundtrip_has_no_raw_escape() {
        assert!(!B64.contains('\u{1b}') && !B64.contains('\'') && !B64.contains('\u{a0}'));
        assert_eq!(
            B64.len(),
            (XTERM_JS.len() + 1 + FIT_JS.len()).div_ceil(3) * 4
        );
    }

    #[test]
    fn theme_is_valid_json() {
        let v: serde_json::Value = serde_json::from_str(THEME_JSON).unwrap();
        assert_eq!(v["theme"]["cursor"], "#ff1a2d");
        assert_eq!(v["scrollback"], 5000);
    }

    #[test]
    fn bridge_has_host_id_and_no_template_literals() {
        let js = bridge_js(7);
        assert!(js.contains("nl-term-7"));
        assert!(!js.contains("${"));
        assert!(!js.contains('`'));
        assert!(!js.contains("__SID__") && !js.contains("__OPTS__"));
    }

    #[test]
    fn protocol_serde() {
        let m: FromJs = serde_json::from_str(r#"{"t":"ready","cols":101,"rows":33}"#).unwrap();
        assert_eq!(
            m,
            FromJs::Ready {
                cols: 101,
                rows: 33
            }
        );
        let m: FromJs = serde_json::from_str(r#"{"t":"in","d":"ls\r"}"#).unwrap();
        assert_eq!(m.bytes().unwrap(), b"ls\r");
        let m: FromJs = serde_json::from_str(r#"{"t":"bin","d":"ÿ\u0001"}"#).unwrap();
        assert_eq!(m.bytes().unwrap(), vec![0xff, 1]);
        assert_eq!(
            serde_json::from_str::<FromJs>(r#"{"t":"close"}"#).unwrap(),
            FromJs::Close
        );
        assert_eq!(
            serde_json::to_string(&ToJs::Out { d: "QQ==".into() }).unwrap(),
            r#"{"t":"out","d":"QQ=="}"#
        );
        assert_eq!(serde_json::to_string(&ToJs::End).unwrap(), r#"{"t":"end"}"#);
        assert_eq!(
            serde_json::to_string(&ToJs::Exit { code: Some(1) }).unwrap(),
            r#"{"t":"exit","code":1}"#
        );
    }
}

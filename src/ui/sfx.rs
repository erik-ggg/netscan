//! Tiny synthesized soundscape (Web Audio, no files) plus the `prefers-reduced-motion` flag.
//! Everything is fire-and-forget: a failure to play never reaches the UI.

use dioxus::document;
use std::sync::atomic::{AtomicBool, Ordering};

static MUTED: AtomicBool = AtomicBool::new(false);
static REDUCED: AtomicBool = AtomicBool::new(false);

pub fn muted() -> bool {
    MUTED.load(Ordering::Relaxed)
}

/// Flips the mute flag; returns the new state (`true` = muted). Silences the hum at once.
pub fn toggle_mute() -> bool {
    let m = !MUTED.fetch_xor(true, Ordering::Relaxed);
    if m {
        let _ = document::eval("window.__nsfx&&window.__nsfx('hum_off')");
    }
    m
}

pub fn reduced_motion() -> bool {
    REDUCED.load(Ordering::Relaxed)
}

/// `kind`: lock, tick, granted, denied, relink, close, abort, hum_on, hum_off.
pub fn play(kind: &str) {
    if muted() && kind != "hum_off" {
        return;
    }
    let _ = document::eval(&format!("window.__nsfx&&window.__nsfx('{kind}')"));
}

const JS: &str = r#"
(function () {
  if (window.__nsfx) return;
  var ctx = null, master = null, hum = null, humTimer = null, noiseBuf = null;
  function ensure() {
    try {
      if (!ctx) {
        var AC = window.AudioContext || window.webkitAudioContext;
        if (!AC) return false;
        ctx = new AC();
        master = ctx.createGain(); master.gain.value = 0.06; master.connect(ctx.destination);
        var n = Math.floor(ctx.sampleRate * 0.3);
        noiseBuf = ctx.createBuffer(1, n, ctx.sampleRate);
        var d = noiseBuf.getChannelData(0);
        for (var i = 0; i < n; i++) d[i] = Math.random() * 2 - 1;
      }
      if (ctx.state !== 'running') ctx.resume();
      return true;
    } catch (e) { return false; }
  }
  // Real user gestures create/resume the context (WKWebView autoplay rules).
  ['pointerdown', 'keydown'].forEach(function (ev) {
    window.addEventListener(ev, ensure, { capture: true });
  });
  function osc(type, f0, f1, t, dur, vol, dest) {
    var o = ctx.createOscillator(), g = ctx.createGain();
    o.type = type; o.frequency.setValueAtTime(f0, t);
    if (f1 !== f0) o.frequency.exponentialRampToValueAtTime(f1, t + dur);
    g.gain.setValueAtTime(vol, t); g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
    o.connect(g); g.connect(dest || master); o.start(t); o.stop(t + dur + 0.02);
  }
  function noise(t, dur, freq, type, vol, q) {
    var s = ctx.createBufferSource(), f = ctx.createBiquadFilter(), g = ctx.createGain();
    s.buffer = noiseBuf; f.type = type; f.frequency.value = freq; f.Q.value = q || 1;
    g.gain.setValueAtTime(vol, t); g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
    s.connect(f); f.connect(g); g.connect(master); s.start(t); s.stop(t + dur + 0.02);
  }
  function humOff() {
    if (humTimer) { clearTimeout(humTimer); humTimer = null; }
    if (hum && ctx) {
      var h = hum; hum = null;
      try {
        var t = ctx.currentTime;
        h.g.gain.cancelScheduledValues(t); h.g.gain.setValueAtTime(h.g.gain.value, t);
        h.g.gain.linearRampToValueAtTime(0, t + 0.25);
        h.o1.stop(t + 0.3); h.o2.stop(t + 0.3);
      } catch (e) {}
    }
  }
  window.__nsfx = function (kind) {
    try {
      if (kind === 'hum_off') { humOff(); return; }
      if (!ensure()) return;
      var t = ctx.currentTime + 0.005;
      switch (kind) {
        case 'lock': osc('square', 900, 1800, t, 0.07, 0.5); break;
        case 'tick': noise(t, 0.008, 3000, 'bandpass', 0.7, 2); break;
        case 'granted': osc('sawtooth', 110, 110, t, 0.4, 0.5); osc('sawtooth', 165, 165, t, 0.4, 0.35); break;
        case 'denied': osc('sawtooth', 220, 80, t, 0.5, 0.45); osc('sawtooth', 227, 84, t, 0.5, 0.45); break;
        case 'relink': osc('square', 700, 1400, t, 0.06, 0.35); osc('sawtooth', 165, 165, t + 0.07, 0.22, 0.3); break;
        case 'close': noise(t, 0.16, 400, 'lowpass', 1.0, 0.7); break;
        case 'abort': osc('square', 600, 200, t, 0.12, 0.35); noise(t, 0.1, 500, 'lowpass', 0.6, 0.7); break;
        case 'hum_on':
          if (hum) return;
          var g = ctx.createGain(), o1 = ctx.createOscillator(), o2 = ctx.createOscillator();
          o1.type = 'sine'; o1.frequency.value = 55; o2.type = 'sine'; o2.frequency.value = 55.7;
          g.gain.setValueAtTime(0, t); g.gain.linearRampToValueAtTime(0.22, t + 0.6);
          o1.connect(g); o2.connect(g); g.connect(master); o1.start(t); o2.start(t);
          hum = { g: g, o1: o1, o2: o2 };
          humTimer = setTimeout(humOff, 12000); // failsafe
          break;
      }
    } catch (e) {}
  };
})();
"#;

/// Defines `window.__nsfx` and reads the reduced-motion preference. Call once at startup.
pub fn install() {
    let _ = document::eval(JS);
    dioxus::prelude::spawn(async {
        let ev = document::eval("return window.matchMedia('(prefers-reduced-motion: reduce)').matches;");
        if let Ok(v) = ev.join::<bool>().await {
            REDUCED.store(v, Ordering::Relaxed);
        }
    });
}

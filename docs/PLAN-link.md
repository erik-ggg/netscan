# PLAN-link.md — netscan "Evidence Classifier + Neural Link" iteration

> Authored by the Opus planning study (read-only; to be saved verbatim). Each phase agent: read this whole file, plus `docs/PLAN-intel.md` for conventions. Implement only your phase and keep earlier phases working.

## 0. Ground truth (verified)

### Code
- **Classifier.** `src/scan/classify.rs` holds `classify(&Device) -> DeviceKind`, an ordered first-match chain (model → keywords → services → vendor → random MAC). `refine(&Device, &DeviceIntel) -> Option<(K, String)>` is a separate first-match chain over deep-scan ports. Neither gives a confidence or an evidence list. `os::guess` (`src/scan/os.rs`) already uses scored candidates with evidence; mirror that style.
- **Classifier bugs:**
- `_amzn-wplay` → Iot (wrong: Fire TV).
- `_hap` → Iot fires before any TV vendor evidence. The LG TV advertised `_airplay`, `_display` and `_hap`; it was only saved by the hostname keyword.
- `"TCT" => Mobile` and `"TP-Link" => Iot` are hard-coded.
- `_ssh` → Computer misfiles the .194 box.
- **mDNS** (`src/scan/mdns.rs`): `Found { services, name, host, model }`. TXT is reduced to `model|md|am|rpMd` and `fn`. Service ports are dropped. `_display._tcp`, `_adb-tls-connect._tcp`, `_adb-tls-pairing._tcp` and `_androidtvremote._tcp` are not in `TYPES` (only reached via the meta-query, if at all).
- **Scan timing** (`$S/real.err`): sweep done at 2.06 s, ARP at 2.07 s, then the enrich `tokio::join!` waits for mDNS (4.5 s browse) until 4.51 s. **About 2.4 s idle window for extra probes.** SSDP multicast got 0 replies on this LAN, while mDNS works (multicast is not blocked for the Terminal-launched binary).
- **Current network** (`$S/now.json`): .1 Starlink gateway; .51 TCT (84:d1:5a, no RTT/TTL, ARP-only); .79/.218 TP-Link 10:5a:95 TTL 64; .124/.142/.242 AI-Link TTL 255; .154 Bilian TTL 64; .135/.189/.243 random MAC; .194 Newport Media f8:f0:05, host `WB277129`, `_ssh._tcp` + `_sftp-ssh._tcp`, dropbear 2018.76 (`$S/intel_194.json`). `$S/scan1.json` is an older scan **with the LG TV** (.32, vendor LG, name "LG webOS TV 2272", model `55NANO796NE`, services `_airplay._tcp _display._tcp _hap._tcp`). It is the offline fixture for the TV path.
- **.194 identification.** Wallbox chargers name themselves "WB" + serial ([jetcharge Wallbox troubleshooting](https://jetcharge.com.au/download/troubleshooting/wallbox), [Wallbox help: SN/UID](https://support.wallbox.com/en/wp-json/wp/v2/ht-kb/130723)). Pulsar Plus runs embedded Linux with SSH reachable on the LAN and needs legacy `ssh-rsa` host keys ([wallbox-pwn](https://github.com/jagheterfredrik/wallbox-pwn), [nzkiwi68/wallbox-pwn](https://github.com/nzkiwi68/wallbox-pwn), [HACF forum thread](https://forum.hacf.fr/t/quelquun-a-une-wallbox-plus-ou-max-ou-autre/27863?page=7)). Conclusion: most likely an **EV charger**, so `DeviceKind::Car` with sub-label "EV CHARGER".
- **OUIs** (`assets/oui.csv`): `84d15a` = "TCT mobile ltd" (TCL Communication handsets; TCL TVs use "TCL King Electrical Appliances (Huizhou)" / "TCL Technoly Electronics"). `f8f005` = Newport Media Inc. (Wi-Fi/IoT module silicon). `b461e9`/`dc9758` = Sichuan AI-Link (Changhong Wi-Fi modules). `203233` = Bilian (Wi-Fi modules/dongles).
- **UI:**
- `src/ui/app.rs` `Focus { None, Lock, Breach, Granted, Dossier, Closing }`. The App root `div.app` `onkeydown` handles `Escape` → `close()`, `m` → mute, `r` → rescan (Dossier). **Any key typed in an embedded terminal would bubble here.**
- The dossier (`src/ui/dossier.rs`) shows a KIND code and `kind_reason` ("◂ RECLASSIFIED (…)"). Section 04 is "OS PROFILE".
- The hover readout lives in `network_map.rs` (`detail` rows).
- The preview harness is `src/ui/mod.rs` (`page()` animation-kill list).
- `ui::base64` exists (hand-written encoder) — reuse it.

### Dioxus 0.7.10 (registry source)
- **`dioxus::document::eval(&str) -> Eval`.** `Eval` is `Copy`. `fn send(&self, impl Serialize) -> Result<(), EvalError>`. `async fn recv<T: DeserializeOwned>(&mut self) -> Result<T, EvalError>`. `async fn join<T>(self)`.
- **Desktop lifecycle** (`dioxus-desktop/src/query.rs`): the script runs as `new AsyncFunction("dioxus", script)`. When the promise resolves, `dioxus.close()` → Drop → the channel is gone. **A bidirectional bridge must keep its promise pending** (`while (true) { const m = await dioxus.recv(); … }`).
- Rust→JS `send` = one `webview.evaluate_script("window.getQuery(id).rustSend(<json>)")` per message, so **batch output**.
- JS→Rust `dioxus.send(x)` = `ipc.postMessage`.
- The Eval box is owned by the query slab, not the component scope, so it survives re-renders. It ends only by JS resolve/GC.
- `recv`/`send` borrow the generational box only inside `poll`, so a single `tokio::select!` over `recv` and an output channel is safe.
- **Hooks/events:** `use_drop(FnOnce)`, `use_hook_with_cleanup` and `use_effect` exist. `Event::stop_propagation()` / `prevent_default()` exist. Dioxus does its own bubbling, so `stop_propagation` on a wrapper prevents the `.app` `onkeydown`.
- **Default macOS menu** (`menubar.rs`): includes `close_window` (Cmd+W), `quit`, `copy`/`paste`/`select_all`. **Cmd+W closes the window (quits the app) and cannot be intercepted by page JS.** Cmd+C/Cmd+V reach the focused textarea, so xterm.js copy/paste works.
- `futures-channel` 0.3.34: use `try_recv()` (`try_next` is deprecated).

### Crates / assets (verified)
| Item | Version | License | Notes |
|---|---|---|---|
| `pty-process` | 0.5.4 | MIT | features `async = [tokio]`. API: `pty_process::open() -> Result<(Pty, Pts)>`; `Pty::resize(Size)`; `Pty::into_split() -> (OwnedReadPty, OwnedWritePty)` (AsyncRead/AsyncWrite; `OwnedWritePty::resize`); `Command::new(p).args(..).envs(..).current_dir(..).kill_on_drop(true).spawn(pts) -> Result<tokio::process::Child>` (builder by value; child becomes session leader with the pty as controlling tty); `Size::new(rows, cols)`. Deps: `rustix ^1.1.5` (lock already has 1.1.6) + tokio. **Chosen.** |
| `portable-pty` | 0.9.0 | MIT | Pulls nix 0.28, serial2, filedescriptor, shell-words, downcast-rs; blocking reader thread needed. Rejected (heavier, not tokio-native). |
| `vt100` 0.18.1 (MIT) / `alacritty_terminal` 0.26.0 (Apache-2.0) | — | — | Rust-side emulators that would need a DOM renderer, selection, IME, scrollback and keymaps written by us. Rejected. |
| ratatui | — | — | A TUI drawing library, not a terminal emulator. Not applicable. |
| `@xterm/xterm` | 6.0.0 | MIT | `lib/xterm.js` UMD 488,663 B (121 KB gz); `css/xterm.css` 7,112 B. The bundle contains a literal ESC (0x1b) and NBSP, so do not splice it raw into a JS string. API verified in typings: `onData`, `onBinary`, `onResize`, `attachCustomKeyEventHandler`, `write(string \| Uint8Array)`, `paste`, `focus`, `dispose`, `loadAddon`, options `theme`, `fontFamily`, `cursorBlink`, `scrollback`. |
| `@xterm/addon-fit` | 0.11.0 | MIT | `lib/addon-fit.js` 1,521 B UMD → `window.FitAddon.FitAddon`; `fit()`, `proposeDimensions()`. |

### cleanyourtv (via `gh api repos/Gathin23/cleanyourtv`)
- MIT License, very active (pushed 2026-11-02).
- **Flow:** enable Developer options → USB/Network debugging on the TV. Then `git clone`, `python3 -m venv tools/venv && tools/venv/bin/pip install -r tools/requirements.txt` (`adb-shell==0.4.4`, `rsa`, `cryptography`), then `export TV_HOST=<ip>`.
- **Tools:**
- `tools/venv/bin/python -I tools/tv.py --probe` — read-only.
- `tools/tv.py 'pm list packages'`
- `tools/disable.sh examples/<model>/debloat.txt` — `pm disable-user` for user 0; records state for undo; refuses non-package lines and core packages.
- `tools/restore.sh <same list> [stock launcher]`
- `tools/check.py`, `tools/privacy.py`
- `launcher/build-and-install.sh` — needs JDK 17–22 + Android SDK 34; out of scope.
- `tools/tv.py` is a pure-Python ADB client on **5555**; stock `adb` is not required. For wireless-debugging-only devices, pair once with stock `adb`, then `adb tcpip 5555`.
- **Not supported:** Samsung Tizen, LG webOS, Roku, Vizio, VIDAA.
- `examples/` holds per-model lists (TCL 81, Sony 46, Xiaomi 41, Philips 22, Skyworth 15, Hisense 14 …).

### Local environment
- `adb` is NOT installed.
- `/usr/bin/ssh` is present.
- `$SHELL=/bin/zsh`.

---

## 1. Task A — Evidence-weighted classifier

### 1.1 Model additions (`src/scan/model.rs`)
Every new field gets `#[serde(default)]` so old JSON still loads. Derives: `Debug, Clone, PartialEq, Default, Serialize, Deserialize`.

```rust
pub enum EvSource { #[default] Role, Model, Name, Mdns, Upnp, Probe, Port, Banner, Vendor, Ttl, Mac }

pub struct Evidence {
  pub kind: DeviceKind,
  pub weight: u8,            // 1..=99, "probability this alone is right"
  pub source: EvSource,
  pub text: String,          // HUD wording, e.g. "MDNS MODEL 55NANO796NE ▸ LG TV LINE"
}

pub struct Classification {
  pub kind: DeviceKind,
  pub confidence: u8,                  // 0..=100
  pub label: Option<String>,           // sub-type: "ANDROID TV", "GOOGLE TV", "STREAMER", "EV CHARGER", "SMART SPEAKER", "WEBOS TV"
  pub reason: String,                  // top evidence text of the winner
  pub evidence: Vec<Evidence>,         // winner's evidence first (desc weight), then the rest
  pub alt: Vec<(DeviceKind, u8)>,      // runner-ups with their p*100, max 2
}

pub struct Ident {                       // one identity answer from a beacon probe
  pub source: String,                  // "CAST" | "ROKU-ECP" | "SAMSUNG-API" | "PHILIPS-JS" | "DIAL"
  pub name: Option<String>, pub model: Option<String>, pub maker: Option<String>,
  pub os: Option<String>, pub is_tv: Option<bool>,
}
pub struct Beacon { pub open: Vec<u16>, pub idents: Vec<Ident>, pub elapsed_ms: u32 }

// Device: new fields
#[serde(default)] pub txt: BTreeMap<String, String>,     // selected mDNS TXT keys
#[serde(default)] pub svc_ports: BTreeMap<String, u16>,  // "_adb-tls-connect" -> 37151
#[serde(default)] pub beacon: Option<Beacon>,
#[serde(default)] pub class: Option<Classification>,

// DeviceIntel: new field (kind/kind_reason kept, filled from it for compat)
#[serde(default)] pub class: Option<Classification>,
```

`Device.kind` stays and always equals `class.kind`. Layout keys off `d.kind`, so positions never jump.

### 1.2 Scoring (`src/scan/classify/mod.rs`)

```rust
pub fn assess(d: &Device, intel: Option<&DeviceIntel>) -> Classification;
pub fn classify(d: &Device) -> DeviceKind { assess(d, None).kind }          // compat
pub fn refine(d: &Device, i: &DeviceIntel) -> Option<(DeviceKind, String)>  // compat: assess(d, Some(i)); Some if kind != d.kind && confidence >= 50
```

- **Collect.** Every rule pushes `Evidence`. Rules carry a stable `id: &'static str` internally; keep the max weight per `(id, kind)` so `_ssh` + `_sftp-ssh` count once.
- **Per-kind noisy-OR:** `p_k = 1 − Π(1 − w_i/100)`.
- **Winner** = argmax `p_k`. Ties break by fixed priority `[Router, Printer, Console, Car, Tv, Media, Tablet, Mobile, Computer, Iot]`.
- **Confidence** = `round(100 · p1 · (1 − p2²/2))`, clamped 1..=99. Role evidence (gateway/self) short-circuits to 100.
- **Floor:** `p1 < 0.30` → `kind = Unknown`. Keep the evidence; `reason = "WEAK: <best> <p1>%"`.
- **Label** = the label carried by the strongest winner evidence that has one (rules may attach a label; store it in a side map keyed by evidence index).
- **Worked numbers:**
- LG TV on (`scan1.json`): Tv ≈ 1.0, Iot (`_hap`) 0.45 → **Tv 90**.
- .51 TCT: Mobile 0.50, Tablet 0.20 → **Mobile 49**.
- .194: Car 0.70, Computer 0.45, Iot 0.35 → **Car 63**, label EV CHARGER.
- AI-Link TTL 255: Iot 0.75 → **Iot 75**.
- Random MAC TTL 64: **Mobile ≈ 49**.

### 1.3 Rule table (`classify/rules.rs`, `classify/patterns.rs`, `classify/brands.rs`)
Weights are starting values; tests pin outcomes, not weights.

| Source | Rule | Evidence |
|---|---|---|
| Role | `is_gateway` / `is_self` | Router / Computer 100 (short-circuit) |
| Model (Apple IDs) | `iphone*`/`ipod*` · `ipad*` · `appletv*` · `audioaccessory*` · `macbook*\|imac*\|macmini*\|macpro*\|mac*,*` · `watch*` | Mobile 97 · Tablet 97 · Tv 97 "APPLE TV" · Media 97 "HOMEPOD" · Computer 97 · Mobile 80 |
| Model patterns (applied to `model`, `txt[md]`, UPnP `model_name`/`model_number`, beacon `Ident.model`, hostname) | LG `^\d{2}(NANO\|UQ\|UR\|UP\|UN\|UM\|UK\|SM\|OLED\|QNED\|LM\|LX)` · Samsung `^(UE\|QE\|UN\|QN\|GQ\|GU\|HG)\d{2}` · Sony `^(KD\|XR\|KDL\|FW)-?\d{2}` · Philips `^\d{2}(PUS\|PFS\|PML\|OLED\|PUD\|PHS)\d` · generic `^(2[4-9]\|[3-9]\d)[A-Z]{1,5}\d{2,4}[A-Z0-9]{0,4}$` | Tv 92 "LG/SAMSUNG/SONY/PHILIPS TV LINE" · generic Tv 60 |
| Name keywords (hostname, mDNS name, UPnP friendly/model/manufacturer, Ident name) — existing `has()` token logic | TV words `webos, bravia, tizen, androidtv, googletv, firetv, fire-tv, roku, chromecast, shield, mibox, mitv, hisensetv, vidaa` → Tv 85 · token `tv` → Tv 65 · phone words → Mobile 70 · `ipad, tablet, tab` → Tablet 70 · printer words → Printer 75 · console words → Console 80 · `tesla, model3, modely` → Car 80 · computer words → Computer 55 (`macbook, imac, thinkpad` 80) · IoT words → Iot 55 · speaker words (`homepod, echo, alexa, sonos, soundbar, nest-mini, nesthub`) → Media 70 | |
| Name patterns | `^LGwebOSTV` or `^\[LG\]` → Tv 90 "WEBOS TV" · `^WB\d{6}$` → Car 60 "EV CHARGER" (Wallbox naming), +10 more if `_ssh` advertised or TTL 64 (→ 70) · `^(ESP\|esp32\|esp8266)[-_]` → Iot 85 · `^Galaxy-` → Mobile 75 · `^android[-_]?[0-9a-f]{6,}` → Mobile 40 + Tv 20 | |
| mDNS service | `_androidtvremote2`/`_androidtvremote` → Tv 90 "ANDROID TV" · `_googlecast` → Media 55 + Tv 35 · `_display` → Tv 60 · `_airplay` (no `_companion-link`) → Media 50 + Tv 30 · `_raop` alone → Media 45 · `_amzn-wplay` → Tv 55 "FIRE TV?" + Media 35 · `_hap` → Iot 45 · `_hue` → Iot 85 · `_matter*` → Iot 70 · `_meshcop` → Media 40 (Thread border router: HomePod/Apple TV/Nest Hub) · `_mqtt` → Iot 50 · `_ipp*`/`_printer`/`_pdl-datastream` → Printer 95 · `_sonos` → Media 90 · `_spotify-connect` → Media 40 · `_nvstream` → Computer 70 · `_smb`/`_afpovertcp`/`_workstation`/`_rdlink` → Computer 60 · `_ssh`/`_sftp-ssh` → Computer 45 · `_adb-tls-connect`/`_adb-tls-pairing` → Mobile 40 + Tv 30 "ANDROID" | |
| mDNS TXT `md` (Cast) | matches `Google TV\|Chromecast\|SHIELD\|BRAVIA\|TV` → Tv 90 ("GOOGLE TV" / "STREAMER") · `Nest Audio\|Nest Mini\|Google Home\|Google Nest` → Media 90 "SMART SPEAKER" · `Nest Hub` → Media 80 | |
| UPnP | `deviceType` MediaRenderer → Tv 45 + Media 45 (TV-maker vendor → Tv 75) · InternetGatewayDevice → Router 85 · manufacturer → brand priors (1.4) at +10 | |
| Beacon ports (sweep) | 6466 or 6467 → Tv 85 "ANDROID TV" · 8008+8009 → Media 50 + Tv 40 · 5555 → Tv 55 + Mobile 30 · 3000+3001 → Tv 80 (LG vendor → 92 "WEBOS TV") · 8001 or 8002 → Tv 80 (Samsung → 92 "TIZEN TV") · 8060 → Tv 90 "ROKU" · 1925 or 1926 → Tv 85 "PHILIPS TV" · 55000 → Tv 70 · 7000 alone → Media 25 | |
| Beacon idents | Cast `model` → model patterns + `md` rule at ≥ 90 · Roku `is_tv=true` → Tv 97 "ROKU TV", `false` → Tv 85 "STREAMER" · Samsung `type` contains "SmartTV" → Tv 97 · Philips ident → Tv 95 · DIAL descriptor → Tv 60 + text rules on its strings | |
| Deep ports (intel) | 62078 → Mobile 85 (Tablet if name has ipad) · 3389 → Computer 85 · 9100/631/515 → Printer 85 · 554 → Iot 55 "CAMERA" (only without TV evidence) · 6668/9999 → Iot 80 · 8123/1883 → Iot 65 · 9922 → Tv 70 (webOS dev mode) · same TV ports as beacon | |
| Banner | SSH distro (`ubuntu, debian, raspbian, freebsd`) → Computer 70 · `dropbear` → Iot 30 + Router 15 · NetBIOS + TTL 128 → Computer 85 | |
| TTL | 255 → Iot 45 (+Router 10) · 128 → Computer 50 · 64 → none | |
| MAC | randomized → Mobile 50, Tablet 15, Computer 15, Tv 10 | |
| Vendor priors (1.4) | max 70, so any specific evidence wins | |

### 1.4 Brand → product-line priors (`classify/brands.rs`)

```rust
pub struct Line { pub brand: &'static str, pub priors: &'static [(DeviceKind, u8)], pub note: &'static str }
pub fn line(vendor: &str) -> Option<&'static Line>;
```

| Brand (pretty vendor) | Priors | Note |
|---|---|---|
| TCT | Mobile 50, Tablet 20, Tv 15 | TCL COMMUNICATION: ALCATEL/TCL PHONES |
| TCL | Tv 70 | TCL KING: TV PANELS |
| Hisense | Tv 65, Mobile 10 | |
| Vestel | Tv 70 | |
| Skyworth / Changhong | Tv 65 | |
| TP Vision / Philips TV | Tv 75 | |
| LG | Tv 55, Mobile 10 | |
| Samsung | Mobile 40, Tv 35, Tablet 10 | |
| Sony | Tv 50, Media 20, Mobile 15 | |
| PlayStation | Console 85 | |
| Roku | Tv 85 "STREAMER" | |
| Amazon | Media 45, Tv 35, Iot 20, Tablet 15 | |
| Google | Media 50, Mobile 30, Tv 25 | |
| Xiaomi | Mobile 45, Iot 30, Tv 20 | |
| Nvidia | Computer 40, Tv 30 | |
| Apple | Mobile 35, Computer 30, Tablet 15 | |
| Espressif / Tuya / Shelly / Sonoff / Signify | Iot 70 | |
| AI-Link | Iot 55 | WI-FI MODULE: APPLIANCES |
| Bilian | Iot 45, Tv 15 | WI-FI MODULE |
| Newport Media | Iot 35 | WI-FI/IOT SILICON |
| TP-Link (non-gateway) | Iot 55, Router 25 | TAPO/KASA OR EXTENDER |
| Router brands (Netgear, ASUS, Ubiquiti, Starlink, AVM, Sagemcom, ZTE, …) | Router 45 | |
| Brother / Epson | Printer 70 | |
| Dell / Lenovo / HP / Intel / Raspberry Pi / Synology / QNAP / Realtek / Microsoft | Computer 55 | |
| Huawei / OnePlus / Oppo / Vivo / Realme / Honor / Motorola / Nothing | Mobile 60 | |
| Nintendo / Valve | Console 80 | |
| Tesla | Car 80 | |
| Sonos | Media 85 | |

`vendor.rs` BRANDS additions:
- `("tp vision","TP Vision")`, `("vestel","Vestel")`, `("skyworth","Skyworth")`, `("changhong","Changhong")`, `("newport media","Newport Media")`.
- "TCL King…" already maps to "TCL"; "TCT mobile" maps to "TCT".

### 1.5 mDNS changes (`src/scan/mdns.rs`)
- `TYPES` add: `_display._tcp`, `_adb-tls-connect._tcp`, `_adb-tls-pairing._tcp`, `_androidtvremote._tcp`, `_amzn-alexa._tcp`.
- `Found` add `txt: BTreeMap<String,String>` for the keys `md, fn, model, am, rpMd, manufacturer, ty, usb_MDL, ca`. Values are `clean()`ed and capped at 80 chars.
- `Found` add `ports: BTreeMap<String,u16>` (short type without `._tcp` → `info.port`).
- `scan/mod.rs` copies both into `Device.txt` / `Device.svc_ports`.

### 1.6 BEACON — cheap TV/streamer probes in the sweep (`src/scan/beacon.rs`)

```rust
pub const TV_PORTS: [u16; 16] = [5555, 6466, 6467, 8008, 8009, 8443, 3000, 3001, 8001, 8002, 7000, 8060, 1925, 1926, 9922, 55000];
pub fn candidates(alive: &HashMap<Ipv4Addr, HostProbe>, arp: &BTreeMap<Ipv4Addr, String>, local: Ipv4Addr, gw: Option<Ipv4Addr>) -> Vec<Ipv4Addr>;
  // every ARP/alive IP except self & gateway, TTL ∈ {64, None} (TVs/boxes are Linux;
  // skip 255 RTOS and 128 Windows), cap 48 hosts.
pub async fn probe_all(hosts: Vec<Ipv4Addr>, cap: Duration) -> BTreeMap<Ipv4Addr, Beacon>;
async fn probe_host(client: &reqwest::Client, ip: Ipv4Addr) -> Beacon;
pub fn parse_eureka(json: &str) -> Option<Ident>;   // top-level "name"; "device_info"{"model_name","manufacturer"} or top-level fallbacks
pub fn parse_roku(xml: &str) -> Option<Ident>;      // <user-device-name> <model-name> <vendor-name> <is-tv>
pub fn parse_samsung(json: &str) -> Option<Ident>;  // device.{name, modelName, OS, type} or top-level name/type
pub fn parse_philips(json: &str) -> Option<Ident>;  // name, model (tolerate missing fields)
pub async fn dial_unicast(sock: &UdpSocket, hosts: &[Ipv4Addr]); // M-SEARCH ST urn:dial-multiscreen-org:service:dial:1 to ip:1900
```

- **Connects.** TCP connect only, all concurrent (`buffer_unordered(256)`), 450 ms timeout. 8 hosts × 16 ports on this LAN = 128 connects.
- **Identity GETs, only if the port is open.** reqwest client: invalid certs allowed, no redirects, connect 500 ms, total 900 ms, body ≤ 32 KiB via `chunk()`.
- 8008 → `GET http://ip:8008/setup/eureka_info?params=name,device_info`; else 8443 → `https://ip:8443/setup/eureka_info?params=name,device_info`. Eureka needs no local auth token ([GHLocalApi](https://rithvikvibhu.github.io/GHLocalApi), [pychromecast dial.py](https://github.com/balloob/pychromecast/blob/063ad9169294315dd80fca91935e674732b5ee9f/pychromecast/dial.py), [killcast endpoints](https://deepwiki.com/thewhiteh4t/killcast/6.1-chromecast-api-endpoints)).
- 8060 → `GET /query/device-info`.
- 8001 → `GET http://ip:8001/api/v2/` (else 8002 https).
- 1925 → `GET http://ip:1925/6/system` (else 1926 https).
- **DIAL.** In parallel, unicast `M-SEARCH` (`ST: urn:dial-multiscreen-org:service:dial:1`, MX 1) to each candidate on 1900. Same socket, 1 s window. For each reply with `LOCATION` host == responder (reuse `ssdp::parse_response` + `ssdp::fetch_description`), add `Ident{source:"DIAL"}` from friendlyName/modelName/manufacturer. Also fill `Device.upnp` when empty.
- **Wiring** (`scan/mod.rs`): right after the ARP phase, `let beacon_task = tokio::spawn(timeout(1800ms, beacon::probe_all(cands, 1700ms)))`. Join it inside the existing enrich `tokio::join!`; it overlaps the mDNS wait, so there is **no added wall time** (finishes ≈ 3.9 s < 4.5 s).
- Log: `"BEACON {n} HOSTS // {p} TV PORTS // {k} IDENTS"`.
- Then `d.beacon = …; let c = classify::assess(d, None); d.kind = c.kind; d.class = Some(c);`.
- **Deep scan:** `intel::deep_scan` Assemble calls `classify::assess(&t.device, Some(&intel))` → `intel.class`. Set `intel.kind`/`kind_reason` from it when the kind differs and confidence ≥ 50.
- **Safety:** in-subnet only (filter with `net::in_subnet`); connects + plain GETs of public info endpoints; no writes, no pairing. Update the README safety text.

### 1.7 CLI for validation (`src/main.rs`)
`--reclassify <scan.json>`: load a `ScanResult`, run `assess` per device, print a table `IP  VENDOR  OLD→NEW  CONF  LABEL  REASON` to stdout. Works offline against `$S/scan1.json` (LG TV present) and `$S/now.json`.

### 1.8 Acceptance tests (table-driven, `classify/tests.rs`)
Fixtures are built with `Device { …, ..Default::default() }`; JSON snippets come from real responses.

| # | Fixture | Expect |
|---|---|---|
| 1 | LG on: vendor LG, host "LG webOS TV 2272", model 55NANO796NE, `_airplay._tcp _display._tcp _hap._tcp` | Tv ≥ 85, reason mentions model or WEBOS |
| 2 | LG, no mDNS, beacon open [3000, 3001] | Tv ≥ 80, label "WEBOS TV" |
| 3 | TCT, nothing else (.51) | Mobile, 35 ≤ conf ≤ 55, `alt` contains Tablet or Tv |
| 4 | TCT + beacon [8008, 8009, 6466] + Cast ident model "TCL Google TV" | Tv ≥ 85, label "GOOGLE TV" or "ANDROID TV" |
| 5 | AI-Link TTL 255 | Iot ≥ 60 |
| 6 | Bilian TTL 64 | Iot, conf ≤ 55 |
| 7 | TP-Link non-gateway TTL 64 | Iot, conf ≤ 60 |
| 8 | random MAC TTL 64 | Mobile 40–55 |
| 9 | Newport Media, host WB277129, `_ssh._tcp _sftp-ssh._tcp`, TTL 64 | Car, label "EV CHARGER", ≥ 50; with intel dropbear banner + 22 open still Car |
| 10 | `_googlecast` + txt md "Chromecast" | Tv, label "STREAMER" |
| 11 | `_googlecast` + md "Google Nest Mini" | Media "SMART SPEAKER" |
| 12 | Amazon + `_amzn-wplay` + beacon 5555 | Tv |
| 13 | beacon Roku ident is_tv=true vendor TCL | Tv ≥ 95 |
| 14 | Samsung + 8001/8002 + ident type "Samsung SmartTV" | Tv ≥ 95; Samsung + random-ish nothing → Mobile |
| 15 | Sony + `_googlecast` md "BRAVIA 4K VH2" | Tv |
| 16 | vendor "TP Vision" | Tv |
| 17 | gateway / self | Router / Computer 100 |
| 18 | `_ipp._tcp` Canon | Printer |
| 19 | intel 62078 open | Mobile (Tablet with ipad name) |
| 20 | all existing `classify`/`refine` tests | same kinds, except the deliberate changes (document each) |

Plus parser tests: `parse_eureka` (new and old shape), `parse_roku` (sample XML), `parse_samsung` (sample JSON), `parse_philips`, `candidates` filter, and an mDNS TXT/port capture unit (pure helper).

### 1.9 Validating on this network
1. `cargo run --release -- --reclassify $S/scan1.json` → .32 Tv ≥ 85; .194 Car EV CHARGER.
2. `cargo run --release -- --cli > $S/after.json 2> $S/after.err` → total ≤ 6 s (expect ~4.5 s). Log shows a `BEACON` line. Kinds: .51 Mobile (~49%), .79/.218 Iot, AI-Link Iot, .154 Iot (low), random MACs Mobile, .194 Car.
3. `--intel 192.168.1.194` → class stays Car.
4. When the LG TV is on: live `--cli` → Tv ≥ 85 (and beacon shows 3000/3001 if the TV answers).
5. If any Android/Google TV appears: beacon 8008/8009/6466 + Cast ident.

### 1.10 Classification UI
- **Hover readout** (`network_map.rs` `detail` rows): add `("CLASS", "DISPLAY 92%")` and `("WHY", class.reason)` (trunc 48), and the label when present (`"DISPLAY // WEBOS TV"`).
- **Map:** nodes with confidence < 50 get `class: "node-body uncertain"`: icon stroke opacity .55, plus a 9-px mono "?" at (+18, +18) inside the ±31 box (the collision test must stay green). Kind label text gets a `·?` suffix.
- **Dossier header `dz-kind`:** code + jp, then `conf_bar(confidence)` + "92%". The label line ("WEBOS TV"). The reason in `.dz-reclass` style. The full evidence list in a `title` attribute (native tooltip).
- **Dossier Section 04** renamed **"PROFILE 基盤"**: two blocks.
- **OS** (unchanged content).
- **CLASS**: up to 6 evidence lines `+92 MODEL 55NANO796NE ▸ LG TV LINE` (winner kind bright, others `--mute` with kind tag), then `ALT ▸ IOT NODE 45%`.
- Use `intel.class` when done, else `device.class`.

---

## 2. Task B — CONNECT + embedded terminal ("NEURAL LINK // 神経接続")

### 2.1 Architecture decision
**xterm.js 6.0.0 + fit addon in the WebView, `pty-process` (tokio) in Rust, one long-lived `document::eval` per session as the bridge.**

Why not the alternatives:
- **Line console (pipes, no PTY):** `ssh` reads passwords from `/dev/tty`, `adb shell` drops to non-interactive mode, and there is no colour, Ctrl+C semantics or curses.
- **`vt100`/`alacritty_terminal` → HTML diff:** we would own selection, IME, scrollback, cursor and key encoding, and Dioxus re-render cost on every byte burst.
- **ratatui:** wrong layer.
- **xterm.js:** gives correct VT emulation, bracketed paste, copy/paste through the native Edit menu, Unicode/CJK width and a good DOM renderer.
- **Cost:** +0.5 MB binary, MIT licenses (ship notices in `assets/vendor/xterm/` and mention them in the README).

**Asset loading:**
- `assets/vendor/xterm/{xterm.js, xterm.css, addon-fit.js, LICENSE-xterm.txt, LICENSE-addon-fit.txt}`, pinned versions, downloaded from unpkg once in Phase 4. Record sha256 in a comment in `src/ui/xterm.rs`.
- `xterm.css` is appended into `ui::css()` (7 KB, always present).
- JS is lazy-loaded on first link via `xterm::ensure_loaded().await`:
- `static B64: LazyLock<String>` = `base64(XTERM_JS + "\n" + FIT_JS)`.
- `document::eval(&format!("if(!window.Terminal){{const b=atob('{b64}');const u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);(0,eval)(new TextDecoder().decode(u));}} return typeof window.Terminal==='function' && !!window.FitAddon;"))` → `join::<bool>()`.
- Base64 avoids the literal ESC/NBSP and quote-escaping hazards. Indirect eval runs the UMD in global scope, so `globalThis.Terminal` and `globalThis.FitAddon` get defined.
- Memoize success in a `static LOADED: AtomicBool`.
- Before `term.open`: `await document.fonts.load("14px 'Share Tech Mono'")` so xterm measures the right cell size.
- Font: `"'Share Tech Mono', Menlo, monospace"`. Share Tech Mono lacks box-drawing glyphs and the DOM renderer falls back per-glyph. If `htop`-style borders misalign in testing, switch the terminal grid font to `Menlo, 'Share Tech Mono'` and keep Share Tech Mono for the chrome.

**Theme (xterm `theme`):**
- background `#060405`, foreground `#f3ebe8`, cursor `#ff1a2d`, cursorAccent `#060405`, selectionBackground `rgba(255,26,45,.35)`.
- black `#1d0709`, red `#ff1a2d`, green `#8fd4a8`, yellow `#e8c070`, blue `#7aa2d6`, magenta `#d06aa8`, cyan `#6fc9c9`, white `#c9bdba`.
- brights: `#4a0e15`, `#ff4a58`, `#b5f0c8`, `#ffe0a0`, `#a8c6f0`, `#f08ac8`, `#9ff0f0`, `#ffffff`.
- Options: `cursorBlink: true`, `scrollback: 5000`, `fontSize: 14`, `lineHeight: 1.1`, `allowProposedApi: false`.

### 2.2 Backend modules

```
src/link/mod.rs      Proto, LinkRequest, validate(), bootstrap() -> SpawnSpec
src/link/tools.rs    Tools { adb, ssh, git, python3, shell }, detect()
src/link/plan.rs     LinkPlan, Readiness, plans(&Device, Option<&DeviceIntel>, &Tools) -> Vec<LinkPlan>
src/link/pty.rs      PtyHandle, PtyCmd, PtyEvent, spawn()
src/link/payload.rs  cleanyourtv presets (pure: id, title, text, destructive, needs)
src/ui/xterm.rs      assets, ensure_loaded(), bridge_js(sid) -> String, theme JSON
src/ui/link.rs       LinkConfig drawer + NeuralLink console components
```

```rust
// link/mod.rs
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)] pub enum Proto { Adb, AdbPair, Ssh, Local }
#[derive(Clone, PartialEq, Debug)]
pub struct LinkRequest {
  pub ip: Ipv4Addr, pub proto: Proto,
  pub ssh_user: Option<String>, pub ssh_port: u16, pub legacy_rsa: bool,
  pub adb_port: u16,                                   // 5555 or the wireless-debugging connect port
  pub pair: Option<(u16 /*pair port*/, String /*6-digit code*/)>,
}
pub fn validate(r: LinkRequest, net: &NetworkInfo) -> anyhow::Result<LinkRequest>;
//   in_subnet(ip); ssh_user ^[a-z_][a-z0-9_.-]{0,31}$; code ^\d{6}$; ports 1..=65535.
//   Device-provided strings (names, models) are NEVER interpolated into commands.
pub struct SpawnSpec { pub program: PathBuf, pub args: Vec<String>, pub env: Vec<(String, String)>, pub cwd: PathBuf, pub typed: Option<String> }
pub fn bootstrap(r: &LinkRequest, t: &Tools) -> SpawnSpec;
```

**Bootstrap = always the user's interactive shell** (`$SHELL -i`, fallback `/bin/zsh -i`) with env:
- `TERM=xterm-256color`, `COLORTERM=truecolor`, `LANG` (default `en_US.UTF-8` if unset)
- `NETSCAN_TARGET=<ip>`, `TV_HOST=<ip>`, `NETSCAN_DATA=$HOME/Library/Application Support/netscan`
- `ANDROID_SERIAL=<ip>:<port>` for ADB
- `PATH` = inherited + `/opt/homebrew/bin:/usr/local/bin:$HOME/Library/Android/sdk/platform-tools`

`typed` is the first line, written into the PTY followed by `\r`:
- **Adb:** `adb connect 192.168.1.32:5555 && adb -s 192.168.1.32:5555 shell`
- **AdbPair:** `adb pair 192.168.1.32:41235 123456 && adb connect 192.168.1.32:37151 && adb -s 192.168.1.32:37151 shell`
- **Ssh:** `ssh -o ConnectTimeout=8 -o ServerAliveInterval=15 [-p P] [-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa] [user@]192.168.1.194`
- **Local:** none (banner comment only: `# netscan link // target $NETSCAN_TARGET`)

Why a shell wrapper:
- The command is visible.
- When `adb shell`/`ssh` exits the user lands in a local shell with `TV_HOST` already set, which is exactly what cleanyourtv needs.
- No credential handling by us. Passwords and host-key prompts happen in the terminal; nothing is stored.

```rust
// link/tools.rs
pub struct Tools { pub adb: Option<PathBuf>, pub ssh: Option<PathBuf>, pub git: Option<PathBuf>, pub python3: Option<PathBuf>, pub shell: PathBuf }
pub fn detect() -> Tools; // PATH entries + /opt/homebrew/bin, /usr/local/bin, ~/Library/Android/sdk/platform-tools; is_file && executable.
// /usr/bin/git and /usr/bin/python3 are CLT stubs: report them as present but flag `clt_stub: bool` if `xcode-select -p` fails (std::process::Command, 1 s).
```

```rust
// link/plan.rs
pub enum Readiness { Ready, NeedsTool { tool: &'static str, install: &'static str }, NeedsDeviceSetup { steps: Vec<&'static str> }, Unlikely }
pub struct LinkPlan { pub proto: Proto, pub title: String, pub why: String, pub port: Option<u16>, pub readiness: Readiness, pub rank: u8 }
pub fn plans(d: &Device, i: Option<&DeviceIntel>, t: &Tools) -> Vec<LinkPlan>; // sorted by rank desc, Local always last
```

Plan rules (port open = beacon.open ∪ intel open ports):

| Condition | Plan |
|---|---|
| 5555 open | Adb, port 5555, rank 90, "5555/TCP ADB ANSWERING". `adb` missing → `NeedsTool{ "adb", "brew install --cask android-platform-tools" }` |
| `svc_ports["_adb-tls-connect"]` present | AdbPair with that connect port, rank 85; pair port from `_adb-tls-pairing` if present, else user enters it |
| Android-ish class (label ANDROID/GOOGLE TV, `_androidtvremote2`, 6466, Cast+Tv) but 5555 closed | Adb, rank 60, `NeedsDeviceSetup{ ["SETTINGS ▸ DEVICE PREFERENCES ▸ ABOUT ▸ BUILD ×7", "DEVELOPER OPTIONS ▸ USB DEBUGGING ON (+ NETWORK/ADB DEBUGGING IF SHOWN)", "OR WIRELESS DEBUGGING ▸ PAIR WITH CODE"] }` |
| 22 open or `_ssh` | Ssh, rank 70; dropbear banner → default user `root`, `legacy_rsa` pre-checked, `why` "DROPBEAR ▸ LEGACY KEYS LIKELY" |
| 9922 open (+LG) | Ssh port 9922 user `prisoner`, rank 65, why "WEBOS DEVELOPER MODE (KEY FROM DEV MODE APP)" |
| LG/webOS class without 9922 | informational `Unlikely`: "WEBOS EXPOSES NO SHELL // SSAP CONTROL = FUTURE" |
| Samsung/Tizen class | `Unlikely`: "TIZEN: SDB 26101 ONLY IN DEVELOPER MODE" |
| always | Local, rank 10, "LOCAL SHELL WITH $TV_HOST SET" |

```rust
// link/pty.rs
pub enum PtyCmd { Input(Vec<u8>), Resize { cols: u16, rows: u16 }, Kill }
pub enum PtyEvent { Output(Vec<u8>), Exited(Option<i32>) }
#[derive(Clone)] pub struct PtyHandle { pub id: u32, tx: futures::channel::mpsc::UnboundedSender<PtyCmd> }
impl PtyHandle { pub fn input(&self, b: Vec<u8>); pub fn resize(&self, cols: u16, rows: u16); pub fn kill(&self); }
pub async fn spawn(spec: SpawnSpec, cols: u16, rows: u16)
  -> anyhow::Result<(PtyHandle, futures::channel::mpsc::UnboundedReceiver<PtyEvent>)>;
```

Implementation of `spawn` (must be awaited inside the tokio runtime; the UI calls it via `tokio::spawn` + oneshot, or directly in a Dioxus task since a tokio context exists — existing code already uses tokio there):
- `let (pty, pts) = pty_process::open()?; pty.resize(Size::new(rows, cols))?;`
- `let mut child = pty_process::Command::new(&spec.program).args(&spec.args).envs(spec.env).current_dir(&spec.cwd).kill_on_drop(true).spawn(pts)?;`
- `let (mut r, mut w) = pty.into_split();`
- **Reader task:** `let mut buf = vec![0; 16384]; loop { match r.read(&mut buf).await { Ok(0) | Err(_) => break, Ok(n) => out_tx.unbounded_send(Output(buf[..n].to_vec())) } }`. macOS returns EIO after the slave side closes; treat it as EOF.
- **Supervisor task:** `loop { tokio::select! { c = cmd_rx.next() => match c { Some(Input(b)) => { let _ = w.write_all(&b).await; } Some(Resize{cols,rows}) => { let _ = w.resize(Size::new(rows, cols)); } Some(Kill) | None => { let _ = child.start_kill(); } }, st = child.wait() => { out_tx.unbounded_send(Exited(st.ok().and_then(|s| s.code()))); break } } }`. After Kill, keep looping until `wait` returns.
- If `typed` is set, send it as the first `Input` after spawn (`typed + "\r"`).
- **Lifecycle guarantees:**
- Explicit Kill on SEVER/unmount.
- Dropping every `PtyHandle` closes `cmd_rx`, which kills the child.
- `kill_on_drop(true)` on the Child.
- On app quit or crash the PTY master fd closes and the kernel hangs up the session, so the session leader gets SIGHUP.
- For ADB, SEVER also runs a one-off `adb disconnect ip:port` (plain `tokio::process::Command`, 2 s timeout).
- The adb server daemon is left alone (shared with other tools; mention it in the README).
- **One link at a time** (modal). The `sid` counter allows future multi-session.

### 2.3 JS bridge (`ui/xterm.rs::bridge_js(sid) -> String`)
Protocol (serde `#[serde(tag = "t", rename_all = "lowercase")]`):
- JS → Rust `FromJs`:
- `{t:"ready",cols,rows}`
- `{t:"in",d:"<utf16 string>"}` — from `onData`; Rust writes `d.as_bytes()` (UTF-8)
- `{t:"bin",d:"<binary string>"}` — from `onBinary`; bytes = chars as u8
- `{t:"resize",cols,rows}`
- `{t:"close"}` — Ctrl+]
- `{t:"ack",n}` — bytes written, for flow control
- Rust → JS `ToJs`:
- `{t:"out",d:"<base64 bytes>"}`
- `{t:"type",d:"<text>"}` — `term.paste` without newline
- `{t:"status",s}`
- `{t:"exit",code}`
- `{t:"focus"}`
- `{t:"end"}`

```js
const host = document.getElementById('nl-term-${sid}');
await document.fonts.load("14px 'Share Tech Mono'");
const term = new Terminal({ ...THEME_OPTS });
const fit = new FitAddon.FitAddon(); term.loadAddon(fit);
term.open(host); fit.fit(); term.focus();
const dec = s => { const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
term.attachCustomKeyEventHandler(e => {
if (e.type === 'keydown' && e.ctrlKey && (e.key === ']' || e.code === 'BracketRight')) { dioxus.send({t:'close'}); return false; }
return true; // ESC, Ctrl+C, arrows… all go to the PTY
});
term.onData(d => dioxus.send({t:'in', d}));
term.onBinary(d => dioxus.send({t:'bin', d}));
term.onResize(({cols, rows}) => dioxus.send({t:'resize', cols, rows}));
const ro = new ResizeObserver(() => { try { fit.fit(); } catch (_) {} }); ro.observe(host);
dioxus.send({t:'ready', cols: term.cols, rows: term.rows});
let pend = 0;
while (true) {
const m = await dioxus.recv();
if (m.t === 'out') { const u = dec(m.d); pend += u.length; term.write(u, () => { pend -= u.length; if (pend === 0) dioxus.send({t:'ack', n: u.length}); }); }
else if (m.t === 'type') { term.paste(m.d); term.focus(); }
else if (m.t === 'exit') { term.write(`\r\n\x1b[31m// LINK DROPPED · EXIT ${m.code ?? '?'} // 切断\x1b[0m\r\n`); }
else if (m.t === 'focus') { term.focus(); }
else if (m.t === 'end') { ro.disconnect(); term.dispose(); return true; }
}
```

**Rust bridge task** (in `NeuralLink`, started from the host div's `onmounted` via `spawn`):
```rust
let ev = document::eval(&xterm::bridge_js(sid));
let mut evr = ev;                                    // Copy: one for recv, one for send
let FromJs::Ready { cols, rows } = evr.recv().await? else { … };
let (h, mut out) = link::pty::spawn(spec, cols, rows).await?;
handle.set(Some(h.clone()));                         // Signal<Option<PtyHandle>> for SEVER / payload
let mut inflight = 0usize;                           // simple flow control
loop {
  tokio::select! {
      m = evr.recv::<FromJs>() => match m {
          Ok(FromJs::In { d }) => h.input(d.into_bytes()),
          Ok(FromJs::Bin { d }) => h.input(d.chars().map(|c| c as u8).collect()),
          Ok(FromJs::Resize { cols, rows }) => h.resize(cols, rows),
          Ok(FromJs::Ack { .. }) => inflight = 0,
          Ok(FromJs::Close) => { on_sever.call(()); break }
          Ok(FromJs::Ready { .. }) => {}
          Err(_) => break,
      },
      o = out.next(), if inflight < 1 << 20 => match o {
          Some(PtyEvent::Output(mut b)) => {
              let mut exit = None;
              while b.len() < 64 * 1024 {
                  match out.try_recv() {
                      Ok(PtyEvent::Output(m)) => b.extend(m),
                      Ok(e) => { exit = Some(e); break }
                      Err(_) => break,
                  }
              }
              watcher.feed(&b, status);                     // status chip heuristics
              inflight += b.len();
              let _ = ev.send(ToJs::Out { d: base64(&b) });
              if let Some(PtyEvent::Exited(c)) = exit { status.set(LinkStatus::Dropped(c)); let _ = ev.send(ToJs::Exit { code: c }); }
          }
          Some(PtyEvent::Exited(c)) => { status.set(LinkStatus::Dropped(c)); let _ = ev.send(ToJs::Exit { code: c }); }
          None => { /* process gone; keep the loop for "type"/close until SEVER */ }
      },
  }
}
```

- **Copy/paste rule:** copy values out of signals before writing them (AlreadyBorrowed lesson).
- **Cleanup:** `use_drop` on `NeuralLink`: `if let Some(h) = handle.peek().clone() { h.kill(); }` (clone first, then call), then `let _ = ev.send(ToJs::End)`. Keep `ev` in a `use_signal(|| None::<Eval>)`, copied out first.
- **Status watcher** (`link::status::Watcher`, pure, tested): keeps a 512-byte lowercase rolling tail and maps phrases to `LinkStatus`:

| Phrase in output | Status |
|---|---|
| `"connected to "` / `"already connected"` | Linked |
| `"unauthorized"`, `"failed to authenticate"` | AwaitingAuth ("ACCEPT PROMPT ON TV 承認待ち") |
| `"password:"`, `"passphrase"` | AwaitingSecret |
| `"connection refused"`, `"no route"`, `"timed out"`, `"cannot connect"`, `"failed to connect"` | Failed |
| `"host key verification failed"`, `"no matching host key type"` | KeyIssue (suggest LEGACY KEYS) |
| `"successfully paired"` | Paired |

The chip is advisory only; it never drives input.

### 2.4 cleanyourtv integration (`link/payload.rs`, PAYLOAD drawer)
Shown only for Adb/AdbPair/Local links whose target class is Tv/Media with an Android label or 5555/6466 open.

```rust
pub struct Preset { pub id: &'static str, pub step: &'static str, pub title: &'static str, pub jp: &'static str,
                  pub text: String, pub destructive: bool, pub needs: &'static [&'static str] /* "git","python3","repo","venv" */ }
pub fn presets(brand_slug: Option<&'static str>) -> Vec<Preset>;
pub fn brand_slug(vendor: &str) -> Option<&'static str>; // whitelist: tcl, sony, xiaomi, philips, skyworth, hisense, sharp, amazon, panasonic, nvidia, google, onn, toshiba…
```

`$CYT` = `"$NETSCAN_DATA/cleanyourtv"` (quoted; the path has a space).

| Step | Text typed (user presses ⏎) | Destructive |
|---|---|---|
| 01 ACQUIRE 取得 | `mkdir -p "$NETSCAN_DATA" && { git -C "$NETSCAN_DATA/cleanyourtv" pull --ff-only 2>/dev/null \|\| git clone --depth 1 https://github.com/Gathin23/cleanyourtv "$NETSCAN_DATA/cleanyourtv"; } && cd "$NETSCAN_DATA/cleanyourtv"` | no |
| 02 ARM 準備 | `python3 -m venv tools/venv && tools/venv/bin/pip install -r tools/requirements.txt` | no |
| 03 PROBE 探査 | `tools/venv/bin/python -I tools/tv.py --probe` | no (read-only) |
| 04 BACKUP 保存 | `mkdir -p backups && tools/venv/bin/python -I tools/tv.py 'pm list packages -f' > "backups/$TV_HOST-$(date +%Y%m%d-%H%M).txt" && echo saved` | no |
| 05 FIND LIST 検索 | `ls examples \| grep -i -- '<slug>'` (slug from the whitelist only; omitted → `ls examples`) | no |
| 06 PURGE 除去 | `tools/disable.sh examples/` (cursor left for the model folder + `/debloat.txt`) | **yes**: confirm modal first; the user still presses ⏎ |
| 07 RESTORE 復元 | `tools/restore.sh examples/` | no (it's the undo) |
| 08 VERIFY 照合 | `tools/venv/bin/python -I tools/check.py examples/` | no |

- Rules:
- Presets only *type* (`ToJs::Type` → `term.paste`); nothing auto-runs.
- Steps needing a missing tool render disabled with the install hint (`git`: `xcode-select --install`; `python3` likewise).
- The drawer header shows "AUTHORIZE THE NEW KEY ON THE TV": `tv.py` uses its own ADB key, so the TV prompts again.
- Footer link text: "LAUNCHER BUILD (JDK 17–22 + SDK 34) ▸ SEE REPO README". It is not automated.
- **Confirm modal (PURGE):**
- "DISABLE PACKAGES ON 192.168.1.32 FOR USER 0 · NOTHING IS UNINSTALLED · UNDO WITH 07 RESTORE".
- Checkbox "BACKUP TAKEN (STEP 04)".
- Buttons `[ABORT 中止]` `[TYPE COMMAND 入力]`.
- Default focus on ABORT. ESC inside the modal = abort (the modal's own handler; stop propagation).
- Optional: if `claude`/`codex`/`gemini` is on PATH, a preset "ASSISTANT 助手" types `cd "$NETSCAN_DATA/cleanyourtv" && claude`, matching the repo's quick start (PROMPT.md).

### 2.5 UX flow and state

```rust
enum Focus { …, Link { idx: usize } }   // idx() covers it; map stays focused/zoomed underneath
// App: link_req: Signal<Option<LinkRequest>>, link_run: Signal<u32> (key for remounts)
```

- **Dossier:**
- New foot button `[C] CONNECT 接続 ▸ ADB` (label = top plan proto), and a small `CONNECT` chip in `dz-kind` when the top plan is `Ready`.
- Shown for all non-Internet devices. Self → Local only.
- Pressing it (or `C` while `Focus::Dossier`) opens the **LINK CONFIG drawer** inside the dossier (local `Signal<bool>`). Inputs there stop keydown propagation.
- **LINK CONFIG** shows:
- plan tabs (ADB / PAIR / SSH / LOCAL with readiness glyph)
- fields (SSH user/port/legacy keys; PAIR port + code + connect port, pre-filled from `svc_ports`)
- an exact command preview (mono, read-only)
- tool status (`adb ✕ NOT INSTALLED ▸ brew install --cask android-platform-tools` + `[TYPE IN LOCAL SHELL]`, which opens a Local link with that text pre-typed)
- device-setup steps
- the scope line "TARGET LOCKED TO 192.168.1.32 // IN-SUBNET ONLY // NO CREDENTIALS STORED"
- `[ENGAGE 接続]`, which calls `link::validate` → `on_connect(req)` → App sets `link_req` and `Focus::Link{idx}`, `sfx::play("link")`
- **NEURAL LINK console** (full screen, z 30, above the dossier, which is unmounted while linked):
- Handshake: 1.2 s **non-blocking**. Reuse `.ix-sweep` + `DecodeText` "NEURAL LINK"; 4 step pips `LOCK ▸ ROUTE ▸ <PROTO> ▸ PTY` light as real states land (Ready → spawned → first output → Linked/AwaitingAuth). The terminal fades in at the first output.
- ESC, Ctrl+C, `r`, `m` all go to the terminal.
- **Close:** `[⏏ SEVER 切断]` button or **Ctrl+]**, then `Focus::Dossier{idx}` with a CRT collapse (reuse `.dz-wrap.closing` keyframes on `.nl-wrap`).
- **Cmd+W is not used** (it closes the window, i.e. quits; the PTY dies via SIGHUP). Footer says `CTRL+] SEVER · ⌘C/⌘V COPY/PASTE`.
- **App key guard (critical):** first line of the `.app` `onkeydown`: `if matches!(*focus.peek(), Focus::Link { .. }) { return; }` (copy out). The terminal host div also has `onkeydown: |e| e.stop_propagation()`. `close()` ignores `Focus::Link`.
- **After exit:** status `LINK DROPPED // EXIT n`; buttons `[RE-ENGAGE 再接続]` (bumps `link_run` key → remount) and `[SEVER]`.
- **Sound** (`sfx.rs`): `link` (rising square 400→1600 Hz 120 ms + saw 82 Hz 300 ms), `sever` (= close). Muted rules unchanged. No hum while linked.
- **Scanlines:** `.app.linked .scanlines { opacity: .35 }` for legibility (add `linked` class when `Focus::Link`).

### 2.6 Wireframes (1280×800)

**A. Dossier + LINK CONFIG drawer** (drawer slides over column 3, right 420 px)

```
┌╱ TARGET PROFILE 標的記録 ── 192.168.1.32 ── SCAN 2.41s ── ● SCAN COMPLETE 完了 ───────── [ESC] DISCONNECT 切断╲┐
│ ┌──────┐ LG WEBOS TV 2272                         DISPLAY 映像 ▮▮▮▮▯ 90%  ┃╱ LINK CONFIG 接続設定 ─────────── ✕ ╲│
│ │ ICON │ 192.168.1.32 · a8:23:fe:… · LG            WEBOS TV                ┃ PROTOCOL                              │
│ └──────┘ OS ▸ WEBOS 85%  RTT 3.2/4.1/6.0  TTL 64   ◂ MODEL 55NANO796NE    ┃ [ADB ✕] [PAIR ✕] [SSH ◐] [LOCAL ●]    │
├───────────────────────────┬────────────────────────────────────────────┃ ── SSH // 9922 WEBOS DEV MODE ─────── │
│ 01 IDENTITY 識別           │ 03 PORT LATTICE 港湾 4/36 OPEN             ┃ USER  [prisoner_____]  PORT [9922]    │
│ …                          │ …                                          ┃ [ ] LEGACY RSA KEYS                   │
├───────────────────────────┤────────────────────────────────────────────┃ COMMAND ─────────────────────────── │
│ 02 SIGNAL 信号             │ 04 PROFILE 基盤                             ┃ $ ssh -o ConnectTimeout=8 -p 9922    │
│                            │ OS  WEBOS (LINUX) ▮▮▮▮▯ 85%                ┃   prisoner@192.168.1.32               │
│                            │ CLASS DISPLAY 90% // WEBOS TV              ┃ ADB ✕ NOT A WEBOS VECTOR              │
│                            │ +92 MODEL 55NANO796NE ▸ LG TV LINE         ┃ ⓘ KEY: DEV MODE APP ▸ KEY SERVER      │
│                            │ +90 NAME "LG webOS TV" ▸ WEBOS             ┃ ▲ TARGET LOCKED 192.168.1.32          │
│                            │ +45 _HAP ▸ IOT        ALT ▸ IOT NODE 45%   ┃   IN-SUBNET ONLY · NO CREDS STORED    │
│                            │                                            ┃          [ ENGAGE 接続 ▸ ]            │
├───────────────────────────┴────────────────────────────────────────────┸──────────────────────────────────────┤
│ 36 PORTS · 4 ECHOES · 2 PROBES       [R] RE-SCAN 再走査  [C] CONNECT 接続 ▸ SSH  [ESC] DISCONNECT   荒坂 SEC-OPS │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**B. NEURAL LINK console** (full screen; inset 28 px; sidebar 300 px right)

```
┌╱ NEURAL LINK 神経接続 ▸ 192.168.1.47 ▸ GOOGLE TV ▸ ADB 5555 ── ◉ LINKED 接続中 ── T+00:42 ────── [⏏ SEVER 切断]╲┐
│ ┌─ LOCK ▣ ─ ROUTE ▣ ─ ADB ▣ ─ PTY ▣ ────────────────────────────────────────┐ ┌ TARGET 標的 ─────────────────┐│
│ │ $ adb connect 192.168.1.47:5555 && adb -s 192.168.1.47:5555 shell          │ │ GOOGLE TV // TCL 55C745       ││
│ │ connected to 192.168.1.47:5555                                             │ │ 192.168.1.47 · ANDROID 85%    ││
│ │ sabrina:/ $ pm list packages | wc -l                                       │ │ PROTO ADB · PTY 118×34        ││
│ │ 214                                                                        │ │ ENV  TV_HOST=192.168.1.47     ││
│ │ sabrina:/ $ █                                                              │ ├ PAYLOAD // CLEANYOURTV 浄化 ──┤│
│ │                                                                            │ │ 01 ACQUIRE 取得     [TYPE ▸]  ││
│ │          (xterm.js, black, crimson cursor, Share Tech Mono 14px)           │ │ 02 ARM 準備         [TYPE ▸]  ││
│ │                                                                            │ │ 03 PROBE 探査       [TYPE ▸]  ││
│ │                                                                            │ │ 04 BACKUP 保存      [TYPE ▸]  ││
│ │                                                                            │ │ 05 FIND LIST 検索   [TYPE ▸]  ││
│ │                                                                            │ │ 06 PURGE 除去 ▲     [ARM… ]   ││
│ │                                                                            │ │ 07 RESTORE 復元     [TYPE ▸]  ││
│ │                                                                            │ │ 08 VERIFY 照合      [TYPE ▸]  ││
│ └────────────────────────────────────────────────────────────────────────────┘ │ TYPED ONLY · YOU PRESS ⏎      ││
│                                                                                └───────────────────────────────┘│
│ CTRL+] SEVER · ⌘C/⌘V COPY/PASTE · ESC → TERMINAL           0xA5C0 // 荒坂 NEURAL-OPS                           │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**C. Missing tool / awaiting auth chips** (inside the console header or config):
```
 ADB ✕ NOT INSTALLED 未導入 ▸ brew install --cask android-platform-tools   [TYPE IN LOCAL SHELL ▸] [RE-CHECK]
 ◐ AWAITING AUTH 承認待ち ▸ ACCEPT "ALLOW USB DEBUGGING?" ON THE TV  (pulsing amber-red)
```

**D. PURGE confirm** (centered 560×260 modal over the console):
```
┌╱ CONFIRM PURGE 除去確認 ──────────────────────────────────────╲┐
│ DISABLE PACKAGES ON 192.168.1.47 FOR USER 0                    │
│ NOTHING IS UNINSTALLED · UNDO: 07 RESTORE (SAME LIST)          │
│ [■] BACKUP TAKEN (STEP 04)                                     │
│ THE COMMAND IS TYPED, NOT RUN. REVIEW, THEN PRESS ⏎.           │
│                         [ ABORT 中止 ]   [ TYPE COMMAND 入力 ▸ ] │
└────────────────────────────────────────────────────────────────┘
```

Layout: `.nl-wrap` fixed inset 28 px, grid `1fr 300px`, header 44 px, footer 28 px. The terminal host is `position:relative; min-height:0` so FitAddon measures the real box. Cut corners via `clip-path` like `.dossier`, 1 px `--red-dim` border, a 2 px red top-left accent. The terminal panel background is exactly `#060405` (xterm draws its own). At 1024×680 the sidebar collapses to 240 px.

### 2.7 Security and safety
- Targets: `LinkRequest.ip` must parse and pass `net::in_subnet`. Every app-built command is assembled only from validated values (IP, numeric ports, regex-checked user, 6-digit code, whitelisted brand slug). Never from hostnames/models/TXT, which are device-controlled and could carry shell metacharacters.
- The local shell is the user's own shell; README states that netscan only *prepares* commands for the selected target.
- No credentials stored; no auto-entered passwords; no brute force; payload steps are typed, never executed; PURGE requires a confirm.
- Processes: the 5-layer cleanup from 2.2. Check after SEVER: `ps -o pid,stat,command -t <tty>` shows nothing, and `pgrep -f "adb -s 192.168.1.47"` is empty.

### 2.8 Future (not this iteration)
LG webOS SSAP control panel: WebSocket on 3000/3001, pairing prompt on the TV, client-key stored only on consent. Volume, inputs, app launch, power off. Would need `tokio-tungstenite` 0.30.0 (MIT). Similar: Roku ECP keypad (`POST :8060/keypress/…`), Samsung remote over `wss :8002`.

---

## 3. Risks / open questions
1. **Beacon false positives.** 3000 (dev servers), 7000 (macOS AirPlay receiver), 8443 (admin UIs). Mitigated by low weights and by requiring pairs (3000+3001, 8008+8009). Tests pin this.
2. **Probe endpoints drift.** Philips `/6/system` fields and Cast eureka on 8008 (some firmware restricts it) are uncertain. Parsers must tolerate missing fields; 8443 is the fallback.
3. **macOS Local Network privacy.** Unicast UDP/TCP to the LAN works today (sweep/intel). A bundled `.app` would need `NSLocalNetworkUsageDescription`; out of scope (still `cargo run`).
4. **The WB###### rule is a heuristic** (Wallbox naming). Labelled "EV CHARGER" at ≤ 70 weight; the dossier evidence line says "WALLBOX-STYLE NAME".
5. **Eval message rate.** Each `send` is an `evaluate_script`. Batching (64 KiB) + ack watermark (1 MiB) bound it. If `adb logcat` floods still stutter, raise the batch to 256 KiB or add an 8 ms coalescing sleep.
6. **Font metrics.** Share Tech Mono lacks box glyphs; there is a fallback plan (2.1).
7. **xterm in SSR previews.** Not runnable; previews render a static mock screen (`NeuralLink { mock: Some(lines) }` prop) to check chrome/layout.
8. **`zsh -i` startup.** User rc files may print or be slow. Acceptable; the `typed` line is queued in the PTY input buffer and runs once the prompt reads it.
9. **CLT stubs.** `/usr/bin/git`/`python3` without Command Line Tools pop the installer. We only type commands, so the user sees what happens.
10. **ADB auth keys.** Stock `adb` (`~/.android/adbkey`) and cleanyourtv's `tv.py` key are separate, so the TV prompts twice. Documented in the drawer.
11. **Cmd+W quits the app.** A custom `with_menu` without `close_window` is possible later; for now SIGHUP cleanup covers it.

---

## 4. Phases

**Every phase:**
- First read this file, `docs/PLAN-intel.md` §0, `src/scan/model.rs`, `src/scan/mod.rs`, `src/ui/app.rs`, `src/ui/dossier.rs`, `assets/main.css`.
- **Verification:**
- `cargo build --release` with **zero warnings**
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `cargo run --release -- --cli` (JSON parses, timings on stderr)
- **Preview:** `S=/private/tmp/claude-502/-Users-erik-gonzalezgarcia-Privado-dev/b054c6e7-cbf4-40f4-b75c-59529f38b668/scratchpad; PREVIEW_DIR=$S PREVIEW_JSON=$S/real.json cargo test dump_ -- --nocapture`, then `$S/shot.sh <name> 1280 800` (and `1024 680`). Read the PNGs and iterate. Real-window screenshots are impossible.
- **Visual phases (3, 5) must invoke the Skill tool `frontend-design:frontend-design` before writing CSS/markup.** Keep the Arasaka language (black, `--red #ff1a2d`, Rajdhani + Share Tech Mono, JP accents, cut corners).
- **Dioxus rule:** never hold `peek()`/`read()` guards while writing the same signal (copy out first). New animated classes go into the preview `page()` override list. No git commits.

### Phase 1 — EVIDENCE CLASSIFIER (backend, pure)
- **Goal:** replace first-match `classify`/`refine` with the scored `assess`; capture mDNS TXT/ports; offline `--reclassify`.
- **Files:**
- `scan/model.rs` (§1.1 types + fields; Beacon/Ident defined now, filled in P2)
- `src/scan/classify.rs` → `src/scan/classify/{mod.rs, rules.rs, patterns.rs, brands.rs, tests.rs}` (§1.2–1.4; keep `classify()`/`refine()` signatures)
- `scan/mdns.rs` (§1.5)
- `scan/mod.rs` (fill `txt`, `svc_ports`, `class`)
- `scan/vendor.rs` (BRANDS additions)
- `scan/intel/mod.rs` (Assemble → `intel.class`)
- `main.rs` (`--reclassify <json>`)
- fix struct literals in `ui/mod.rs` previews if needed (`..Default::default()`)
- **Signatures:** `classify::assess(&Device, Option<&DeviceIntel>) -> Classification`; `brands::line(&str) -> Option<&'static Line>`; `patterns::tv_model(&str) -> Option<(u8, &'static str)>`; `patterns::host_label(&str) -> Vec<(DeviceKind, u8, &'static str, Option<&'static str>)>`.
- **Acceptance:**
- §1.8 rows 1–3, 5–11, 15–20 pass (rows 4, 12–14 use hand-built `Beacon` values and must pass too).
- `--reclassify $S/scan1.json` shows .32 Tv ≥ 85 and .194 Car "EV CHARGER".
- `--reclassify $S/now.json` matches §1.9.
- Old JSON (no new fields) deserializes.
- **Pitfalls:**
- Dedupe evidence per rule id.
- Keep `Device.kind == class.kind`.
- Don't change layout inputs.
- `has()` short-keyword token semantics: reuse it.

### Phase 2 — BEACON (sweep probes)
- **Goal:** §1.6 end-to-end, with real-network validation, without increasing scan time.
- **Files:** NEW `scan/beacon.rs`; `scan/mod.rs` (spawn after ARP, join in enrich, log line, fill `beacon` and `upnp` from DIAL); `scan/ssdp.rs` (extract a reusable `unicast_search(sock, ip, st)` helper if useful); `scan/intel/mod.rs` (reuse it in `upnp_unicast`); README safety paragraph.
- **Signatures:** as in §1.6.
- **Acceptance:**
- `--cli` total ≤ 6 s (expect ≈ 4.5 s) with a `BEACON` log line.
- Parser tests with fixture strings (eureka new/old, Roku XML, Samsung JSON, Philips JSON).
- Loopback test: `probe_host` against `127.0.0.1` with a tokio `TcpListener` serving canned eureka JSON on an ephemeral port. Make the port table a parameter: `probe_host_ports(client, ip, &[(port, Fetch)])`.
- `candidates()` filter test.
- Write `$S/after.json` and paste the reclassified table into the phase report.
- **Pitfalls:**
- Cap bodies (≤ 32 KiB `chunk()` loop).
- Accept invalid certs only for 8443/8002/1926.
- Never follow redirects or LOCATIONs off the responder IP.
- The task must not delay `scan()` beyond the mDNS join (wrap in `timeout(1800ms)`).

### Phase 3 — CLASSIFICATION UI (visual; invoke frontend-design first)
- **Goal:** §1.10 — hover CLASS/WHY rows, uncertain node styling, dossier header confidence + label + reason tooltip, Section 04 "PROFILE 基盤" with the CLASS evidence block.
- **Files:** `ui/network_map.rs`, `ui/dossier.rs`, `assets/main.css`, `ui/mod.rs` (preview: `dossier_class.html` from a fixture LG TV device with class + evidence; refresh `real.html`/`real_hover.html`; `$S/real.json` may be regenerated by `--cli`).
- **Acceptance:**
- Previews at 1280×800 and 1024×680 show conf bars, evidence lines and the "?" on low-confidence nodes.
- The layout collision test is still green.
- Values ellipsize; nothing overflows.
- **Pitfalls:** `title` tooltips must be plain text; keep Section 04 height similar (max 6 evidence lines).

### Phase 4 — LINK BACKEND
- **Goal:** everything in §2.2–2.4 that is not visual, testable headless.
- **Files:**
- `Cargo.toml`: `pty-process = { version = "0.5.4", features = ["async"] }`
- NEW `assets/vendor/xterm/*`: `curl -sL https://unpkg.com/@xterm/xterm@6.0.0/lib/xterm.js`, `…/css/xterm.css`, `https://unpkg.com/@xterm/addon-fit@0.11.0/lib/addon-fit.js`, and both LICENSE files; record sha256
- NEW `src/link/{mod,tools,plan,pty,payload,status}.rs`
- NEW `src/ui/xterm.rs` (`XTERM_JS`, `FIT_JS`, `XTERM_CSS` via `include_str!`; `ensure_loaded()`; `bridge_js(sid)`; `THEME_JSON`)
- `ui/mod.rs` (`css()` appends `XTERM_CSS`; move `base64` to `pub(crate)`)
- `main.rs`: `--link-plan <ip>` runs `scan()` and prints `plans()` + `bootstrap()` for each; `--pty-echo` spawns `/bin/sh -c 'stty size; echo ok'` at 33×101 and prints the output
- **Signatures:** §2.2, §2.3 (`FromJs`/`ToJs` serde enums), `status::Watcher::feed(&mut self, &[u8]) -> Option<LinkStatus>`.
- **Acceptance:**
- Tests: pty spawn `echo hi` → Output contains "hi", Exited(Some(0)); `stty size` after spawn at (rows 33, cols 101) prints "33 101"; Resize then `stty size` reflects it; Kill on `sleep 30` → Exited within 1 s; drop handle → child gone.
- `validate` rejects out-of-subnet, bad user, bad code.
- `bootstrap` golden strings for Adb/AdbPair/Ssh(legacy)/Local.
- `plans()` table for .194 (Ssh first, root, legacy), an Android TV with 5555 open and adb missing (NeedsTool), LG without 9922 (Unlikely note), self (Local only).
- `Watcher` phrase table.
- `bridge_js` contains `nl-term-<sid>` and no unescaped `${`.
- Binary grows by ≈ 0.5 MB; still zero warnings.
- **Pitfalls:**
- pty-process needs the tokio reactor (tests use `#[tokio::test]`).
- Treat read `Err` (EIO) as EOF.
- Spawn with `kill_on_drop(true)`.
- `try_recv`, not `try_next`.
- Don't interpolate device strings into commands.

### Phase 5 — NEURAL LINK UI (visual; invoke frontend-design first)
- **Goal:** §2.5–2.6 end-to-end — CONNECT, LINK CONFIG, console with live PTY, PAYLOAD drawer + PURGE confirm, handshake, key guards, sounds, README.
- **Files:**
- `ui/app.rs` (`Focus::Link`, `idx()`, key guard, `link_req`, `link_run`, `.app.linked` class)
- `ui/dossier.rs` (CONNECT button, `C` key via an `on_link` prop, drawer)
- NEW `ui/link.rs` (`LinkConfig { device, intel, network, tools, on_connect, on_cancel }`, `NeuralLink { device, req, run: u32, on_sever, #[props(default)] mock: Option<Vec<String>> }`, `Payload`, `ConfirmPurge`)
- `ui/sfx.rs` (`link`)
- `assets/main.css` (`/* ---------- neural link ---------- */` block)
- `ui/mod.rs` previews: `link_config_ssh.html` (.194), `link_config_noadb.html`, `link_console.html` (mock lines), `link_purge.html`
- README: "Neural link" section, keys, safety, xterm MIT notice, cleanyourtv credit/link
- **Acceptance (manual, real window by the user; the agent verifies via previews + logs):**
- CONNECT on the gateway/self opens a Local shell. Typing works; ESC reaches the shell (e.g. `vi`); `r`/`m` don't rescan/mute.
- Window resize reflows (`tput cols` changes).
- Ctrl+C interrupts `ping 192.168.1.1`.
- ⌘C/⌘V work.
- Ctrl+] severs, back to the dossier; no orphan processes (`pgrep -f "netscan link"` / `ps -t`).
- SSH to .194 shows the host-key prompt (legacy toggle prefilled).
- PAYLOAD presets type without executing; PURGE needs the confirm.
- Previews OK at 1280×800 and 1024×680.
- **Pitfalls:**
- Start the bridge from `onmounted` of the host div (element must exist).
- One eval per mount (key the component on `run`).
- `use_drop` → kill + `End` (copy handles out of signals first).
- Inputs in LinkConfig stop keydown propagation.
- The console is modal: map clicks are ignored while `Focus::Link`.
- Don't animate `filter` on large elements.
- Add new animated classes to `page()`.

---

## Sources
- [Wallbox Help Center — serial number / UID](https://support.wallbox.com/en/wp-json/wp/v2/ht-kb/130723)
- [Wallbox Help Center — charger name](https://support.wallbox.com/en/knowledge-base/how-to-change-a-chargers-name-on-the-mywallbox-portal)
- [Jetcharge — Wallbox troubleshooting ("WB" + serial)](https://jetcharge.com.au/download/troubleshooting/wallbox)
- [KATEK ghost ONE manual (host name/MAC access data)](https://www.manualslib.mx/manual/843936/Katek-Ghost-One-Basic.html?page=30)
- [wallbox-pwn](https://github.com/jagheterfredrik/wallbox-pwn) · [nzkiwi68/wallbox-pwn](https://github.com/nzkiwi68/wallbox-pwn)
- [HACF forum — Wallbox SSH / ssh-rsa](https://forum.hacf.fr/t/quelquun-a-une-wallbox-plus-ou-max-ou-autre/27863?page=7)
- [Home Assistant community — Wallbox Pulsar Plus integration](https://community.home-assistant.io/t/wallbox-pulsar-plus-integration/200339?page=41)
- [Apache NuttX dropbear docs](https://nuttx.apache.org/docs/latest/applications/netutils/dropbear/index.html)
- [pychromecast dial.py (eureka_info)](https://github.com/balloob/pychromecast/blob/063ad9169294315dd80fca91935e674732b5ee9f/pychromecast/dial.py)
- [dart_chromecast issue (8443 eureka_info params)](https://github.com/terrabythia/dart_chromecast/issues/2)
- [killcast Chromecast API endpoints](https://deepwiki.com/thewhiteh4t/killcast/6.1-chromecast-api-endpoints)
- [Google Home local API (unofficial)](https://rithvikvibhu.github.io/GHLocalApi)
- [Gathin23/cleanyourtv](https://github.com/Gathin23/cleanyourtv) (README, `tools/disable.sh`, `tools/restore.sh`, `tools/requirements.txt`, LICENSE, via `gh api`)
- npm registry / unpkg: `@xterm/xterm@6.0.0`, `@xterm/addon-fit@0.11.0`
- crates.io API: `pty-process` 0.5.4, `portable-pty` 0.9.0

### Critical Files for Implementation
- /Users/erik.gonzalezgarcia/Privado/dev/netscan/src/scan/classify.rs (→ `src/scan/classify/` module)
- /Users/erik.gonzalezgarcia/Privado/dev/netscan/src/scan/mod.rs (beacon wiring, `txt`/`svc_ports`/`class` fill)
- /Users/erik.gonzalezgarcia/Privado/dev/netscan/src/scan/model.rs (Classification, Evidence, Beacon, Ident, new Device fields)
- /Users/erik.gonzalezgarcia/Privado/dev/netscan/src/ui/app.rs (`Focus::Link`, key guard, link state)
- /Users/erik.gonzalezgarcia/Privado/dev/netscan/src/ui/dossier.rs (CONNECT, LINK CONFIG drawer, PROFILE/CLASS section)
- New: /Users/erik.gonzalezgarcia/Privado/dev/netscan/src/link/pty.rs, /Users/erik.gonzalezgarcia/Privado/dev/netscan/src/ui/link.rs, /Users/erik.gonzalezgarcia/Privado/dev/netscan/src/ui/xterm.rs, /Users/erik.gonzalezgarcia/Privado/dev/netscan/src/scan/beacon.rs
# PLAN-intel.md — netscan "Deep Intel + Intrusion" iteration

> Authored by the Opus planning study. Implementation is done phase by phase (one agent per phase). Each phase agent: read this whole file first, implement ONLY your phase, keep earlier phases working.

## 0. Ground truth (verified in code)

- **State flow** (`src/ui/app.rs`): `App` owns signals `stage`, `phase`, `logs`, `result: Signal<Option<ScanResult>>`, `hovered: Signal<Option<usize>>`. Scan runs via `tokio::spawn(scan::scan(cb))`; a `futures::channel::mpsc::unbounded` channel is drained in a Dioxus `spawn` that writes signals. **Reuse this exact pattern**: network work on tokio, signal writes on the Dioxus-local task (`Signal` is not `Send`).
- **`NetworkMap(result: ScanResult, hovered: Signal<Option<usize>>)`** (`src/ui/network_map.rs`): calls `layout::layout(devs)` every render; Internet node uses pseudo-index `devs.len()`; router drawn at `(CX, CY)` with `router_id`; devices are `g` with `onmouseenter`/`onmouseleave` — no click handlers yet; footer `legend` shows a readout built from `detail`.
- **SVG/z-order**: viewBox 1280×760 (`layout.rs` W/H), `preserveAspectRatio xMidYMid meet`. SMIL pulses injected with `dangerous_inner_html` (`pulses()`). `.scanlines` z 50, `.vignette` z 49 → new overlays at z 20–40 so scanlines stay on top.
- **`Device`** (`src/scan/model.rs`): `ip, mac, is_self, is_gateway, hostname, vendor, model, services, kind, mac_randomized`; `label()` falls back hostname → model → vendor → kind name. Built as a struct literal in 6 places (`scan/mod.rs` ×2, `classify.rs` tests, `layout.rs` tests, `ui/mod.rs` preview `fake()`) → **add `Default` first**.
- **`ping.rs`**: `icmp_probe` returns `bool` (drops `(IcmpPacket, Duration)`); `sweep` returns `HashSet<Ipv4Addr>`; `TCP_PORTS = [80, 443, 22, 62078, 8080, 554]`; `udp_touch` already hits UDP 137.
- **`classify::classify(&Device) -> DeviceKind`**: model → keywords → mDNS services → vendor → randomized MAC.
- **Preview harness**: `ui/mod.rs::preview::dump_preview` uses `VirtualDom` + `dioxus_ssr`; `page()` disables animations via a CSS override listing specific classes — **new animated classes must be added to that list** or previews catch them mid-animation (invisible). Screenshot: `"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu --hide-scrollbars --window-size=1280,800 --screenshot=<out.png> file://<dir>/<name>.html`.
- **Crates**: no new crates needed. `surge_ping::Icmpv4Packet::get_ttl() -> Option<u8>`; `ping()` returns `(IcmpPacket, Duration)`; `reqwest::ClientBuilder::tls_danger_accept_invalid_certs` / `tls_danger_accept_invalid_hostnames` / `redirect(Policy::none())`; `dioxus::document::eval` (`Eval::send/recv/join`); dioxus-html `MountedData::set_focus`, `KeyboardData::key() -> Key`. (`roxmltree 0.21.2` / `quick-xml 0.42` exist but hand-written tag extraction is enough.)

## 1. Data / backend design

### 1.1 What runs when

| Technique | When | Cost | Why |
|---|---|---|---|
| ICMP RTT + TTL | Sweep (already pinging) | 0 | free OS hint + latency for map |
| SSDP M-SEARCH (`ssdp:all`, MX=2) | Sweep, spawned alongside mDNS | ~2.5 s background | one multicast covers LAN |
| UPnP description XML (LOCATION) | Sweep, enrich phase (cap 2.5 s, 1.5 s/fetch) | few HTTP GETs | `friendlyName` → better labels/classify |
| OS guess | Computed (sweep facts + intel when present) | 0 | |
| 4× timed ping (min/avg/max/loss) | Deep | ~0.4 s | drives "ECHO" lines |
| TCP connect scan, 36 ports | Deep | ≤0.7 s (all concurrent) | |
| Banner read (21/22/23) | Deep, open only | ≤0.6 s | read-only, never write |
| HTTP(S) GET `/` (title, Server, auth realm, X-Powered-By) | Deep, open HTTP-ish ports | ≤2 s | |
| RTSP `OPTIONS` (554) | Deep, if open | ≤0.6 s | `Server:` names camera vendor |
| NetBIOS NBSTAT (UDP 137) | Deep, always | ≤0.8 s | Windows/Samba name, workgroup, MAC |
| UPnP unicast M-SEARCH to ip:1900 | Deep, only if sweep missed it | ≤1 s | |

### 1.2 New and changed files

```
src/scan/model.rs     (+Default, new fields, new structs: UpnpInfo, OsGuess, DeviceIntel, ...)
src/scan/ping.rs      sweep -> HashMap<Ipv4Addr, HostProbe>
src/scan/ssdp.rs      NEW  discover(), parse_response(), fetch_description(), parse_description()
src/scan/os.rs        NEW  guess(&Device, Option<&DeviceIntel>) -> OsGuess
src/scan/textutil.rs  NEW  xml_tag(), html_title(), clean() (shared by ssdp + intel)
src/scan/intel/mod.rs NEW  deep_scan(), IntelEvent, stage orchestration, hard cap
src/scan/intel/ports.rs   NEW  PORTS table + connect scan
src/scan/intel/probe.rs   NEW  banner(), http_fingerprint(), rtsp_options()
src/scan/intel/netbios.rs NEW  build_query(), parse_status(), query()
src/scan/intel/risk.rs    NEW  notes + exposure
src/scan/classify.rs  + refine(&Device, &DeviceIntel) -> Option<(DeviceKind, String)>
src/main.rs           + `--intel <ip>` CLI mode
```

### 1.3 Structs (`model.rs`; derive `Debug, Clone, PartialEq, Serialize, Deserialize`)

```rust
#[derive(Default)] pub enum DeviceKind { ..., #[default] Unknown }

#[derive(Default)]
pub struct Device {
    /* existing fields */
    #[serde(default)] pub rtt_ms: Option<f32>,      // first ICMP echo (or TCP connect time)
    #[serde(default)] pub ttl: Option<u8>,          // ICMP reply TTL
    #[serde(default)] pub upnp: Option<UpnpInfo>,   // from SSDP+XML in sweep
}
// label(): hostname -> upnp.friendly_name -> model -> upnp.model_name -> vendor -> kind
// serde(default) keeps old PREVIEW_JSON dumps loadable.

pub struct UpnpInfo {
    pub location: String, pub server: Option<String>, pub device_type: Option<String>,
    pub friendly_name: Option<String>, pub manufacturer: Option<String>,
    pub model_name: Option<String>, pub model_number: Option<String>,
    pub model_description: Option<String>, pub presentation_url: Option<String>,
}

pub enum OsFamily { Ios, MacOs, Android, Windows, Linux, WebOs, Tizen, Embedded, NetworkOs, Unknown }
pub struct OsGuess { pub family: OsFamily, pub label: String /* "IOS / IPADOS" */,
                     pub short: String /* "IOS","MAC","AND","WIN","LNX","WOS","TZN","RTOS","NOS","---" */,
                     pub confidence: u8, pub evidence: Vec<String> }

pub enum PortState { Open, Closed, Filtered }
pub enum Risk { Info, Low, Medium, High }
pub struct PortInfo { pub port: u16, pub state: PortState, pub service: String, pub meaning: String, pub risk: Risk }
pub struct PingStats { pub sent: u8, pub recv: u8, pub min_ms: f32, pub avg_ms: f32, pub max_ms: f32,
                       pub samples: Vec<Option<f32>>, pub ttl: Option<u8> }
pub struct HttpFingerprint { pub port: u16, pub tls: bool, pub status: u16, pub server: Option<String>,
                             pub title: Option<String>, pub powered_by: Option<String>,
                             pub auth_realm: Option<String>, pub redirect: Option<String> }
pub struct Banner { pub port: u16, pub proto: String /* "SSH","FTP","TELNET","RTSP" */, pub text: String }
pub struct NetBiosInfo { pub name: String, pub group: Option<String>, pub mac: Option<String> }
pub struct Note { pub risk: Risk, pub text: String }

pub struct DeviceIntel {
    pub ip: String, pub complete: bool, pub elapsed_ms: u32,
    pub ping: Option<PingStats>,
    pub ports: Vec<PortInfo>,            // every scanned port, table order
    pub banners: Vec<Banner>, pub http: Vec<HttpFingerprint>,
    pub upnp: Option<UpnpInfo>, pub netbios: Option<NetBiosInfo>,
    pub os: OsGuess,
    pub kind: Option<DeviceKind>,        // refined kind (None = unchanged)
    pub kind_reason: Option<String>,     // "62078/TCP OPEN → APPLE LOCKDOWN"
    pub notes: Vec<Note>, pub exposure: Risk,
}

pub enum IntelStage { Echo, Lattice, Fingerprint, Assemble }   // 4 stages = 4 ICE rings / 4 daemons
pub enum IntelEvent {
    Stage { stage: IntelStage, pct: u8 },          // overall pct 0..=100
    Log(String),                                    // pre-formatted HUD line
    Echo { seq: u8, rtt_ms: Option<f32>, ttl: Option<u8> },
    Port { port: u16, state: PortState },
    Snapshot(Box<DeviceIntel>),                     // after each stage (partial)
    Done(Box<DeviceIntel>),                         // final; complete = true
}
```

### 1.4 API

```rust
// scan/intel/mod.rs
pub struct Target { pub device: Device, pub network: NetworkInfo }
pub async fn deep_scan(t: Target, emit: impl Fn(IntelEvent) + Send + Sync + 'static) -> DeviceIntel;
```

- **Guard**: unless `net::in_subnet(&t.network, ip)`, refuse: return `complete = true` with note "OUT OF SCOPE".
- **Hard cap**: `tokio::time::timeout` per stage, overall 7 s. A timed-out stage leaves partial data. `Done` is always emitted.
- **Stages** (share of overall pct):
  1. **Echo 0–15%**: new `surge_ping::Client`, 4 seqs 100 ms apart, 600 ms timeout each, random `PingIdentifier`.
  2. **Lattice 15–55%**: all 36 ports concurrently (`FuturesUnordered`), 700 ms timeout each; emit `Port` as each resolves; pct follows count done. `Ok` → Open; `ConnectionRefused` → Closed; timeout / `HostUnreachable` / `NetworkUnreachable` → Filtered.
  3. **Fingerprint 55–90%** (`tokio::join!`): banners on open 21/22/23 (read ≤256 B, 600 ms, never write); HTTP on open {80, 443, 3000, 5000, 5001, 7000, 8001, 8008, 8080, 8123, 8443, 9000, 32400}, TLS for {443, 5001, 8443, 3001, 8009}; RTSP OPTIONS if 554 open; NetBIOS; UPnP = reuse sweep `upnp`, else 1 s unicast M-SEARCH to `ip:1900`.
  4. **Assemble 90–100%**: `os::guess`, `classify::refine`, `risk::assess`.
- **HTTP client** (once per deep scan): `reqwest::Client::builder().tls_danger_accept_invalid_certs(true).tls_danger_accept_invalid_hostnames(true).redirect(Policy::none()).connect_timeout(800ms).timeout(2s).user_agent("netscan/0.1")`. Read body with `resp.chunk()` up to 64 KiB → `from_utf8_lossy` → `textutil::html_title`. `Location` header → `redirect`.
- **NetBIOS** NBSTAT query (50 bytes): txid, flags 0, qd=1; name `0x20` + `"CK" + "A"*30` + `0x00`; type `0x0021`, class `0x0001`. Response: skip 12-byte header + echoed name (34 B), then type/class/ttl/rdlen (10 B), `num` (1 B), `num` × 18 B entries (15 B name, 1 B suffix, 2 B flags; 0x8000 = group), then 6-byte MAC. Unique name suffix 0x00 = host name; group suffix 0x00 = workgroup.
- **Ports table** (`ports.rs`): `pub struct PortSpec { port: u16, service: &'static str, meaning: &'static str, risk: Risk }`, `PORTS: [PortSpec; 36]`, `pub fn spec(port) -> Option<&'static PortSpec>`:
  21 FTP (plaintext file transfer, Medium) · 22 SSH (remote shell, Low) · 23 TELNET (plaintext remote admin, High) · 53 DNS (resolver, Info) · 80 HTTP (web interface, Low) · 139 NETBIOS-SSN (legacy Windows sharing, Medium) · 443 HTTPS (secure web interface, Info) · 445 SMB (file sharing, Medium) · 515 LPD (legacy printing, Info) · 548 AFP (Apple file sharing, Low) · 554 RTSP (video stream / IP camera, Medium) · 631 IPP (network printing, Info) · 1883 MQTT (IoT broker, unencrypted, Medium) · 2049 NFS (network filesystem, Medium) · 3000 WEBOS-SSAP / DEV-HTTP (LG TV control or dev server, Low) · 3001 WEBOS-SSAP-TLS (LG TV control, Low) · 3389 RDP (Windows remote desktop, High) · 3689 DAAP (iTunes/Music sharing, Info) · 5000 UPNP / AIRPLAY / NAS (Low) · 5001 NAS-HTTPS (Synology DSM, Low) · 5555 ADB (Android debug bridge, High) · 5900 VNC (screen sharing, High) · 6668 TUYA (Tuya local control, Low) · 7000 AIRPLAY (Apple media receiver, Info) · 8001 SAMSUNG-TV (Tizen remote API, Low) · 8008 CAST-HTTP (Google Cast, Info) · 8009 CAST-TLS (Google Cast control, Info) · 8080 HTTP-ALT (alt web/admin, Low) · 8123 HOME-ASSISTANT (home automation hub, Low) · 8443 HTTPS-ALT (alt secure admin, Info) · 9000 HTTP-ALT / GRPC (management API, Low) · 9100 JETDIRECT (raw printing, Low) · 9999 KASA (TP-Link smart plug control, Medium) · 32400 PLEX (media server, Info) · 49152 UPNP-HTTP (UPnP control endpoint, Low) · 62078 LOCKDOWN (iOS sync service, Info).
- **`classify::refine(d, intel) -> Option<(DeviceKind, String)>`**: `Some` only on strong evidence and only if kind differs. Never override `is_gateway`/`is_self`.
  62078 → Mobile (Tablet if model/name has "ipad") · 5555 → Tv if vendor TV-ish or 8008 open, else Mobile · 3389, or NetBIOS name + TTL 128 → Computer · 9100/631/515 → Printer · 8008+8009 → Media (Tv if TV maker) · 3000+3001 or "webos" in UPnP/Server → Tv · 8001 + Samsung → Tv · 554 w/o TV evidence → Iot · 6668 or 9999 → Iot · 8123 or 1883 → Iot · SSH banner with Ubuntu/Debian/Raspbian/FreeBSD → Computer · UPnP `InternetGatewayDevice` → Router; `MediaRenderer` → Tv/Media.
- **`os::guess`** (score candidates, keep evidence, take max): iPhone/iPad model 95 or 62078 open 85 → iOS · Apple vendor + Computer, `_companion-link` or AFP → macOS 80 · SSH banner distro 90, or `Server: Linux/x UPnP` 60 → Linux · 5555 70, `_androidtvremote2` 70, Cast+Google 50 → Android · 3389 80, NetBIOS 60 (+TTL 128), TTL 128 alone 55 → Windows · LG + 3000/3001 85 or "webos" → webOS · Samsung + 8001 → Tizen 80 · Espressif/Tuya/Shelly 70 or TTL 255 50 → Embedded/RTOS · router vendor or IGD UPnP → NetworkOs 60 · TTL 64 + randomized MAC → "MOBILE (IOS/ANDROID)" 40 · TTL 64 alone → "UNIX-LIKE" 30 · else Unknown 0.
- **`risk::assess`**: ports with risk ≥ Medium → notes; plus HTTP without TLS where title/realm suggests admin/login; IGD present ("UPnP gateway accepts port-forward requests"); `Server` headers disclosing versions. Exposure = max note risk, +1 level if ≥3 Medium notes. No notes → add "NO EXPOSED SERVICES IN PROBE SET". Wording factual ("exposed service"), never alarmist.
- **Caching**: UI owns `Signal<HashMap<String /*ip*/, IntelSession>>`; backend stateless.
- **Concurrency**: one deep scan at a time (UI-enforced; overlay is modal).
- **Sweep changes**: `ping::sweep` → `HashMap<Ipv4Addr, HostProbe { rtt: Option<Duration>, ttl: Option<u8> }>`; `icmp_probe` → `Option<(Duration, Option<u8>)>` via `IcmpPacket::V4(p) => p.get_ttl()`; `tcp_probe` → `Option<Duration>`. In `scan()`: `alive.keys()`, fill `rtt_ms`/`ttl`. `ssdp::discover(2500ms)` `tokio::spawn`ed next to `mdns_task`; in enrich phase `join_all` description fetches (first LOCATION per IP) under 2.5 s timeout inside the existing `tokio::join!`. Log line `"SSDP {n} DEVICES // UPNP {m} DESCRIPTORS"`. Total scan time stays ~4.5–5.5 s.
- **SSDP**: bind `0.0.0.0:0`, `set_multicast_ttl_v4(2)`, send `M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n` twice 300 ms apart; `recv_from` until deadline; parse headers case-insensitively (LOCATION, SERVER, ST, USN). **Only accept a LOCATION whose host equals the responder IP** and is in-subnet.

## 2. UX / flow design

### 2.1 State machine (App level)

```rust
#[derive(Clone, PartialEq)]
enum Focus { None, Lock{idx}, Breach{idx}, Granted{idx, denied: bool, partial: bool}, Dossier{idx}, Closing{idx} }
struct IntelSession { ip: String, log: Vec<LogLine>, stage: IntelStage, pct: u8,
                      ports: Vec<(u16, PortState)>, echoes: Vec<Option<f32>>,
                      intel: Option<DeviceIntel>, done: bool, run: u32 /* bumps on rescan */ }
```

- Click device/router: not cached → `Lock` (450 ms) → `Breach` → when `done` and ≥2.6 s elapsed (or 8 s regardless) → `Granted` (900 ms) → `Dossier`. Cached → `Lock` (300 ms) → short "RE-LINK" `Granted` (500 ms) → `Dossier`.
- Internet node NOT clickable (keeps hover readout, `cursor: default`).
- Self node: same flow, title variant "SELF-DIAGNOSTIC // 自己診断".
- ESC during Breach: abort overlay (scan keeps running and fills cache). ESC in Dossier → `Closing` (350 ms) → `None`. Backdrop click / DISCONNECT = ESC in dossier.
- R in dossier: re-scan (`run += 1`, back to `Breach`).

### 2.2 Map behaviour (`network_map.rs`)

- New props: `focus: Option<usize>`, `intel: Signal<HashMap<String, IntelSession>>` (read-only), `on_target: EventHandler<usize>`. SSR previews pass `None` and a `use_signal(HashMap::new)` (or fake data).
- **Camera**: wrap scene in `g { class: "camera", style: "transform: translate({tx}px,{ty}px) scale({s})" }`; focused: `s = 1.55`, `tx = CX - p.x*s`, `ty = CY - p.y*s`, clamped so no more than ~120 units of empty space shows. CSS `.camera { transform-box: view-box; transform-origin: 0 0; transition: transform .6s cubic-bezier(.7,0,.2,1) }`.
- **Dim**: SVG `mask` (white rect, black circle r=70 at target) on `rect.dim { fill: rgba(6,4,5,.78) }`, above nodes, below reticle; fade via opacity.
- **Reticle** `g.reticle` at target: 4 corner brackets (±46), rotating dashed ring (r=58), 4 crosshair hairlines to ±600, text `LOCK 標的捕捉` + coords `X0412 Y0233` mono. Enter: `scale(2.4) rotate(45deg)` → none, 380 ms `cubic-bezier(.2,1.4,.4,1)`, then 2-frame brightness flash.
- **Trace link**: router→target edge gets `edge trace`: stroke `--red-hi`, width 2.4, `stroke-dasharray: 6 4`, dashoffset animation 0.4 s linear infinite.
- **Pulses** hidden while focused (`.map.focused .pulses { display:none }`).
- **Persistent additions** (keep layout collision test green): IP line → `tspan.os` "IOS · " + IP when guess confidence ≥40; pulse `dur = clamp(1.4 + rtt_ms/20, 1.4, 4.5)` (unknown RTT → current seeded value); scanned nodes get a corner chip at (22,−22) (small rotated square with open-port count, `class: "chip"`) + inner octagon stroke `frame2`, inside ±31 box; icon kind = `intel.kind.unwrap_or(d.kind)` but layout uses original `d.kind` (positions never jump); one-shot `reclass` glitch on icon when kind changes (keyed on kind); hover readout adds `RTT 3.2ms`, `TTL 64`, `OS IOS 85%`, plus `.ro-hint "CLICK ▸ BREACH 侵入"`.

### 2.3 Breach overlay — "INTRUSION // 侵入" (1280×800)

```
┌╱INTRUSION 侵入 ▸ TARGET 192.168.1.34 ▸ LG WEBOS TV ───────────────── T+01.84s ── [ESC] ABORT 中止╲┐
│┌ CODE STREAM 符号 ─────────┐                                       ┌ TRACE 追跡 ────────────────────┐│
││ 1C 7A E9 55 BD 0F 9A 21   │                                       │> LINK 192.168.1.34 // L2 DIRECT │
││ 55 3E[1C 7A E9 55]03 C4   │◄ seq band locks per stage             │> ECHO 1/4  3.2ms  TTL 064       │
││ 8 cols × 22 rows, cols    │            ╭─ ─ ICE-4 ─ ─╮            │> PORT 0021 ······· CLOSED       │
││ drift up at varied speeds │         ╭─╱  ╭─ICE-3─╮   ╲─╮          │> PORT 0080 ······· OPEN // HTTP │
│└───────────────────────────┘        │   │ ┌[NODE]┐ │    │  (map,    │> PORT 0554 ··· FILTERED         │
│┌ DAEMONS 常駐 ──────────────┐        │   │ └──────┘ │    │  zoomed,  │> HTTP :80 200 "webOS TV"        │
││ SPIKE.ECHO    ▮▮▮▮▮▮ EXEC │         ╲─╲  ╰───────╯  ╱─╱  in SVG)  │  (≤14 lines, newest bright)     │
││ LATTICE.SWEEP ▮▮▮▯▯▯ 54%  │            ╰─ ─ ─ ─ ─ ─╯               └─────────────────────────────────┘│
││ MIRROR.PRINT  ▯▯▯▯▯▯ QUEUE│                                         ┌ PORT LATTICE 港湾 ── 3 OPEN ───┐│
││ DOSSIER.ASM   ▯▯▯▯▯▯ QUEUE│                                         │ ■□□■□□ □□▨□□□ ... 6×6 cells    ││
│└───────────────────────────┘                                         └─────────────────────────────────┘│
│ BREACH ▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▮▯▯▯▯▯▯▯▯▯▯▯▯▯▯▯  58%   STAGE 02/04 ▸ LATTICE SWEEP ポート走査                 │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

- Panels: left 300 px at 28 px inset; right 380 px; bottom bar 64 px. Cut-corner `clip-path` like `.segs`, 1 px `--red-dim` border, `rgba(6,4,5,.82)` background, no backdrop-filter. Centre transparent so the zoomed SVG target + ICE rings show through.
- **ICE rings** live in SVG at target: 4 concentric (r = 72/88/104/120 scene units ÷ camera scale), dashed, `pathLength=100`, dasharray `{p} 100` = stage progress; alternating rotation speed/direction. On stage complete: "crack" (6-segment dash, flash, opacity → 0.35).
- Entry: panels wipe `clip-path: inset(0 100% 0 0)` → `inset(0)` 280 ms, stagger 60 ms; horizontal scan bar sweeps top→bottom 400 ms.
- States: running; slow (>8 s → Granted with "PARTIAL ACCESS 部分"); unreachable (0 open ports, 0 echoes, no banners → DENIED stamp; dossier opens in "TARGET DARK" mode with sweep facts only).

### 2.4 Stamp

Full-width 120 px band, centred, `--red` background; "ACCESS GRANTED" Rajdhani 64 px, letter-spacing .3em + "アクセス許可" mono 18 px. Slams `scale(1.35)` → 1 in 120 ms with 3 glitch frames (RGB-split text-shadow −4px red / +4px cyan + clip-path slices); hold 500 ms; scanline wipe into dossier. **Denied**: inverse — black band, red outline text, "ACCESS DENIED // 拒否", heavier jitter.

### 2.5 Dossier modal — "TARGET PROFILE // 標的記録"

```
┌╱ TARGET PROFILE 標的記録 ── 192.168.1.34 ── SCAN 2.84s ── ACCESS GRANTED アクセス許可 ───── [ESC] DISCONNECT 切断╲┐
│ ┌──────┐ LG WEBOS TV UQ75                       DISPLAY 映像 ◂ RECLASSIFIED (3000+3001/TCP + LG)   EXPOSURE      │
│ │ ICON │ 192.168.1.34 · a8:23:fe:12:34:56 · LG                                                  ▮▮▯▯ MEDIUM   │
│ └──────┘ OS ▸ WEBOS (LINUX) ▮▮▮▮▯ 85%      RTT 3.2/4.1/6.0 ms   TTL 64   LINK DIRECT L2 VIA 192.168.1.1          │
├──────────────────────────────┬────────────────────────────────────┬──────────────────────────────────────────────┤
│ 01 IDENTITY 識別              │ 03 PORT LATTICE 港湾  3/36 OPEN     │ 05 WEB SURFACE 表層                           │
│ NAME    [LG] webOS TV UQ75   │ 6×6 cells: open=solid red,          │ :3000 HTTP 200 ─ "webOS TV"                   │
│ HOST    LGwebOSTV            │ closed=outline, filtered=hatched     │   SERVER WebOS/4.1 UPnP/1.0 ⚠ version leak   │
│ MAKER   LG Electronics       │ list of open ports: port/service/   │ (none) → "NO WEB SURFACE // 無"              │
│ MODEL   UQ75006LF / 75UQ75   │ meaning                              ├──────────────────────────────────────────────┤
│ MAC     a8:23:..  (OUI LG)   │                                      │ 06 UPNP DESCRIPTOR 機器記述                   │
│ NETBIOS —                    │                                      │ TYPE / MAKER / NAME / MODEL                  │
├──────────────────────────────┤──────────────────────────────────────├──────────────────────────────────────────────┤
│ 02 SIGNAL 信号                │ 04 OS PROFILE 基盤                  │ 07 EXPOSURE NOTES 脆弱性                       │
│ ECHO ▁▂▁▃ 4/4 avg 4.1ms      │ WEBOS (LINUX) ▮▮▮▮▯ 85%            │ ▲ MED  UPnP control surface on LAN           │
│ TTL 64 → UNIX-LIKE STACK     │  · evidence lines                   │ ● INFO Server header discloses version       │
│ MDNS / SSDP services         │                                      │                                              │
├──────────────────────────────┴────────────────────────────────────┴──────────────────────────────────────────────┤
│ 36 PORTS · 4 ECHOES · 2 PROBES · 0 ERRORS       [R] RE-SCAN 再走査   [ESC] DISCONNECT 切断      0xA5C0 // 荒坂 SEC-OPS │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

- Inset 36 × 44 px (~1192×728 at 1280×800). At 1024×680 min, columns `minmax(0,1fr)` and values ellipsize. CSS grid, cut corners, 2 px red top-left accent like `.hud::after`, black panel.
- Assembly motion: frame outline wipe 300 ms → header title **decode** (scrambled `ABCDEF0123456789アイウエオ#%` settling left→right ~500 ms, Rust-driven) → sections fade/slide-up 6 px, stagger 70 ms → values **typewriter** (CSS `steps()`, 250 ms) → lattice cells light in diagonal sweep (`animation-delay: calc(var(--i) * 18ms)`).
- Section states: `pending` (shimmer + "DECRYPTING… 復号中"), value, `empty` ("NO SIGNAL // 無信号"), `failed` ("PROBE BLOCKED // 遮断"). Reads live from `IntelSession`, so pending sections fill in.
- Close: CRT collapse (scaleY → 0.02 → 0, 350 ms), then camera zooms out 600 ms and dim fades.

## 3. Hacking effects (ORIGINAL; non-interactive; CSS/SVG/Rust only)

No game names, logos, assets or sounds. Not a playable minigame: no grid selection, no buffer, no player input.

1. **LOCK-ON reticle** (2.2).
2. **TRACE link**: dash-offset flow on router→target edge + a bright "packet" (`animateMotion`, 0.5 s) per echo event.
3. **CODE STREAM**: 8 columns of hex bytes, deterministic from hash(IP+MAC) via small xorshift (no RNG crate). Each column = one `div` (`white-space: pre`) with a duplicated 44-line block animated `translateY(0 → -50%)` 6–14 s linear infinite (8 transforms total). Above it 4 absolutely-positioned **sequence bands**, one per stage, each showing 4 real bytes (MAC bytes, RTT ms as hex, open-port count…) that "lock" on stage complete (red box, ink text, flash). Decorative only.
4. **ICE rings** (2.3).
5. **DAEMONS**: rows `SPIKE.ECHO 針`, `LATTICE.SWEEP 格子`, `MIRROR.PRINT 鏡`, `DOSSIER.ASM 記録`; 12 segments each (reuse `.seg`), filled from real stage pct; status QUEUED / UPLOADING nn% / EXECUTED.
6. **TRACE terminal**: real lines; OPEN `--red-hi` bold, CLOSED `--mute`, FILTERED `--red-dim` italic; max 14 DOM lines; `line-in` keyframe; blinking cursor on last.
7. **Glitch burst** on each OPEN port and each stage completion: re-render `div.burst { key: "{burst_n}" }`, full-overlay, 160 ms once: clip-path slice jumps + translateX ±6 px, red/cyan text-shadow on panel titles, 1-frame opacity .6 flash. Only transform/opacity/clip-path — no `filter` animation.
8. **Scanline wipe**: 3 px bright bar + 80 px gradient tail, `translateY(-10% → 110%)` 420 ms at entry, stamp and dossier entry.
9. **ACCESS GRANTED / DENIED stamp** (2.4).
10. **Decode text**: component `DecodeText { text, ms }` (`use_hook` + `spawn`, ~16 frames × 30 ms, local signal). Max 2 instances (dossier title, breach target name).
11. **Typewriter**: `.tw { display:inline-block; overflow:hidden; white-space:nowrap; animation: tw .25s steps(var(--n)) both; }` with `--n` = char count from Rust; `@keyframes tw { from { max-width: 0 } to { max-width: calc(var(--n) * 1ch) } }`.

**Driving/timing**: UI consumer applies each `IntelEvent` to `IntelSession`, then sleeps 40 ms after Log/Port events (0 otherwise) → ~1.9 s drip; backend buffers in the unbounded channel. After `Done` applied: `sleep(MIN_BREACH.saturating_sub(elapsed))`, `MIN_BREACH = 2.6s` → Granted. Watchdog → `Granted { partial }` at `MAX_BREACH = 8s`. Constants in `ui/intrusion.rs`.

**Performance (WKWebView)**: hide SMIL pulses while focused; no `filter` on large/animated elements; `will-change: transform` only on code columns + camera; no `backdrop-filter`; terminal ≤14 DOM lines; Rust-driven re-renders ≤ ~25/s.

**Sound** (Phase 5, minimal): on first click (user gesture) one `document::eval` installs `window.__nsfx = (kind) => {...}` with lazily-created `AudioContext`, master gain 0.06. `lock` square chirp 900→1800 Hz 70 ms; `tick` 8 ms noise burst @3 kHz per OPEN port; `granted` saw 110+165 Hz 400 ms decay; `denied` detuned saws 220→80 Hz; `close` low-passed noise thump. Fire-and-forget `document::eval("window.__nsfx&&__nsfx('tick')")`. Key `M` toggles mute (footer hint "M ▸ AUDIO"). On by default at low level. If WKWebView misbehaves, drop sound (isolated by design).

## 4. Phases

**Every phase**: first read `src/ui/app.rs`, `src/ui/network_map.rs`, `src/scan/mod.rs`, `src/scan/model.rs`, `assets/main.css`, and this file. Any phase touching visuals must **invoke the Skill tool with `frontend-design:frontend-design` before writing CSS/markup**, and keep the Arasaka language (black, `--red #ff1a2d`, Rajdhani + Share Tech Mono, JP accents, cut corners).

**Verification (all phases)**: `cargo build --release` with **zero warnings**; `cargo test`; `cargo clippy --all-targets -- -D warnings`; `cargo run --release -- --cli` (JSON must parse); preview: `PREVIEW_DIR=$S PREVIEW_JSON=$S/real.json cargo test dump_preview -- --nocapture`, then headless Chrome screenshot (section 0) at 1280×800, Read the PNGs and iterate. Do NOT attempt real-window screenshots (no permission). Scratch dir `$S` = `/private/tmp/claude-502/-Users-erik-gonzalezgarcia-Privado-dev/b054c6e7-cbf4-40f4-b75c-59529f38b668/scratchpad`. Don't commit to git.

### Phase 1 — SWEEP INTEL
- **Goal**: per-host RTT/TTL, SSDP + UPnP descriptors, OS guess, better labels and hover readout. No click UI yet.
- **Files**: `scan/model.rs` (add ALL model structs from 1.3 now so Phase 2 only adds logic), `scan/ping.rs`, `scan/mod.rs`, NEW `scan/ssdp.rs`, NEW `scan/os.rs`, NEW `scan/textutil.rs`, `scan/classify.rs` (feed UPnP friendly_name/model_name/manufacturer into keyword text; add "webos" → Tv), `ui/network_map.rs` (readout + OS tspan), `assets/main.css`, `ui/mod.rs` (fix `fake()` with `..Default::default()`).
- **Signatures**: `pub struct HostProbe { pub rtt: Option<Duration>, pub ttl: Option<u8> }`; `pub async fn sweep(..) -> HashMap<Ipv4Addr, HostProbe>`; `ssdp::discover(dur: Duration) -> BTreeMap<Ipv4Addr, SsdpHit>`; `ssdp::parse_response(&str) -> Option<SsdpHit>`; `ssdp::fetch_description(client: &reqwest::Client, ip: Ipv4Addr, loc: &str) -> Option<UpnpInfo>`; `ssdp::parse_description(xml: &str, loc: &str) -> UpnpInfo`; `textutil::xml_tag(xml, tag) -> Option<String>` (first `<tag>`…`</tag>`, unescape `&amp; &lt; &gt; &quot; &apos;`, trim, cap 120 chars); `os::guess(d: &Device, intel: Option<&DeviceIntel>) -> OsGuess`.
- **Acceptance**: CLI JSON shows `rtt_ms`/`ttl` for responders and `upnp` for at least TV/router if they answer SSDP; scan < ~5.5 s; hover readout shows RTT/TTL/OS; OS tag in IP line; layout test passes.
- **Tests**: SSDP response parsing (header case variants); `xml_tag` on sample LG / IGD descriptors (namespace-free root, entities); `os::guess` table cases; old JSON without new fields deserializes.
- **Pitfalls**: `serde(default)` on every new field; `#[default]` on `DeviceKind::Unknown`; check whether macOS DGRAM ICMP returns a TTL (`get_ttl()` may be `None` — if always None, log it, keep RTT); SSDP socket spawned at the very start like `mdns_task`; only accept LOCATION whose host == source IP.

### Phase 2 — DEEP-SCAN ENGINE
- **Goal**: `intel::deep_scan` backend with events, refine, risk, testable from CLI. No UI.
- **Files**: NEW `scan/intel/{mod,ports,probe,netbios,risk}.rs`; `scan/mod.rs` (`pub mod intel;`); `scan/classify.rs` (`refine`); `scan/os.rs` (use intel evidence); `main.rs` (`--intel <ip>`: full `scan()` first, find device, `deep_scan`, events to stderr in HUD style, final JSON to stdout).
- **Signatures**: 1.4 plus `ports::scan(ip, ports: &[u16], on_port: impl Fn(u16, PortState)) -> Vec<PortInfo>` (port list param so tests use loopback); `probe::banner(ip, port) -> Option<Banner>`; `probe::http_fingerprint(&Client, ip, port, tls) -> Option<HttpFingerprint>`; `probe::rtsp_options(ip) -> Option<Banner>`; `netbios::build_query(txid: u16) -> [u8; 50]`; `netbios::parse_status(&[u8]) -> Option<NetBiosInfo>`; `netbios::query(ip) -> Option<NetBiosInfo>`; `risk::assess(&Device, &DeviceIntel) -> (Vec<Note>, Risk)`.
- **Acceptance**: `--intel <tv-ip>` typically < 3 s, worst < 7.5 s; lists open ports with meanings, HTTP fingerprint where applicable, OS guess, notes; SSH box shows banner; phone with 62078 open → Mobile; out-of-subnet IP refused.
- **Tests**: loopback `TcpListener` ephemeral port: `[open, closed]` → Open/Closed; local tokio TCP server with canned HTTP (`<TITLE>`, `Server`) → `http_fingerprint`; SSH-like banner server; NetBIOS `parse_status` on hand-built bytes; `refine` table; `risk` with 23 open → High.
- **Pitfalls**: test loopback via `ports::scan` directly (subnet guard); reqwest bodies via `chunk()` with cap, never unbounded `text()`; map `io::ErrorKind` carefully (macOS `HostUnreachable`); `emit` is `Send + Sync + 'static` (wrap in `Arc` across join branches); never write to telnet/FTP sockets.

### Phase 3 — DOSSIER + TARGETING UI
- **Goal**: click → deep scan → dossier end-to-end with simple transitions (no breach spectacle yet). Map targeting: camera, dim, reticle, trace edge, chips.
- **Files**: `ui/app.rs` (`Focus`, `IntelSession` cache, `start_deep_scan(idx)` using the tokio::spawn + mpsc pattern); `ui/network_map.rs` (props, camera group, mask/dim, reticle, `onclick`, chips, icon override); NEW `ui/dossier.rs` (`#[component] pub fn Dossier(device: Device, session: IntelSession, closing: bool, on_close: EventHandler<()>, on_rescan: EventHandler<()>) -> Element`); `ui/mod.rs` (`pub mod dossier;`, previews `dossier_full.html`, `dossier_pending.html`, `dossier_dark.html` from fake intel, plus `map_locked.html`); `assets/main.css`.
- **Signatures**: `IntelSession::apply(&mut self, ev: IntelEvent)` — pure, unit-tested.
- **Acceptance**: clicking any device/router dims, zooms, locks reticle, opens dossier, sections fill live; ESC / backdrop / DISCONNECT close; reopen uses cache; R re-scans; Internet node not clickable; node positions never change after reclassification; previews OK at 1280×800 and 1024×680.
- **Pitfalls (Dioxus 0.7)**: overlay root `tabindex: "-1"`, `onmounted: move |e| async move { let _ = e.set_focus(true).await; }`, `onkeydown: move |e| if e.key() == Key::Escape {…}` (if focus lost after inner clicks, also `tabindex` on root `.app`); inner panel clicks `e.stop_propagation()`; never move `Signal`s into `tokio::spawn`; props `Clone + PartialEq`; `onclick` on SVG `g` works, `cursor: crosshair` only on device nodes; CSS transform on SVG `g` needs `transform-box: view-box; transform-origin: 0 0`; unique mask id `dim-mask`; add new animated classes to the preview `page()` override list.

### Phase 4 — INTRUSION SEQUENCE
- **Goal**: full breach overlay + stamp (section 3) driven by real events, with min/max timing.
- **Files**: NEW `ui/intrusion.rs` (`#[component] pub fn Intrusion(device: Device, session: IntelSession, elapsed_ms: u32, on_abort: EventHandler<()>) -> Element`, `Stamp { denied: bool, partial: bool }`, `CodeStream { seed: u64, locks: [Option<[u8;4]>;4] }`, `DecodeText { text: String, ms: u32 }`); `ui/network_map.rs` (SVG ICE rings at target, from session stage/pct via props); `ui/app.rs` (Lock → Breach → Granted → Dossier timing, 40 ms drip, MIN 2.6 s / MAX 8 s watchdog, `burst_n`); `ui/dossier.rs` (decode title, typewriter values, staggered sections); `assets/main.css` (all keyframes in a `/* ---------- intrusion ---------- */` block); `ui/mod.rs` (previews `breach_25.html`, `breach_70.html`, `stamp.html`, `stamp_denied.html` from fixed sessions).
- **Acceptance**: real click → ~3–3.5 s sequence on TV and SSH box, then dossier; every terminal line = a real event; bursts on OPEN ports; unreachable → DENIED + dark dossier; ESC aborts anytime; no visible jank; nothing interactive inside the effect; no game names/logos/assets.
- **Pitfalls**: restart CSS animation by changing `key`; `elapsed_ms` from a 100 ms Dioxus ticker only during Breach (cancel task on exit, `Task::cancel`); decode timer local to its component; hex columns are text, not per-byte spans; `dangerous_inner_html` OK for static SMIL only, not reactive parts.

### Phase 5 — POLISH: SOUND, RE-LINK, PERFORMANCE, A11Y
- **Goal**: synthesized audio (section 3), fast re-link for cached targets, pause pulses/halos when focused, `prefers-reduced-motion` (no camera zoom, instant stamp, no bursts), README update ("Deep intel" section, techniques, safety statement: only in-subnet hosts, connect scans + standard benign requests, no login attempts).
- **Files**: NEW `ui/sfx.rs` (`pub fn install()`, `pub fn play(kind: &str)`, `static MUTED: AtomicBool`); `ui/app.rs` (M key); `assets/main.css`; `README.md`.
- **Acceptance**: sound after first click; M mutes; no console errors; reduced-motion previews render; re-link ~0.8 s; all checks pass.
- **Pitfalls**: `document::eval` returns an `Eval` you may drop — don't await in hot paths; AudioContext must be created within the click call stack — install on first `onclick`, `resume()` on every play.

## 5. Risks / open questions
- TTL may be missing on macOS DGRAM ICMP → OS guess loses one signal; RTT still works. Verify in Phase 1.
- macOS Local Network privacy could block SSDP/UDP 137 for an app bundle; works from Terminal today (mDNS works).
- Phones with randomized MACs often filter everything → expect "TARGET DARK"; acceptable by design.
- Camera zoom near edges needs clamping; tune `s` and clamp in Phase 3 previews.
- Exposure wording: factual ("exposed service"), never "vulnerable".
- Scope safety: deep scans only target in-subnet hosts, connect + standard benign requests only; state in README.

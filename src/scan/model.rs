use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub interface: String,
    pub local_ip: String,
    pub local_mac: Option<String>,
    pub prefix: u8,
    pub netmask: String,
    pub gateway_ip: Option<String>,
    pub gateway_mac: Option<String>,
    /// Subnet actually scanned, e.g. `192.168.1.0/24`.
    pub subnet_cidr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum DeviceKind {
    Internet,
    Router,
    Computer,
    Mobile,
    Tablet,
    Tv,
    Media,
    Iot,
    Printer,
    Car,
    Console,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Device {
    pub ip: String,
    pub mac: Option<String>,
    pub is_self: bool,
    pub is_gateway: bool,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    /// Hardware model from mDNS TXT (e.g. `MacBookPro18,3`, `AudioAccessory5,1`).
    pub model: Option<String>,
    pub services: Vec<String>,
    pub kind: DeviceKind,
    pub mac_randomized: bool,
    /// First ICMP echo (or TCP connect) round-trip time.
    #[serde(default)]
    pub rtt_ms: Option<f32>,
    /// TTL of the ICMP echo reply, when the OS exposes it.
    #[serde(default)]
    pub ttl: Option<u8>,
    /// UPnP descriptor gathered from SSDP + description XML.
    #[serde(default)]
    pub upnp: Option<UpnpInfo>,
    /// Selected mDNS TXT keys (`md`, `fn`, `model`, ...).
    #[serde(default)]
    pub txt: BTreeMap<String, String>,
    /// Advertised mDNS service ports, e.g. `_adb-tls-connect` -> 37151.
    #[serde(default)]
    pub svc_ports: BTreeMap<String, u16>,
    /// Cheap TV/streamer probe results (filled by the beacon phase).
    #[serde(default)]
    pub beacon: Option<Beacon>,
    /// Scored classification; `kind` always equals `class.kind` once set.
    #[serde(default)]
    pub class: Option<Classification>,
}

/// Where a piece of classification evidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EvSource {
    #[default]
    Role,
    Model,
    Name,
    Mdns,
    Upnp,
    Probe,
    Port,
    Banner,
    Vendor,
    Ttl,
    Mac,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: DeviceKind,
    /// 1..=99: probability that this evidence alone is right.
    pub weight: u8,
    pub source: EvSource,
    /// HUD wording, e.g. `MODEL 55NANO796NE \u{25B8} LG TV LINE`.
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Classification {
    pub kind: DeviceKind,
    /// 0..=100.
    pub confidence: u8,
    /// Sub-type: `ANDROID TV`, `EV CHARGER`, `WEBOS TV`, ...
    #[serde(default)]
    pub label: Option<String>,
    pub reason: String,
    /// Winner's evidence first (descending weight), then the rest.
    pub evidence: Vec<Evidence>,
    /// Runner-up kinds with their probability in percent (max 2).
    #[serde(default)]
    pub alt: Vec<(DeviceKind, u8)>,
}

/// One identity answer from a beacon probe.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Ident {
    /// `CAST`, `ROKU-ECP`, `SAMSUNG-API`, `PHILIPS-JS`, `DIAL`.
    pub source: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub maker: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub is_tv: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Beacon {
    pub open: Vec<u16>,
    #[serde(default)]
    pub idents: Vec<Ident>,
    #[serde(default)]
    pub elapsed_ms: u32,
}

impl DeviceKind {
    /// Short generic name used as the last-resort label.
    pub fn name(self) -> &'static str {
        use DeviceKind::*;
        match self {
            Internet => "INTERNET",
            Router => "ROUTER",
            Computer => "COMPUTER",
            Mobile => "MOBILE",
            Tablet => "TABLET",
            Tv => "DISPLAY",
            Media => "MEDIA",
            Iot => "IOT",
            Printer => "PRINTER",
            Car => "VEHICLE",
            Console => "CONSOLE",
            Unknown => "DEVICE",
        }
    }
}

impl Device {
    /// Best human-readable name: hostname, UPnP name, model, UPnP model, vendor, else kind name.
    /// Never the IP (the map always shows that on its own line).
    pub fn label(&self) -> String {
        let up = self.upnp.as_ref();
        self.hostname
            .clone()
            .or_else(|| up.and_then(|u| u.friendly_name.clone()))
            .or_else(|| self.model.clone())
            .or_else(|| up.and_then(|u| u.model_name.clone()))
            .or_else(|| self.vendor.clone())
            .unwrap_or_else(|| self.kind.name().to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    pub network: NetworkInfo,
    pub public_ip: Option<String>,
    /// ISP / organisation owning the public IP (ipinfo.io).
    pub isp: Option<String>,
    pub devices: Vec<Device>,
}

/// Progress events emitted during a scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanProgress {
    Phase { name: String, pct: u8 },
    Log(String),
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct UpnpInfo {
    pub location: String,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub device_type: Option<String>,
    #[serde(default)]
    pub friendly_name: Option<String>,
    #[serde(default)]
    pub manufacturer: Option<String>,
    #[serde(default)]
    pub model_name: Option<String>,
    #[serde(default)]
    pub model_number: Option<String>,
    #[serde(default)]
    pub model_description: Option<String>,
    #[serde(default)]
    pub presentation_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum OsFamily {
    Ios,
    MacOs,
    Android,
    Windows,
    Linux,
    WebOs,
    Tizen,
    Embedded,
    NetworkOs,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct OsGuess {
    pub family: OsFamily,
    /// Long label, e.g. `IOS / IPADOS`.
    pub label: String,
    /// Map tag: IOS, MAC, AND, WIN, LNX, WOS, TZN, RTOS, NOS, `---`.
    pub short: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    #[default]
    Filtered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub enum Risk {
    #[default]
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub state: PortState,
    pub service: String,
    pub meaning: String,
    pub risk: Risk,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PingStats {
    pub sent: u8,
    pub recv: u8,
    pub min_ms: f32,
    pub avg_ms: f32,
    pub max_ms: f32,
    pub samples: Vec<Option<f32>>,
    pub ttl: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct HttpFingerprint {
    pub port: u16,
    pub tls: bool,
    pub status: u16,
    pub server: Option<String>,
    pub title: Option<String>,
    pub powered_by: Option<String>,
    pub auth_realm: Option<String>,
    pub redirect: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Banner {
    pub port: u16,
    /// `SSH`, `FTP`, `TELNET`, `RTSP`.
    pub proto: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct NetBiosInfo {
    pub name: String,
    pub group: Option<String>,
    pub mac: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Note {
    pub risk: Risk,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DeviceIntel {
    pub ip: String,
    pub complete: bool,
    pub elapsed_ms: u32,
    pub ping: Option<PingStats>,
    pub ports: Vec<PortInfo>,
    pub banners: Vec<Banner>,
    pub http: Vec<HttpFingerprint>,
    pub upnp: Option<UpnpInfo>,
    pub netbios: Option<NetBiosInfo>,
    pub os: OsGuess,
    /// Refined kind (`None` = unchanged).
    pub kind: Option<DeviceKind>,
    pub kind_reason: Option<String>,
    /// Full scored classification including deep-scan evidence.
    #[serde(default)]
    pub class: Option<Classification>,
    pub notes: Vec<Note>,
    pub exposure: Risk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntelStage {
    Echo,
    Lattice,
    Fingerprint,
    Assemble,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IntelEvent {
    Stage {
        stage: IntelStage,
        pct: u8,
    },
    Log(String),
    Echo {
        seq: u8,
        rtt_ms: Option<f32>,
        ttl: Option<u8>,
    },
    Port {
        port: u16,
        state: PortState,
    },
    Snapshot(Box<DeviceIntel>),
    Done(Box<DeviceIntel>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_json_deserializes() {
        let j = r#"{"ip":"1.2.3.4","mac":null,"is_self":false,"is_gateway":false,"hostname":null,"vendor":null,"model":null,"services":[],"kind":"Tv","mac_randomized":false}"#;
        let d: Device = serde_json::from_str(j).unwrap();
        assert_eq!(d.kind, DeviceKind::Tv);
        assert!(d.rtt_ms.is_none() && d.ttl.is_none() && d.upnp.is_none());
    }

    #[test]
    fn label_falls_back_through_upnp() {
        let d = Device {
            upnp: Some(UpnpInfo {
                friendly_name: Some("Living TV".into()),
                ..Default::default()
            }),
            vendor: Some("LG".into()),
            ..Default::default()
        };
        assert_eq!(d.label(), "Living TV");
    }
}

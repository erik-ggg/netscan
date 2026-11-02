use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Best human-readable name: hostname, else model, else vendor, else kind name.
    /// Never the IP (the map always shows that on its own line).
    pub fn label(&self) -> String {
        self.hostname
            .clone()
            .or_else(|| self.model.clone())
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

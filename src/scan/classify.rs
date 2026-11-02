//! Ordered heuristics mapping a device's gathered facts to a `DeviceKind`.

use super::model::{Device, DeviceKind as K};

/// Keyword match: long keywords match as substrings, short ones as whole
/// tokens (optionally followed by digits, e.g. `esp32`, `tv2`).
fn has(text: &str, kw: &str) -> bool {
    if kw.len() >= 5 {
        return text.contains(kw);
    }
    text.split(|c: char| !c.is_ascii_alphanumeric()).any(|t| {
        t.strip_prefix(kw).is_some_and(|r| r.chars().all(|c| c.is_ascii_digit()))
    })
}

fn any(text: &str, kws: &[&str]) -> bool {
    kws.iter().any(|k| has(text, k))
}

pub fn classify(d: &Device) -> K {
    if d.is_gateway {
        return K::Router;
    }
    if d.is_self {
        return K::Computer;
    }
    let model = d.model.as_deref().unwrap_or("").to_lowercase();
    let host = d.hostname.as_deref().unwrap_or("").to_lowercase();
    let vendor = d.vendor.as_deref().unwrap_or("");
    let svc = |s: &str| d.services.iter().any(|x| x.split_once('.').map_or(x.as_str(), |p| p.0) == s);
    let svc_any = |l: &[&str]| l.iter().any(|s| svc(s));
    let text = format!("{host} {model}");

    // 1. Explicit hardware model (Apple identifiers etc.).
    if model.starts_with("iphone") || model.starts_with("ipod") {
        return K::Mobile;
    }
    if model.starts_with("ipad") {
        return K::Tablet;
    }
    if model.starts_with("audioaccessory") || model.starts_with("appletv") {
        return if model.starts_with("appletv") { K::Tv } else { K::Media };
    }
    if ["macbook", "imac", "macmini", "macpro"].iter().any(|p| model.starts_with(p))
        || model.starts_with("mac") && model.contains(',')
    {
        return K::Computer;
    }
    if model.starts_with("watch") {
        return K::Mobile;
    }

    // 2. Hostname / model keywords, most specific first.
    let rules: &[(&[&str], K)] = &[
        (&["tesla", "model3", "modely"], K::Car),
        (&["playstation", "ps5", "ps4", "xbox", "nintendo", "switch", "steamdeck"], K::Console),
        (&["printer", "laserjet", "officejet", "deskjet", "epson", "brother", "canon", "mfc"], K::Printer),
        (&["iphone", "android", "galaxy", "pixel", "redmi", "xiaomi", "oneplus", "huawei", "phone", "poco", "oppo", "realme"], K::Mobile),
        (&["ipad", "tablet", "tab"], K::Tablet),
        (&["chromecast", "roku", "firetv", "fire-tv", "appletv", "apple-tv", "bravia", "webos", "tizen", "androidtv", "shield", "tv"], K::Tv),
        (&["homepod", "echo", "alexa", "sonos", "speaker", "nest-mini", "nesthub", "soundbar", "audio"], K::Media),
        (&["macbook", "imac", "desktop", "laptop", "pc", "workstation", "thinkpad", "ubuntu", "linux", "windows", "mac", "nas", "synology", "qnap", "raspberry", "raspi", "server"], K::Computer),
        (&["esp", "shelly", "tuya", "hue", "cam", "camera", "bulb", "plug", "sensor", "thermostat", "roomba", "vacuum", "robot", "ring", "doorbell", "wiz", "tasmota", "zigbee", "matter", "light", "lamp", "wyze", "ezviz", "hikvision", "reolink"], K::Iot),
    ];
    for (kws, kind) in rules {
        if any(&text, kws) {
            return *kind;
        }
    }

    // 3. Advertised services.
    if svc_any(&["_printer", "_ipp", "_ipps", "_pdl-datastream"]) {
        return K::Printer;
    }
    if svc("_androidtvremote2") {
        return K::Tv;
    }
    if svc("_googlecast") {
        return K::Media;
    }
    if svc("_sonos") || (svc_any(&["_airplay", "_raop"]) && !svc("_companion-link")) {
        return if matches!(vendor, "Samsung" | "LG" | "Sony" | "TCL" | "Hisense") { K::Tv } else { K::Media };
    }
    if svc("_nvstream") {
        return K::Computer;
    }
    if svc_any(&["_hap", "_homekit", "_hue", "_matter", "_matterc", "_meshcop", "_mqtt", "_amzn-wplay"]) {
        return K::Iot;
    }
    if svc_any(&["_smb", "_afpovertcp", "_ssh", "_sftp-ssh", "_workstation", "_rdlink"]) {
        return K::Computer;
    }

    // 4. Vendor.
    match vendor {
        "Sony" if svc("_airplay") => return K::Tv,
        "Nintendo" | "Valve" | "PlayStation" => return K::Console,
        "Tesla" => return K::Car,
        "Roku" | "Hisense" | "TCL" => return K::Tv,
        "TCT" => return K::Mobile,
        "Sonos" => return K::Media,
        "Brother" | "Epson" => return K::Printer, // Canon also makes cameras: needs a printer service
        "Espressif" | "Tuya" | "Shelly" | "Signify" | "Sonoff" | "AI-Link" | "Bilian" | "Philips Hue" | "Nest" | "Ring" | "Wyze" | "Ezviz" | "Hikvision"
        | "Reolink" | "iRobot" | "Ecovacs" | "Roborock" | "Meross" | "Yeelight" | "Withings" | "Dyson" | "BSH" => {
            return K::Iot;
        }
        "Dell" | "Lenovo" | "HP" | "Intel" | "Raspberry Pi" | "Synology" | "QNAP" | "Realtek" | "Nvidia"
        | "Microsoft" => {
            return K::Computer;
        }
        "Xiaomi" | "Huawei" | "OnePlus" | "Oppo" | "Vivo" | "Realme" | "Honor" | "Motorola" | "Nothing" => {
            return K::Mobile;
        }
        "Amazon" => return K::Media,
        "Google" => return K::Media,
        "Apple" | "Samsung" | "LG" | "Garmin" | "Fitbit" | "Amazfit" => {
            return if vendor == "LG" || (vendor == "Samsung" && svc_any(&["_airplay"])) { K::Tv } else { K::Mobile };
        }
        "TP-Link" => return K::Iot, // non-gateway TP-Link: Tapo/Kasa plugs, cams, bulbs
        "Netgear" | "ASUS" | "Ubiquiti" | "Starlink" | "AVM" | "Sagemcom" | "ZTE" | "Technicolor" | "MitraStar"
        | "Askey" | "Cisco" | "D-Link" | "Arris" | "Compal" | "Vodafone" | "Digi" => return K::Unknown,
        _ => {}
    }

    // 5. Private (randomized) MACs are what iOS/Android use per network.
    if d.mac_randomized {
        return K::Mobile;
    }
    K::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> Device {
        Device {
            ip: "192.168.1.50".into(),
            mac: None,
            is_self: false,
            is_gateway: false,
            hostname: None,
            vendor: None,
            model: None,
            services: vec![],
            kind: K::Unknown,
            mac_randomized: false,
        }
    }

    #[test]
    fn gateway_and_self() {
        assert_eq!(classify(&Device { is_gateway: true, ..dev() }), K::Router);
        assert_eq!(classify(&Device { is_self: true, ..dev() }), K::Computer);
    }

    #[test]
    fn by_model() {
        assert_eq!(classify(&Device { model: Some("iPhone14,2".into()), ..dev() }), K::Mobile);
        assert_eq!(classify(&Device { model: Some("MacBookPro18,3".into()), ..dev() }), K::Computer);
        assert_eq!(classify(&Device { model: Some("AudioAccessory5,1".into()), ..dev() }), K::Media);
        assert_eq!(classify(&Device { model: Some("AppleTV11,1".into()), ..dev() }), K::Tv);
    }

    #[test]
    fn by_hostname_services_vendor() {
        assert_eq!(classify(&Device { hostname: Some("Erik-s-iPad".into()), ..dev() }), K::Tablet);
        assert_eq!(classify(&Device { hostname: Some("ESP_A1B2C3".into()), ..dev() }), K::Iot);
        assert_eq!(classify(&Device { hostname: Some("Salon TV".into()), ..dev() }), K::Tv);
        assert_eq!(classify(&Device { services: vec!["_ipp".into()], ..dev() }), K::Printer);
        assert_eq!(classify(&Device { vendor: Some("Espressif".into()), ..dev() }), K::Iot);
        assert_eq!(classify(&Device { vendor: Some("Sony".into()), services: vec!["_airplay".into()], ..dev() }), K::Tv);
    }

    #[test]
    fn new_vendors() {
        let v = |n: &str| classify(&Device { vendor: Some(n.into()), ..dev() });
        assert_eq!(v("PlayStation"), K::Console);
        assert_eq!(v("Signify"), K::Iot);
        assert_eq!(v("Microsoft"), K::Computer);
        assert_eq!(v("Starlink"), K::Unknown);
        assert_eq!(v("Murata"), K::Unknown);
        assert_eq!(v("Canon"), K::Unknown);
        assert_eq!(classify(&Device { vendor: Some("Canon".into()), services: vec!["_ipp._tcp".into()], ..dev() }), K::Printer);
    }

    #[test]
    fn randomized_fallback() {
        assert_eq!(classify(&Device { mac_randomized: true, ..dev() }), K::Mobile);
        assert_eq!(classify(&dev()), K::Unknown);
    }
}

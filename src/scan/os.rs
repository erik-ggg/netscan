//! Heuristic OS guess from sweep facts (TTL, model, vendor, services, UPnP).

use super::model::*;

fn family_label(f: OsFamily) -> (&'static str, &'static str) {
    use OsFamily::*;
    match f {
        Ios => ("IOS / IPADOS", "IOS"),
        MacOs => ("MACOS", "MAC"),
        Android => ("ANDROID", "AND"),
        Windows => ("WINDOWS", "WIN"),
        Linux => ("LINUX", "LNX"),
        WebOs => ("WEBOS (LINUX)", "WOS"),
        Tizen => ("TIZEN", "TZN"),
        Embedded => ("EMBEDDED RTOS", "RTOS"),
        NetworkOs => ("NETWORK OS", "NOS"),
        Unknown => ("UNKNOWN", "---"),
    }
}

pub fn guess(d: &Device, intel: Option<&DeviceIntel>) -> OsGuess {
    if d.is_self {
        // Our own host: the compile-time OS is certain.
        let f = if cfg!(target_os = "macos") {
            OsFamily::MacOs
        } else if cfg!(target_os = "windows") {
            OsFamily::Windows
        } else {
            OsFamily::Linux
        };
        let (label, short) = family_label(f);
        return OsGuess {
            family: f,
            label: label.into(),
            short: short.into(),
            confidence: 100,
            evidence: vec!["LOCAL HOST".into()],
        };
    }
    let model = d.model.as_deref().unwrap_or("").to_lowercase();
    let host = d.hostname.as_deref().unwrap_or("").to_lowercase();
    let vendor = d.vendor.as_deref().unwrap_or("");
    let svc = |s: &str| {
        d.services
            .iter()
            .any(|x| x.split_once('.').map_or(x.as_str(), |p| p.0) == s)
    };
    let up = d.upnp.as_ref().or(intel.and_then(|i| i.upnp.as_ref()));
    let server = up
        .and_then(|u| u.server.as_deref())
        .unwrap_or("")
        .to_lowercase();
    let upnp_text = format!(
        "{} {} {}",
        server,
        up.and_then(|u| u.friendly_name.as_deref()).unwrap_or(""),
        up.and_then(|u| u.model_name.as_deref()).unwrap_or("")
    )
    .to_lowercase();
    let open = |p: u16| {
        intel.is_some_and(|i| {
            i.ports
                .iter()
                .any(|x| x.port == p && x.state == PortState::Open)
        })
    };
    let ttl = d
        .ttl
        .or(intel.and_then(|i| i.ping.as_ref().and_then(|p| p.ttl)));
    let tv_maker = |v: &str| vendor.eq_ignore_ascii_case(v);

    let mut c: Vec<(OsFamily, u8, String)> = vec![];
    let mut add = |f: OsFamily, s: u8, e: &str| c.push((f, s, e.to_string()));

    if model.starts_with("iphone") || model.starts_with("ipad") || model.starts_with("ipod") {
        add(OsFamily::Ios, 95, "MODEL ID IPHONE/IPAD");
    }
    if open(62078) {
        add(OsFamily::Ios, 85, "62078/TCP LOCKDOWN OPEN");
    }
    if vendor == "Apple" && (d.kind == DeviceKind::Computer || model.starts_with("mac")) {
        add(OsFamily::MacOs, 80, "APPLE COMPUTER");
    }
    if svc("_companion-link")
        && vendor == "Apple"
        && !model.starts_with("iphone")
        && !model.starts_with("ipad")
    {
        add(OsFamily::MacOs, 80, "_COMPANION-LINK SERVICE");
    }
    if open(548) {
        add(OsFamily::MacOs, 80, "548/TCP AFP OPEN");
    }
    if let Some(b) = intel.and_then(|i| i.banners.iter().find(|b| b.proto == "SSH")) {
        let t = b.text.to_lowercase();
        if ["ubuntu", "debian", "raspbian", "linux"]
            .iter()
            .any(|k| t.contains(k))
        {
            add(OsFamily::Linux, 90, "SSH BANNER DISTRO");
        } else if t.contains("dropbear") {
            // Dropbear is the SSH daemon of choice on embedded boxes (routers, cameras, NAS).
            add(OsFamily::Linux, 70, "SSH BANNER DROPBEAR");
        }
    }
    if server.contains("linux") {
        add(OsFamily::Linux, 60, "UPNP SERVER: LINUX");
    }
    if open(5555) {
        add(OsFamily::Android, 70, "5555/TCP ADB OPEN");
    }
    if svc("_androidtvremote2") {
        add(OsFamily::Android, 70, "_ANDROIDTVREMOTE2 SERVICE");
    }
    if svc("_googlecast") && tv_maker("Google") {
        add(OsFamily::Android, 50, "CAST + GOOGLE");
    }
    if open(3389) {
        add(OsFamily::Windows, 80, "3389/TCP RDP OPEN");
    }
    if intel.is_some_and(|i| i.netbios.is_some()) {
        add(
            OsFamily::Windows,
            if ttl == Some(128) { 70 } else { 60 },
            "NETBIOS NAME",
        );
    }
    if ttl == Some(128) {
        add(OsFamily::Windows, 55, "TTL 128");
    }
    if tv_maker("LG") && (open(3000) || open(3001)) {
        add(OsFamily::WebOs, 85, "LG + 3000/3001 OPEN");
    }
    if upnp_text.contains("webos") || host.contains("webos") {
        add(OsFamily::WebOs, 85, "WEBOS STRING");
    }
    if tv_maker("Samsung") && open(8001) {
        add(OsFamily::Tizen, 80, "SAMSUNG + 8001 OPEN");
    }
    if upnp_text.contains("tizen") {
        add(OsFamily::Tizen, 80, "TIZEN STRING");
    }
    if matches!(vendor, "Espressif" | "Tuya" | "Shelly") {
        add(OsFamily::Embedded, 70, "IOT SILICON VENDOR");
    }
    if ttl == Some(255) {
        add(OsFamily::Embedded, 50, "TTL 255");
    }
    let igd = up
        .and_then(|u| u.device_type.as_deref())
        .is_some_and(|t| t.contains("InternetGatewayDevice"));
    if (d.is_gateway && !vendor.is_empty()) || igd {
        add(
            OsFamily::NetworkOs,
            60,
            if igd { "UPNP IGD" } else { "GATEWAY VENDOR" },
        );
    }

    if let Some((f, s, _)) = c.iter().max_by_key(|(_, s, _)| *s).cloned() {
        let (label, short) = family_label(f);
        let evidence: Vec<String> = c
            .into_iter()
            .filter(|(cf, _, _)| *cf == f)
            .map(|(_, _, e)| e)
            .collect();
        let label = if f == OsFamily::Linux
            && s < 90
            && evidence.iter().any(|e| e == "SSH BANNER DROPBEAR")
        {
            "EMBEDDED LINUX"
        } else {
            label
        };
        return OsGuess {
            family: f,
            label: label.into(),
            short: short.into(),
            confidence: s,
            evidence,
        };
    }
    match (ttl, d.mac_randomized) {
        (Some(64), true) => OsGuess {
            family: OsFamily::Unknown,
            label: "MOBILE (IOS/ANDROID)".into(),
            short: "MOB".into(),
            confidence: 40,
            evidence: vec!["TTL 64".into(), "PRIVATE MAC".into()],
        },
        (Some(64), false) => OsGuess {
            family: OsFamily::Unknown,
            label: "UNIX-LIKE".into(),
            short: "NIX".into(),
            confidence: 30,
            evidence: vec!["TTL 64".into()],
        },
        _ => OsGuess {
            family: OsFamily::Unknown,
            label: "UNKNOWN".into(),
            short: "---".into(),
            confidence: 0,
            evidence: vec![],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_is_known_host_os() {
        let d = Device {
            is_self: true,
            ttl: Some(64),
            mac_randomized: true,
            ..Default::default()
        };
        let g = guess(&d, None);
        assert_eq!(g.confidence, 100);
        assert_eq!(g.evidence, vec!["LOCAL HOST".to_string()]);
        if cfg!(target_os = "macos") {
            assert_eq!(g.family, OsFamily::MacOs);
        }
    }

    #[test]
    fn iphone_model() {
        let d = Device {
            model: Some("iPhone14,2".into()),
            ..Default::default()
        };
        let g = guess(&d, None);
        assert_eq!(
            (g.family, g.confidence, g.short.as_str()),
            (OsFamily::Ios, 95, "IOS")
        );
    }

    #[test]
    fn windows_ttl_and_unix() {
        let d = Device {
            ttl: Some(128),
            ..Default::default()
        };
        assert_eq!(guess(&d, None).family, OsFamily::Windows);
        let d = Device {
            ttl: Some(64),
            ..Default::default()
        };
        assert_eq!(guess(&d, None).confidence, 30);
        let d = Device {
            ttl: Some(64),
            mac_randomized: true,
            ..Default::default()
        };
        assert_eq!(guess(&d, None).confidence, 40);
    }

    #[test]
    fn webos_upnp_and_embedded() {
        let d = Device {
            upnp: Some(UpnpInfo {
                server: Some("WebOS/4.1 UPnP/1.0".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(guess(&d, None).family, OsFamily::WebOs);
        let d = Device {
            vendor: Some("Espressif".into()),
            ..Default::default()
        };
        assert_eq!(guess(&d, None).family, OsFamily::Embedded);
        assert_eq!(guess(&Device::default(), None).short, "---");
    }

    #[test]
    fn dropbear_is_embedded_linux() {
        let i = DeviceIntel {
            banners: vec![Banner {
                port: 22,
                proto: "SSH".into(),
                text: "SSH-2.0-dropbear_2018.76".into(),
            }],
            ..Default::default()
        };
        let g = guess(&Device::default(), Some(&i));
        assert_eq!(
            (g.family, g.confidence, g.label.as_str()),
            (OsFamily::Linux, 70, "EMBEDDED LINUX")
        );
    }

    #[test]
    fn igd_is_network_os() {
        let d = Device {
            upnp: Some(UpnpInfo {
                device_type: Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(guess(&d, None).family, OsFamily::NetworkOs);
    }
}

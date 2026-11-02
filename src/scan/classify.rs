//! Ordered heuristics mapping a device's gathered facts to a `DeviceKind`.

use super::model::{Device, DeviceIntel, DeviceKind as K};

/// Keyword match: long keywords match as substrings, short ones as whole
/// tokens (optionally followed by digits, e.g. `esp32`, `tv2`).
fn has(text: &str, kw: &str) -> bool {
    if kw.len() >= 5 {
        return text.contains(kw);
    }
    text.split(|c: char| !c.is_ascii_alphanumeric()).any(|t| {
        t.strip_prefix(kw)
            .is_some_and(|r| r.chars().all(|c| c.is_ascii_digit()))
    })
}

fn any(text: &str, kws: &[&str]) -> bool {
    kws.iter().any(|k| has(text, k))
}

fn vendor_is_tv(v: &str) -> bool {
    matches!(v, "Samsung" | "LG" | "Sony" | "TCL" | "Hisense")
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
    let svc = |s: &str| {
        d.services
            .iter()
            .any(|x| x.split_once('.').map_or(x.as_str(), |p| p.0) == s)
    };
    let svc_any = |l: &[&str]| l.iter().any(|s| svc(s));
    let up = d.upnp.as_ref();
    let up_text = [
        up.and_then(|u| u.friendly_name.as_deref()),
        up.and_then(|u| u.model_name.as_deref()),
        up.and_then(|u| u.manufacturer.as_deref()),
        up.and_then(|u| u.server.as_deref()),
    ]
    .iter()
    .flatten()
    .copied()
    .collect::<Vec<_>>()
    .join(" ")
    .to_lowercase();
    let text = format!("{host} {model} {up_text}");

    // 1. Explicit hardware model (Apple identifiers etc.).
    if model.starts_with("iphone") || model.starts_with("ipod") {
        return K::Mobile;
    }
    if model.starts_with("ipad") {
        return K::Tablet;
    }
    if model.starts_with("audioaccessory") || model.starts_with("appletv") {
        return if model.starts_with("appletv") {
            K::Tv
        } else {
            K::Media
        };
    }
    if ["macbook", "imac", "macmini", "macpro"]
        .iter()
        .any(|p| model.starts_with(p))
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
        (
            &[
                "playstation",
                "ps5",
                "ps4",
                "xbox",
                "nintendo",
                "switch",
                "steamdeck",
            ],
            K::Console,
        ),
        (
            &[
                "printer",
                "laserjet",
                "officejet",
                "deskjet",
                "epson",
                "brother",
                "canon",
                "mfc",
            ],
            K::Printer,
        ),
        (
            &[
                "iphone", "android", "galaxy", "pixel", "redmi", "xiaomi", "oneplus", "huawei",
                "phone", "poco", "oppo", "realme",
            ],
            K::Mobile,
        ),
        (&["ipad", "tablet", "tab"], K::Tablet),
        (
            &[
                "chromecast",
                "roku",
                "firetv",
                "fire-tv",
                "appletv",
                "apple-tv",
                "bravia",
                "webos",
                "tizen",
                "androidtv",
                "shield",
                "tv",
            ],
            K::Tv,
        ),
        (
            &[
                "homepod",
                "echo",
                "alexa",
                "sonos",
                "speaker",
                "nest-mini",
                "nesthub",
                "soundbar",
                "audio",
            ],
            K::Media,
        ),
        (
            &[
                "macbook",
                "imac",
                "desktop",
                "laptop",
                "pc",
                "workstation",
                "thinkpad",
                "ubuntu",
                "linux",
                "windows",
                "mac",
                "nas",
                "synology",
                "qnap",
                "raspberry",
                "raspi",
                "server",
            ],
            K::Computer,
        ),
        (
            &[
                "esp",
                "shelly",
                "tuya",
                "hue",
                "cam",
                "camera",
                "bulb",
                "plug",
                "sensor",
                "thermostat",
                "roomba",
                "vacuum",
                "robot",
                "ring",
                "doorbell",
                "wiz",
                "tasmota",
                "zigbee",
                "matter",
                "light",
                "lamp",
                "wyze",
                "ezviz",
                "hikvision",
                "reolink",
            ],
            K::Iot,
        ),
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
        return if matches!(vendor, "Samsung" | "LG" | "Sony" | "TCL" | "Hisense") {
            K::Tv
        } else {
            K::Media
        };
    }
    if svc("_nvstream") {
        return K::Computer;
    }
    if svc_any(&[
        "_hap",
        "_homekit",
        "_hue",
        "_matter",
        "_matterc",
        "_meshcop",
        "_mqtt",
        "_amzn-wplay",
    ]) {
        return K::Iot;
    }
    if svc_any(&[
        "_smb",
        "_afpovertcp",
        "_ssh",
        "_sftp-ssh",
        "_workstation",
        "_rdlink",
    ]) {
        return K::Computer;
    }

    if up
        .and_then(|u| u.device_type.as_deref())
        .is_some_and(|t| t.contains("MediaRenderer"))
        && vendor_is_tv(vendor)
    {
        return K::Tv;
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
        "Espressif" | "Tuya" | "Shelly" | "Signify" | "Sonoff" | "AI-Link" | "Bilian"
        | "Philips Hue" | "Nest" | "Ring" | "Wyze" | "Ezviz" | "Hikvision" | "Reolink"
        | "iRobot" | "Ecovacs" | "Roborock" | "Meross" | "Yeelight" | "Withings" | "Dyson"
        | "BSH" => {
            return K::Iot;
        }
        "Dell" | "Lenovo" | "HP" | "Intel" | "Raspberry Pi" | "Synology" | "QNAP" | "Realtek"
        | "Nvidia" | "Microsoft" => {
            return K::Computer;
        }
        "Xiaomi" | "Huawei" | "OnePlus" | "Oppo" | "Vivo" | "Realme" | "Honor" | "Motorola"
        | "Nothing" => {
            return K::Mobile;
        }
        "Amazon" => return K::Media,
        "Google" => return K::Media,
        "Apple" | "Samsung" | "LG" | "Garmin" | "Fitbit" | "Amazfit" => {
            return if vendor == "LG" || (vendor == "Samsung" && svc_any(&["_airplay"])) {
                K::Tv
            } else {
                K::Mobile
            };
        }
        "TP-Link" => return K::Iot, // non-gateway TP-Link: Tapo/Kasa plugs, cams, bulbs
        "Netgear" | "ASUS" | "Ubiquiti" | "Starlink" | "AVM" | "Sagemcom" | "ZTE"
        | "Technicolor" | "MitraStar" | "Askey" | "Cisco" | "D-Link" | "Arris" | "Compal"
        | "Vodafone" | "Digi" => return K::Unknown,
        _ => {}
    }

    // 5. Private (randomized) MACs are what iOS/Android use per network.
    if d.mac_randomized {
        return K::Mobile;
    }
    K::Unknown
}

/// Refine a device's kind from deep-scan evidence. `Some` only on strong
/// evidence and only when it differs from the current kind.
pub fn refine(d: &Device, i: &DeviceIntel) -> Option<(K, String)> {
    use super::model::PortState;
    if d.is_gateway || d.is_self {
        return None;
    }
    let open = |p: u16| {
        i.ports
            .iter()
            .any(|x| x.port == p && x.state == PortState::Open)
    };
    let vendor = d.vendor.as_deref().unwrap_or("");
    let tv_maker = vendor_is_tv(vendor);
    let up = d.upnp.as_ref().or(i.upnp.as_ref());
    let up_text = [
        up.and_then(|u| u.server.as_deref()),
        up.and_then(|u| u.friendly_name.as_deref()),
        up.and_then(|u| u.model_name.as_deref()),
        up.and_then(|u| u.device_type.as_deref()),
    ]
    .iter()
    .flatten()
    .copied()
    .collect::<Vec<_>>()
    .join(" ")
    .to_lowercase();
    let http_text = i
        .http
        .iter()
        .filter_map(|h| h.server.as_deref())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let name = format!(
        "{} {}",
        d.hostname.as_deref().unwrap_or(""),
        d.model.as_deref().unwrap_or("")
    )
    .to_lowercase();
    let ttl = d.ttl.or(i.ping.as_ref().and_then(|p| p.ttl));
    let ssh_distro = i.banners.iter().any(|b| {
        b.proto == "SSH" && {
            let t = b.text.to_lowercase();
            ["ubuntu", "debian", "raspbian", "freebsd"]
                .iter()
                .any(|k| t.contains(k))
        }
    });
    let tv_evidence = tv_maker
        || d.kind == K::Tv
        || up_text.contains("webos")
        || up_text.contains("mediarenderer");

    let c: Option<(K, String)> = if open(62078) {
        let k = if name.contains("ipad") {
            K::Tablet
        } else {
            K::Mobile
        };
        Some((k, "62078/TCP OPEN \u{2192} APPLE LOCKDOWN".into()))
    } else if open(5555) {
        Some(if tv_maker || open(8008) {
            (K::Tv, "5555/TCP ADB + TV EVIDENCE".into())
        } else {
            (
                K::Mobile,
                "5555/TCP OPEN \u{2192} ANDROID DEBUG BRIDGE".into(),
            )
        })
    } else if open(3389) {
        Some((K::Computer, "3389/TCP OPEN \u{2192} RDP".into()))
    } else if i.netbios.is_some() && ttl == Some(128) {
        Some((
            K::Computer,
            "NETBIOS NAME + TTL 128 \u{2192} WINDOWS HOST".into(),
        ))
    } else if open(9100) || open(631) || open(515) {
        Some((K::Printer, "PRINT SERVICE OPEN (9100/631/515)".into()))
    } else if open(8008) && open(8009) {
        Some((
            if tv_maker { K::Tv } else { K::Media },
            "8008+8009/TCP OPEN \u{2192} GOOGLE CAST".into(),
        ))
    } else if (open(3000) && open(3001)) || up_text.contains("webos") || http_text.contains("webos")
    {
        Some((K::Tv, "WEBOS CONTROL PORTS / STRING".into()))
    } else if open(8001) && vendor == "Samsung" {
        Some((K::Tv, "8001/TCP OPEN + SAMSUNG \u{2192} TIZEN TV".into()))
    } else if open(554) && !tv_evidence {
        Some((K::Iot, "554/TCP OPEN \u{2192} RTSP STREAM (CAMERA)".into()))
    } else if open(6668) || open(9999) {
        Some((K::Iot, "SMART-HOME CONTROL PORT (6668/9999)".into()))
    } else if open(8123) || open(1883) {
        Some((K::Iot, "HOME-AUTOMATION PORT (8123/1883)".into()))
    } else if ssh_distro {
        Some((K::Computer, "SSH BANNER \u{2192} LINUX/BSD HOST".into()))
    } else if up
        .and_then(|u| u.device_type.as_deref())
        .is_some_and(|t| t.contains("InternetGatewayDevice"))
    {
        Some((K::Router, "UPNP INTERNETGATEWAYDEVICE".into()))
    } else if up
        .and_then(|u| u.device_type.as_deref())
        .is_some_and(|t| t.contains("MediaRenderer"))
    {
        Some(if tv_maker {
            (K::Tv, "UPNP MEDIARENDERER + TV MAKER".into())
        } else {
            (K::Media, "UPNP MEDIARENDERER".into())
        })
    } else {
        None
    };
    c.filter(|(k, _)| *k != d.kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> Device {
        Device {
            ip: "192.168.1.50".into(),
            ..Default::default()
        }
    }

    #[test]
    fn gateway_and_self() {
        assert_eq!(
            classify(&Device {
                is_gateway: true,
                ..dev()
            }),
            K::Router
        );
        assert_eq!(
            classify(&Device {
                is_self: true,
                ..dev()
            }),
            K::Computer
        );
    }

    #[test]
    fn by_model() {
        assert_eq!(
            classify(&Device {
                model: Some("iPhone14,2".into()),
                ..dev()
            }),
            K::Mobile
        );
        assert_eq!(
            classify(&Device {
                model: Some("MacBookPro18,3".into()),
                ..dev()
            }),
            K::Computer
        );
        assert_eq!(
            classify(&Device {
                model: Some("AudioAccessory5,1".into()),
                ..dev()
            }),
            K::Media
        );
        assert_eq!(
            classify(&Device {
                model: Some("AppleTV11,1".into()),
                ..dev()
            }),
            K::Tv
        );
    }

    #[test]
    fn by_hostname_services_vendor() {
        assert_eq!(
            classify(&Device {
                hostname: Some("Erik-s-iPad".into()),
                ..dev()
            }),
            K::Tablet
        );
        assert_eq!(
            classify(&Device {
                hostname: Some("ESP_A1B2C3".into()),
                ..dev()
            }),
            K::Iot
        );
        assert_eq!(
            classify(&Device {
                hostname: Some("Salon TV".into()),
                ..dev()
            }),
            K::Tv
        );
        assert_eq!(
            classify(&Device {
                services: vec!["_ipp".into()],
                ..dev()
            }),
            K::Printer
        );
        assert_eq!(
            classify(&Device {
                vendor: Some("Espressif".into()),
                ..dev()
            }),
            K::Iot
        );
        assert_eq!(
            classify(&Device {
                vendor: Some("Sony".into()),
                services: vec!["_airplay".into()],
                ..dev()
            }),
            K::Tv
        );
    }

    #[test]
    fn new_vendors() {
        let v = |n: &str| {
            classify(&Device {
                vendor: Some(n.into()),
                ..dev()
            })
        };
        assert_eq!(v("PlayStation"), K::Console);
        assert_eq!(v("Signify"), K::Iot);
        assert_eq!(v("Microsoft"), K::Computer);
        assert_eq!(v("Starlink"), K::Unknown);
        assert_eq!(v("Murata"), K::Unknown);
        assert_eq!(v("Canon"), K::Unknown);
        assert_eq!(
            classify(&Device {
                vendor: Some("Canon".into()),
                services: vec!["_ipp._tcp".into()],
                ..dev()
            }),
            K::Printer
        );
    }

    #[test]
    fn upnp_text_feeds_keywords() {
        use crate::scan::model::UpnpInfo;
        let u = |n: &str| {
            Some(UpnpInfo {
                friendly_name: Some(n.into()),
                ..Default::default()
            })
        };
        assert_eq!(
            classify(&Device {
                upnp: u("[LG] webOS TV UQ75"),
                ..dev()
            }),
            K::Tv
        );
        assert_eq!(
            classify(&Device {
                upnp: u("Epson XP-2100"),
                ..dev()
            }),
            K::Printer
        );
    }

    #[test]
    fn randomized_fallback() {
        assert_eq!(
            classify(&Device {
                mac_randomized: true,
                ..dev()
            }),
            K::Mobile
        );
        assert_eq!(classify(&dev()), K::Unknown);
    }

    fn intel_open(ports: &[u16]) -> DeviceIntel {
        use crate::scan::model::PortState;
        DeviceIntel {
            ports: ports
                .iter()
                .map(|&p| crate::scan::intel::ports::info(p, PortState::Open))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn refine_table() {
        let r = |d: &Device, p: &[u16]| refine(d, &intel_open(p)).map(|x| x.0);
        assert_eq!(r(&dev(), &[62078]), Some(K::Mobile));
        assert_eq!(
            r(
                &Device {
                    hostname: Some("Erik-iPad".into()),
                    ..dev()
                },
                &[62078]
            ),
            Some(K::Tablet)
        );
        assert_eq!(r(&dev(), &[9100]), Some(K::Printer));
        assert_eq!(r(&dev(), &[3000, 3001]), Some(K::Tv));
        assert_eq!(r(&dev(), &[554]), Some(K::Iot));
        assert_eq!(
            r(
                &Device {
                    kind: K::Iot,
                    ..dev()
                },
                &[554]
            ),
            None
        );
        assert_eq!(r(&dev(), &[8008, 8009]), Some(K::Media));
        assert_eq!(r(&dev(), &[]), None);
        assert_eq!(
            r(
                &Device {
                    is_gateway: true,
                    ..dev()
                },
                &[62078]
            ),
            None
        );
        assert_eq!(
            r(
                &Device {
                    is_self: true,
                    ..dev()
                },
                &[3389]
            ),
            None
        );
    }
}

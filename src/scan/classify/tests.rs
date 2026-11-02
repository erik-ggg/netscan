use super::*;
use crate::scan::model::{
    Banner, Beacon, DeviceIntel, Ident, NetBiosInfo, PingStats, PortState, UpnpInfo,
};

fn dev() -> Device {
    Device {
        ip: "192.168.1.50".into(),
        ..Default::default()
    }
}

fn v(vendor: &str) -> Device {
    Device {
        vendor: Some(vendor.into()),
        ..dev()
    }
}

fn svcs(l: &[&str]) -> Vec<String> {
    l.iter().map(|s| s.to_string()).collect()
}

fn beacon(open: &[u16], idents: Vec<Ident>) -> Option<Beacon> {
    Some(Beacon {
        open: open.to_vec(),
        idents,
        elapsed_ms: 100,
    })
}

fn txt(k: &str, val: &str) -> std::collections::BTreeMap<String, String> {
    [(k.to_string(), val.to_string())].into()
}

fn intel_open(ports: &[u16]) -> DeviceIntel {
    DeviceIntel {
        ports: ports
            .iter()
            .map(|&p| crate::scan::intel::ports::info(p, PortState::Open))
            .collect(),
        ..Default::default()
    }
}

#[test]
fn row1_lg_tv_on() {
    let c = assess(
        &Device {
            vendor: Some("LG".into()),
            hostname: Some("LG webOS TV 2272".into()),
            model: Some("55NANO796NE".into()),
            services: svcs(&["_airplay._tcp", "_display._tcp", "_hap._tcp"]),
            ..dev()
        },
        None,
    );
    assert_eq!(c.kind, K::Tv);
    assert!(c.confidence >= 85, "{c:?}");
    assert!(
        c.reason.contains("55NANO796NE") || c.reason.contains("WEBOS"),
        "{}",
        c.reason
    );
    assert!(c.alt.iter().any(|a| a.0 == K::Iot));
}

#[test]
fn row2_lg_beacon_webos() {
    let c = assess(
        &Device {
            beacon: beacon(&[3000, 3001], vec![]),
            ..v("LG")
        },
        None,
    );
    assert_eq!(c.kind, K::Tv);
    assert!(c.confidence >= 80);
    assert_eq!(c.label.as_deref(), Some("WEBOS TV"));
    // Only one of the two ports is not enough for webOS.
    let c = assess(
        &Device {
            beacon: beacon(&[3000], vec![]),
            ..dev()
        },
        None,
    );
    assert_eq!(c.kind, K::Unknown);
}

#[test]
fn row3_tct_alone() {
    let c = assess(&v("TCT"), None);
    assert_eq!(c.kind, K::Mobile);
    assert!((35..=55).contains(&c.confidence), "{}", c.confidence);
    assert!(c.alt.iter().any(|a| a.0 == K::Tablet || a.0 == K::Tv));
}

#[test]
fn row4_tct_google_tv_cast() {
    let c = assess(
        &Device {
            beacon: beacon(
                &[8008, 8009, 6466],
                vec![Ident {
                    source: "CAST".into(),
                    model: Some("TCL Google TV".into()),
                    ..Default::default()
                }],
            ),
            ..v("TCT")
        },
        None,
    );
    assert_eq!(c.kind, K::Tv);
    assert!(c.confidence >= 85);
    assert!(matches!(
        c.label.as_deref(),
        Some("GOOGLE TV" | "ANDROID TV")
    ));
}

#[test]
fn rows5_to_8_embedded_and_random() {
    let c = assess(
        &Device {
            ttl: Some(255),
            ..v("AI-Link")
        },
        None,
    );
    assert_eq!(c.kind, K::Iot);
    assert!(c.confidence >= 60);
    // Raw IEEE name as stored by older scans.
    let c = assess(
        &Device {
            ttl: Some(255),
            ..v("Sichuan AI-Link Technology")
        },
        None,
    );
    assert_eq!(c.kind, K::Iot);

    let c = assess(
        &Device {
            ttl: Some(64),
            ..v("Bilian")
        },
        None,
    );
    assert_eq!(c.kind, K::Iot);
    assert!(c.confidence <= 55);

    let c = assess(
        &Device {
            ttl: Some(64),
            ..v("TP-Link")
        },
        None,
    );
    assert_eq!(c.kind, K::Iot);
    assert!(c.confidence <= 60);

    let c = assess(
        &Device {
            ttl: Some(64),
            mac_randomized: true,
            ..dev()
        },
        None,
    );
    assert_eq!(c.kind, K::Mobile);
    assert!((40..=55).contains(&c.confidence));
}

fn wallbox() -> Device {
    Device {
        vendor: Some("Newport Media".into()),
        hostname: Some("WB277129".into()),
        services: svcs(&["_ssh._tcp", "_sftp-ssh._tcp"]),
        ttl: Some(64),
        ..dev()
    }
}

#[test]
fn row9_wallbox_ev_charger() {
    let c = assess(&wallbox(), None);
    assert_eq!(c.kind, K::Car);
    assert_eq!(c.label.as_deref(), Some("EV CHARGER"));
    assert!(c.confidence >= 50);
    let mut i = intel_open(&[22]);
    i.banners = vec![Banner {
        port: 22,
        proto: "SSH".into(),
        text: "SSH-2.0-dropbear_2018.76".into(),
    }];
    let c = assess(&wallbox(), Some(&i));
    assert_eq!(c.kind, K::Car);
    assert!(c.confidence >= 50);
    // _ssh + _sftp-ssh count once.
    assert_eq!(
        c.evidence
            .iter()
            .filter(|e| e.kind == K::Computer && e.text.contains("SSH"))
            .count(),
        1
    );
}

#[test]
fn rows10_11_cast_md() {
    let cast = |md: &str| Device {
        services: svcs(&["_googlecast._tcp"]),
        txt: txt("md", md),
        ..dev()
    };
    let c = assess(&cast("Chromecast"), None);
    assert_eq!(c.kind, K::Tv);
    assert_eq!(c.label.as_deref(), Some("STREAMER"));
    let c = assess(&cast("Google Nest Mini"), None);
    assert_eq!(c.kind, K::Media);
    assert_eq!(c.label.as_deref(), Some("SMART SPEAKER"));
    // Bare cast receiver with no md: media first.
    assert_eq!(
        assess(
            &Device {
                services: svcs(&["_googlecast._tcp"]),
                ..dev()
            },
            None
        )
        .kind,
        K::Media
    );
}

#[test]
fn row12_fire_tv() {
    let d = Device {
        services: svcs(&["_amzn-wplay._tcp"]),
        beacon: beacon(&[5555], vec![]),
        ..v("Amazon")
    };
    assert_eq!(assess(&d, None).kind, K::Tv);
}

#[test]
fn row13_roku_ident() {
    let id = |tv| Ident {
        source: "ROKU-ECP".into(),
        is_tv: Some(tv),
        ..Default::default()
    };
    let d = Device {
        beacon: beacon(&[8060], vec![id(true)]),
        ..v("TCL")
    };
    let c = assess(&d, None);
    assert_eq!(c.kind, K::Tv);
    assert!(c.confidence >= 95);
    let d = Device {
        beacon: beacon(&[], vec![id(false)]),
        ..dev()
    };
    assert_eq!(assess(&d, None).label.as_deref(), Some("STREAMER"));
}

#[test]
fn row14_samsung() {
    let d = Device {
        beacon: beacon(
            &[8001, 8002],
            vec![Ident {
                source: "SAMSUNG-API".into(),
                is_tv: Some(true),
                name: Some("Samsung SmartTV".into()),
                ..Default::default()
            }],
        ),
        ..v("Samsung")
    };
    let c = assess(&d, None);
    assert_eq!(c.kind, K::Tv);
    assert!(c.confidence >= 95);
    assert_eq!(assess(&v("Samsung"), None).kind, K::Mobile);
}

#[test]
fn row15_sony_bravia() {
    let d = Device {
        services: svcs(&["_googlecast._tcp"]),
        txt: txt("md", "BRAVIA 4K VH2"),
        ..v("Sony")
    };
    assert_eq!(assess(&d, None).kind, K::Tv);
}

#[test]
fn row16_tp_vision() {
    assert_eq!(assess(&v("TP Vision"), None).kind, K::Tv);
}

#[test]
fn row17_roles() {
    let c = assess(
        &Device {
            is_gateway: true,
            ..dev()
        },
        None,
    );
    assert_eq!((c.kind, c.confidence), (K::Router, 100));
    let c = assess(
        &Device {
            is_self: true,
            ..dev()
        },
        None,
    );
    assert_eq!((c.kind, c.confidence), (K::Computer, 100));
}

#[test]
fn row18_ipp_canon() {
    let d = Device {
        services: svcs(&["_ipp._tcp"]),
        ..v("Canon")
    };
    assert_eq!(assess(&d, None).kind, K::Printer);
}

#[test]
fn row19_62078() {
    let r = |d: &Device| assess(d, Some(&intel_open(&[62078]))).kind;
    assert_eq!(r(&dev()), K::Mobile);
    assert_eq!(
        r(&Device {
            hostname: Some("Erik-iPad".into()),
            ..dev()
        }),
        K::Tablet
    );
}

#[test]
fn tv_model_shapes() {
    use patterns::tv_model;
    assert_eq!(tv_model("55NANO796NE").unwrap().0, 92);
    assert_eq!(tv_model("OLED55C1PUB").unwrap().1, "LG OLED LINE");
    assert_eq!(tv_model("UE55AU7100").unwrap().1, "SAMSUNG TV LINE");
    assert_eq!(tv_model("QN65Q60").unwrap().1, "SAMSUNG TV LINE");
    assert_eq!(tv_model("KD-55X80J").unwrap().1, "SONY TV LINE");
    assert_eq!(tv_model("XR65A80J").unwrap().1, "SONY TV LINE");
    assert_eq!(tv_model("55PUS8808").unwrap().1, "PHILIPS TV LINE");
    assert_eq!(tv_model("43C645").unwrap().0, 60);
    assert!(tv_model("MacBookPro18,3").is_none());
    assert!(tv_model("iPhone14,2").is_none());
    assert!(tv_model("WB277129").is_none());
    assert!(tv_model("12AB345").is_none());
}

#[test]
fn host_label_patterns() {
    use patterns::host_label;
    let kinds = |s: &str| host_label(s).into_iter().map(|h| h.0).collect::<Vec<_>>();
    assert!(kinds("[LG] webOS TV UQ75").contains(&K::Tv));
    assert!(kinds("Salon TV").contains(&K::Tv));
    assert!(!kinds("Settings").contains(&K::Tv));
    assert_eq!(host_label("WB277129")[0].3, Some("EV CHARGER"));
    assert!(kinds("ESP_A1B2C3").contains(&K::Iot));
    assert!(kinds("android-1a2b3c4d5e6f7a8b").contains(&K::Mobile));
    assert!(kinds("Galaxy-S21").contains(&K::Mobile));
}

// ---- legacy classify()/refine() expectations --------------------------------

#[test]
fn legacy_by_model() {
    let m = |s: &str| {
        classify(&Device {
            model: Some(s.into()),
            ..dev()
        })
    };
    assert_eq!(m("iPhone14,2"), K::Mobile);
    assert_eq!(m("MacBookPro18,3"), K::Computer);
    assert_eq!(m("AudioAccessory5,1"), K::Media);
    assert_eq!(m("AppleTV11,1"), K::Tv);
    assert_eq!(m("iPad13,1"), K::Tablet);
}

#[test]
fn legacy_hostname_services_vendor() {
    let h = |s: &str| {
        classify(&Device {
            hostname: Some(s.into()),
            ..dev()
        })
    };
    assert_eq!(h("Erik-s-iPad"), K::Tablet);
    assert_eq!(h("ESP_A1B2C3"), K::Iot);
    assert_eq!(h("Salon TV"), K::Tv);
    assert_eq!(
        classify(&Device {
            services: svcs(&["_ipp"]),
            ..dev()
        }),
        K::Printer
    );
    assert_eq!(classify(&v("Espressif")), K::Iot);
    assert_eq!(
        classify(&Device {
            services: svcs(&["_airplay"]),
            ..v("Sony")
        }),
        K::Tv
    );
    assert_eq!(
        classify(&Device {
            services: svcs(&["_airplay"]),
            ..v("Samsung")
        }),
        K::Tv
    );
}

#[test]
fn legacy_vendors() {
    assert_eq!(classify(&v("PlayStation")), K::Console);
    assert_eq!(classify(&v("Signify")), K::Iot);
    assert_eq!(classify(&v("Microsoft")), K::Computer);
    assert_eq!(classify(&v("Murata")), K::Unknown);
    assert_eq!(classify(&v("Canon")), K::Unknown);
    assert_eq!(
        classify(&Device {
            services: svcs(&["_ipp._tcp"]),
            ..v("Canon")
        }),
        K::Printer
    );
    assert_eq!(classify(&v("Tesla")), K::Car);
    assert_eq!(classify(&v("Sonos")), K::Media);
    assert_eq!(classify(&v("Brother")), K::Printer);
    // Deliberate change: router-brand OUIs are now weak Router evidence (was Unknown).
    assert_eq!(classify(&v("Starlink")), K::Router);
    // Deliberate change: TCT handsets are only ~50% Mobile, but still Mobile.
    assert_eq!(classify(&v("TCT")), K::Mobile);
}

#[test]
fn legacy_upnp_text_feeds_keywords() {
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
    let d = Device {
        upnp: Some(UpnpInfo {
            device_type: Some("urn:schemas-upnp-org:device:MediaRenderer:1".into()),
            ..Default::default()
        }),
        ..v("LG")
    };
    assert_eq!(classify(&d), K::Tv);
}

#[test]
fn legacy_randomized_and_empty() {
    assert_eq!(
        classify(&Device {
            mac_randomized: true,
            ..dev()
        }),
        K::Mobile
    );
    assert_eq!(classify(&dev()), K::Unknown);
    assert_eq!(assess(&dev(), None).confidence, 0);
}

#[test]
fn weak_floor_is_unknown_with_reason() {
    // Vendor prior of 15/20 alone stays below the 30% floor.
    let c = assess(&v("Microsoft"), None);
    assert_eq!(c.kind, K::Computer);
    let d = Device {
        ttl: Some(255),
        ..dev()
    };
    assert_eq!(assess(&d, None).kind, K::Iot);
    let c = assess(
        &Device {
            upnp: Some(UpnpInfo {
                manufacturer: Some("Sony".into()),
                ..Default::default()
            }),
            ..dev()
        },
        None,
    );
    assert_eq!(c.kind, K::Tv);
    let weak = assess(
        &Device {
            beacon: beacon(&[7000], vec![]),
            ..dev()
        },
        None,
    );
    assert_eq!(weak.kind, K::Unknown);
    assert!(weak.reason.starts_with("WEAK:"), "{}", weak.reason);
    assert!(!weak.evidence.is_empty());
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
    // 554 next to TV evidence is not a camera.
    assert_ne!(r(&v("LG"), &[554]), Some(K::Iot));
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
    assert_eq!(r(&dev(), &[3389]), Some(K::Computer));
}

#[test]
fn refine_banner_and_netbios() {
    let mut i = intel_open(&[22]);
    i.banners = vec![Banner {
        port: 22,
        proto: "SSH".into(),
        text: "SSH-2.0-OpenSSH_9.2 Debian-2".into(),
    }];
    assert_eq!(refine(&dev(), &i).map(|x| x.0), Some(K::Computer));
    let i = DeviceIntel {
        netbios: Some(NetBiosInfo {
            name: "PC1".into(),
            ..Default::default()
        }),
        ping: Some(PingStats {
            ttl: Some(128),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(refine(&dev(), &i).map(|x| x.0), Some(K::Computer));
}

#[test]
fn evidence_ordering_and_invariants() {
    let c = assess(&wallbox(), None);
    assert_eq!(c.evidence[0].kind, K::Car);
    assert!(c.alt.len() <= 2);
    assert!((1..=99).contains(&c.confidence));
    let ws: Vec<u8> = c
        .evidence
        .iter()
        .take_while(|e| e.kind == K::Car)
        .map(|e| e.weight)
        .collect();
    assert!(ws.windows(2).all(|w| w[0] >= w[1]));
}

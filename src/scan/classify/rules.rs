//! Evidence rules: every rule pushes `Ev`s; scoring happens in `mod.rs`.

use super::{brands, patterns};
use crate::scan::model::{
    Device, DeviceIntel, DeviceKind as K, EvSource as S, PortState, UpnpInfo,
};
use crate::scan::vendor::pretty_vendor;
use std::collections::BTreeSet;

const ARROW: &str = "\u{25B8}";

#[derive(Debug, Clone)]
pub struct Ev {
    pub id: String,
    pub kind: K,
    pub weight: u8,
    pub source: S,
    pub text: String,
    pub label: Option<&'static str>,
}

fn ev(id: &str, kind: K, weight: u8, source: S, text: String, label: Option<&'static str>) -> Ev {
    Ev {
        id: id.to_string(),
        kind,
        weight,
        source,
        text,
        label,
    }
}

pub fn tv_maker(vendor: &str) -> bool {
    matches!(
        vendor,
        "Samsung"
            | "LG"
            | "Sony"
            | "TCL"
            | "Hisense"
            | "Vestel"
            | "Skyworth"
            | "Changhong"
            | "TP Vision"
    )
}

struct Cx<'a> {
    d: &'a Device,
    intel: Option<&'a DeviceIntel>,
    vendor: String,
    svc: BTreeSet<String>,
    open: BTreeSet<u16>,
    ttl: Option<u8>,
    upnp: Option<&'a UpnpInfo>,
}

impl<'a> Cx<'a> {
    fn new(d: &'a Device, intel: Option<&'a DeviceIntel>) -> Self {
        let mut open: BTreeSet<u16> = d
            .beacon
            .as_ref()
            .map(|b| b.open.iter().copied().collect())
            .unwrap_or_default();
        if let Some(i) = intel {
            open.extend(
                i.ports
                    .iter()
                    .filter(|p| p.state == PortState::Open)
                    .map(|p| p.port),
            );
        }
        Cx {
            d,
            intel,
            vendor: d.vendor.as_deref().map(pretty_vendor).unwrap_or_default(),
            svc: d
                .services
                .iter()
                .map(|s| s.split_once('.').map_or(s.as_str(), |p| p.0).to_string())
                .collect(),
            open,
            ttl: d
                .ttl
                .or(intel.and_then(|i| i.ping.as_ref().and_then(|p| p.ttl))),
            upnp: d.upnp.as_ref().or(intel.and_then(|i| i.upnp.as_ref())),
        }
    }
    fn svc(&self, s: &str) -> bool {
        self.svc.contains(s)
    }
    fn svc_any(&self, l: &[&str]) -> bool {
        l.iter().any(|s| self.svc(s))
    }
    fn port(&self, p: u16) -> bool {
        self.open.contains(&p)
    }
}

pub fn collect(d: &Device, intel: Option<&DeviceIntel>) -> Vec<Ev> {
    let cx = Cx::new(d, intel);
    let mut out = Vec::new();
    model_rules(&cx, &mut out);
    name_rules(&cx, &mut out);
    mdns_rules(&cx, &mut out);
    upnp_rules(&cx, &mut out);
    port_rules(&cx, &mut out);
    ident_rules(&cx, &mut out);
    banner_rules(&cx, &mut out);
    ttl_mac_rules(&cx, &mut out);
    vendor_rules(&cx, &mut out);
    // RTSP only means camera when nothing says TV.
    if cx.port(554) && !out.iter().any(|e| e.kind == K::Tv && e.weight >= 50) {
        out.push(ev(
            "port:554",
            K::Iot,
            55,
            S::Port,
            format!("PORT 554 {ARROW} RTSP STREAM (CAMERA)"),
            Some("CAMERA"),
        ));
    }
    out
}

fn model_strings<'a>(cx: &Cx<'a>) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    v.extend(cx.d.model.clone());
    v.extend(cx.d.txt.get("md").cloned());
    v.extend(cx.d.txt.get("model").cloned());
    if let Some(u) = cx.upnp {
        v.extend(u.model_name.clone());
        v.extend(u.model_number.clone());
    }
    if let Some(b) = &cx.d.beacon {
        v.extend(b.idents.iter().filter_map(|i| i.model.clone()));
    }
    v.extend(cx.d.hostname.clone());
    v.dedup();
    v
}

fn model_rules(cx: &Cx, out: &mut Vec<Ev>) {
    if let Some(m) = cx.d.model.as_deref()
        && let Some((k, w, t)) = patterns::apple_model(m)
    {
        out.push(ev(
            "model:apple",
            k,
            w,
            S::Model,
            format!("MODEL {m} {ARROW} {t}"),
            (k == K::Media)
                .then_some("HOMEPOD")
                .or((k == K::Tv).then_some("APPLE TV")),
        ));
    }
    for m in model_strings(cx) {
        if let Some((w, t)) = patterns::tv_model(&m) {
            out.push(ev(
                "model:tv",
                K::Tv,
                w,
                S::Model,
                format!("MODEL {m} {ARROW} {t}"),
                None,
            ));
        }
    }
}

fn name_rules(cx: &Cx, out: &mut Vec<Ev>) {
    let mut names: Vec<(S, &str, String)> = Vec::new();
    if let Some(h) = &cx.d.hostname {
        names.push((S::Name, "NAME", h.clone()));
    }
    if let Some(m) = &cx.d.model {
        names.push((S::Model, "MODEL", m.clone()));
    }
    if let Some(u) = cx.upnp {
        for (t, v) in [
            ("UPNP NAME", &u.friendly_name),
            ("UPNP MODEL", &u.model_name),
            ("UPNP MAKER", &u.manufacturer),
        ] {
            if let Some(v) = v {
                names.push((S::Upnp, t, v.clone()));
            }
        }
    }
    if let Some(b) = &cx.d.beacon {
        for i in &b.idents {
            for v in [&i.name, &i.model, &i.maker].into_iter().flatten() {
                names.push((S::Probe, "PROBE", v.clone()));
            }
        }
    }
    for (src, tag, s) in names {
        for (k, w, t, label) in patterns::host_label(&s) {
            out.push(ev(
                &format!("name:{k:?}"),
                k,
                w,
                src,
                format!("{tag} \"{s}\" {ARROW} {}", t.to_uppercase()),
                label,
            ));
        }
    }
    // Wallbox naming plus a Linux/SSH sign: more likely a charger than a PC.
    if let Some(h) =
        cx.d.hostname
            .as_deref()
            .filter(|h| patterns::is_wallbox_name(h))
        && (cx.svc_any(&["_ssh", "_sftp-ssh"]) || cx.ttl == Some(64))
    {
        out.push(ev(
            "name:Car",
            K::Car,
            70,
            S::Name,
            format!("NAME \"{h}\" {ARROW} WALLBOX-STYLE NAME + LINUX/SSH"),
            Some("EV CHARGER"),
        ));
    }
}

fn mdns_rules(cx: &Cx, out: &mut Vec<Ev>) {
    let m = |id: &str, k: K, w: u8, t: &str, label: Option<&'static str>, out: &mut Vec<Ev>| {
        out.push(ev(id, k, w, S::Mdns, format!("MDNS {t}"), label));
    };
    if cx.svc_any(&["_androidtvremote2", "_androidtvremote"]) {
        m(
            "svc:atv",
            K::Tv,
            90,
            &format!("_ANDROIDTVREMOTE {ARROW} ANDROID TV"),
            Some("ANDROID TV"),
            out,
        );
    }
    if cx.svc("_googlecast") {
        m(
            "svc:cast",
            K::Media,
            55,
            &format!("_GOOGLECAST {ARROW} CAST RECEIVER"),
            None,
            out,
        );
        m(
            "svc:cast",
            K::Tv,
            35,
            &format!("_GOOGLECAST {ARROW} CAST RECEIVER"),
            None,
            out,
        );
        if let Some(md) = cx.d.txt.get("md")
            && let Some((k, w, t, label)) = patterns::cast_md(md)
        {
            m(
                "svc:castmd",
                k,
                w,
                &format!("MD \"{md}\" {ARROW} {t}"),
                label,
                out,
            );
        }
    }
    if cx.svc("_display") {
        m(
            "svc:display",
            K::Tv,
            60,
            &format!("_DISPLAY {ARROW} DISPLAY"),
            None,
            out,
        );
    }
    let airplay = cx.svc("_airplay");
    if airplay && !cx.svc("_companion-link") {
        m(
            "svc:airplay",
            K::Media,
            50,
            &format!("_AIRPLAY {ARROW} RECEIVER"),
            None,
            out,
        );
        m(
            "svc:airplay",
            K::Tv,
            30,
            &format!("_AIRPLAY {ARROW} RECEIVER"),
            None,
            out,
        );
    }
    if !airplay && cx.svc("_raop") {
        m(
            "svc:raop",
            K::Media,
            45,
            &format!("_RAOP {ARROW} AUDIO RECEIVER"),
            None,
            out,
        );
    }
    if (airplay || cx.svc("_raop")) && tv_maker(&cx.vendor) {
        m(
            "svc:airplay-tv",
            K::Tv,
            60,
            &format!("AIRPLAY + {} {ARROW} TV MAKER", cx.vendor.to_uppercase()),
            None,
            out,
        );
    }
    if cx.svc("_amzn-wplay") {
        m(
            "svc:wplay",
            K::Tv,
            55,
            &format!("_AMZN-WPLAY {ARROW} FIRE TV?"),
            Some("FIRE TV?"),
            out,
        );
        m(
            "svc:wplay",
            K::Media,
            35,
            &format!("_AMZN-WPLAY {ARROW} FIRE TV?"),
            None,
            out,
        );
    }
    if cx.svc("_amzn-alexa") {
        m(
            "svc:alexa",
            K::Media,
            70,
            &format!("_AMZN-ALEXA {ARROW} ALEXA"),
            None,
            out,
        );
    }
    if cx.svc_any(&["_hap", "_homekit"]) {
        m(
            "svc:hap",
            K::Iot,
            45,
            &format!("_HAP {ARROW} HOMEKIT ACCESSORY"),
            None,
            out,
        );
    }
    if cx.svc("_hue") {
        m(
            "svc:hue",
            K::Iot,
            85,
            &format!("_HUE {ARROW} HUE BRIDGE"),
            None,
            out,
        );
    }
    if cx.svc_any(&["_matter", "_matterc"]) {
        m(
            "svc:matter",
            K::Iot,
            70,
            &format!("_MATTER {ARROW} MATTER NODE"),
            None,
            out,
        );
    }
    if cx.svc("_meshcop") {
        m(
            "svc:meshcop",
            K::Media,
            40,
            &format!("_MESHCOP {ARROW} THREAD BORDER ROUTER"),
            None,
            out,
        );
    }
    if cx.svc("_mqtt") {
        m(
            "svc:mqtt",
            K::Iot,
            50,
            &format!("_MQTT {ARROW} BROKER/CLIENT"),
            None,
            out,
        );
    }
    if cx.svc_any(&["_ipp", "_ipps", "_printer", "_pdl-datastream"]) {
        m(
            "svc:print",
            K::Printer,
            95,
            &format!("PRINT SERVICE {ARROW} PRINTER"),
            None,
            out,
        );
    }
    if cx.svc("_sonos") {
        m(
            "svc:sonos",
            K::Media,
            90,
            &format!("_SONOS {ARROW} SONOS SPEAKER"),
            None,
            out,
        );
    }
    if cx.svc("_spotify-connect") {
        m(
            "svc:spotify",
            K::Media,
            40,
            &format!("_SPOTIFY-CONNECT {ARROW} PLAYER"),
            None,
            out,
        );
    }
    if cx.svc("_nvstream") {
        m(
            "svc:nv",
            K::Computer,
            70,
            &format!("_NVSTREAM {ARROW} GAMESTREAM HOST"),
            None,
            out,
        );
    }
    if cx.svc_any(&["_smb", "_afpovertcp", "_workstation", "_rdlink"]) {
        m(
            "svc:share",
            K::Computer,
            60,
            &format!("FILE SHARING {ARROW} COMPUTER"),
            None,
            out,
        );
    }
    if cx.svc_any(&["_ssh", "_sftp-ssh"]) {
        m(
            "svc:ssh",
            K::Computer,
            45,
            &format!("_SSH {ARROW} SHELL HOST"),
            None,
            out,
        );
    }
    if cx.svc_any(&["_adb-tls-connect", "_adb-tls-pairing"]) {
        m(
            "svc:adb",
            K::Mobile,
            40,
            &format!("_ADB-TLS {ARROW} ANDROID"),
            None,
            out,
        );
        m(
            "svc:adb",
            K::Tv,
            30,
            &format!("_ADB-TLS {ARROW} ANDROID"),
            None,
            out,
        );
    }
}

fn upnp_rules(cx: &Cx, out: &mut Vec<Ev>) {
    let Some(u) = cx.upnp else { return };
    let dt = u.device_type.as_deref().unwrap_or("");
    let p = |t: &str| format!("UPNP {t}");
    if dt.contains("MediaRenderer") {
        if tv_maker(&cx.vendor) {
            out.push(ev(
                "upnp:render",
                K::Tv,
                75,
                S::Upnp,
                p(&format!("MEDIARENDERER + TV MAKER {ARROW} DISPLAY")),
                None,
            ));
        } else {
            out.push(ev(
                "upnp:render",
                K::Tv,
                45,
                S::Upnp,
                p(&format!("MEDIARENDERER {ARROW} DISPLAY/AUDIO")),
                None,
            ));
        }
        out.push(ev(
            "upnp:render",
            K::Media,
            45,
            S::Upnp,
            p(&format!("MEDIARENDERER {ARROW} DISPLAY/AUDIO")),
            None,
        ));
    }
    if dt.contains("InternetGatewayDevice") {
        out.push(ev(
            "upnp:igd",
            K::Router,
            85,
            S::Upnp,
            p(&format!("INTERNETGATEWAYDEVICE {ARROW} ROUTER")),
            None,
        ));
    }
    if let Some(l) = u.manufacturer.as_deref().and_then(brands::line) {
        for &(k, w) in l.priors {
            out.push(ev(
                "upnp:brand",
                k,
                w.saturating_add(10).min(99),
                S::Upnp,
                p(&format!(
                    "MAKER {} {ARROW} PRODUCT LINE",
                    l.brand.to_uppercase()
                )),
                None,
            ));
        }
    }
}

fn port_rules(cx: &Cx, out: &mut Vec<Ev>) {
    let t = |p: &str, why: &str| format!("PORT {p} {ARROW} {why}");
    let lg = cx.vendor == "LG";
    let samsung = cx.vendor == "Samsung";
    let mut push = |id: &str, k: K, w: u8, text: String, label: Option<&'static str>| {
        out.push(ev(id, k, w, S::Port, text, label));
    };
    if cx.port(6466) || cx.port(6467) {
        push(
            "port:atv",
            K::Tv,
            85,
            t("6466/6467", "ANDROID TV REMOTE"),
            Some("ANDROID TV"),
        );
    }
    if cx.port(8008) && cx.port(8009) {
        push(
            "port:cast",
            K::Media,
            55,
            t("8008+8009", "GOOGLE CAST"),
            None,
        );
        push("port:cast", K::Tv, 40, t("8008+8009", "GOOGLE CAST"), None);
    }
    if cx.port(5555) {
        push("port:adb", K::Tv, 55, t("5555", "ADB ANSWERING"), None);
        push("port:adb", K::Mobile, 30, t("5555", "ADB ANSWERING"), None);
    }
    if cx.port(3000) && cx.port(3001) {
        if lg {
            push(
                "port:webos",
                K::Tv,
                92,
                t("3000+3001", "WEBOS CONTROL + LG"),
                Some("WEBOS TV"),
            );
        } else {
            push(
                "port:webos",
                K::Tv,
                80,
                t("3000+3001", "WEBOS CONTROL PORTS"),
                None,
            );
        }
    }
    if cx.port(8001) || cx.port(8002) {
        if samsung {
            push(
                "port:tizen",
                K::Tv,
                92,
                t("8001/8002", "SAMSUNG SMART TV API"),
                Some("TIZEN TV"),
            );
        } else {
            push(
                "port:tizen",
                K::Tv,
                80,
                t("8001/8002", "SMART TV API"),
                None,
            );
        }
    }
    if cx.port(8060) {
        push("port:roku", K::Tv, 90, t("8060", "ROKU ECP"), Some("ROKU"));
    }
    if cx.port(1925) || cx.port(1926) {
        push(
            "port:philips",
            K::Tv,
            85,
            t("1925/1926", "PHILIPS JOINTSPACE"),
            Some("PHILIPS TV"),
        );
    }
    if cx.port(55000) {
        push(
            "port:remote",
            K::Tv,
            70,
            t("55000", "TV REMOTE PROTOCOL"),
            None,
        );
    }
    if cx.port(9922) {
        push(
            "port:webosdev",
            K::Tv,
            70,
            t("9922", "WEBOS DEV MODE"),
            None,
        );
    }
    if cx.port(7000)
        && !cx.open.iter().any(|p| {
            matches!(
                p,
                6466 | 6467 | 8008 | 8009 | 3000 | 3001 | 8001 | 8002 | 8060
            )
        })
    {
        push(
            "port:7000",
            K::Media,
            25,
            t("7000", "AIRPLAY RECEIVER?"),
            None,
        );
    }
    // Deep-scan ports.
    if cx.port(62078) {
        let ipad = [cx.d.hostname.as_deref(), cx.d.model.as_deref()]
            .into_iter()
            .flatten()
            .any(|s| s.to_lowercase().contains("ipad"));
        let k = if ipad { K::Tablet } else { K::Mobile };
        push("port:62078", k, 85, t("62078", "APPLE LOCKDOWN"), None);
    }
    if cx.port(3389) {
        push("port:3389", K::Computer, 85, t("3389", "RDP"), None);
    }
    if cx.port(9100) || cx.port(631) || cx.port(515) {
        push(
            "port:print",
            K::Printer,
            85,
            t("9100/631/515", "PRINT SERVICE"),
            None,
        );
    }
    if cx.port(6668) || cx.port(9999) {
        push(
            "port:smart",
            K::Iot,
            80,
            t("6668/9999", "SMART-HOME CONTROL"),
            None,
        );
    }
    if cx.port(8123) || cx.port(1883) {
        push(
            "port:home",
            K::Iot,
            65,
            t("8123/1883", "HOME AUTOMATION"),
            None,
        );
    }
}

fn ident_rules(cx: &Cx, out: &mut Vec<Ev>) {
    let Some(b) = &cx.d.beacon else { return };
    for i in &b.idents {
        let who = |what: &str| format!("{} {ARROW} {what}", i.source);
        match i.source.as_str() {
            "CAST" => {
                if let Some(md) = i.model.as_deref()
                    && let Some((k, w, t, label)) = patterns::cast_md(md)
                {
                    out.push(ev(
                        "ident:cast",
                        k,
                        w.max(90),
                        S::Probe,
                        format!("CAST MODEL \"{md}\" {ARROW} {t}"),
                        label,
                    ));
                }
            }
            "ROKU-ECP" => match i.is_tv {
                Some(true) => out.push(ev(
                    "ident:roku",
                    K::Tv,
                    97,
                    S::Probe,
                    who("ROKU TV"),
                    Some("ROKU TV"),
                )),
                Some(false) => out.push(ev(
                    "ident:roku",
                    K::Tv,
                    85,
                    S::Probe,
                    who("ROKU STREAMER"),
                    Some("STREAMER"),
                )),
                None => out.push(ev(
                    "ident:roku",
                    K::Tv,
                    85,
                    S::Probe,
                    who("ROKU"),
                    Some("ROKU"),
                )),
            },
            "SAMSUNG-API" => {
                if i.is_tv != Some(false) {
                    out.push(ev(
                        "ident:samsung",
                        K::Tv,
                        97,
                        S::Probe,
                        who("SAMSUNG SMARTTV"),
                        Some("TIZEN TV"),
                    ));
                }
            }
            "PHILIPS-JS" => out.push(ev(
                "ident:philips",
                K::Tv,
                95,
                S::Probe,
                who("PHILIPS TV API"),
                Some("PHILIPS TV"),
            )),
            "DIAL" => out.push(ev(
                "ident:dial",
                K::Tv,
                60,
                S::Probe,
                who("DIAL SCREEN"),
                None,
            )),
            _ => {}
        }
    }
}

fn banner_rules(cx: &Cx, out: &mut Vec<Ev>) {
    let Some(i) = cx.intel else { return };
    for b in i.banners.iter().filter(|b| b.proto == "SSH") {
        let t = b.text.to_lowercase();
        if let Some(k) = ["ubuntu", "debian", "raspbian", "freebsd"]
            .iter()
            .find(|k| t.contains(*k))
        {
            out.push(ev(
                "banner:distro",
                K::Computer,
                70,
                S::Banner,
                format!("SSH BANNER {ARROW} {} HOST", k.to_uppercase()),
                None,
            ));
        }
        if t.contains("dropbear") {
            out.push(ev(
                "banner:dropbear",
                K::Iot,
                30,
                S::Banner,
                format!("SSH BANNER {ARROW} DROPBEAR (EMBEDDED)"),
                None,
            ));
            out.push(ev(
                "banner:dropbear",
                K::Router,
                15,
                S::Banner,
                format!("SSH BANNER {ARROW} DROPBEAR (EMBEDDED)"),
                None,
            ));
        }
    }
    if i.netbios.is_some() && cx.ttl == Some(128) {
        out.push(ev(
            "banner:nb",
            K::Computer,
            85,
            S::Banner,
            format!("NETBIOS NAME + TTL 128 {ARROW} WINDOWS HOST"),
            None,
        ));
    }
}

fn ttl_mac_rules(cx: &Cx, out: &mut Vec<Ev>) {
    match cx.ttl {
        Some(255) => {
            out.push(ev(
                "ttl",
                K::Iot,
                45,
                S::Ttl,
                format!("TTL 255 {ARROW} EMBEDDED STACK"),
                None,
            ));
            out.push(ev(
                "ttl",
                K::Router,
                10,
                S::Ttl,
                format!("TTL 255 {ARROW} EMBEDDED STACK"),
                None,
            ));
        }
        Some(128) => out.push(ev(
            "ttl",
            K::Computer,
            50,
            S::Ttl,
            format!("TTL 128 {ARROW} WINDOWS STACK"),
            None,
        )),
        _ => {}
    }
    if cx.d.mac_randomized {
        for (k, w) in [
            (K::Mobile, 50),
            (K::Tablet, 15),
            (K::Computer, 15),
            (K::Tv, 10),
        ] {
            out.push(ev(
                "mac:rand",
                k,
                w,
                S::Mac,
                format!("PRIVATE MAC {ARROW} PHONE-CLASS"),
                None,
            ));
        }
    }
}

fn vendor_rules(cx: &Cx, out: &mut Vec<Ev>) {
    let Some(l) = brands::line(&cx.vendor) else {
        return;
    };
    let why = if l.note.is_empty() {
        "PRODUCT LINE"
    } else {
        l.note
    };
    let label = (l.brand == "Roku").then_some("STREAMER");
    for &(k, w) in l.priors {
        out.push(ev(
            "vendor",
            k,
            w,
            S::Vendor,
            format!("VENDOR {} {ARROW} {why}", l.brand.to_uppercase()),
            label,
        ));
    }
}

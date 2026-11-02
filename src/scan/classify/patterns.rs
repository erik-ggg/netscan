//! Text patterns: keyword families, TV model-number shapes, Apple IDs, Cast `md`.

use crate::scan::model::DeviceKind as K;

/// Keyword match: long keywords match as substrings, short ones as whole
/// tokens (optionally followed by digits, e.g. `esp32`, `tv2`). `text` is lowercase.
pub fn has(text: &str, kw: &str) -> bool {
    if kw.len() >= 5 {
        return text.contains(kw);
    }
    text.split(|c: char| !c.is_ascii_alphanumeric()).any(|t| {
        t.strip_prefix(kw)
            .is_some_and(|r| r.chars().all(|c| c.is_ascii_digit()))
    })
}

fn first<'a>(text: &str, kws: &[&'a str]) -> Option<&'a str> {
    kws.iter().copied().find(|k| has(text, k))
}

fn digits_at(s: &[u8], n: usize) -> bool {
    s.len() >= n && s[..n].iter().all(u8::is_ascii_digit)
}

/// TV model-number shapes (input is matched case-insensitively, whole string).
/// Returns `(weight, wording)`.
pub fn tv_model(s: &str) -> Option<(u8, &'static str)> {
    let u = s.trim().to_ascii_uppercase();
    let b = u.as_bytes();
    // Philips: 55PUS8808, 43PFS5505, 65OLED806 ...
    if digits_at(b, 2) {
        let rest = &u[2..];
        for p in ["PUS", "PFS", "PML", "OLED", "PUD", "PHS"] {
            if rest
                .strip_prefix(p)
                .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
            {
                return Some((92, "PHILIPS TV LINE"));
            }
        }
        for p in [
            "NANO", "UQ", "UR", "UP", "UN", "UM", "UK", "SM", "OLED", "QNED", "LM", "LX",
        ] {
            if rest.starts_with(p) {
                return Some((92, "LG TV LINE"));
            }
        }
    }
    if u.strip_prefix("OLED").is_some_and(|r| {
        digits_at(r.as_bytes(), 2) && r.len() > 2 && r.as_bytes()[2].is_ascii_alphabetic()
    }) {
        return Some((90, "LG OLED LINE"));
    }
    for p in ["UE", "QE", "UN", "QN", "GQ", "GU", "HG"] {
        if u.strip_prefix(p)
            .is_some_and(|r| digits_at(r.as_bytes(), 2))
        {
            return Some((92, "SAMSUNG TV LINE"));
        }
    }
    for p in ["KDL", "KD", "XR", "FW"] {
        if let Some(r) = u.strip_prefix(p) {
            let r = r.strip_prefix('-').unwrap_or(r);
            if digits_at(r.as_bytes(), 2) {
                return Some((92, "SONY TV LINE"));
            }
        }
    }
    // Generic: 24..99 + 1-5 letters + 2-4 digits + up to 4 alnum.
    if digits_at(b, 2) && matches!(b[0], b'2'..=b'9') && (b[0] != b'2' || b[1] >= b'4') {
        let rest = &b[2..];
        let l = rest.iter().take_while(|c| c.is_ascii_uppercase()).count();
        let after = &rest[l..];
        let d = after.iter().take_while(|c| c.is_ascii_digit()).count();
        let tail = &after[d..];
        if (1..=5).contains(&l)
            && (2..=4).contains(&d)
            && tail.len() <= 4
            && tail
                .iter()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            return Some((60, "TV MODEL SHAPE"));
        }
    }
    None
}

/// Apple hardware identifiers: `(kind, weight, wording)`.
pub fn apple_model(model: &str) -> Option<(K, u8, &'static str)> {
    let m = model.to_lowercase();
    if m.starts_with("iphone") || m.starts_with("ipod") {
        Some((K::Mobile, 97, "IPHONE"))
    } else if m.starts_with("ipad") {
        Some((K::Tablet, 97, "IPAD"))
    } else if m.starts_with("appletv") {
        Some((K::Tv, 97, "APPLE TV"))
    } else if m.starts_with("audioaccessory") {
        Some((K::Media, 97, "HOMEPOD"))
    } else if ["macbook", "imac", "macmini", "macpro"]
        .iter()
        .any(|p| m.starts_with(p))
        || (m.starts_with("mac") && m.contains(','))
    {
        Some((K::Computer, 97, "MAC"))
    } else if m.starts_with("watch") {
        Some((K::Mobile, 80, "APPLE WATCH"))
    } else {
        None
    }
}

/// Wallbox chargers name themselves `WB` + 6 digits.
pub fn is_wallbox_name(s: &str) -> bool {
    let b = s.trim().as_bytes();
    b.len() == 8
        && (b[0] == b'W' || b[0] == b'w')
        && (b[1] == b'B' || b[1] == b'b')
        && digits_at(&b[2..], 6)
}

/// Chromecast / Google Cast `md` strings: `(kind, weight, wording, label)`.
pub fn cast_md(md: &str) -> Option<(K, u8, &'static str, Option<&'static str>)> {
    let l = md.to_lowercase();
    if l.contains("nest hub") {
        return Some((K::Media, 80, "NEST HUB", Some("SMART DISPLAY")));
    }
    if ["nest audio", "nest mini", "google home", "google nest"]
        .iter()
        .any(|k| l.contains(k))
    {
        return Some((K::Media, 90, "SMART SPEAKER", Some("SMART SPEAKER")));
    }
    if l.contains("chromecast") && l.contains("audio") {
        return Some((K::Media, 85, "CAST AUDIO", Some("AUDIO STREAMER")));
    }
    if l.contains("google tv") {
        return Some((K::Tv, 90, "GOOGLE TV", Some("GOOGLE TV")));
    }
    if l.contains("chromecast") {
        return Some((K::Tv, 90, "CHROMECAST", Some("STREAMER")));
    }
    if l.contains("shield") {
        return Some((K::Tv, 90, "SHIELD", Some("STREAMER")));
    }
    if l.contains("bravia") {
        return Some((K::Tv, 90, "BRAVIA", Some("ANDROID TV")));
    }
    if l.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|t| t == "tv")
    {
        return Some((K::Tv, 90, "TV", None));
    }
    None
}

pub type Hit = (K, u8, &'static str, Option<&'static str>);

fn push(v: &mut Vec<Hit>, h: Hit) {
    if let Some(x) = v.iter_mut().find(|x| x.0 == h.0) {
        if h.1 > x.1 {
            *x = h;
        }
    } else {
        v.push(h);
    }
}

const TV_WORDS: &[&str] = &[
    "webos",
    "bravia",
    "tizen",
    "androidtv",
    "googletv",
    "firetv",
    "fire-tv",
    "roku",
    "chromecast",
    "shield",
    "mibox",
    "mitv",
    "hisensetv",
    "vidaa",
    "appletv",
    "apple-tv",
];
const PHONE_WORDS: &[&str] = &[
    "iphone", "galaxy", "pixel", "redmi", "xiaomi", "oneplus", "huawei", "phone", "poco", "oppo",
    "realme",
];
const PRINTER_WORDS: &[&str] = &[
    "printer",
    "laserjet",
    "officejet",
    "deskjet",
    "epson",
    "brother",
    "canon",
    "mfc",
];
const CONSOLE_WORDS: &[&str] = &["playstation", "ps5", "ps4", "xbox", "nintendo", "steamdeck"];
const CAR_WORDS: &[&str] = &["tesla", "model3", "modely"];
const SPEAKER_WORDS: &[&str] = &[
    "homepod",
    "echo",
    "alexa",
    "sonos",
    "speaker",
    "nest-mini",
    "nesthub",
    "soundbar",
    "audio",
];
const COMPUTER_STRONG: &[&str] = &["macbook", "imac", "thinkpad"];
const COMPUTER_WORDS: &[&str] = &[
    "desktop",
    "laptop",
    "pc",
    "workstation",
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
];
const IOT_WORDS: &[&str] = &[
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
];

/// Name evidence for a hostname / friendly name / model string, one hit per kind (max weight).
/// The wording is a static string (matched keyword or pattern); the optional label is a sub-type.
pub fn host_label(s: &str) -> Vec<Hit> {
    let mut v: Vec<Hit> = Vec::new();
    let lower = s.trim().to_lowercase();
    if lower.is_empty() {
        return v;
    }
    let compact: String = lower
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    // Patterns.
    if compact.starts_with("lgwebostv") || lower.starts_with("[lg]") {
        push(&mut v, (K::Tv, 90, "WEBOS TV", Some("WEBOS TV")));
    }
    if is_wallbox_name(s) {
        push(
            &mut v,
            (K::Car, 60, "WALLBOX-STYLE NAME", Some("EV CHARGER")),
        );
    }
    if ["esp-", "esp_", "esp32-", "esp32_", "esp8266-", "esp8266_"]
        .iter()
        .any(|p| lower.starts_with(p))
    {
        push(&mut v, (K::Iot, 85, "ESP NAME", None));
    }
    if lower.starts_with("galaxy-") {
        push(&mut v, (K::Mobile, 75, "GALAXY NAME", None));
    }
    let android_hex = lower.strip_prefix("android").and_then(|r| {
        let r = r.strip_prefix(['-', '_']).unwrap_or(r);
        (r.len() >= 6 && r.chars().all(|c| c.is_ascii_hexdigit())).then_some(())
    });
    if android_hex.is_some() {
        push(&mut v, (K::Mobile, 40, "ANDROID DEFAULT NAME", None));
        push(&mut v, (K::Tv, 20, "ANDROID DEFAULT NAME", None));
    }

    // Keyword families.
    let tv_word = first(&lower, TV_WORDS);
    if let Some(k) = tv_word {
        push(&mut v, (K::Tv, 85, k, None));
    } else if has(&lower, "tv") {
        push(&mut v, (K::Tv, 65, "tv", None));
    }
    if tv_word.is_none() && android_hex.is_none() && has(&lower, "android") {
        push(&mut v, (K::Mobile, 45, "android", None));
        push(&mut v, (K::Tv, 15, "android", None));
    }
    if let Some(k) = first(&lower, PHONE_WORDS) {
        push(&mut v, (K::Mobile, 70, k, None));
    }
    if let Some(k) = first(&lower, &["ipad", "tablet", "tab"]) {
        push(&mut v, (K::Tablet, 70, k, None));
    }
    if let Some(k) = first(&lower, PRINTER_WORDS) {
        push(&mut v, (K::Printer, 75, k, None));
    }
    if let Some(k) = first(&lower, CONSOLE_WORDS) {
        push(&mut v, (K::Console, 80, k, None));
    }
    if let Some(k) = first(&lower, CAR_WORDS) {
        push(&mut v, (K::Car, 80, k, None));
    }
    if let Some(k) = first(&lower, SPEAKER_WORDS) {
        push(&mut v, (K::Media, 70, k, None));
    }
    if let Some(k) = first(&lower, COMPUTER_STRONG) {
        push(&mut v, (K::Computer, 80, k, None));
    } else if let Some(k) = first(&lower, COMPUTER_WORDS) {
        push(&mut v, (K::Computer, 55, k, None));
    }
    if let Some(k) = first(&lower, IOT_WORDS) {
        push(&mut v, (K::Iot, 55, k, None));
    }
    v
}

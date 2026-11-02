//! Brand -> product-line priors: what a vendor's OUI alone suggests.

use crate::scan::model::DeviceKind as K;
use crate::scan::vendor::pretty_vendor;

pub struct Line {
    pub brand: &'static str,
    pub priors: &'static [(K, u8)],
    pub note: &'static str,
}

const fn l(brand: &'static str, priors: &'static [(K, u8)], note: &'static str) -> Line {
    Line {
        brand,
        priors,
        note,
    }
}

const IOT70: &[(K, u8)] = &[(K::Iot, 70)];
const ROUTER45: &[(K, u8)] = &[(K::Router, 45)];
const PC55: &[(K, u8)] = &[(K::Computer, 55)];
const PHONE60: &[(K, u8)] = &[(K::Mobile, 60)];
const PRINT70: &[(K, u8)] = &[(K::Printer, 70)];
const TV65: &[(K, u8)] = &[(K::Tv, 65)];
const CONSOLE80: &[(K, u8)] = &[(K::Console, 80)];

static LINES: &[Line] = &[
    l(
        "TCT",
        &[(K::Mobile, 50), (K::Tablet, 20), (K::Tv, 15)],
        "TCL COMMUNICATION: ALCATEL/TCL PHONES",
    ),
    l("TCL", &[(K::Tv, 70)], "TCL KING: TV PANELS"),
    l("Hisense", &[(K::Tv, 65), (K::Mobile, 10)], ""),
    l("Vestel", &[(K::Tv, 70)], ""),
    l("Skyworth", TV65, ""),
    l("Changhong", TV65, ""),
    l("TP Vision", &[(K::Tv, 75)], "PHILIPS TV MAKER"),
    l("LG", &[(K::Tv, 55), (K::Mobile, 10)], ""),
    l(
        "Samsung",
        &[(K::Mobile, 40), (K::Tv, 35), (K::Tablet, 10)],
        "",
    ),
    l("Sony", &[(K::Tv, 50), (K::Media, 20), (K::Mobile, 15)], ""),
    l("PlayStation", &[(K::Console, 85)], ""),
    l("Roku", &[(K::Tv, 85)], "STREAMER"),
    l(
        "Amazon",
        &[(K::Media, 45), (K::Tv, 35), (K::Iot, 20), (K::Tablet, 15)],
        "",
    ),
    l(
        "Google",
        &[(K::Media, 50), (K::Mobile, 30), (K::Tv, 25)],
        "",
    ),
    l("Xiaomi", &[(K::Mobile, 45), (K::Iot, 30), (K::Tv, 20)], ""),
    l("Nvidia", &[(K::Computer, 40), (K::Tv, 30)], ""),
    l(
        "Apple",
        &[(K::Mobile, 35), (K::Computer, 30), (K::Tablet, 15)],
        "",
    ),
    l("Espressif", IOT70, ""),
    l("Tuya", IOT70, ""),
    l("Shelly", IOT70, ""),
    l("Sonoff", IOT70, ""),
    l("Signify", IOT70, ""),
    l("Philips Hue", IOT70, ""),
    l("Nest", IOT70, ""),
    l("Ring", IOT70, ""),
    l("Wyze", IOT70, ""),
    l("Ezviz", IOT70, ""),
    l("Hikvision", IOT70, ""),
    l("Reolink", IOT70, ""),
    l("iRobot", IOT70, ""),
    l("Ecovacs", IOT70, ""),
    l("Roborock", IOT70, ""),
    l("Meross", IOT70, ""),
    l("Yeelight", IOT70, ""),
    l("Withings", IOT70, ""),
    l("Dyson", IOT70, ""),
    l("BSH", IOT70, ""),
    l("AI-Link", &[(K::Iot, 55)], "WI-FI MODULE: APPLIANCES"),
    l("Bilian", &[(K::Iot, 45), (K::Tv, 15)], "WI-FI MODULE"),
    l("Newport Media", &[(K::Iot, 35)], "WI-FI/IOT SILICON"),
    l(
        "TP-Link",
        &[(K::Iot, 55), (K::Router, 25)],
        "TAPO/KASA OR EXTENDER",
    ),
    l("Netgear", ROUTER45, ""),
    l("ASUS", ROUTER45, ""),
    l("Ubiquiti", ROUTER45, ""),
    l("Starlink", ROUTER45, ""),
    l("AVM", ROUTER45, ""),
    l("Sagemcom", ROUTER45, ""),
    l("ZTE", ROUTER45, ""),
    l("Technicolor", ROUTER45, ""),
    l("MitraStar", ROUTER45, ""),
    l("Askey", ROUTER45, ""),
    l("Cisco", ROUTER45, ""),
    l("D-Link", ROUTER45, ""),
    l("Arris", ROUTER45, ""),
    l("Compal", ROUTER45, ""),
    l("Vodafone", ROUTER45, ""),
    l("Digi", ROUTER45, ""),
    l("Linksys", ROUTER45, ""),
    l("MikroTik", ROUTER45, ""),
    l("Brother", PRINT70, ""),
    l("Epson", PRINT70, ""),
    l("Dell", PC55, ""),
    l("Lenovo", PC55, ""),
    l("HP", PC55, ""),
    l("Intel", PC55, ""),
    l("Raspberry Pi", PC55, ""),
    l("Synology", PC55, ""),
    l("QNAP", PC55, ""),
    l("Realtek", PC55, ""),
    l("Microsoft", PC55, ""),
    l("Huawei", PHONE60, ""),
    l("OnePlus", PHONE60, ""),
    l("Oppo", PHONE60, ""),
    l("Vivo", PHONE60, ""),
    l("Realme", PHONE60, ""),
    l("Honor", PHONE60, ""),
    l("Motorola", PHONE60, ""),
    l("Nothing", PHONE60, ""),
    l("Garmin", &[(K::Mobile, 55)], "WEARABLE"),
    l("Fitbit", &[(K::Mobile, 55)], "WEARABLE"),
    l("Amazfit", &[(K::Mobile, 55)], "WEARABLE"),
    l("Nintendo", CONSOLE80, ""),
    l("Valve", CONSOLE80, ""),
    l("Tesla", &[(K::Car, 80)], ""),
    l("Sonos", &[(K::Media, 85)], ""),
];

/// Product-line priors for a vendor (raw IEEE name or already-pretty brand).
pub fn line(vendor: &str) -> Option<&'static Line> {
    let find = |v: &str| LINES.iter().find(|x| x.brand.eq_ignore_ascii_case(v));
    let v = vendor.trim();
    if v.is_empty() {
        return None;
    }
    find(v).or_else(|| find(&pretty_vendor(v)))
}

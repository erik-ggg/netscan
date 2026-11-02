//! Vendor-name normalisation: IEEE registry names -> short brand names.

/// (lowercase leading words, brand). A rule matches when the cleaned name
/// equals the needle or starts with it followed by a space.
const BRANDS: &[(&str, &str)] = &[
    ("tp-link", "TP-Link"),
    ("tp link", "TP-Link"),
    ("tibro", "Starlink"),
    ("space exploration", "Starlink"),
    ("apple", "Apple"),
    ("samsung", "Samsung"),
    ("espressif", "Espressif"),
    ("amazon", "Amazon"),
    ("google", "Google"),
    ("lg electronics", "LG"),
    ("lg innotek", "LG"),
    ("sony interactive", "PlayStation"),
    ("sony", "Sony"),
    ("hon hai", "Foxconn"),
    ("foxconn", "Foxconn"),
    ("xiaomi", "Xiaomi"),
    ("raspberry pi", "Raspberry Pi"),
    ("intel", "Intel"),
    ("realtek", "Realtek"),
    ("microsoft", "Microsoft"),
    ("dell", "Dell"),
    ("lenovo", "Lenovo"),
    ("hewlett packard", "HP"),
    ("hp", "HP"),
    ("huawei", "Huawei"),
    ("honor device", "Honor"),
    ("oneplus", "OnePlus"),
    ("guangdong oppo", "Oppo"),
    ("oppo", "Oppo"),
    ("vivo", "Vivo"),
    ("realme", "Realme"),
    ("motorola", "Motorola"),
    ("nintendo", "Nintendo"),
    ("valve", "Valve"),
    ("tesla", "Tesla"),
    ("sonos", "Sonos"),
    ("roku", "Roku"),
    ("brother", "Brother"),
    ("canon", "Canon"),
    ("seiko epson", "Epson"),
    ("epson", "Epson"),
    ("signify", "Signify"),
    ("philips lighting", "Signify"),
    ("murata", "Murata"),
    ("liteon", "Liteon"),
    ("lite-on", "Liteon"),
    ("azurewave", "AzureWave"),
    ("universal global scientific", "USI"),
    ("sagemcom", "Sagemcom"),
    ("askey", "Askey"),
    ("mitrastar", "MitraStar"),
    ("ubiquiti", "Ubiquiti"),
    ("netgear", "Netgear"),
    ("asustek", "ASUS"),
    ("asus", "ASUS"),
    ("avm", "AVM"),
    ("zte", "ZTE"),
    ("technicolor", "Technicolor"),
    ("cisco", "Cisco"),
    ("d-link", "D-Link"),
    ("arris", "Arris"),
    ("compal", "Compal"),
    ("vodafone", "Vodafone"),
    ("synology", "Synology"),
    ("qnap", "QNAP"),
    ("nvidia", "Nvidia"),
    ("shelly", "Shelly"),
    ("allterco", "Shelly"),
    ("tuya", "Tuya"),
    ("hangzhou ezviz", "Ezviz"),
    ("hikvision", "Hikvision"),
    ("hangzhou hikvision", "Hikvision"),
    ("reolink", "Reolink"),
    ("irobot", "iRobot"),
    ("roborock", "Roborock"),
    ("ecovacs", "Ecovacs"),
    ("withings", "Withings"),
    ("garmin", "Garmin"),
    ("fitbit", "Fitbit"),
    ("bose", "Bose"),
    ("hisense", "Hisense"),
    ("tcl", "TCL"),
    ("tct mobile", "TCT"),
    ("bilian", "Bilian"),
    ("itead", "Sonoff"),
    ("sichuan ai-link", "AI-Link"),
    ("ai-link", "AI-Link"),
    ("belkin", "Belkin"),
    ("linksys", "Linksys"),
    ("mikrotik", "MikroTik"),
    ("hui zhou gaoshengda", "Gaoshengda"),
    ("tp vision", "TP Vision"),
    ("vestel", "Vestel"),
    ("skyworth", "Skyworth"),
    ("changhong", "Changhong"),
    ("newport media", "Newport Media"),
];

/// Trailing corporate words dropped one at a time (after punctuation removal).
const SUFFIXES: &[&str] = &[
    "inc",
    "corp",
    "corporation",
    "corporate",
    "co",
    "ltd",
    "limited",
    "llc",
    "gmbh",
    "sa",
    "ag",
    "bv",
    "nv",
    "oy",
    "ab",
    "as",
    "plc",
    "pte",
    "pty",
    "sas",
    "srl",
    "spa",
    "kg",
    "kk",
    "lp",
    "company",
    "holdings",
    "group",
    "technologies",
    "technology",
    "tech",
    "systems",
    "system",
    "electronics",
    "electronic",
    "electric",
    "international",
    "intl",
    "communication",
    "communications",
    "industries",
    "industrial",
    "manufacturing",
    "semiconductor",
    "computer",
    "networks",
    "network",
    "devices",
    "digital",
    "mobile",
    "wireless",
    "telecom",
    "broadband",
    "multimedia",
    "intelligent",
    "products",
    "enterprise",
    "enterprises",
    "trading",
    "of",
];

const PREFIXES: &[&str] = &[
    "shenzhen",
    "beijing",
    "guangdong",
    "hangzhou",
    "shanghai",
    "dongguan",
    "zhejiang",
    "xiamen",
    "sichuan",
    "chengdu",
    "nanjing",
    "hong",
    "kong",
];

fn clean_words(raw: &str) -> Vec<String> {
    raw.replace(['.', ',', '，'], " ")
        .split_whitespace()
        .map(|w| w.trim_matches(['(', ')']).to_string())
        .filter(|w| !w.is_empty())
        .collect()
}

/// Short, display-friendly vendor name.
pub fn pretty_vendor(raw: &str) -> String {
    let words = clean_words(raw);
    if words.is_empty() {
        return String::new();
    }
    let lower = words
        .iter()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    for (needle, brand) in BRANDS {
        if lower == *needle
            || lower
                .strip_prefix(needle)
                .is_some_and(|r| r.starts_with(' '))
        {
            return (*brand).to_string();
        }
    }
    let mut words = words;
    while words.len() > 1 && PREFIXES.contains(&words[0].to_lowercase().as_str()) {
        words.remove(0);
    }
    // Drop trailing corporate words, keeping at least one word.
    while words.len() > 1 && SUFFIXES.contains(&words[words.len() - 1].to_lowercase().as_str()) {
        words.pop();
    }
    // A brand rule may now match the trimmed name (e.g. after dropping "Shenzhen").
    let lower = words
        .iter()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    for (needle, brand) in BRANDS {
        if lower == *needle
            || lower
                .strip_prefix(needle)
                .is_some_and(|r| r.starts_with(' '))
        {
            return (*brand).to_string();
        }
    }
    words.iter().map(|w| title(w)).collect::<Vec<_>>().join(" ")
}

/// Title-case SHOUTING words longer than 4 letters; keep short acronyms and mixed case.
fn title(w: &str) -> String {
    let letters = w.chars().filter(|c| c.is_alphabetic()).count();
    if letters > 4 && w.chars().all(|c| !c.is_lowercase()) {
        let mut cs = w.chars();
        let first = cs
            .next()
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_default();
        format!("{first}{}", cs.as_str().to_lowercase())
    } else {
        w.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::pretty_vendor as p;

    #[test]
    fn brands() {
        assert_eq!(p("TP-LINK SYSTEMS INC"), "TP-Link");
        assert_eq!(p("Apple Inc."), "Apple");
        assert_eq!(p("Samsung Electronics Co Ltd"), "Samsung");
        assert_eq!(p("Amazon Technologies Inc."), "Amazon");
        assert_eq!(p("LG Electronics (Mobile Communications)"), "LG");
        assert_eq!(p("Sony Interactive Entertainment Inc."), "PlayStation");
        assert_eq!(p("Hon Hai Precision Ind. Co.,Ltd."), "Foxconn");
        assert_eq!(p("Beijing Xiaomi Mobile Software Co Ltd"), "Xiaomi");
        assert_eq!(p("Raspberry Pi Trading Ltd"), "Raspberry Pi");
        assert_eq!(p("Space Exploration Technologies Corporation"), "Starlink");
        assert_eq!(p("Intelbras"), "Intelbras");
        assert_eq!(p("HP Inc."), "HP");
    }

    #[test]
    fn generic_cleanup() {
        assert_eq!(p("Foo Bar Technologies Co., Ltd."), "Foo Bar");
        assert_eq!(p("SHENZHEN BILIAN ELECTRONIC CO.,LTD"), "Bilian");
        assert_eq!(p("Bilian Electronic CO ，LTD"), "Bilian");
        assert_eq!(p("Sichuan AI-Link Technology Co., Ltd."), "AI-Link");
        assert_eq!(p("Systems"), "Systems");
    }
}

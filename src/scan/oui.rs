//! Vendor lookup from the IEEE MA-L registry (`assets/oui.csv`, `prefix,vendor`).

use std::sync::LazyLock;

static TABLE: LazyLock<Vec<(u32, &'static str)>> = LazyLock::new(|| {
    let mut v: Vec<(u32, &str)> = include_str!("../../assets/oui.csv")
        .lines()
        .filter_map(|l| {
            let (p, v) = l.split_once(',')?;
            Some((u32::from_str_radix(p, 16).ok()?, v))
        })
        .collect();
    v.sort_unstable_by_key(|e| e.0);
    v
});

/// Display-ready vendor for a `aa:bb:cc:dd:ee:ff` MAC. `None` for randomized or unknown prefixes.
pub fn lookup(mac: &str) -> Option<String> {
    if super::arp::is_randomized(mac) {
        return None;
    }
    let p = u32::from_str_radix(&mac.get(..8)?.replace(':', ""), 16).ok()?;
    let i = TABLE.binary_search_by_key(&p, |e| e.0).ok()?;
    Some(super::vendor::pretty_vendor(TABLE[i].1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_prefixes() {
        assert_eq!(lookup("3c:22:fb:00:11:22").as_deref(), Some("Apple"));
        assert_eq!(lookup("b8:27:eb:00:00:01").as_deref(), Some("Raspberry Pi"));
        assert_eq!(lookup("74:24:9f:00:00:01").as_deref(), Some("Starlink"));
    }

    #[test]
    fn randomized_and_unknown() {
        assert_eq!(lookup("3e:22:fb:00:11:22"), None); // locally administered
        assert_eq!(lookup("fc:ff:fe:00:00:00"), None);
    }
}

//! cleanyourtv presets (https://github.com/Gathin23/cleanyourtv, MIT).
//! Presets are only ever TYPED into the terminal; the user presses Enter.

pub struct Preset {
    pub id: &'static str,
    pub step: &'static str,
    pub title: &'static str,
    pub jp: &'static str,
    pub text: String,
    /// Needs a confirmation modal before the text is typed.
    pub destructive: bool,
    /// Subset of `git`, `python3`, `repo`, `venv`.
    pub needs: &'static [&'static str],
}

/// Whitelisted `examples/` folder slugs; the only vendor-derived text allowed in a command.
const SLUGS: &[(&str, &str)] = &[
    ("tcl", "tcl"),
    ("sony", "sony"),
    ("xiaomi", "xiaomi"),
    ("philips", "philips"),
    ("tp vision", "philips"),
    ("skyworth", "skyworth"),
    ("hisense", "hisense"),
    ("sharp", "sharp"),
    ("amazon", "amazon"),
    ("panasonic", "panasonic"),
    ("nvidia", "nvidia"),
    ("google", "google"),
    ("onn", "onn"),
    ("toshiba", "toshiba"),
];

pub fn brand_slug(vendor: &str) -> Option<&'static str> {
    let v = vendor.to_lowercase();
    SLUGS
        .iter()
        .find(|(k, _)| {
            if *k == "onn" {
                v == "onn"
            } else {
                v.contains(k)
            }
        })
        .map(|(_, s)| *s)
}

pub fn presets(brand: Option<&'static str>) -> Vec<Preset> {
    let find = match brand {
        Some(s) => format!("ls examples | grep -i -- '{s}'"),
        None => "ls examples".to_string(),
    };
    let p = |id, step, title, jp, text: &str, destructive, needs| Preset {
        id,
        step,
        title,
        jp,
        text: text.to_string(),
        destructive,
        needs,
    };
    vec![
        p(
            "acquire",
            "01",
            "ACQUIRE",
            "取得",
            "mkdir -p \"$NETSCAN_DATA\" && { git -C \"$NETSCAN_DATA/cleanyourtv\" pull --ff-only 2>/dev/null || git clone --depth 1 https://github.com/Gathin23/cleanyourtv \"$NETSCAN_DATA/cleanyourtv\"; } && cd \"$NETSCAN_DATA/cleanyourtv\"",
            false,
            &["git"],
        ),
        p(
            "arm",
            "02",
            "ARM",
            "準備",
            "python3 -m venv tools/venv && tools/venv/bin/pip install -r tools/requirements.txt",
            false,
            &["python3", "repo"],
        ),
        p(
            "probe",
            "03",
            "PROBE",
            "探査",
            "tools/venv/bin/python -I tools/tv.py --probe",
            false,
            &["repo", "venv"],
        ),
        p(
            "backup",
            "04",
            "BACKUP",
            "保存",
            "mkdir -p backups && tools/venv/bin/python -I tools/tv.py 'pm list packages -f' > \"backups/$TV_HOST-$(date +%Y%m%d-%H%M).txt\" && echo saved",
            false,
            &["repo", "venv"],
        ),
        p("find", "05", "FIND LIST", "検索", &find, false, &["repo"]),
        p(
            "purge",
            "06",
            "PURGE",
            "除去",
            "tools/disable.sh examples/",
            true,
            &["repo", "venv"],
        ),
        p(
            "restore",
            "07",
            "RESTORE",
            "復元",
            "tools/restore.sh examples/",
            false,
            &["repo", "venv"],
        ),
        p(
            "verify",
            "08",
            "VERIFY",
            "照合",
            "tools/venv/bin/python -I tools/check.py examples/",
            false,
            &["repo", "venv"],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_whitelisted() {
        assert_eq!(brand_slug("TCL"), Some("tcl"));
        assert_eq!(brand_slug("Sony Corporation"), Some("sony"));
        assert_eq!(brand_slug("TP Vision"), Some("philips"));
        assert_eq!(brand_slug("LG"), None);
        assert_eq!(brand_slug("x'; rm -rf ~ #"), None);
    }

    #[test]
    fn only_purge_is_destructive_and_text_is_safe() {
        let v = presets(Some("tcl"));
        assert_eq!(v.len(), 8);
        let d: Vec<_> = v.iter().filter(|p| p.destructive).map(|p| p.id).collect();
        assert_eq!(d, vec!["purge"]);
        assert_eq!(v[4].text, "ls examples | grep -i -- 'tcl'");
        assert_eq!(presets(None)[4].text, "ls examples");
        for p in &v {
            assert!(!p.text.contains('\n') && !p.text.contains('\r'), "{}", p.id);
        }
        assert_eq!(v[5].text, "tools/disable.sh examples/");
        assert!(v[0].text.starts_with("mkdir -p \"$NETSCAN_DATA\""));
    }
}

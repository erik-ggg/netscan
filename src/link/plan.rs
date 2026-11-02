//! Which ways of linking to a device make sense, and whether they are ready.

use super::tools::Tools;
use super::{LinkRequest, Proto};
use crate::scan::model::{Device, DeviceIntel, DeviceKind, PortState};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq)]
pub enum Readiness {
    Ready,
    NeedsTool {
        tool: &'static str,
        install: &'static str,
    },
    NeedsDeviceSetup {
        steps: Vec<&'static str>,
    },
    Unlikely,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinkPlan {
    pub proto: Proto,
    pub title: String,
    pub why: String,
    /// ADB connect port / SSH port.
    pub port: Option<u16>,
    pub readiness: Readiness,
    pub rank: u8,
    /// Default SSH user.
    pub user: Option<&'static str>,
    pub legacy_rsa: bool,
    /// ADB pairing port advertised over mDNS.
    pub pair_port: Option<u16>,
}

const ADB_INSTALL: &str = "brew install --cask android-platform-tools";

fn plan(
    proto: Proto,
    title: &str,
    why: &str,
    port: Option<u16>,
    readiness: Readiness,
    rank: u8,
) -> LinkPlan {
    LinkPlan {
        proto,
        title: title.into(),
        why: why.into(),
        port,
        readiness,
        rank,
        user: None,
        legacy_rsa: false,
        pair_port: None,
    }
}

fn open_ports(d: &Device, i: Option<&DeviceIntel>) -> BTreeSet<u16> {
    let mut s: BTreeSet<u16> = d
        .beacon
        .as_ref()
        .map(|b| b.open.iter().copied().collect())
        .unwrap_or_default();
    if let Some(i) = i {
        s.extend(
            i.ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .map(|p| p.port),
        );
    }
    s
}

fn has_service(d: &Device, prefix: &str) -> bool {
    d.services.iter().any(|s| s.starts_with(prefix))
}

pub fn plans(d: &Device, i: Option<&DeviceIntel>, t: &Tools) -> Vec<LinkPlan> {
    let local = plan(
        Proto::Local,
        "LOCAL",
        "LOCAL SHELL WITH $TV_HOST SET",
        None,
        Readiness::Ready,
        10,
    );
    if d.is_self {
        return vec![local];
    }
    let open = open_ports(d, i);
    let class = i.and_then(|i| i.class.as_ref()).or(d.class.as_ref());
    let kind = class.map(|c| c.kind).unwrap_or(d.kind);
    let label = class
        .and_then(|c| c.label.as_deref())
        .unwrap_or("")
        .to_uppercase();
    let vendor = d.vendor.as_deref().unwrap_or("").to_lowercase();
    let adb_ready = |ready_ok: bool| {
        if t.adb.is_some() || !ready_ok {
            Readiness::Ready
        } else {
            Readiness::NeedsTool {
                tool: "adb",
                install: ADB_INSTALL,
            }
        }
    };
    let mut v: Vec<LinkPlan> = Vec::new();

    if open.contains(&5555) {
        v.push(plan(
            Proto::Adb,
            "ADB",
            "5555/TCP ADB ANSWERING",
            Some(5555),
            adb_ready(true),
            90,
        ));
    }
    if let Some(&cp) = d.svc_ports.get("_adb-tls-connect") {
        let mut p = plan(
            Proto::AdbPair,
            "PAIR",
            "WIRELESS DEBUGGING ADVERTISED OVER MDNS",
            Some(cp),
            adb_ready(true),
            85,
        );
        p.pair_port = d.svc_ports.get("_adb-tls-pairing").copied();
        v.push(p);
    }
    let androidish = label.contains("ANDROID")
        || label.contains("GOOGLE TV")
        || has_service(d, "_androidtvremote")
        || open.contains(&6466)
        || ((has_service(d, "_googlecast") || open.contains(&8009)) && kind == DeviceKind::Tv);
    if androidish
        && !v
            .iter()
            .any(|p| matches!(p.proto, Proto::Adb | Proto::AdbPair))
    {
        v.push(plan(
            Proto::Adb,
            "ADB",
            "ANDROID-STYLE DEVICE // DEBUGGING NOT EXPOSED",
            Some(5555),
            Readiness::NeedsDeviceSetup {
                steps: vec![
                    "SETTINGS > DEVICE PREFERENCES > ABOUT > BUILD x7",
                    "DEVELOPER OPTIONS > USB DEBUGGING ON (+ NETWORK/ADB DEBUGGING IF SHOWN)",
                    "OR WIRELESS DEBUGGING > PAIR WITH CODE",
                ],
            },
            60,
        ));
    }

    // Wallbox chargers run dropbear with legacy host keys even before a banner is read.
    let banner_dropbear = label == "EV CHARGER"
        || i.is_some_and(|i| {
            i.banners
                .iter()
                .any(|b| b.text.to_lowercase().contains("dropbear"))
        });
    if open.contains(&22) || has_service(d, "_ssh") {
        let ready = if t.ssh.is_some() || t.shell.as_os_str().is_empty() {
            Readiness::Ready
        } else {
            Readiness::NeedsTool {
                tool: "ssh",
                install: "xcode-select --install",
            }
        };
        let mut p = plan(
            Proto::Ssh,
            "SSH",
            if banner_dropbear {
                "DROPBEAR > LEGACY KEYS LIKELY"
            } else {
                "SSH ANSWERING"
            },
            Some(22),
            ready,
            70,
        );
        if banner_dropbear {
            p.user = Some("root");
            p.legacy_rsa = true;
        }
        v.push(p);
    }
    let webos = label.contains("WEBOS") || vendor.starts_with("lg");
    if open.contains(&9922) {
        let mut p = plan(
            Proto::Ssh,
            "SSH",
            "WEBOS DEVELOPER MODE (KEY FROM DEV MODE APP)",
            Some(9922),
            Readiness::Ready,
            65,
        );
        p.user = Some("prisoner");
        v.push(p);
    } else if webos && kind == DeviceKind::Tv {
        v.push(plan(
            Proto::Ssh,
            "SSH",
            "WEBOS EXPOSES NO SHELL // SSAP CONTROL = FUTURE",
            Some(9922),
            Readiness::Unlikely,
            20,
        ));
    }
    if label.contains("TIZEN") || (vendor.contains("samsung") && kind == DeviceKind::Tv) {
        v.push(plan(
            Proto::Adb,
            "SDB",
            "TIZEN: SDB 26101 ONLY IN DEVELOPER MODE",
            Some(26101),
            Readiness::Unlikely,
            20,
        ));
    }

    v.sort_by_key(|p| std::cmp::Reverse(p.rank));
    v.push(local);
    v
}

/// Default request for a plan (user/port/legacy prefilled; pairing code left empty).
pub fn request_for(ip: Ipv4Addr, p: &LinkPlan) -> LinkRequest {
    let mut r = LinkRequest::new(ip, p.proto);
    match p.proto {
        Proto::Ssh => {
            r.ssh_port = p.port.unwrap_or(22);
            r.ssh_user = p.user.map(str::to_string);
            r.legacy_rsa = p.legacy_rsa;
        }
        Proto::Adb => r.adb_port = p.port.unwrap_or(5555),
        Proto::AdbPair => {
            r.adb_port = p.port.unwrap_or(5555);
            r.pair = p.pair_port.map(|pp| (pp, String::new()));
        }
        Proto::Local => {}
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::model::{Banner, Beacon, Classification, PortInfo};
    use std::path::PathBuf;

    fn tools(adb: bool) -> Tools {
        Tools {
            adb: adb.then(|| PathBuf::from("/opt/homebrew/bin/adb")),
            ssh: Some(PathBuf::from("/usr/bin/ssh")),
            shell: PathBuf::from("/bin/zsh"),
            ..Default::default()
        }
    }

    #[test]
    fn wallbox_dropbear_ssh_first() {
        let d = Device {
            ip: "192.168.1.194".into(),
            services: vec!["_ssh._tcp".into(), "_sftp-ssh._tcp".into()],
            kind: DeviceKind::Car,
            ..Default::default()
        };
        // no banner and no label: plain SSH, no legacy assumption
        assert!(!plans(&d, None, &tools(false))[0].legacy_rsa);
        let i = DeviceIntel {
            ports: vec![PortInfo {
                port: 22,
                state: PortState::Open,
                ..Default::default()
            }],
            banners: vec![Banner {
                port: 22,
                proto: "SSH".into(),
                text: "SSH-2.0-dropbear_2018.76".into(),
            }],
            ..Default::default()
        };
        let p = plans(&d, Some(&i), &tools(false));
        assert_eq!(p[0].proto, Proto::Ssh);
        assert_eq!(p[0].user, Some("root"));
        assert!(p[0].legacy_rsa);
        assert_eq!(p[0].readiness, Readiness::Ready);
        assert_eq!(p.last().unwrap().proto, Proto::Local);
        let r = request_for("192.168.1.194".parse().unwrap(), &p[0]);
        assert_eq!(r.ssh_user.as_deref(), Some("root"));
        assert!(r.legacy_rsa);
    }

    #[test]
    fn android_tv_needs_adb() {
        let d = Device {
            ip: "192.168.1.47".into(),
            kind: DeviceKind::Tv,
            beacon: Some(Beacon {
                open: vec![5555, 8009, 6466],
                ..Default::default()
            }),
            ..Default::default()
        };
        let p = plans(&d, None, &tools(false));
        assert_eq!(p[0].proto, Proto::Adb);
        assert_eq!(p[0].port, Some(5555));
        assert_eq!(
            p[0].readiness,
            Readiness::NeedsTool {
                tool: "adb",
                install: "brew install --cask android-platform-tools"
            }
        );
        assert_eq!(plans(&d, None, &tools(true))[0].readiness, Readiness::Ready);
    }

    #[test]
    fn android_without_5555_needs_setup_and_pair_from_mdns() {
        let mut d = Device {
            ip: "192.168.1.47".into(),
            kind: DeviceKind::Tv,
            services: vec!["_androidtvremote2._tcp".into()],
            ..Default::default()
        };
        let p = plans(&d, None, &tools(true));
        assert!(matches!(p[0].readiness, Readiness::NeedsDeviceSetup { .. }));
        d.svc_ports.insert("_adb-tls-connect".into(), 37151);
        d.svc_ports.insert("_adb-tls-pairing".into(), 41235);
        let p = plans(&d, None, &tools(true));
        assert_eq!(p[0].proto, Proto::AdbPair);
        assert_eq!(p[0].port, Some(37151));
        assert_eq!(p[0].pair_port, Some(41235));
        assert_eq!(p.iter().filter(|x| x.proto == Proto::Adb).count(), 0);
    }

    #[test]
    fn lg_without_9922_is_unlikely_with_9922_is_ssh() {
        let mut d = Device {
            ip: "192.168.1.32".into(),
            vendor: Some("LG".into()),
            kind: DeviceKind::Tv,
            class: Some(Classification {
                kind: DeviceKind::Tv,
                label: Some("WEBOS TV".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let p = plans(&d, None, &tools(true));
        assert_eq!(p[0].readiness, Readiness::Unlikely);
        assert!(p[0].why.contains("WEBOS"));
        assert_eq!(p.len(), 2);
        d.beacon = Some(Beacon {
            open: vec![9922],
            ..Default::default()
        });
        let p = plans(&d, None, &tools(true));
        assert_eq!(p[0].proto, Proto::Ssh);
        assert_eq!(p[0].port, Some(9922));
        assert_eq!(p[0].user, Some("prisoner"));
        assert_eq!(p[0].readiness, Readiness::Ready);
    }

    #[test]
    fn self_is_local_only() {
        let d = Device {
            ip: "192.168.1.114".into(),
            is_self: true,
            services: vec!["_ssh._tcp".into()],
            ..Default::default()
        };
        let p = plans(&d, None, &tools(true));
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].proto, Proto::Local);
    }
}

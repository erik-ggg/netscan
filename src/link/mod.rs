//! Neural link backend: connection requests, validation, shell bootstrap, PTY.
//!
//! Security rule: commands are assembled only from validated values (in-subnet
//! IP, numeric ports, regex-checked user, six-digit code). Device-provided
//! strings (hostnames, models, banners) never reach a command line.

pub mod payload;
pub mod plan;
pub mod pty;
pub mod status;
pub mod tools;

use crate::scan::model::NetworkInfo;
use crate::scan::net::in_subnet;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use tools::Tools;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Proto {
    Adb,
    AdbPair,
    Ssh,
    Local,
}

#[derive(Clone, PartialEq, Debug)]
pub struct LinkRequest {
    pub ip: Ipv4Addr,
    pub proto: Proto,
    pub ssh_user: Option<String>,
    pub ssh_port: u16,
    pub legacy_rsa: bool,
    /// 5555, or the wireless-debugging connect port.
    pub adb_port: u16,
    /// (pair port, six-digit code)
    pub pair: Option<(u16, String)>,
}

impl LinkRequest {
    pub fn new(ip: Ipv4Addr, proto: Proto) -> Self {
        Self {
            ip,
            proto,
            ssh_user: None,
            ssh_port: 22,
            legacy_rsa: false,
            adb_port: 5555,
            pair: None,
        }
    }
}

fn valid_user(u: &str) -> bool {
    let b = u.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.' | b'-')
        })
}

/// Checks a request against the scanned network. Returns it unchanged when safe.
pub fn validate(r: LinkRequest, net: &NetworkInfo) -> Result<LinkRequest> {
    if !in_subnet(net, r.ip) {
        bail!("target {} is outside {}", r.ip, net.subnet_cidr);
    }
    if r.ip.is_loopback() || r.ip.is_multicast() || r.ip.is_unspecified() {
        bail!("target {} is not a unicast LAN address", r.ip);
    }
    if r.ssh_port == 0 || r.adb_port == 0 {
        bail!("port must be 1..=65535");
    }
    if r.ssh_user.as_deref().is_some_and(|u| !valid_user(u)) {
        bail!("invalid ssh user");
    }
    if r.proto == Proto::AdbPair {
        match &r.pair {
            Some((p, code)) => {
                if *p == 0 {
                    bail!("pairing port must be 1..=65535");
                }
                if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) {
                    bail!("pairing code must be exactly 6 digits");
                }
            }
            None => bail!("pairing requires a port and a 6-digit code"),
        }
    }
    Ok(r)
}

#[derive(Clone, PartialEq, Debug)]
pub struct SpawnSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    /// First line typed into the PTY (a `\r` is appended by `pty::spawn`).
    pub typed: Option<String>,
}

pub fn data_dir() -> PathBuf {
    tools::home().join("Library/Application Support/netscan")
}

/// The command line typed for a request. Only call with a validated request.
pub fn typed_line(r: &LinkRequest) -> Option<String> {
    let ip = r.ip;
    match r.proto {
        Proto::Adb => {
            let t = format!("{ip}:{}", r.adb_port);
            Some(format!("adb connect {t} && adb -s {t} shell"))
        }
        Proto::AdbPair => {
            let (pp, code) = r.pair.clone().unwrap_or((0, String::new()));
            let t = format!("{ip}:{}", r.adb_port);
            Some(format!(
                "adb pair {ip}:{pp} {code} && adb connect {t} && adb -s {t} shell"
            ))
        }
        Proto::Ssh => {
            let mut s = String::from("ssh -o ConnectTimeout=8 -o ServerAliveInterval=15");
            if r.ssh_port != 22 {
                s.push_str(&format!(" -p {}", r.ssh_port));
            }
            if r.legacy_rsa {
                s.push_str(" -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa");
            }
            match &r.ssh_user {
                Some(u) => s.push_str(&format!(" {u}@{ip}")),
                None => s.push_str(&format!(" {ip}")),
            }
            Some(s)
        }
        Proto::Local => None,
    }
}

/// The user's interactive shell (so rc files / PATH apply). For a remote link the
/// command runs *as* the session (`shell -i -c`), echoed first so it stays visible:
/// when ssh/adb ends the PTY exits and the UI shows LINK DROPPED, instead of
/// silently falling back to a local prompt that looks like a successful link.
pub fn bootstrap(r: &LinkRequest, t: &Tools) -> SpawnSpec {
    let ip = r.ip;
    let home = tools::home();
    let shell = if t.shell.as_os_str().is_empty() {
        PathBuf::from("/bin/zsh")
    } else {
        t.shell.clone()
    };
    let mut path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    for d in tools::extra_dirs() {
        if !path.contains(&d) {
            path.push(d);
        }
    }
    let path = std::env::join_paths(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let lang = std::env::var("LANG")
        .ok()
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "en_US.UTF-8".into());
    let mut env = vec![
        ("TERM".to_string(), "xterm-256color".to_string()),
        ("COLORTERM".to_string(), "truecolor".to_string()),
        ("LANG".to_string(), lang),
        ("NETSCAN_TARGET".to_string(), ip.to_string()),
        ("TV_HOST".to_string(), ip.to_string()),
        (
            "NETSCAN_DATA".to_string(),
            data_dir().to_string_lossy().into_owned(),
        ),
        ("PATH".to_string(), path),
    ];
    if matches!(r.proto, Proto::Adb | Proto::AdbPair) {
        env.push(("ANDROID_SERIAL".to_string(), format!("{ip}:{}", r.adb_port)));
    }
    let args = match typed_line(r) {
        // Validated request only: IP, ports, user and pair code are checked, and the
        // line never contains a single quote, so quoting it for the echo is safe.
        Some(t) => vec![
            "-i".to_string(),
            "-c".to_string(),
            format!("printf '%s\\n' '$ {t}'; {t}"),
        ],
        None => vec!["-i".to_string()],
    };
    SpawnSpec {
        program: shell,
        args,
        env,
        cwd: home,
        typed: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn netinfo() -> NetworkInfo {
        NetworkInfo {
            interface: "en0".into(),
            local_ip: "192.168.1.114".into(),
            local_mac: None,
            prefix: 24,
            netmask: "255.255.255.0".into(),
            gateway_ip: Some("192.168.1.1".into()),
            gateway_mac: None,
            subnet_cidr: "192.168.1.0/24".into(),
        }
    }

    fn req(proto: Proto) -> LinkRequest {
        LinkRequest::new("192.168.1.194".parse().unwrap(), proto)
    }

    #[test]
    fn validate_rejects_bad_input() {
        let n = netinfo();
        assert!(validate(req(Proto::Ssh), &n).is_ok());
        let mut r = req(Proto::Ssh);
        r.ip = "10.0.0.5".parse().unwrap();
        assert!(validate(r, &n).is_err(), "out of subnet");
        for bad in [
            "Root",
            "ro ot",
            "a;b",
            "$(id)",
            "",
            "-x",
            "a".repeat(33).as_str(),
        ] {
            let mut r = req(Proto::Ssh);
            r.ssh_user = Some(bad.into());
            assert!(validate(r, &n).is_err(), "user {bad:?}");
        }
        for ok in ["root", "_svc", "pi.2-x", "prisoner"] {
            let mut r = req(Proto::Ssh);
            r.ssh_user = Some(ok.into());
            assert!(validate(r, &n).is_ok(), "user {ok:?}");
        }
        for bad in ["12345", "1234567", "12a456", "", " 12345"] {
            let mut r = req(Proto::AdbPair);
            r.pair = Some((41235, bad.into()));
            assert!(validate(r, &n).is_err(), "code {bad:?}");
        }
        let mut r = req(Proto::AdbPair);
        assert!(validate(r.clone(), &n).is_err(), "missing pair");
        r.pair = Some((41235, "123456".into()));
        assert!(validate(r, &n).is_ok());
        let mut r = req(Proto::Adb);
        r.adb_port = 0;
        assert!(validate(r, &n).is_err());
    }

    #[test]
    fn bootstrap_golden() {
        let t = Tools {
            shell: PathBuf::from("/bin/zsh"),
            ..Default::default()
        };
        let mut r = req(Proto::Adb);
        r.ip = "192.168.1.32".parse().unwrap();
        let s = bootstrap(&r, &t);
        assert_eq!(s.program, PathBuf::from("/bin/zsh"));
        assert_eq!(s.args[..2], ["-i", "-c"]);
        assert!(s.args[2].ends_with("; adb connect 192.168.1.32:5555 && adb -s 192.168.1.32:5555 shell"));
        assert_eq!(s.typed, None);
        assert_eq!(
            typed_line(&r).as_deref(),
            Some("adb connect 192.168.1.32:5555 && adb -s 192.168.1.32:5555 shell")
        );
        let env = |k: &str| s.env.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
        assert_eq!(env("TV_HOST").as_deref(), Some("192.168.1.32"));
        assert_eq!(env("NETSCAN_TARGET").as_deref(), Some("192.168.1.32"));
        assert_eq!(env("ANDROID_SERIAL").as_deref(), Some("192.168.1.32:5555"));
        assert_eq!(env("TERM").as_deref(), Some("xterm-256color"));
        assert!(env("PATH").unwrap().contains("/opt/homebrew/bin"));
        assert!(
            env("NETSCAN_DATA")
                .unwrap()
                .ends_with("Application Support/netscan")
        );

        let mut r = req(Proto::AdbPair);
        r.ip = "192.168.1.32".parse().unwrap();
        r.adb_port = 37151;
        r.pair = Some((41235, "123456".into()));
        assert_eq!(
            typed_line(&r).as_deref(),
            Some(
                "adb pair 192.168.1.32:41235 123456 && adb connect 192.168.1.32:37151 && adb -s 192.168.1.32:37151 shell"
            )
        );

        let mut r = req(Proto::Ssh);
        r.ssh_user = Some("root".into());
        r.legacy_rsa = true;
        let s = bootstrap(&r, &t);
        assert_eq!(
            typed_line(&r).as_deref(),
            Some(
                "ssh -o ConnectTimeout=8 -o ServerAliveInterval=15 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa root@192.168.1.194"
            )
        );
        assert!(!s.env.iter().any(|(k, _)| k == "ANDROID_SERIAL"));
        let mut r = req(Proto::Ssh);
        r.ssh_port = 9922;
        r.ssh_user = Some("prisoner".into());
        assert_eq!(
            typed_line(&r).as_deref(),
            Some(
                "ssh -o ConnectTimeout=8 -o ServerAliveInterval=15 -p 9922 prisoner@192.168.1.194"
            )
        );
        assert_eq!(
            typed_line(&req(Proto::Ssh)).as_deref(),
            Some("ssh -o ConnectTimeout=8 -o ServerAliveInterval=15 192.168.1.194")
        );

        let s = bootstrap(&req(Proto::Local), &t);
        assert_eq!(s.typed, None);
        assert_eq!(s.args, vec!["-i"]);
    }

    #[test]
    fn empty_shell_falls_back() {
        let s = bootstrap(&req(Proto::Local), &Tools::default());
        assert_eq!(s.program, PathBuf::from("/bin/zsh"));
    }
}

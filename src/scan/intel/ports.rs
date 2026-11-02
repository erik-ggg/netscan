//! TCP connect scan over a fixed table of well-known service ports.

use crate::scan::model::{PortInfo, PortState, Risk};
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(700);

pub struct PortSpec {
    pub port: u16,
    pub service: &'static str,
    pub meaning: &'static str,
    pub risk: Risk,
}

const fn p(port: u16, service: &'static str, meaning: &'static str, risk: Risk) -> PortSpec {
    PortSpec {
        port,
        service,
        meaning,
        risk,
    }
}

use Risk::{High, Info, Low, Medium};

pub const PORTS: [PortSpec; 36] = [
    p(21, "FTP", "plaintext file transfer", Medium),
    p(22, "SSH", "remote shell", Low),
    p(23, "TELNET", "plaintext remote admin", High),
    p(53, "DNS", "resolver", Info),
    p(80, "HTTP", "web interface", Low),
    p(139, "NETBIOS-SSN", "legacy Windows sharing", Medium),
    p(443, "HTTPS", "secure web interface", Info),
    p(445, "SMB", "file sharing", Medium),
    p(515, "LPD", "legacy printing", Info),
    p(548, "AFP", "Apple file sharing", Low),
    p(554, "RTSP", "video stream / IP camera", Medium),
    p(631, "IPP", "network printing", Info),
    p(1883, "MQTT", "IoT broker, unencrypted", Medium),
    p(2049, "NFS", "network filesystem", Medium),
    p(3000, "WEBOS-SSAP", "LG TV control or dev server", Low),
    p(3001, "WEBOS-SSAP-TLS", "LG TV control", Low),
    p(3389, "RDP", "Windows remote desktop", High),
    p(3689, "DAAP", "iTunes/Music sharing", Info),
    p(5000, "UPNP", "UPnP / AirPlay / NAS", Low),
    p(5001, "NAS-HTTPS", "Synology DSM", Low),
    p(5555, "ADB", "Android debug bridge", High),
    p(5900, "VNC", "screen sharing", High),
    p(6668, "TUYA", "Tuya local control", Low),
    p(7000, "AIRPLAY", "Apple media receiver", Info),
    p(8001, "SAMSUNG-TV", "Tizen remote API", Low),
    p(8008, "CAST-HTTP", "Google Cast", Info),
    p(8009, "CAST-TLS", "Google Cast control", Info),
    p(8080, "HTTP-ALT", "alt web/admin", Low),
    p(8123, "HOME-ASSISTANT", "home automation hub", Low),
    p(8443, "HTTPS-ALT", "alt secure admin", Info),
    p(9000, "HTTP-ALT", "management API", Low),
    p(9100, "JETDIRECT", "raw printing", Low),
    p(9999, "KASA", "TP-Link smart plug control", Medium),
    p(32400, "PLEX", "media server", Info),
    p(49152, "UPNP-HTTP", "UPnP control endpoint", Low),
    p(62078, "LOCKDOWN", "iOS sync service", Info),
];

pub fn spec(port: u16) -> Option<&'static PortSpec> {
    PORTS.iter().find(|s| s.port == port)
}

pub fn all_ports() -> Vec<u16> {
    PORTS.iter().map(|s| s.port).collect()
}

/// Build the `PortInfo` row for a port (unknown ports get empty metadata).
pub fn info(port: u16, state: PortState) -> PortInfo {
    match spec(port) {
        Some(s) => PortInfo {
            port,
            state,
            service: s.service.into(),
            meaning: s.meaning.into(),
            risk: s.risk,
        },
        None => PortInfo {
            port,
            state,
            service: String::new(),
            meaning: String::new(),
            risk: Risk::Info,
        },
    }
}

async fn probe(ip: Ipv4Addr, port: u16) -> PortState {
    match timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect(SocketAddr::new(IpAddr::V4(ip), port)),
    )
    .await
    {
        Ok(Ok(_)) => PortState::Open,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortState::Closed,
        // Timeout, HostUnreachable, NetworkUnreachable, ...
        _ => PortState::Filtered,
    }
}

/// Connect-scan every port concurrently. `on_port` fires as each one resolves;
/// the result is in the order of `ports`.
pub async fn scan(ip: Ipv4Addr, ports: &[u16], on_port: impl Fn(u16, PortState)) -> Vec<PortInfo> {
    let mut futs: FuturesUnordered<_> = ports
        .iter()
        .enumerate()
        .map(|(i, &port)| async move { (i, port, probe(ip, port).await) })
        .collect();
    let mut out: Vec<Option<PortInfo>> = vec![None; ports.len()];
    while let Some((i, port, state)) = futs.next().await {
        on_port(port, state);
        out[i] = Some(info(port, state));
    }
    out.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn open_and_closed() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = l.local_addr().unwrap().port();
        let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = tmp.local_addr().unwrap().port();
        drop(tmp);
        let seen = std::sync::Mutex::new(vec![]);
        let r = scan(Ipv4Addr::LOCALHOST, &[open, closed], |p, s| {
            seen.lock().unwrap().push((p, s))
        })
        .await;
        assert_eq!(r[0].state, PortState::Open);
        assert_eq!(r[1].state, PortState::Closed);
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn table_lookup() {
        assert_eq!(spec(23).unwrap().risk, Risk::High);
        assert_eq!(PORTS.len(), 36);
        assert!(spec(1).is_none());
    }
}

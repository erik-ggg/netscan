use futures::stream::{self, StreamExt};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use surge_ping::{Client, Config, ICMP, IcmpPacket, PingIdentifier, PingSequence};
use tokio::net::TcpStream;
use tokio::time::timeout;

const CONCURRENCY: usize = 256;
const TIMEOUT: Duration = Duration::from_millis(700);
const HOST_DEADLINE: Duration = Duration::from_millis(2500);
/// Whole-sweep cap; partial results are returned when it fires.
const SWEEP_DEADLINE: Duration = Duration::from_secs(8);
const ATTEMPTS: usize = 2;
const TCP_PORTS: [u16; 6] = [80, 443, 22, 62078, 8080, 554];

/// What a live host told us during the sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct HostProbe {
    pub rtt: Option<Duration>,
    pub ttl: Option<u8>,
}

/// Sweep `hosts` and return the addresses that answered (ICMP echo, or a TCP
/// probe: connect success/refusal both prove the host is alive and fill ARP),
/// with RTT and (ICMP only) TTL. `on_progress` receives the percentage done.
pub async fn sweep(
    hosts: Vec<Ipv4Addr>,
    on_progress: impl Fn(u8) + Send + Sync,
) -> HashMap<Ipv4Addr, HostProbe> {
    // Populate the ARP cache first (works even when ICMP/TCP are filtered).
    udp_touch(&hosts).await;
    let client = Client::new(&Config::builder().kind(ICMP::V4).build()).ok();
    let total = hosts.len().max(1);
    let client = client.as_ref();
    let mut done = 0;
    let mut last = 255u8;
    let mut alive = HashMap::new();
    let mut results = stream::iter(hosts)
        .enumerate()
        .map(|(n, ip)| async move {
            // Hard per-host cap: a stuck ICMP socket once stalled the whole sweep.
            let probe = async {
                if let Some(c) = client
                    && let Some((rtt, ttl)) = icmp_probe(c, ip, n as u16).await
                {
                    return Some(HostProbe {
                        rtt: Some(rtt),
                        ttl,
                    });
                }
                tcp_probe(ip).await.map(|rtt| HostProbe {
                    rtt: Some(rtt),
                    ttl: None,
                })
            };
            let up = timeout(HOST_DEADLINE, probe).await.unwrap_or(None);
            (ip, up)
        })
        .buffer_unordered(CONCURRENCY);
    let deadline = tokio::time::Instant::now() + SWEEP_DEADLINE;
    while let Ok(Some((ip, up))) = tokio::time::timeout_at(deadline, results.next()).await {
        done += 1;
        if let Some(p) = up {
            alive.insert(ip, p);
        }
        let pct = (done * 100 / total) as u8;
        if pct != last {
            last = pct;
            on_progress(pct);
        }
    }
    alive
}

/// Every host gets its own identifier (host index) and unique sequence numbers,
/// so concurrent echoes can never be matched to the wrong waiter.
async fn icmp_probe(client: &Client, ip: Ipv4Addr, n: u16) -> Option<(Duration, Option<u8>)> {
    let mut pinger = client
        .pinger(IpAddr::V4(ip), PingIdentifier(n.wrapping_add(0x4e53)))
        .await;
    pinger.timeout(TIMEOUT);
    for a in 0..ATTEMPTS as u16 {
        if let Ok((pkt, rtt)) = pinger
            .ping(PingSequence(n.wrapping_mul(2).wrapping_add(a)), &[0; 16])
            .await
        {
            let ttl = match pkt {
                IcmpPacket::V4(p) => p.get_ttl(),
                _ => None,
            };
            return Some((rtt, ttl));
        }
    }
    None
}

/// Send a 1-byte UDP datagram to every host: the kernel must ARP-resolve each
/// destination, which fills the ARP table for any live host.
async fn udp_touch(hosts: &[Ipv4Addr]) {
    let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
        return;
    };
    for ip in hosts {
        for port in [9u16, 137] {
            let _ = sock.try_send_to(&[0], SocketAddr::new(IpAddr::V4(*ip), port));
        }
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
}

/// Fallback probe. Even failed connects trigger an ARP resolution, so the
/// ARP table gets filled for hosts that drop ICMP; here we only report hosts
/// that accepted or actively refused the connection (with the fastest time).
async fn tcp_probe(ip: Ipv4Addr) -> Option<Duration> {
    let probes = TCP_PORTS.iter().map(|&p| async move {
        let t0 = Instant::now();
        match timeout(
            TIMEOUT / 2,
            TcpStream::connect(SocketAddr::new(IpAddr::V4(ip), p)),
        )
        .await
        {
            Ok(Ok(_)) => Some(t0.elapsed()),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(t0.elapsed()),
            _ => None,
        }
    });
    futures::future::join_all(probes)
        .await
        .into_iter()
        .flatten()
        .min()
}

//! Deep scan of a single in-subnet host: echo timing, TCP connect lattice,
//! read-only service fingerprinting, then OS / kind / exposure assessment.

pub mod netbios;
pub mod ports;
pub mod probe;
pub mod risk;

use super::model::*;
use super::{classify, net, os, ssdp};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::timeout;

pub struct Target {
    pub device: Device,
    pub network: NetworkInfo,
}

const OVERALL_CAP: Duration = Duration::from_secs(7);
const HTTP_PORTS: [u16; 13] = [
    80, 443, 3000, 5000, 5001, 7000, 8001, 8008, 8080, 8123, 8443, 9000, 32400,
];
const TLS_PORTS: [u16; 5] = [443, 5001, 8443, 3001, 8009];

type Emit = Arc<dyn Fn(IntelEvent) + Send + Sync>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn ms(d: Duration) -> f32 {
    (d.as_secs_f32() * 10000.0).round() / 10.0
}

async fn echo_stage(ip: Ipv4Addr, emit: &Emit, state: &Mutex<DeviceIntel>) {
    use surge_ping::{Client, Config, ICMP, IcmpPacket, PingIdentifier, PingSequence};
    const SENT: u8 = 4;
    let Ok(client) = Client::new(&Config::builder().kind(ICMP::V4).build()) else {
        emit(IntelEvent::Log("ECHO // ICMP SOCKET UNAVAILABLE".into()));
        return;
    };
    let base = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos())
        & 0xffff) as u16;
    let samples = Arc::new(Mutex::new(vec![None::<f32>; SENT as usize]));
    let ttl = Arc::new(Mutex::new(None::<u8>));
    let futs = (0..SENT).map(|seq| {
        let (client, emit, samples, ttl) = (&client, emit, samples.clone(), ttl.clone());
        async move {
            tokio::time::sleep(Duration::from_millis(100 * seq as u64)).await;
            let mut p = client
                .pinger(
                    IpAddr::V4(ip),
                    PingIdentifier(base.wrapping_add(seq as u16)),
                )
                .await;
            p.timeout(Duration::from_millis(600));
            let (rtt, t) = match p.ping(PingSequence(seq as u16), &[0; 16]).await {
                Ok((IcmpPacket::V4(pk), rtt)) => (Some(ms(rtt)), pk.get_ttl()),
                Ok((_, rtt)) => (Some(ms(rtt)), None),
                Err(_) => (None, None),
            };
            lock(&samples)[seq as usize] = rtt;
            if t.is_some() {
                *lock(&ttl) = t;
            }
            emit(IntelEvent::Echo {
                seq,
                rtt_ms: rtt,
                ttl: t,
            });
        }
    });
    let _ = timeout(Duration::from_millis(1500), futures::future::join_all(futs)).await;
    let samples = lock(&samples).clone();
    let got: Vec<f32> = samples.iter().flatten().copied().collect();
    let (min, max) = got
        .iter()
        .fold((f32::MAX, 0f32), |(a, b), &x| (a.min(x), b.max(x)));
    let avg = if got.is_empty() {
        0.0
    } else {
        got.iter().sum::<f32>() / got.len() as f32
    };
    let ttl = *lock(&ttl);
    lock(state).ping = Some(PingStats {
        sent: SENT,
        recv: got.len() as u8,
        min_ms: if got.is_empty() { 0.0 } else { min },
        avg_ms: avg,
        max_ms: max,
        samples,
        ttl,
    });
}

async fn upnp_unicast(client: &reqwest::Client, ip: Ipv4Addr) -> Option<UpnpInfo> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    ssdp::unicast_search(&sock, ip, "upnp:rootdevice", 1)
        .await
        .ok()?;
    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let (n, from) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        if from.ip() != IpAddr::V4(ip) {
            continue;
        }
        let hit = ssdp::parse_response(&String::from_utf8_lossy(&buf[..n]))?;
        let loc = hit.location?;
        let mut info = ssdp::fetch_description(client, ip, &loc)
            .await
            .unwrap_or(UpnpInfo {
                location: loc,
                ..Default::default()
            });
        info.server = hit.server;
        return Some(info);
    }
}

async fn fingerprint_stage(ip: Ipv4Addr, device: &Device, emit: &Emit, state: &Mutex<DeviceIntel>) {
    let open: Vec<u16> = lock(state)
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .map(|p| p.port)
        .collect();
    let is_open = |p: u16| open.contains(&p);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(800))
        .timeout(Duration::from_secs(2))
        .user_agent("netscan/0.1")
        .build()
        .ok();

    let banners = async {
        let futs = [21u16, 22, 23]
            .into_iter()
            .filter(|p| is_open(*p))
            .map(|p| async move { probe::banner(ip, p).await });
        for b in futures::future::join_all(futs).await.into_iter().flatten() {
            emit(IntelEvent::Log(format!(
                "BANNER {}/TCP {} // {}",
                b.port, b.proto, b.text
            )));
            lock(state).banners.push(b);
        }
    };
    let http = async {
        let Some(client) = client.as_ref() else {
            return;
        };
        let futs = HTTP_PORTS
            .into_iter()
            .filter(|p| is_open(*p))
            .map(|p| async move {
                probe::http_fingerprint(client, ip, p, TLS_PORTS.contains(&p)).await
            });
        for f in futures::future::join_all(futs).await.into_iter().flatten() {
            emit(IntelEvent::Log(format!(
                "HTTP {}/TCP {} // {}{}",
                f.port,
                f.status,
                f.server.as_deref().unwrap_or("-"),
                f.title
                    .as_deref()
                    .map(|t| format!(" // \"{t}\""))
                    .unwrap_or_default()
            )));
            lock(state).http.push(f);
        }
    };
    let rtsp = async {
        if is_open(554)
            && let Some(b) = probe::rtsp_options(ip).await
        {
            emit(IntelEvent::Log(format!("RTSP 554/TCP // {}", b.text)));
            lock(state).banners.push(b);
        }
    };
    let nb = async {
        if let Some(n) = netbios::query(ip).await {
            emit(IntelEvent::Log(format!(
                "NETBIOS // {}{}",
                n.name,
                n.group
                    .as_deref()
                    .map(|g| format!(" ({g})"))
                    .unwrap_or_default()
            )));
            lock(state).netbios = Some(n);
        }
    };
    let upnp = async {
        if device.upnp.is_some() {
            lock(state).upnp = device.upnp.clone();
        } else if let Some(client) = client.as_ref()
            && let Some(u) = upnp_unicast(client, ip).await
        {
            emit(IntelEvent::Log(format!(
                "UPNP // {}",
                u.friendly_name
                    .as_deref()
                    .or(u.server.as_deref())
                    .unwrap_or("DESCRIPTOR")
            )));
            lock(state).upnp = Some(u);
        }
    };
    tokio::join!(banners, http, rtsp, nb, upnp);
    // Keep output order stable regardless of completion order.
    let mut s = lock(state);
    s.banners.sort_by_key(|b| b.port);
    s.http.sort_by_key(|h| h.port);
}

/// Run the four-stage deep scan. `Done` is always emitted exactly once, last.
pub async fn deep_scan(
    t: Target,
    emit: impl Fn(IntelEvent) + Send + Sync + 'static,
) -> DeviceIntel {
    let emit: Emit = Arc::new(emit);
    let t0 = Instant::now();
    let stage = |s: IntelStage, pct: u8| emit(IntelEvent::Stage { stage: s, pct });
    let mut intel = DeviceIntel {
        ip: t.device.ip.clone(),
        ..Default::default()
    };

    let ip = t
        .device
        .ip
        .parse::<Ipv4Addr>()
        .ok()
        .filter(|ip| net::in_subnet(&t.network, *ip));
    let Some(ip) = ip else {
        emit(IntelEvent::Log(format!(
            "OUT OF SCOPE // {} NOT IN {}",
            t.device.ip, t.network.subnet_cidr
        )));
        intel.complete = true;
        intel.notes = vec![Note {
            risk: Risk::Info,
            text: "OUT OF SCOPE".into(),
        }];
        emit(IntelEvent::Stage {
            stage: IntelStage::Assemble,
            pct: 100,
        });
        emit(IntelEvent::Done(Box::new(intel.clone())));
        return intel;
    };

    let state = Arc::new(Mutex::new(intel));
    let snapshot = |state: &Mutex<DeviceIntel>| {
        let mut s = lock(state).clone();
        s.elapsed_ms = t0.elapsed().as_millis() as u32;
        emit(IntelEvent::Snapshot(Box::new(s)));
    };
    let remaining = |stage_cap: Duration| stage_cap.min(OVERALL_CAP.saturating_sub(t0.elapsed()));

    // 1. ECHO 0..15
    stage(IntelStage::Echo, 0);
    emit(IntelEvent::Log(format!("ECHO // {ip} 4 PROBES")));
    let _ = timeout(
        remaining(Duration::from_millis(1800)),
        echo_stage(ip, &emit, &state),
    )
    .await;
    stage(IntelStage::Echo, 15);
    snapshot(&state);

    // 2. LATTICE 15..55
    stage(IntelStage::Lattice, 15);
    let all = ports::all_ports();
    emit(IntelEvent::Log(format!("LATTICE // {} PORTS", all.len())));
    let resolved = Arc::new(Mutex::new(Vec::<(u16, PortState)>::new()));
    let r2 = resolved.clone();
    let e2 = emit.clone();
    let total = all.len();
    let scanned = timeout(
        remaining(Duration::from_millis(1500)),
        ports::scan(ip, &all, move |port, st| {
            let n = {
                let mut r = lock(&r2);
                r.push((port, st));
                r.len()
            };
            e2(IntelEvent::Port { port, state: st });
            e2(IntelEvent::Stage {
                stage: IntelStage::Lattice,
                pct: 15 + (40 * n / total) as u8,
            });
        }),
    )
    .await;
    let port_infos = scanned.unwrap_or_else(|_| {
        let r = lock(&resolved);
        all.iter()
            .map(|&p| {
                ports::info(
                    p,
                    r.iter()
                        .find(|x| x.0 == p)
                        .map_or(PortState::Filtered, |x| x.1),
                )
            })
            .collect()
    });
    let n_open = port_infos
        .iter()
        .filter(|p| p.state == PortState::Open)
        .count();
    emit(IntelEvent::Log(format!("LATTICE // {n_open} OPEN")));
    lock(&state).ports = port_infos;
    stage(IntelStage::Lattice, 55);
    snapshot(&state);

    // 3. FINGERPRINT 55..90
    stage(IntelStage::Fingerprint, 55);
    emit(IntelEvent::Log("FINGERPRINT // SERVICES".into()));
    let _ = timeout(
        remaining(Duration::from_millis(3800)),
        fingerprint_stage(ip, &t.device, &emit, &state),
    )
    .await;
    stage(IntelStage::Fingerprint, 90);
    snapshot(&state);

    // 4. ASSEMBLE 90..100
    stage(IntelStage::Assemble, 90);
    let mut intel = lock(&state).clone();
    intel.os = os::guess(&t.device, Some(&intel));
    let class = classify::assess(&t.device, Some(&intel));
    if class.kind != t.device.kind && class.confidence >= 50 {
        intel.kind = Some(class.kind);
        intel.kind_reason = Some(class.reason.clone());
    }
    intel.class = Some(class);
    let (notes, exposure) = risk::assess(&t.device, &intel);
    intel.notes = notes;
    intel.exposure = exposure;
    intel.complete = true;
    intel.elapsed_ms = t0.elapsed().as_millis() as u32;
    emit(IntelEvent::Log(format!(
        "OS // {} ({}%)",
        intel.os.label, intel.os.confidence
    )));
    stage(IntelStage::Assemble, 100);
    emit(IntelEvent::Done(Box::new(intel.clone())));
    intel
}

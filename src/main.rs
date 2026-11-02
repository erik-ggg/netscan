// Phase 4: UI consumers arrive in Phase 5.
mod link;
mod scan;
mod ui;

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};

fn main() {
    if std::env::args().any(|a| a == "--cli") {
        run_cli();
        return;
    }
    if let Some(i) = std::env::args().position(|a| a == "--reclassify") {
        let Some(path) = std::env::args().nth(i + 1) else {
            eprintln!("usage: netscan --reclassify <scan.json>");
            std::process::exit(2);
        };
        run_reclassify(&path);
        return;
    }
    if let Some(i) = std::env::args().position(|a| a == "--intel") {
        let Some(ip) = std::env::args().nth(i + 1) else {
            eprintln!("usage: netscan --intel <ip>");
            std::process::exit(2);
        };
        run_intel(ip);
        return;
    }
    if std::env::args().any(|a| a == "--pty-echo") {
        run_pty_echo();
        return;
    }
    if let Some(i) = std::env::args().position(|a| a == "--link-plan") {
        let Some(ip) = std::env::args().nth(i + 1) else {
            eprintln!("usage: netscan --link-plan <ip>");
            std::process::exit(2);
        };
        run_link_plan(ip);
        return;
    }
    let window = WindowBuilder::new()
        .with_title("NETSCAN // 荒坂")
        .with_min_inner_size(LogicalSize::new(1024.0, 680.0))
        .with_inner_size(LogicalSize::new(1280.0, 800.0));
    let cfg = Config::new()
        .with_window(window)
        .with_background_color((6, 4, 5, 255))
        .with_disable_context_menu(!cfg!(debug_assertions));
    dioxus::LaunchBuilder::desktop()
        .with_cfg(cfg)
        .launch(ui::app::App);
}

fn run_cli() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let t0 = std::time::Instant::now();
    let res = rt.block_on(scan::scan(move |p| match p {
        scan::model::ScanProgress::Phase { name, pct } => {
            eprintln!("[{:5.2}s] {pct:>3}% {name}", t0.elapsed().as_secs_f32())
        }
        scan::model::ScanProgress::Log(l) => {
            eprintln!("[{:5.2}s]      > {l}", t0.elapsed().as_secs_f32())
        }
    }));
    eprintln!("[total] {:.2}s", t0.elapsed().as_secs_f32());
    match res {
        Ok(r) => println!("{}", serde_json::to_string_pretty(&r).unwrap()),
        Err(e) => {
            eprintln!("scan failed: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Full sweep, then a deep scan of one host; HUD-style events on stderr, JSON on stdout.
fn run_intel(ip: String) {
    use scan::model::IntelEvent;
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let res = match rt.block_on(scan::scan(|_| {})) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("scan failed: {e:#}");
            std::process::exit(1);
        }
    };
    let device = res
        .devices
        .iter()
        .find(|d| d.ip == ip)
        .cloned()
        .unwrap_or_else(|| scan::model::Device {
            ip: ip.clone(),
            ..Default::default()
        });
    let t0 = std::time::Instant::now();
    let target = scan::intel::Target {
        device,
        network: res.network.clone(),
    };
    let intel = rt.block_on(scan::intel::deep_scan(target, move |ev| {
        let t = t0.elapsed().as_secs_f32();
        match ev {
            IntelEvent::Stage { stage, pct } => eprintln!("[{t:5.2}s] {pct:>3}% {stage:?}"),
            IntelEvent::Log(l) => eprintln!("[{t:5.2}s]      > {l}"),
            IntelEvent::Echo { seq, rtt_ms, ttl } => {
                eprintln!("[{t:5.2}s]      echo #{seq} {rtt_ms:?} ttl {ttl:?}")
            }
            IntelEvent::Port { port, state } => {
                if state == scan::model::PortState::Open {
                    eprintln!("[{t:5.2}s]      port {port} OPEN")
                }
            }
            IntelEvent::Snapshot(_) | IntelEvent::Done(_) => {}
        }
    }));
    eprintln!("[total] {} ms", intel.elapsed_ms);
    println!("{}", serde_json::to_string_pretty(&intel).unwrap());
}

/// Offline: re-run the evidence classifier over a saved scan and print a table.
fn run_reclassify(path: &str) {
    let res: scan::model::ScanResult = match std::fs::read_to_string(path)
        .map_err(anyhow::Error::from)
        .and_then(|t| serde_json::from_str(&t).map_err(Into::into))
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot load {path}: {e:#}");
            std::process::exit(1);
        }
    };
    println!(
        "{:<15} {:<14} {:<18} {:>4}  {:<14} REASON",
        "IP", "VENDOR", "OLD->NEW", "CONF", "LABEL"
    );
    for d in &res.devices {
        let c = scan::classify::assess(d, None);
        let vendor: String = d
            .vendor
            .as_deref()
            .unwrap_or("-")
            .chars()
            .take(14)
            .collect();
        println!(
            "{:<15} {:<14} {:<18} {:>3}%  {:<14} {}",
            d.ip,
            vendor,
            format!("{:?}->{:?}", d.kind, c.kind),
            c.confidence,
            c.label.as_deref().unwrap_or("-"),
            c.reason
        );
    }
}

/// Headless PTY smoke test: `stty size; echo ok` at 33 rows x 101 cols.
fn run_pty_echo() {
    use futures::StreamExt;
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let spec = link::SpawnSpec {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "stty size; echo ok".into()],
            env: vec![("TERM".into(), "xterm-256color".into())],
            cwd: "/".into(),
            typed: None,
        };
        let (_h, mut rx) = match link::pty::spawn(spec, 101, 33).await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("pty spawn failed: {e:#}");
                std::process::exit(1);
            }
        };
        while let Some(ev) = rx.next().await {
            match ev {
                link::pty::PtyEvent::Output(b) => print!("{}", String::from_utf8_lossy(&b)),
                link::pty::PtyEvent::Exited(c) => {
                    println!("[exit {c:?}]");
                    break;
                }
            }
        }
    });
}

/// Sweep, then print the link plans and the typed bootstrap command for one host.
fn run_link_plan(ip: String) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let res = match rt.block_on(scan::scan(|_| {})) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("scan failed: {e:#}");
            std::process::exit(1);
        }
    };
    let Some(device) = res.devices.iter().find(|d| d.ip == ip) else {
        eprintln!("{ip} not found in scan");
        std::process::exit(1);
    };
    let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() else {
        eprintln!("bad ip {ip}");
        std::process::exit(2);
    };
    let intel = rt.block_on(scan::intel::deep_scan(
        scan::intel::Target {
            device: device.clone(),
            network: res.network.clone(),
        },
        |_| {},
    ));
    let device = &scan::model::Device {
        class: intel.class.clone().or_else(|| device.class.clone()),
        ..device.clone()
    };
    let tools = link::tools::detect();
    println!(
        "TOOLS adb={:?} ssh={:?} git={:?} python3={:?} shell={:?} clt_stub={}",
        tools.adb, tools.ssh, tools.git, tools.python3, tools.shell, tools.clt_stub
    );
    let cls = device.class.as_ref();
    println!(
        "TARGET {ip} kind={:?} label={:?} conf={:?}",
        device.kind,
        cls.and_then(|c| c.label.clone()),
        cls.map(|c| c.confidence)
    );
    for p in link::plan::plans(device, Some(&intel), &tools) {
        println!(
            "PLAN rank={:>2} {:?} port={:?} user={:?} legacy={} :: {} :: {:?}",
            p.rank, p.proto, p.port, p.user, p.legacy_rsa, p.why, p.readiness
        );
        let mut req = link::plan::request_for(addr, &p);
        if p.proto == link::Proto::AdbPair {
            let pp = req.pair.as_ref().map_or(0, |x| x.0);
            req.pair = Some((pp, "123456".into())); // example code
        }
        match link::validate(req, &res.network) {
            Ok(req) => {
                let spec = link::bootstrap(&req, &tools);
                println!(
                    "     SPAWN {} {:?}",
                    spec.program.display(),
                    spec.args
                );
            }
            Err(e) => println!("     INVALID {e:#}"),
        }
    }
}

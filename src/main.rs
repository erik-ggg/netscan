mod scan;
mod ui;

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};

fn main() {
    if std::env::args().any(|a| a == "--cli") {
        run_cli();
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

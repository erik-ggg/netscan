mod scan;
mod ui;

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};

fn main() {
    if std::env::args().any(|a| a == "--cli") {
        run_cli();
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
    dioxus::LaunchBuilder::desktop().with_cfg(cfg).launch(ui::app::App);
}

fn run_cli() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let t0 = std::time::Instant::now();
    let res = rt.block_on(scan::scan(move |p| match p {
        scan::model::ScanProgress::Phase { name, pct } => {
            eprintln!("[{:5.2}s] {pct:>3}% {name}", t0.elapsed().as_secs_f32())
        }
        scan::model::ScanProgress::Log(l) => eprintln!("[{:5.2}s]      > {l}", t0.elapsed().as_secs_f32()),
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


use super::{css, loading::Loading, network_map::NetworkMap};
use crate::scan::{self, model::*};
use dioxus::prelude::*;
use futures::StreamExt;
use std::time::{Duration, Instant};

const MIN_LOADING: Duration = Duration::from_millis(1500);

#[derive(Clone, PartialEq)]
enum Stage {
    Loading,
    Exiting,
    Map,
    Failed(String),
}

#[component]
pub fn App() -> Element {
    let mut stage = use_signal(|| Stage::Loading);
    let mut phase = use_signal(|| ("Initialising".to_string(), 0u8));
    let mut logs = use_signal(Vec::<String>::new);
    let mut result = use_signal(|| None::<ScanResult>);

    use_hook(|| {
        spawn(async move {
            let started = Instant::now();
            let (tx, mut rx) = futures::channel::mpsc::unbounded::<ScanProgress>();
            let handle = tokio::spawn(scan::scan(move |p| {
                let _ = tx.unbounded_send(p);
            }));
            while let Some(p) = rx.next().await {
                match p {
                    ScanProgress::Phase { name, pct } => phase.set((name, pct)),
                    ScanProgress::Log(l) => logs.with_mut(|v| v.push(l)),
                }
            }
            let outcome = match handle.await {
                Ok(r) => r.map_err(|e| format!("{e:#}")),
                Err(e) => Err(e.to_string()),
            };
            match outcome {
                Ok(r) => {
                    let name = phase.read().0.clone();
                    phase.set((name, 100));
                    let left = MIN_LOADING.saturating_sub(started.elapsed());
                    tokio::time::sleep(left.max(Duration::from_millis(450))).await;
                    result.set(Some(r));
                    stage.set(Stage::Exiting);
                    tokio::time::sleep(Duration::from_millis(650)).await;
                    stage.set(Stage::Map);
                }
                Err(e) => {
                    tokio::time::sleep(MIN_LOADING.saturating_sub(started.elapsed())).await;
                    stage.set(Stage::Failed(e));
                }
            }
        })
    });

    let hovered = use_signal(|| None::<usize>);
    let st = stage();
    rsx! {
        style { "{css()}" }
        div { class: "app",
            div { class: "bg-grid" }
            match st {
                Stage::Loading | Stage::Exiting => rsx! {
                    Loading {
                        phase: phase().0,
                        pct: phase().1,
                        logs: logs(),
                        exiting: st == Stage::Exiting,
                    }
                },
                Stage::Failed(msg) => rsx! { Failure { msg } },
                Stage::Map => rsx! {
                    if let Some(r) = result() {
                        NetworkMap { result: r, hovered }
                    }
                },
            }
            div { class: "scanlines" }
            div { class: "vignette" }
        }
    }
}

#[component]
fn Failure(msg: String) -> Element {
    rsx! {
        div { class: "loading failure",
            div { class: "brackets" }
            div { class: "fail-code", "ERR // 0xA5C0 // 接続失敗" }
            h1 { class: "fail-title", "SCAN ABORTED" }
            p { class: "fail-msg", "{msg}" }
            p { class: "fail-hint", "Check that this machine is connected to a local network, then restart netscan." }
        }
    }
}

//! PTY session: spawn / resize / write / kill, tokio-native.

use super::SpawnSpec;
use anyhow::{Context, Result};
use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq)]
pub enum PtyCmd {
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Kill,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PtyEvent {
    Output(Vec<u8>),
    Exited(Option<i32>),
}

/// Cheap, cloneable control handle. Dropping every clone kills the child.
#[derive(Clone)]
pub struct PtyHandle {
    #[allow(dead_code)] // identifies the session in logs/tests
    pub id: u32,
    pub pid: Option<u32>,
    tx: UnboundedSender<PtyCmd>,
}

impl PtyHandle {
    pub fn input(&self, b: Vec<u8>) {
        let _ = self.tx.unbounded_send(PtyCmd::Input(b));
    }
    pub fn resize(&self, cols: u16, rows: u16) {
        let _ = self.tx.unbounded_send(PtyCmd::Resize { cols, rows });
    }
    pub fn kill(&self) {
        let _ = self.tx.unbounded_send(PtyCmd::Kill);
    }
}

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// Must be awaited inside the tokio runtime.
pub async fn spawn(
    spec: SpawnSpec,
    cols: u16,
    rows: u16,
) -> Result<(PtyHandle, UnboundedReceiver<PtyEvent>)> {
    let (pty, pts) = pty_process::open().context("open pty")?;
    pty.resize(pty_process::Size::new(rows, cols))
        .context("size pty")?;
    let mut child = pty_process::Command::new(&spec.program)
        .args(&spec.args)
        .envs(spec.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .current_dir(&spec.cwd)
        .kill_on_drop(true)
        .spawn(pts)
        .with_context(|| format!("spawn {}", spec.program.display()))?;
    let pid = child.id();
    let (mut r, mut w) = pty.into_split();
    let (out_tx, out_rx) = unbounded::<PtyEvent>();
    let (cmd_tx, mut cmd_rx) = unbounded::<PtyCmd>();

    let reader_tx = out_tx.clone();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match r.read(&mut buf).await {
                // macOS reports EIO once the slave side is closed: that is EOF.
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if reader_tx
                        .unbounded_send(PtyEvent::Output(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    tokio::spawn(async move {
        let mut cmds_open = true;
        let mut killed = false;
        let status = loop {
            tokio::select! {
                c = cmd_rx.next(), if cmds_open => match c {
                    Some(PtyCmd::Input(b)) => { let _ = w.write_all(&b).await; }
                    Some(PtyCmd::Resize { cols, rows }) => {
                        let _ = w.resize(pty_process::Size::new(rows, cols));
                    }
                    Some(PtyCmd::Kill) | None => {
                        cmds_open = false;
                        if !killed { killed = true; let _ = child.start_kill(); }
                    }
                },
                st = child.wait() => break st,
            }
        };
        // let the reader drain what the child wrote before it died
        let _ = tokio::time::timeout(Duration::from_millis(300), reader).await;
        let _ = out_tx.unbounded_send(PtyEvent::Exited(status.ok().and_then(|s| s.code())));
    });

    let handle = PtyHandle {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        pid,
        tx: cmd_tx,
    };
    if let Some(t) = &spec.typed {
        handle.input(format!("{t}\r").into_bytes());
    }
    Ok((handle, out_rx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Instant;

    fn sh(cmd: &str) -> SpawnSpec {
        SpawnSpec {
            program: PathBuf::from("/bin/sh"),
            args: vec!["-c".into(), cmd.into()],
            env: vec![("TERM".into(), "xterm-256color".into())],
            cwd: PathBuf::from("/"),
            typed: None,
        }
    }

    /// Collect output until Exited (or `max`).
    async fn drain(
        rx: &mut UnboundedReceiver<PtyEvent>,
        max: Duration,
    ) -> (String, Option<Option<i32>>) {
        let mut out = Vec::new();
        let mut exit = None;
        let t0 = Instant::now();
        while t0.elapsed() < max {
            match tokio::time::timeout(max - t0.elapsed(), rx.next()).await {
                Ok(Some(PtyEvent::Output(b))) => out.extend(b),
                Ok(Some(PtyEvent::Exited(c))) => {
                    exit = Some(c);
                    break;
                }
                _ => break,
            }
        }
        (String::from_utf8_lossy(&out).into_owned(), exit)
    }

    #[tokio::test]
    async fn echo_hi() {
        let (_h, mut rx) = spawn(sh("echo hi"), 80, 24).await.unwrap();
        let (out, exit) = drain(&mut rx, Duration::from_secs(5)).await;
        assert!(out.contains("hi"), "{out:?}");
        assert_eq!(exit, Some(Some(0)));
    }

    #[tokio::test]
    async fn initial_size() {
        let (_h, mut rx) = spawn(sh("stty size"), 101, 33).await.unwrap();
        let (out, exit) = drain(&mut rx, Duration::from_secs(5)).await;
        assert!(out.contains("33 101"), "{out:?}");
        assert_eq!(exit, Some(Some(0)));
    }

    #[tokio::test]
    async fn resize_is_reflected() {
        let (h, mut rx) = spawn(sh("read x; stty size"), 101, 33).await.unwrap();
        h.resize(120, 40);
        tokio::time::sleep(Duration::from_millis(200)).await;
        h.input(b"\n".to_vec());
        let (out, exit) = drain(&mut rx, Duration::from_secs(5)).await;
        assert!(out.contains("40 120"), "{out:?}");
        assert_eq!(exit, Some(Some(0)));
    }

    #[tokio::test]
    async fn typed_line_is_sent() {
        let mut s = sh("read x; echo got:$x");
        s.typed = Some("abc".into());
        let (_h, mut rx) = spawn(s, 80, 24).await.unwrap();
        let (out, exit) = drain(&mut rx, Duration::from_secs(5)).await;
        assert!(out.contains("got:abc"), "{out:?}");
        assert_eq!(exit, Some(Some(0)));
    }

    #[tokio::test]
    async fn kill_exits_quickly() {
        let (h, mut rx) = spawn(sh("exec sleep 30"), 80, 24).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t0 = Instant::now();
        h.kill();
        let (_, exit) = drain(&mut rx, Duration::from_secs(1)).await;
        assert!(exit.is_some(), "no exit event");
        assert!(t0.elapsed() < Duration::from_secs(1));
    }

    fn alive(pid: u32) -> bool {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[tokio::test]
    async fn drop_handle_kills_child() {
        let (h, mut rx) = spawn(sh("exec sleep 30"), 80, 24).await.unwrap();
        let pid = h.pid.expect("pid");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(alive(pid));
        drop(h);
        let (_, exit) = drain(&mut rx, Duration::from_secs(1)).await;
        assert!(exit.is_some(), "no exit event after drop");
        assert!(!alive(pid), "child survived");
    }
}

//! Read-only service probes: banners (never written to), HTTP GET /, RTSP OPTIONS.

use crate::scan::model::{Banner, HttpFingerprint};
use crate::scan::textutil::{clean, html_title};
use reqwest::Client;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const IO_TIMEOUT: Duration = Duration::from_millis(600);

async fn connect(ip: Ipv4Addr, port: u16) -> Option<TcpStream> {
    timeout(
        IO_TIMEOUT,
        TcpStream::connect(SocketAddr::new(IpAddr::V4(ip), port)),
    )
    .await
    .ok()?
    .ok()
}

/// Printable text of a raw banner: Telnet IAC sequences are dropped.
fn printable(raw: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == 0xff {
            i += 3; // IAC <cmd> <opt>
            continue;
        }
        out.push(if raw[i].is_ascii_graphic() || raw[i] == b' ' {
            raw[i] as char
        } else {
            ' '
        });
        i += 1;
    }
    clean(&out)
}

/// Passive banner grab for FTP / SSH / Telnet: connect and read what the
/// server volunteers. Nothing is ever written to the socket.
pub async fn banner(ip: Ipv4Addr, port: u16) -> Option<Banner> {
    let proto = match port {
        21 => "FTP",
        22 => "SSH",
        23 => "TELNET",
        _ => return None,
    };
    let mut s = connect(ip, port).await?;
    let mut buf = [0u8; 256];
    let n = timeout(IO_TIMEOUT, s.read(&mut buf)).await.ok()?.ok()?;
    if n == 0 {
        return None;
    }
    // Only the first line is a banner; SSH follows it with binary key-exchange data.
    let first = buf[..n].split(|&b| b == b'\n').next().unwrap_or(&[]);
    let mut text = printable(first);
    if text.is_empty() && port == 23 {
        text = "TELNET NEGOTIATION (IAC)".into();
    }
    (!text.is_empty()).then(|| Banner {
        port,
        proto: proto.into(),
        text,
    })
}

fn realm(www_auth: &str) -> Option<String> {
    let l = www_auth.to_ascii_lowercase();
    let i = l.find("realm=")? + 6;
    let rest = &www_auth[i..];
    let v = match rest.strip_prefix('"') {
        Some(r) => r.split('"').next()?,
        None => rest.split([',', ' ']).next()?,
    };
    let v = clean(v);
    (!v.is_empty()).then_some(v)
}

/// `GET /` and extract status, Server, title, X-Powered-By, auth realm, redirect.
pub async fn http_fingerprint(
    client: &Client,
    ip: Ipv4Addr,
    port: u16,
    tls: bool,
) -> Option<HttpFingerprint> {
    let url = format!("{}://{ip}:{port}/", if tls { "https" } else { "http" });
    let mut resp = client.get(&url).send().await.ok()?;
    let h = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(clean)
            .filter(|s| !s.is_empty())
    };
    let (server, powered_by, redirect) = (h("server"), h("x-powered-by"), h("location"));
    let auth_realm = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .and_then(realm);
    let status = resp.status().as_u16();
    let mut body = Vec::new();
    while let Ok(Some(c)) = resp.chunk().await {
        body.extend_from_slice(&c);
        if body.len() > 64 * 1024
            || String::from_utf8_lossy(&body)
                .to_ascii_lowercase()
                .contains("</title>")
        {
            break;
        }
    }
    let title = html_title(&String::from_utf8_lossy(&body));
    Some(HttpFingerprint {
        port,
        tls,
        status,
        server,
        title,
        powered_by,
        auth_realm,
        redirect,
    })
}

/// RTSP `OPTIONS`: the `Server:` header usually names the camera vendor.
pub async fn rtsp_options(ip: Ipv4Addr) -> Option<Banner> {
    let mut s = connect(ip, 554).await?;
    let req =
        format!("OPTIONS rtsp://{ip}:554/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: netscan/0.1\r\n\r\n");
    timeout(IO_TIMEOUT, s.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = [0u8; 1024];
    let n = timeout(IO_TIMEOUT, s.read(&mut buf)).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);
    let mut lines = text.lines();
    let status = lines.next().filter(|l| l.starts_with("RTSP/"))?;
    let mut parts = vec![clean(status)];
    for l in lines {
        if let Some((k, v)) = l.split_once(':')
            && matches!(k.trim().to_ascii_lowercase().as_str(), "server" | "public")
        {
            parts.push(format!("{}: {}", k.trim(), clean(v)));
        }
    }
    Some(Banner {
        port: 554,
        proto: "RTSP".into(),
        text: parts.join(" // "),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn serve(canned: &'static [u8], read_first: bool) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                if read_first {
                    let mut b = [0u8; 512];
                    let _ = s.read(&mut b).await;
                }
                let _ = s.write_all(canned).await;
                let _ = s.shutdown().await;
            }
        });
        port
    }

    #[tokio::test]
    async fn http_title_server_realm() {
        let port = serve(
            b"HTTP/1.1 401 Unauthorized\r\nServer: lighttpd/1.4.55\r\nWWW-Authenticate: Basic realm=\"Router Admin\"\r\nContent-Length: 40\r\n\r\n<html><TITLE> Login </TITLE></html>",
            true,
        )
        .await;
        let c = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let f = http_fingerprint(&c, Ipv4Addr::LOCALHOST, port, false)
            .await
            .unwrap();
        assert_eq!(f.status, 401);
        assert_eq!(f.server.as_deref(), Some("lighttpd/1.4.55"));
        assert_eq!(f.title.as_deref(), Some("Login"));
        assert_eq!(f.auth_realm.as_deref(), Some("Router Admin"));
    }

    #[tokio::test]
    async fn banner_text_cleaning() {
        assert_eq!(
            printable(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"),
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
        );
        assert_eq!(printable(&[0xff, 0xfd, 0x18, 0xff, 0xfd, 0x20]), "");
        assert_eq!(
            printable(
                b"SSH-2.0-x\r\n\x00\x01bin"
                    .split(|&b| b == b'\n')
                    .next()
                    .unwrap()
            ),
            "SSH-2.0-x"
        );
        assert_eq!(realm("Digest realm=cam, nonce=1").as_deref(), Some("cam"));
    }

    #[tokio::test]
    async fn banner_over_socket() {
        let port = serve(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n", false).await;
        // `banner` only knows standard ports; exercise the raw read path directly.
        let mut s = connect(Ipv4Addr::LOCALHOST, port).await.unwrap();
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf).await.unwrap();
        assert!(printable(&buf[..n]).starts_with("SSH-2.0"));
    }

    #[tokio::test]
    async fn rtsp_ok() {
        let l = TcpListener::bind("127.0.0.1:554").await;
        if let Ok(l) = l {
            tokio::spawn(async move {
                if let Ok((mut s, _)) = l.accept().await {
                    let mut b = [0u8; 512];
                    let _ = s.read(&mut b).await;
                    let _ = s.write_all(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hikvision-Webs\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n").await;
                }
            });
            let b = rtsp_options(Ipv4Addr::LOCALHOST).await.unwrap();
            assert!(b.text.contains("Hikvision-Webs"));
        }
    }
}

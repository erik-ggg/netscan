//! SSDP (UPnP) discovery: one multicast M-SEARCH covers the whole LAN, then the
//! device description XML gives friendly names and model data.

use super::model::UpnpInfo;
use super::textutil::{clean, xml_tag};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

const MSEARCH: &str = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SsdpHit {
    pub location: Option<String>,
    pub server: Option<String>,
    pub st: Vec<String>,
    pub usn: Option<String>,
}

/// Parse one SSDP response (headers are case-insensitive).
pub fn parse_response(text: &str) -> Option<SsdpHit> {
    let mut lines = text.lines();
    let first = lines.next()?;
    if !first.starts_with("HTTP/1.1 200") && !first.to_ascii_uppercase().starts_with("NOTIFY") {
        return None;
    }
    let mut hit = SsdpHit::default();
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "location" => hit.location = Some(v.to_string()),
            "server" => hit.server = Some(clean(v)),
            "st" | "nt" => hit.st.push(v.to_string()),
            "usn" => hit.usn = Some(v.to_string()),
            _ => {}
        }
    }
    Some(hit)
}

/// Multicast M-SEARCH for `dur`; returns merged hits per responder IP.
pub async fn discover(dur: Duration) -> BTreeMap<Ipv4Addr, SsdpHit> {
    let mut out: BTreeMap<Ipv4Addr, SsdpHit> = BTreeMap::new();
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        return out;
    };
    let _ = sock.set_multicast_ttl_v4(2);
    let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);
    let _ = sock.send_to(MSEARCH.as_bytes(), dest).await;
    let deadline = tokio::time::Instant::now() + dur;
    let mut resent = false;
    let mut buf = [0u8; 2048];
    loop {
        if !resent
            && tokio::time::Instant::now() + dur.saturating_sub(Duration::from_millis(300))
                >= deadline
        {
            resent = true;
            let _ = sock.send_to(MSEARCH.as_bytes(), dest).await;
        }
        let Ok(Ok((n, from))) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await
        else {
            break;
        };
        let IpAddr::V4(ip) = from.ip() else { continue };
        let Some(hit) = parse_response(&String::from_utf8_lossy(&buf[..n])) else {
            continue;
        };
        let e = out.entry(ip).or_default();
        if e.location.is_none() {
            e.location = hit.location;
        }
        if e.server.is_none() {
            e.server = hit.server;
        }
        if e.usn.is_none() {
            e.usn = hit.usn;
        }
        e.st.extend(hit.st);
    }
    out
}

/// Host part of an `http://host[:port]/path` URL.
fn location_host(loc: &str) -> Option<&str> {
    let rest = loc.strip_prefix("http://")?;
    let auth = rest.split('/').next()?;
    Some(auth.rsplit_once(':').map_or(auth, |(h, _)| h))
}

/// Fetch and parse the description XML. Only LOCATIONs whose host equals the
/// responder IP are fetched (never follow a device to a third party).
pub async fn fetch_description(
    client: &reqwest::Client,
    ip: Ipv4Addr,
    loc: &str,
) -> Option<UpnpInfo> {
    if location_host(loc)? != ip.to_string() {
        return None;
    }
    let mut resp = client.get(loc).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let mut body = Vec::new();
    while let Ok(Some(c)) = resp.chunk().await {
        body.extend_from_slice(&c);
        if body.len() > 64 * 1024 {
            break;
        }
    }
    Some(parse_description(&String::from_utf8_lossy(&body), loc))
}

pub fn parse_description(xml: &str, loc: &str) -> UpnpInfo {
    UpnpInfo {
        location: loc.to_string(),
        server: None,
        device_type: xml_tag(xml, "deviceType"),
        friendly_name: xml_tag(xml, "friendlyName"),
        manufacturer: xml_tag(xml, "manufacturer"),
        model_name: xml_tag(xml, "modelName"),
        model_number: xml_tag(xml, "modelNumber"),
        model_description: xml_tag(xml, "modelDescription"),
        presentation_url: xml_tag(xml, "presentationURL"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_headers_case_insensitively() {
        let r = "HTTP/1.1 200 OK\r\nCache-Control: max-age=1800\r\nLocation: http://192.168.1.34:3000/dd.xml\r\nSERVER: WebOS/4.1 UPnP/1.0\r\nst: upnp:rootdevice\r\nUSN: uuid:abc::upnp:rootdevice\r\n\r\n";
        let h = parse_response(r).unwrap();
        assert_eq!(
            h.location.as_deref(),
            Some("http://192.168.1.34:3000/dd.xml")
        );
        assert_eq!(h.server.as_deref(), Some("WebOS/4.1 UPnP/1.0"));
        assert_eq!(h.st, vec!["upnp:rootdevice"]);
        assert!(parse_response("garbage").is_none());
    }

    #[test]
    fn parses_igd_description() {
        let x = r#"<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<friendlyName>Starlink &amp; Co</friendlyName><manufacturer>SpaceX</manufacturer>
<modelName>Dishy</modelName></device></root>"#;
        let u = parse_description(x, "http://192.168.1.1:49152/d.xml");
        assert_eq!(u.friendly_name.as_deref(), Some("Starlink & Co"));
        assert!(u.device_type.unwrap().contains("InternetGatewayDevice"));
        assert_eq!(u.model_name.as_deref(), Some("Dishy"));
    }

    #[test]
    fn location_host_checked() {
        assert_eq!(location_host("http://10.0.0.5:80/x"), Some("10.0.0.5"));
        assert_eq!(location_host("http://10.0.0.5/x"), Some("10.0.0.5"));
        assert_eq!(location_host("https://10.0.0.5/x"), None);
    }

    #[tokio::test]
    async fn fetch_description_loopback_and_host_guard() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 512];
            let _ = s.read(&mut b).await;
            let body = "<root><device><friendlyName>Test TV</friendlyName></device></root>";
            let _ = s
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await;
        });
        let c = reqwest::Client::new();
        let loc = format!("http://127.0.0.1:{port}/d.xml");
        // Responder IP differs from the LOCATION host: refused without a request.
        assert!(
            fetch_description(&c, Ipv4Addr::new(10, 9, 9, 9), &loc)
                .await
                .is_none()
        );
        let u = fetch_description(&c, Ipv4Addr::LOCALHOST, &loc)
            .await
            .unwrap();
        assert_eq!(u.friendly_name.as_deref(), Some("Test TV"));
    }
}

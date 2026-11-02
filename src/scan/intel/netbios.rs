//! NetBIOS node status (NBSTAT) over UDP 137: Windows/Samba host name + workgroup.

use crate::scan::model::NetBiosInfo;
use crate::scan::net::fmt_mac;
use crate::scan::textutil::clean;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// 50-byte NBSTAT request for the wildcard name `*`.
pub fn build_query(txid: u16) -> [u8; 50] {
    let mut q = [0u8; 50];
    q[0..2].copy_from_slice(&txid.to_be_bytes());
    q[5] = 1; // QDCOUNT = 1
    q[12] = 0x20;
    q[13] = b'C';
    q[14] = b'K';
    for b in &mut q[15..45] {
        *b = b'A';
    }
    // q[45] = 0 terminator
    q[47] = 0x21; // type NBSTAT
    q[49] = 0x01; // class IN
    q
}

pub fn parse_status(b: &[u8]) -> Option<NetBiosInfo> {
    // 12 header + 34 echoed name + type/class/ttl/rdlen (10) = 56, then count.
    let num = *b.get(56)? as usize;
    if num == 0 {
        return None;
    }
    let mut name = None;
    let mut group = None;
    for i in 0..num {
        let e = b.get(57 + i * 18..57 + (i + 1) * 18)?;
        let text = clean(&String::from_utf8_lossy(&e[..15]));
        let suffix = e[15];
        let is_group = u16::from_be_bytes([e[16], e[17]]) & 0x8000 != 0;
        if suffix != 0 || text.is_empty() {
            continue;
        }
        if is_group {
            group.get_or_insert(text);
        } else {
            name.get_or_insert(text);
        }
    }
    let mac = b
        .get(57 + num * 18..57 + num * 18 + 6)
        .map(|m| fmt_mac([m[0], m[1], m[2], m[3], m[4], m[5]]))
        .filter(|m| m != "00:00:00:00:00:00");
    Some(NetBiosInfo {
        name: name?,
        group,
        mac,
    })
}

pub async fn query(ip: Ipv4Addr) -> Option<NetBiosInfo> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect(SocketAddr::new(IpAddr::V4(ip), 137))
        .await
        .ok()?;
    let txid = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .subsec_nanos()
        & 0xffff) as u16;
    sock.send(&build_query(txid)).await.ok()?;
    let mut buf = [0u8; 1024];
    let n = timeout(Duration::from_millis(800), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n < 57 || buf[0..2] != txid.to_be_bytes() {
        return None;
    }
    parse_status(&buf[..n])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_layout() {
        let q = build_query(0x1234);
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(q[5], 1);
        assert_eq!(q[12], 0x20);
        assert_eq!(&q[13..15], b"CK");
        assert_eq!(q[47], 0x21);
        assert_eq!(q[49], 1);
    }

    fn entry(name: &str, suffix: u8, flags: u16) -> Vec<u8> {
        let mut e = format!("{name:<15}").into_bytes();
        e.push(suffix);
        e.extend_from_slice(&flags.to_be_bytes());
        e
    }

    #[test]
    fn parse_names_and_mac() {
        let mut b = vec![0u8; 56];
        b.push(3);
        b.extend(entry("DESKTOP-ABC", 0x00, 0x0400));
        b.extend(entry("WORKGROUP", 0x00, 0x8400));
        b.extend(entry("DESKTOP-ABC", 0x20, 0x0400));
        b.extend([0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33]);
        let i = parse_status(&b).unwrap();
        assert_eq!(i.name, "DESKTOP-ABC");
        assert_eq!(i.group.as_deref(), Some("WORKGROUP"));
        assert_eq!(i.mac.as_deref(), Some("aa:bb:cc:11:22:33"));
        assert!(parse_status(&[0u8; 20]).is_none());
    }
}

//! Radial layout: devices are grouped by category into angular sectors and
//! spread over 1–3 elliptical rings around the router.

use crate::scan::model::{Device, DeviceKind};

pub const W: f64 = 1280.0;
pub const H: f64 = 760.0;
pub const CX: f64 = 640.0;
pub const CY: f64 = 392.0;
pub const NET_POS: (f64, f64) = (640.0, 62.0);

#[derive(Debug, Clone, Copy)]
pub struct Placed {
    /// Index into the device slice passed to `layout`.
    pub idx: usize,
    pub x: f64,
    pub y: f64,
}

const R1: &[(f64, f64)] = &[(400.0, 235.0)];
const R2: &[(f64, f64)] = &[(300.0, 175.0), (510.0, 272.0)];
const R3: &[(f64, f64)] = &[(270.0, 150.0), (400.0, 215.0), (525.0, 280.0)];

/// Ring radii, ring assignment pattern (weighted toward the longer outer
/// rings) and node scale for a given device count. Tuned against the
/// collision test below.
fn config(n: usize) -> (&'static [(f64, f64)], &'static [usize], f64) {
    match n {
        0..=7 => (R1, &[0], 1.0),
        8..=9 => (R2, &[1, 0], 1.0),
        10..=14 => (R2, &[1, 0], 1.0),
        15..=19 => (R3, &[2, 1, 2, 0], 0.8),
        20..=25 => (R3, &[2, 1, 2, 0], 0.66),
        _ => (R3, &[2, 1, 2, 0], 0.6),
    }
}

/// Visual scale of device nodes (and their labels) for a given device count.
pub fn node_scale(n: usize) -> f64 {
    config(n).2
}

fn order(k: DeviceKind) -> u8 {
    use DeviceKind::*;
    match k {
        Computer => 0,
        Mobile => 1,
        Tablet => 2,
        Iot => 3,
        Tv => 4,
        Media => 5,
        Car => 6,
        Printer => 7,
        Console => 8,
        Unknown => 9,
        Router => 10,
        Internet => 11,
    }
}

fn ip_key(ip: &str) -> u32 {
    ip.parse::<std::net::Ipv4Addr>().map(u32::from).unwrap_or(0)
}

/// Index of the router (gateway) in `devices`, if any.
pub fn router_index(devices: &[Device]) -> Option<usize> {
    devices
        .iter()
        .position(|d| d.is_gateway)
        .or_else(|| devices.iter().position(|d| d.kind == DeviceKind::Router))
}

pub fn layout(devices: &[Device]) -> Vec<Placed> {
    let router = router_index(devices);
    let mut idxs: Vec<usize> = (0..devices.len()).filter(|&i| Some(i) != router).collect();
    idxs.sort_by_key(|&i| {
        let d = &devices[i];
        (order(d.kind), !d.is_self, ip_key(&d.ip))
    });
    let n = idxs.len();
    if n == 0 {
        return vec![];
    }
    let (rings, pattern, _) = config(n);

    let groups = 1 + idxs
        .windows(2)
        .filter(|w| devices[w[0]].kind != devices[w[1]].kind)
        .count();
    let gap = 0.4;
    let units = n as f64 + gap * (groups as f64 - 1.0);
    let full = 360.0 - 2.0 * 30.0;
    let unit_deg = (full / units).min(36.0);
    let used = unit_deg * units;
    let start = 180.0 - used / 2.0;

    let mut pos = 0.0;
    let mut out = Vec::with_capacity(n);
    for (k, &i) in idxs.iter().enumerate() {
        if k > 0 && devices[idxs[k - 1]].kind != devices[i].kind {
            pos += gap;
        }
        let a = (start + (pos + 0.5) * unit_deg).to_radians();
        pos += 1.0;
        let (rx, ry) = rings[pattern[k % pattern.len()]];
        out.push(Placed {
            idx: i,
            x: CX + rx * a.sin(),
            y: CY - ry * a.cos(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(i: usize, kind: DeviceKind) -> Device {
        Device {
            ip: format!("192.168.1.{}", i + 2),
            is_gateway: i == 0,
            kind: if i == 0 { DeviceKind::Router } else { kind },
            ..Default::default()
        }
    }

    /// Node (+-31) and label (+-65 wide, 38..68 below) boxes, scaled by `sc`.
    fn boxes(p: &Placed, sc: f64) -> [(f64, f64, f64, f64); 2] {
        [
            (
                p.x - 31.0 * sc,
                p.y - 31.0 * sc,
                p.x + 31.0 * sc,
                p.y + 31.0 * sc,
            ),
            (
                p.x - 65.0 * sc,
                p.y + 38.0 * sc,
                p.x + 65.0 * sc,
                p.y + 68.0 * sc,
            ),
        ]
    }

    fn collide(a: &Placed, b: &Placed, sc: f64) -> bool {
        boxes(a, sc).iter().any(|r| {
            boxes(b, sc)
                .iter()
                .any(|q| r.0 < q.2 && q.0 < r.2 && r.1 < q.3 && q.1 < r.3)
        })
    }

    #[test]
    fn no_overlap_for_1_to_40() {
        use DeviceKind::*;
        let kinds = [
            Mobile, Iot, Unknown, Computer, Tv, Car, Printer, Console, Media, Tablet,
        ];
        for n in 1..=40 {
            let devs: Vec<Device> = (0..=n).map(|i| dev(i, kinds[i % 10])).collect();
            let p = layout(&devs);
            assert_eq!(p.len(), n);
            for a in 0..p.len() {
                assert!(p[a].x > 70.0 && p[a].x < W - 60.0 && p[a].y > 90.0 && p[a].y < H - 70.0);
                for b in a + 1..p.len() {
                    let d = ((p[a].x - p[b].x).powi(2) + (p[a].y - p[b].y).powi(2)).sqrt();
                    let sc = node_scale(n);
                    assert!(d > 62.0 * sc, "n={n} nodes {a},{b} too close: {d}");
                    assert!(!collide(&p[a], &p[b], sc), "n={n} nodes {a},{b} collide");
                }
            }
        }
    }
}

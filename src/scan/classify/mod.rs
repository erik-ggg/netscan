//! Evidence-weighted device classification.
//!
//! Every rule (see `rules.rs`) pushes weighted `Evidence`; per-kind weights
//! are combined with a noisy-OR and the strongest kind wins.

pub mod brands;
pub mod patterns;
mod rules;
#[cfg(test)]
mod tests;

use super::model::{Classification, Device, DeviceIntel, DeviceKind as K, Evidence};
use rules::Ev;

/// Tie-break order when two kinds have equal probability.
const PRIORITY: [K; 10] = [
    K::Router,
    K::Printer,
    K::Console,
    K::Car,
    K::Tv,
    K::Media,
    K::Tablet,
    K::Mobile,
    K::Computer,
    K::Iot,
];

fn role(kind: K, text: &str) -> Classification {
    Classification {
        kind,
        confidence: 100,
        label: None,
        reason: text.into(),
        evidence: vec![Evidence {
            kind,
            weight: 99,
            source: super::model::EvSource::Role,
            text: text.into(),
        }],
        alt: vec![],
    }
}

/// Noisy-OR of a kind's evidence, ignoring generic priors (vendor, TTL, MAC).
fn specific_p(evs: &[Ev], k: K) -> f32 {
    use super::model::EvSource as S;
    1.0 - evs
        .iter()
        .filter(|e| e.kind == k && !matches!(e.source, S::Vendor | S::Ttl | S::Mac))
        .fold(1.0, |m, e| m * (1.0 - e.weight as f32 / 100.0))
}

/// Score a device from everything known about it (`intel` adds deep-scan facts).
pub fn assess(d: &Device, intel: Option<&DeviceIntel>) -> Classification {
    if d.is_gateway {
        return role(K::Router, "ROLE \u{25B8} DEFAULT GATEWAY");
    }
    if d.is_self {
        return role(K::Computer, "ROLE \u{25B8} THIS MACHINE");
    }
    // One entry per (rule id, kind): keep the strongest.
    let mut evs: Vec<Ev> = Vec::new();
    for e in rules::collect(d, intel) {
        match evs.iter_mut().find(|x| x.id == e.id && x.kind == e.kind) {
            Some(x) if e.weight > x.weight => *x = e,
            Some(_) => {}
            None => evs.push(e),
        }
    }
    if evs.is_empty() {
        return Classification {
            kind: K::Unknown,
            reason: "NO EVIDENCE".into(),
            ..Default::default()
        };
    }
    // Per-kind noisy-OR.
    let mut ps: Vec<(K, f32)> = PRIORITY
        .iter()
        .filter_map(|&k| {
            let mut miss = 1.0f32;
            let mut any = false;
            for e in evs.iter().filter(|e| e.kind == k) {
                miss *= 1.0 - e.weight as f32 / 100.0;
                any = true;
            }
            any.then_some((k, 1.0 - miss))
        })
        .collect();
    // Stable sort keeps PRIORITY order on ties.
    ps.sort_by(|a, b| {
        if (a.1 - b.1).abs() < 1e-6 {
            std::cmp::Ordering::Equal
        } else {
            b.1.total_cmp(&a.1)
        }
    });
    let (best, p1) = ps.first().copied().unwrap_or((K::Unknown, 0.0));
    let p2 = ps.get(1).map_or(0.0, |x| x.1);

    evs.sort_by_key(|e| std::cmp::Reverse(e.weight));
    let winner_top = evs.iter().find(|e| e.kind == best);
    let alt: Vec<(K, u8)> = ps
        .iter()
        .skip(1)
        .take(2)
        .map(|&(k, p)| (k, (p * 100.0).round() as u8))
        .collect();

    let (kind, confidence, label, reason) = if p1 < 0.30 {
        (
            K::Unknown,
            (p1 * 100.0).round() as u8,
            None,
            format!("WEAK: {} {}%", best.name(), (p1 * 100.0).round() as u8),
        )
    } else {
        // Generic priors (vendor/TTL/MAC) cannot dent a winner that direct
        // evidence already settles.
        let p2 = if specific_p(&evs, best) >= 0.9 {
            PRIORITY
                .iter()
                .filter(|&&k| k != best)
                .map(|&k| specific_p(&evs, k))
                .fold(0.0, f32::max)
        } else {
            p2
        };
        let conf = (100.0 * p1 * (1.0 - p2 * p2 / 2.0))
            .round()
            .clamp(1.0, 99.0) as u8;
        let label = evs
            .iter()
            .filter(|e| e.kind == best)
            .find_map(|e| e.label)
            .map(String::from);
        (
            best,
            conf,
            label,
            winner_top.map(|e| e.text.clone()).unwrap_or_default(),
        )
    };

    // Winner's evidence first, then the rest (each descending by weight).
    let (mut ordered, rest): (Vec<&Ev>, Vec<&Ev>) = evs.iter().partition(|e| e.kind == best);
    ordered.extend(rest);
    Classification {
        kind,
        confidence,
        label,
        reason,
        evidence: ordered
            .into_iter()
            .map(|e| Evidence {
                kind: e.kind,
                weight: e.weight,
                source: e.source,
                text: e.text.clone(),
            })
            .collect(),
        alt,
    }
}

/// Compatibility wrapper: the winning kind from sweep facts only.
#[allow(dead_code)] // compat API; the pipeline calls `assess` directly
pub fn classify(d: &Device) -> K {
    assess(d, None).kind
}

/// Re-assess with deep-scan facts. `Some` only when the kind changes with confidence >= 50.
#[allow(dead_code)]
pub fn refine(d: &Device, i: &DeviceIntel) -> Option<(K, String)> {
    if d.is_gateway || d.is_self {
        return None;
    }
    let c = assess(d, Some(i));
    (c.kind != d.kind && c.confidence >= 50).then_some((c.kind, c.reason))
}

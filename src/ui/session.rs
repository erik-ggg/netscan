//! Live state of one deep scan, folded from `IntelEvent`s. Pure: unit-tested without a UI.

use crate::scan::model::*;

#[derive(Debug, Clone, PartialEq)]
pub struct IntelSession {
    pub ip: String,
    pub log: Vec<String>,
    pub stage: IntelStage,
    pub pct: u8,
    pub ports: Vec<(u16, PortState)>,
    pub echoes: Vec<Option<f32>>,
    pub intel: Option<DeviceIntel>,
    pub done: bool,
    /// Bumps on every re-scan; lets a stale event pump know it was superseded.
    pub run: u32,
}

/// Terminal line for one resolved port (state word is last-but-service so the UI can colour it).
fn port_line(port: u16, state: PortState) -> String {
    match state {
        PortState::Open => format!(
            "PORT {port:04} ······· OPEN // {}",
            crate::scan::intel::ports::spec(port).map_or("?", |s| s.service)
        ),
        PortState::Closed => format!("PORT {port:04} ······· CLOSED"),
        PortState::Filtered => format!("PORT {port:04} ······· FILTERED"),
    }
}

impl IntelSession {
    pub fn new(ip: &str, run: u32) -> Self {
        Self {
            ip: ip.to_string(),
            log: vec![],
            stage: IntelStage::Echo,
            pct: 0,
            ports: vec![],
            echoes: vec![],
            intel: None,
            done: false,
            run,
        }
    }

    pub fn apply(&mut self, ev: IntelEvent) {
        match ev {
            IntelEvent::Stage { stage, pct } => {
                self.stage = stage;
                self.pct = self.pct.max(pct.min(100));
            }
            IntelEvent::Log(l) => self.log.push(l),
            IntelEvent::Echo { seq, rtt_ms, ttl } => {
                self.log.push(match rtt_ms {
                    Some(r) => format!(
                        "ECHO {}/4 ······· {r:.1}ms TTL {:03}",
                        seq as usize + 1,
                        ttl.unwrap_or(0)
                    ),
                    None => format!("ECHO {}/4 ······· LOST", seq as usize + 1),
                });
                let i = seq as usize;
                if self.echoes.len() <= i {
                    self.echoes.resize(i + 1, None);
                }
                self.echoes[i] = rtt_ms;
            }
            IntelEvent::Port { port, state } => {
                self.log.push(port_line(port, state));
                self.set_port(port, state)
            }
            IntelEvent::Snapshot(i) => self.intel = Some(*i),
            IntelEvent::Done(i) => {
                self.intel = Some(*i);
                self.done = true;
                self.pct = 100;
            }
        }
    }

    fn set_port(&mut self, port: u16, state: PortState) {
        match self.ports.iter_mut().find(|p| p.0 == port) {
            Some(p) => p.1 = state,
            None => self.ports.push((port, state)),
        }
    }

    pub fn open_count(&self) -> usize {
        match &self.intel {
            Some(i) if !i.ports.is_empty() => i
                .ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .count(),
            _ => self.ports.iter().filter(|p| p.1 == PortState::Open).count(),
        }
    }

    /// Finished scan where nothing answered: no open port and no echo reply.
    pub fn is_dark(&self) -> bool {
        self.done
            && self.open_count() == 0
            && self
                .intel
                .as_ref()
                .is_none_or(|i| i.ping.as_ref().is_none_or(|p| p.recv == 0))
    }

    /// Has the Fingerprint stage's data landed (snapshot with ports populated)?
    pub fn fingerprinted(&self) -> bool {
        self.done || matches!(self.stage, IntelStage::Assemble)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intel(open: &[u16], recv: u8) -> Box<DeviceIntel> {
        Box::new(DeviceIntel {
            ip: "1.1.1.1".into(),
            complete: true,
            ports: open
                .iter()
                .map(|&p| PortInfo {
                    port: p,
                    state: PortState::Open,
                    ..Default::default()
                })
                .collect(),
            ping: Some(PingStats {
                sent: 4,
                recv,
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    #[test]
    fn folds_events() {
        let mut s = IntelSession::new("1.1.1.1", 1);
        s.apply(IntelEvent::Stage {
            stage: IntelStage::Echo,
            pct: 10,
        });
        s.apply(IntelEvent::Echo {
            seq: 2,
            rtt_ms: Some(3.0),
            ttl: Some(64),
        });
        s.apply(IntelEvent::Echo {
            seq: 0,
            rtt_ms: None,
            ttl: None,
        });
        assert_eq!(s.echoes, vec![None, None, Some(3.0)]);
        s.apply(IntelEvent::Port {
            port: 22,
            state: PortState::Filtered,
        });
        s.apply(IntelEvent::Port {
            port: 22,
            state: PortState::Open,
        });
        s.apply(IntelEvent::Port {
            port: 80,
            state: PortState::Closed,
        });
        assert_eq!(
            s.ports,
            vec![(22, PortState::Open), (80, PortState::Closed)]
        );
        assert_eq!(s.open_count(), 1);
        s.apply(IntelEvent::Log("x".into()));
        // 2 echo lines + 3 port lines + the explicit log
        assert_eq!(s.log.len(), 6);
        assert_eq!(s.log[0], "ECHO 3/4 ······· 3.0ms TTL 064");
        assert!(s.log.iter().any(|l| l == "PORT 0080 ······· CLOSED"));
        assert!(!s.done && s.intel.is_none());
    }

    #[test]
    fn pct_never_decreases_and_done_finishes() {
        let mut s = IntelSession::new("1.1.1.1", 1);
        s.apply(IntelEvent::Stage {
            stage: IntelStage::Lattice,
            pct: 40,
        });
        s.apply(IntelEvent::Stage {
            stage: IntelStage::Lattice,
            pct: 20,
        });
        assert_eq!(s.pct, 40);
        s.apply(IntelEvent::Snapshot(intel(&[80], 4)));
        assert!(s.intel.is_some() && !s.done);
        s.apply(IntelEvent::Done(intel(&[80], 4)));
        assert!(s.done && s.pct == 100);
        assert!(!s.is_dark());
    }

    #[test]
    fn dark_target() {
        let mut s = IntelSession::new("1.1.1.1", 1);
        assert!(!s.is_dark());
        s.apply(IntelEvent::Done(intel(&[], 0)));
        assert!(s.is_dark());
    }
}

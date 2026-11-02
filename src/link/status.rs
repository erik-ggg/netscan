//! Advisory link status derived from terminal output. Never drives input.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkStatus {
    Linked,
    AwaitingAuth,
    AwaitingSecret,
    HostKeyPrompt,
    Failed,
    KeyIssue,
    Paired,
    Dropped(Option<i32>),
}

/// (phrase, status). Later position in the tail wins; ties go to table order.
const PHRASES: &[(&str, LinkStatus)] = &[
    ("connected to ", LinkStatus::Linked),
    ("already connected", LinkStatus::Linked),
    ("unauthorized", LinkStatus::AwaitingAuth),
    ("failed to authenticate", LinkStatus::AwaitingAuth),
    ("password:", LinkStatus::AwaitingSecret),
    ("passphrase", LinkStatus::AwaitingSecret),
    (
        "are you sure you want to continue connecting",
        LinkStatus::HostKeyPrompt,
    ),
    ("connection refused", LinkStatus::Failed),
    ("no route", LinkStatus::Failed),
    ("timed out", LinkStatus::Failed),
    ("cannot connect", LinkStatus::Failed),
    ("failed to connect", LinkStatus::Failed),
    ("host key verification failed", LinkStatus::KeyIssue),
    ("no matching host key type", LinkStatus::KeyIssue),
    ("successfully paired", LinkStatus::Paired),
];

const TAIL: usize = 512;

#[derive(Default)]
pub struct Watcher {
    tail: String,
}

impl Watcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed raw output; returns a status when a phrase newly appears.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<LinkStatus> {
        self.tail
            .push_str(&String::from_utf8_lossy(bytes).to_lowercase());
        if self.tail.len() > TAIL {
            let mut cut = self.tail.len() - TAIL;
            while !self.tail.is_char_boundary(cut) {
                cut += 1;
            }
            self.tail.drain(..cut);
        }
        let hit = PHRASES
            .iter()
            .filter_map(|(p, s)| self.tail.rfind(p).map(|pos| (pos, *s)))
            .max_by_key(|(pos, _)| *pos);
        if hit.is_some() {
            // consume: the same phrase must not fire again on the next chunk
            self.tail.clear();
        }
        hit.map(|(_, s)| s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(s: &str) -> Option<LinkStatus> {
        Watcher::new().feed(s.as_bytes())
    }

    #[test]
    fn phrase_table() {
        use LinkStatus::*;
        for (txt, want) in [
            ("connected to 192.168.1.32:5555\r\n", Some(Linked)),
            ("already connected to 192.168.1.32:5555", Some(Linked)),
            ("error: device unauthorized.", Some(AwaitingAuth)),
            (
                "failed to authenticate to 192.168.1.32:5555",
                Some(AwaitingAuth),
            ),
            ("root@192.168.1.194's Password: ", Some(AwaitingSecret)),
            ("Enter passphrase for key", Some(AwaitingSecret)),
            (
                "Are you sure you want to continue connecting (yes/no)?",
                Some(HostKeyPrompt),
            ),
            ("ssh: connect: Connection refused", Some(Failed)),
            ("No route to host", Some(Failed)),
            ("Connection timed out", Some(Failed)),
            ("failed to connect to 1.2.3.4:5555", Some(Failed)),
            ("Host key verification failed.", Some(KeyIssue)),
            (
                "Unable to negotiate: no matching host key type found",
                Some(KeyIssue),
            ),
            ("Successfully paired to 192.168.1.32:41235", Some(Paired)),
            ("just a shell prompt $ ", None),
        ] {
            assert_eq!(one(txt), want, "{txt}");
        }
    }

    #[test]
    fn phrase_split_across_chunks_and_no_refire() {
        let mut w = Watcher::new();
        assert_eq!(w.feed(b"Pass"), None);
        assert_eq!(w.feed(b"word: "), Some(LinkStatus::AwaitingSecret));
        assert_eq!(w.feed(b"hello"), None);
    }

    #[test]
    fn latest_phrase_wins() {
        let mut w = Watcher::new();
        let s = w.feed(b"failed to authenticate to x\r\nconnected to x:5555\r\n");
        assert_eq!(s, Some(LinkStatus::Linked));
    }

    #[test]
    fn tail_is_bounded_and_utf8_safe() {
        let mut w = Watcher::new();
        for _ in 0..200 {
            w.feed("接続 xx".as_bytes());
        }
        assert!(w.tail.len() <= TAIL);
    }
}

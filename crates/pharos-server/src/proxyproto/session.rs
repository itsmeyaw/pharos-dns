//! Bounded, expiring UDP session cache for Cloudflare Spectrum style PROXY headers.

use std::{collections::HashMap, net::SocketAddr, time::Duration, time::Instant};

// CoreDNS v1.15.0 plugin/pkg/proxyproto/udp_session.go udpSessionMaxEntries.
pub const DEFAULT_MAX_SESSIONS: usize = 10_240;
const NONE: usize = usize::MAX;

struct Node {
    key: SocketAddr,
    source: SocketAddr,
    tlv: Box<str>,
    expires: Instant,
    newer: usize,
    older: usize,
}

/// Maps the proxy-side address of a datagram flow to the client address its header named.
pub struct Sessions {
    ttl: Duration,
    capacity: usize,
    index: HashMap<SocketAddr, usize>,
    nodes: Vec<Node>,
    free: Vec<usize>,
    newest: usize,
    oldest: usize,
}

impl Sessions {
    #[must_use]
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            index: HashMap::new(),
            nodes: Vec::new(),
            free: Vec::new(),
            newest: NONE,
            oldest: NONE,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Insert or refresh the session of `key`; a full cache evicts its least recently used entry.
    pub fn store(&mut self, key: SocketAddr, source: SocketAddr, tlv: &str, now: Instant) {
        let expires = now + self.ttl;
        if let Some(&at) = self.index.get(&key) {
            let node = &mut self.nodes[at];
            node.source = source;
            node.expires = expires;
            // Only a changed vector allocates, so a steady stream of identical headers does not.
            if *node.tlv != *tlv {
                node.tlv = tlv.into();
            }
            self.touch(at);
            return;
        }
        if self.index.len() >= self.capacity {
            self.remove(self.oldest);
        }
        let node = Node {
            key,
            source,
            tlv: tlv.into(),
            expires,
            newer: NONE,
            older: NONE,
        };
        let at = match self.free.pop() {
            Some(at) => {
                self.nodes[at] = node;
                at
            }
            None => {
                self.nodes.push(node);
                self.nodes.len() - 1
            }
        };
        self.index.insert(key, at);
        self.link_newest(at);
    }

    /// Return the client address of a live session, refreshing its expiry, and copy its TLV hex into `tlv`.
    pub fn lookup(
        &mut self,
        key: SocketAddr,
        now: Instant,
        tlv: &mut String,
    ) -> Option<SocketAddr> {
        let at = *self.index.get(&key)?;
        if self.nodes[at].expires <= now {
            self.remove(at);
            return None;
        }
        self.nodes[at].expires = now + self.ttl;
        self.touch(at);
        let node = &self.nodes[at];
        tlv.clear();
        tlv.push_str(&node.tlv);
        Some(node.source)
    }

    fn touch(&mut self, at: usize) {
        if self.newest != at {
            self.unlink(at);
            self.link_newest(at);
        }
    }

    fn remove(&mut self, at: usize) {
        self.unlink(at);
        self.index.remove(&self.nodes[at].key);
        self.nodes[at].tlv = Box::default();
        self.free.push(at);
    }

    fn unlink(&mut self, at: usize) {
        let (newer, older) = (self.nodes[at].newer, self.nodes[at].older);
        match newer {
            NONE => self.newest = older,
            newer => self.nodes[newer].older = older,
        }
        match older {
            NONE => self.oldest = newer,
            older => self.nodes[older].newer = newer,
        }
    }

    fn link_newest(&mut self, at: usize) {
        self.nodes[at].newer = NONE;
        self.nodes[at].older = self.newest;
        match self.newest {
            NONE => self.oldest = at,
            newest => self.nodes[newest].newer = at,
        }
        self.newest = at;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn lookup(sessions: &mut Sessions, key: &str, now: Instant) -> Option<SocketAddr> {
        sessions.lookup(addr(key), now, &mut String::new())
    }

    #[test]
    fn stored_session_is_found() {
        let now = Instant::now();
        let mut sessions = Sessions::new(Duration::from_secs(1), DEFAULT_MAX_SESSIONS);
        sessions.store(addr("10.0.0.1:5000"), addr("192.168.1.1:12345"), "", now);
        assert_eq!(
            lookup(&mut sessions, "10.0.0.1:5000", now),
            Some(addr("192.168.1.1:12345"))
        );
    }

    #[test]
    fn lookup_misses_on_an_empty_cache() {
        let mut sessions = Sessions::new(Duration::from_secs(1), DEFAULT_MAX_SESSIONS);
        assert_eq!(lookup(&mut sessions, "10.0.0.1:5000", Instant::now()), None);
    }

    #[test]
    fn expired_session_is_missing_and_released() {
        let now = Instant::now();
        let mut sessions = Sessions::new(Duration::from_millis(50), DEFAULT_MAX_SESSIONS);
        sessions.store(addr("10.0.0.1:5000"), addr("192.168.1.1:12345"), "", now);
        let later = now + Duration::from_millis(100);
        assert_eq!(lookup(&mut sessions, "10.0.0.1:5000", later), None);
        assert!(sessions.is_empty());
    }

    #[test]
    fn lookup_refreshes_the_expiry() {
        let now = Instant::now();
        let mut sessions = Sessions::new(Duration::from_millis(50), DEFAULT_MAX_SESSIONS);
        sessions.store(addr("10.0.0.1:5000"), addr("192.168.1.1:12345"), "", now);
        assert!(
            lookup(
                &mut sessions,
                "10.0.0.1:5000",
                now + Duration::from_millis(30)
            )
            .is_some()
        );
        // 60 ms after the store: past the original expiry, inside the refreshed one.
        assert!(
            lookup(
                &mut sessions,
                "10.0.0.1:5000",
                now + Duration::from_millis(60)
            )
            .is_some()
        );
    }

    #[test]
    fn store_refreshes_the_expiry_and_replaces_the_source() {
        let now = Instant::now();
        let mut sessions = Sessions::new(Duration::from_millis(50), DEFAULT_MAX_SESSIONS);
        sessions.store(addr("10.0.0.1:5000"), addr("192.168.1.1:1"), "", now);
        sessions.store(
            addr("10.0.0.1:5000"),
            addr("192.168.1.2:2"),
            "",
            now + Duration::from_millis(40),
        );
        assert_eq!(
            lookup(
                &mut sessions,
                "10.0.0.1:5000",
                now + Duration::from_millis(80)
            ),
            Some(addr("192.168.1.2:2"))
        );
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn custom_capacity_caps_the_cache() {
        let now = Instant::now();
        let mut sessions = Sessions::new(Duration::from_secs(1), 5);
        for port in 0..10 {
            let key = SocketAddr::from(([10, 0, 0, 1], port));
            sessions.store(key, SocketAddr::from(([1, 1, 1, 1], port)), "", now);
        }
        assert_eq!(sessions.len(), 5);
    }

    #[test]
    fn full_cache_evicts_the_least_recently_used_session() {
        let now = Instant::now();
        let mut sessions = Sessions::new(Duration::from_secs(60), 2);
        sessions.store(addr("10.0.0.1:1"), addr("1.1.1.1:1"), "", now);
        sessions.store(addr("10.0.0.2:2"), addr("2.2.2.2:2"), "", now);
        sessions.store(addr("10.0.0.3:3"), addr("3.3.3.3:3"), "", now);
        assert_eq!(lookup(&mut sessions, "10.0.0.1:1", now), None);
        assert!(lookup(&mut sessions, "10.0.0.2:2", now).is_some());
        assert!(lookup(&mut sessions, "10.0.0.3:3", now).is_some());
    }

    #[test]
    fn lookup_protects_a_session_from_eviction() {
        let now = Instant::now();
        let mut sessions = Sessions::new(Duration::from_secs(60), 2);
        sessions.store(addr("10.0.0.1:1"), addr("1.1.1.1:1"), "", now);
        sessions.store(addr("10.0.0.2:2"), addr("2.2.2.2:2"), "", now);
        assert!(lookup(&mut sessions, "10.0.0.1:1", now).is_some());
        sessions.store(addr("10.0.0.3:3"), addr("3.3.3.3:3"), "", now);
        assert!(lookup(&mut sessions, "10.0.0.1:1", now).is_some());
        assert_eq!(lookup(&mut sessions, "10.0.0.2:2", now), None);
    }

    #[test]
    fn released_slots_are_reused() {
        let now = Instant::now();
        let mut sessions = Sessions::new(Duration::from_secs(60), 1);
        for port in 0..100 {
            sessions.store(
                SocketAddr::from(([10, 0, 0, 1], port)),
                addr("1.1.1.1:1"),
                "",
                now,
            );
        }
        assert_eq!((sessions.len(), sessions.nodes.len()), (1, 1));
    }

    #[test]
    fn lookup_copies_the_tlv_hex() {
        let now = Instant::now();
        let mut sessions = Sessions::new(Duration::from_secs(1), DEFAULT_MAX_SESSIONS);
        sessions.store(
            addr("10.0.0.1:5000"),
            addr("192.168.1.1:1"),
            "ea0001ff",
            now,
        );
        let mut tlv = String::from("stale");
        sessions.lookup(addr("10.0.0.1:5000"), now, &mut tlv);
        assert_eq!(tlv, "ea0001ff");
    }
}

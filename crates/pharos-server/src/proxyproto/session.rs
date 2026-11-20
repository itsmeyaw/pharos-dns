//! Bounded, expiring UDP session cache for Cloudflare Spectrum style PROXY headers.

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

// CoreDNS v1.15.0 plugin/pkg/proxyproto/udp_session.go udpSessionMaxEntries.
pub const DEFAULT_MAX_SESSIONS: usize = 10_240;
const NONE: usize = usize::MAX;

struct Node {
    key: SocketAddr,
    source: SocketAddr,
    tlv: Box<str>,
    seen: Instant,
    newer: usize,
    older: usize,
}

/// Maps the proxy-side address of a datagram flow to the client address its header named.
// CoreDNS v1.15.0 plugin/pkg/proxyproto/udp_session.go: a bounded LRU whose entries expire after the TTL.
pub struct Sessions {
    capacity: usize,
    index: HashMap<SocketAddr, usize>,
    nodes: Vec<Node>,
    free: Vec<usize>,
    newest: usize,
    oldest: usize,
}

impl Sessions {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
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
    pub fn store(&mut self, key: SocketAddr, (source, tlv): (SocketAddr, &str), now: Instant) {
        if let Some(&at) = self.index.get(&key) {
            let node = &mut self.nodes[at];
            node.source = source;
            node.seen = now;
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
            seen: now,
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

    /// The source of a live session, without refreshing its expiry.
    #[must_use]
    pub fn peek(&self, key: SocketAddr, now: Instant, ttl: Duration) -> Option<SocketAddr> {
        let node = &self.nodes[*self.index.get(&key)?];
        (now.saturating_duration_since(node.seen) < ttl).then_some(node.source)
    }

    /// Return the client address of a live session, refreshing its expiry, and copy its TLV hex into `tlv`.
    pub fn lookup(
        &mut self,
        key: SocketAddr,
        now: Instant,
        ttl: Duration,
        tlv: &mut String,
    ) -> Option<SocketAddr> {
        let at = *self.index.get(&key)?;
        // Reload: the session ages against the TTL in force now, not the one it was stored under.
        if now.saturating_duration_since(self.nodes[at].seen) >= ttl {
            self.remove(at);
            return None;
        }
        self.nodes[at].seen = now;
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
mod tests;

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    hash::BuildHasher,
    ops::{Deref, DerefMut},
};

#[derive(Eq, Hash, PartialEq)]
pub(super) struct Address([u8; 45]);

impl Address {
    pub(super) fn new(ip: &str) -> Self {
        let mut bytes = [0; 45];
        bytes[..ip.len()].copy_from_slice(ip.as_bytes());
        Self(bytes)
    }
}

#[derive(Default)]
pub(super) struct Seen {
    buckets: HashMap<u64, usize>,
    entries: Vec<Entry>,
    bytes: Vec<u8>,
}

struct Entry {
    start: usize,
    first_len: usize,
    second_len: usize,
    port: u16,
    next: Option<usize>,
}

impl Seen {
    pub(super) fn insert(&mut self, first: &[u8], second: &[u8], port: u16) -> bool {
        let hash = self.buckets.hasher().hash_one((first, second, port));
        let mut next = self.buckets.get(&hash).copied();
        while let Some(index) = next {
            let entry = &self.entries[index];
            let middle = entry.start + entry.first_len;
            let end = middle + entry.second_len;
            if entry.port == port
                && &self.bytes[entry.start..middle] == first
                && &self.bytes[middle..end] == second
            {
                return false;
            }
            next = entry.next;
        }
        let start = self.bytes.len();
        self.bytes.extend_from_slice(first);
        self.bytes.extend_from_slice(second);
        let index = self.entries.len();
        self.entries.push(Entry {
            start,
            first_len: first.len(),
            second_len: second.len(),
            port,
            next: self.buckets.insert(hash, index),
        });
        true
    }

    fn clear(&mut self) {
        self.buckets.clear();
        self.entries.clear();
        self.bytes.clear();
    }
}

#[derive(Default)]
pub(super) struct Scratch {
    pub(super) addresses: HashSet<Address>,
    pub(super) srv: Seen,
    pub(super) extra: Seen,
}

thread_local! {
    static POOL: RefCell<Vec<Scratch>> = const { RefCell::new(Vec::new()) };
}

pub(super) struct Lease(Option<Scratch>);

pub(super) fn lease() -> Lease {
    Lease(Some(
        POOL.with(|pool| pool.borrow_mut().pop().unwrap_or_default()),
    ))
}

impl Deref for Lease {
    type Target = Scratch;
    fn deref(&self) -> &Scratch {
        self.0.as_ref().unwrap()
    }
}

impl DerefMut for Lease {
    fn deref_mut(&mut self) -> &mut Scratch {
        self.0.as_mut().unwrap()
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut scratch = self.0.take().unwrap();
        scratch.addresses.clear();
        scratch.srv.clear();
        scratch.extra.clear();
        let _ = POOL.try_with(|pool| pool.borrow_mut().push(scratch));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pooled_sets_retain_capacity_and_clear_between_leases() {
        let mut first = lease();
        assert!(first.addresses.insert(Address::new("192.0.2.1")));
        assert!(!first.addresses.insert(Address::new("192.0.2.1")));
        assert!(first.srv.insert(b"host.example.", b"", 80));
        assert!(!first.srv.insert(b"host.example.", b"", 80));
        assert!(first.srv.insert(b"host.example.", b"", 443));
        assert!(first.extra.insert(b"host.example.", b"192.0.2.1", 0));
        assert!(!first.extra.insert(b"host.example.", b"192.0.2.1", 0));
        assert!(first.extra.insert(b"other.example.", b"192.0.2.1", 0));
        let capacity = first.addresses.capacity();
        drop(first);
        let mut reused = lease();
        assert_eq!(reused.addresses.capacity(), capacity);
        assert!(reused.addresses.insert(Address::new("192.0.2.1")));
        assert!(reused.srv.insert(b"host.example.", b"", 80));
        assert!(reused.extra.insert(b"host.example.", b"192.0.2.1", 0));
    }

    #[test]
    fn long_hostnames_and_overlapping_leases_are_distinct() {
        let host = vec![b'x'; 8192];
        let mut first = lease();
        assert!(first.extra.insert(&host, &host, 0));
        assert!(!first.extra.insert(&host, &host, 0));
        let mut other = host.clone();
        other[8191] = b'y';
        assert!(first.extra.insert(&host, &other, 0));
        let mut second = lease();
        assert!(second.extra.insert(&host, &host, 0));
    }

    #[test]
    fn hash_collisions_compare_complete_keys() {
        let mut seen = Seen::default();
        assert!(seen.insert(b"first", b"address", 80));
        let hash = seen
            .buckets
            .hasher()
            .hash_one((&b"second"[..], &b"address"[..], 80u16));
        seen.buckets.insert(hash, 0);
        assert!(seen.insert(b"second", b"address", 80));
        assert!(!seen.insert(b"second", b"address", 80));
    }
}

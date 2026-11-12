use pharos_proto::NameRef;
use std::{
    collections::HashSet,
    fmt,
    net::IpAddr,
    ops::{Deref, DerefMut},
    sync::Mutex,
};

#[derive(Eq, Hash, PartialEq)]
pub(super) struct Name([u8; 255]);

impl Name {
    pub(super) fn new(name: NameRef<'_>) -> Self {
        let mut wire = [0; 255];
        let mut offset = 0;
        for label in name.labels() {
            wire[offset] = label.len() as u8;
            offset += 1;
            wire[offset..offset + label.len()].copy_from_slice(label);
            offset += label.len();
        }
        Self(wire)
    }
}

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
pub(super) struct Scratch {
    pub(super) addresses: HashSet<Address>,
    pub(super) names: HashSet<Name>,
    pub(super) srv: HashSet<(Name, u16)>,
    pub(super) extra: HashSet<(Name, Address)>,
}

#[derive(Default)]
pub(super) struct Pool(Mutex<Vec<Scratch>>);

pub(super) struct Lease<'a> {
    pool: &'a Pool,
    scratch: Option<Scratch>,
}

impl Pool {
    pub(super) fn lease(&self) -> Lease<'_> {
        Lease {
            pool: self,
            scratch: Some(self.0.lock().unwrap().pop().unwrap_or_default()),
        }
    }
}

impl Deref for Lease<'_> {
    type Target = Scratch;
    fn deref(&self) -> &Scratch {
        self.scratch.as_ref().unwrap()
    }
}

impl DerefMut for Lease<'_> {
    fn deref_mut(&mut self) -> &mut Scratch {
        self.scratch.as_mut().unwrap()
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let mut scratch = self.scratch.take().unwrap();
        scratch.addresses.clear();
        scratch.names.clear();
        scratch.srv.clear();
        scratch.extra.clear();
        self.pool.0.lock().unwrap().push(scratch);
    }
}

pub(crate) struct IpText {
    bytes: [u8; 45],
    len: usize,
}

impl IpText {
    pub(crate) fn new(ip: IpAddr) -> Self {
        use fmt::Write;
        let mut text = Self {
            bytes: [0; 45],
            len: 0,
        };
        write!(&mut text, "{ip}").unwrap();
        text
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).unwrap()
    }
}

impl fmt::Write for IpText {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Address, Pool};

    #[test]
    fn overlapping_leases_are_independent_and_reused() {
        let pool = Pool::default();
        let mut first = pool.lease();
        assert!(first.addresses.insert(Address::new("192.0.2.1")));
        let mut second = pool.lease();
        assert!(second.addresses.insert(Address::new("192.0.2.1")));
        let capacity = first.addresses.capacity();
        drop(second);
        drop(first);
        let reused = pool.lease();
        assert!(reused.addresses.is_empty());
        assert_eq!(reused.addresses.capacity(), capacity);
    }

    #[test]
    fn concurrent_leases_do_not_hold_the_pool_lock() {
        let pool = Pool::default();
        let held = pool.lease();
        std::thread::scope(|scope| {
            let (sender, receiver) = std::sync::mpsc::channel();
            let pool = &pool;
            scope.spawn(move || {
                let mut scratch = pool.lease();
                sender
                    .send(scratch.addresses.insert(Address::new("192.0.2.1")))
                    .unwrap();
            });
            let acquired = receiver.recv_timeout(std::time::Duration::from_secs(1));
            drop(held);
            assert!(acquired.unwrap());
        });
    }

    #[test]
    fn unwinding_returns_cleared_scratch_to_the_pool() {
        let pool = Pool::default();
        let result = std::panic::catch_unwind(|| {
            let mut scratch = pool.lease();
            scratch.addresses.insert(Address::new("192.0.2.1"));
            panic!("test unwind");
        });
        assert!(result.is_err());
        let scratch = pool.lease();
        assert!(scratch.addresses.is_empty());
        assert!(scratch.addresses.capacity() > 0);
    }
}

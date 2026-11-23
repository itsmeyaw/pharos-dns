//! Reusable strings for the keys of a lookup, so a Query that the view answers allocates none.

use std::{
    cell::RefCell,
    ops::{Deref, DerefMut},
};

/// Strings kept per thread; one is taken for each key a lookup builds.
const POOL_LIMIT: usize = 16;
/// A string that grew past this is dropped rather than kept.
const KEEP_CAPACITY: usize = 4096;

thread_local! {
    static POOL: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// A string on loan from the pool of the thread; it goes back, emptied, when dropped.
// shortcut: a string dropped on another thread than it was taken on joins that thread's pool, so a Query that waits for etcd may allocate a new one; switch to a shared pool if misses show up in profiles.
pub(super) struct Buf(String);

pub(super) fn lease() -> Buf {
    Buf(POOL
        .try_with(|pool| pool.borrow_mut().pop())
        .ok()
        .flatten()
        .unwrap_or_default())
}

impl Deref for Buf {
    type Target = String;

    fn deref(&self) -> &String {
        &self.0
    }
}

impl DerefMut for Buf {
    fn deref_mut(&mut self) -> &mut String {
        &mut self.0
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        let mut string = std::mem::take(&mut self.0);
        if string.capacity() == 0 || string.capacity() > KEEP_CAPACITY {
            return;
        }
        string.clear();
        let _ = POOL.try_with(|pool| {
            let mut pool = pool.borrow_mut();
            if pool.len() < POOL_LIMIT {
                pool.push(string);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dropped_string_is_reused_empty() {
        let mut first = lease();
        first.push_str("/skydns/test");
        let address = first.as_ptr();
        drop(first);
        let second = lease();
        assert!(second.is_empty());
        assert_eq!(second.as_ptr(), address);
    }

    #[test]
    fn the_pool_is_bounded() {
        let held: Vec<Buf> = (0..POOL_LIMIT * 2)
            .map(|_| {
                let mut buf = lease();
                buf.push('a');
                buf
            })
            .collect();
        drop(held);
        assert_eq!(POOL.with(|pool| pool.borrow().len()), POOL_LIMIT);
    }
}

//! Bounded stacks of reusable buffers, so a warm Query reuses memory instead of allocating.

use std::sync::{Mutex, PoisonError};

/// RFC 1035 §4.2.2, RFC 9250 §4.2: a DNS Message is at most 65,535 octets; the rest is the slack of
/// a `Vec` that grew by doubling while filling.
pub const MESSAGE_CAPACITY: usize = 128 * 1024;

/// Items kept for reuse, bounded in count, in the size of one and in total size.
pub struct Stash<T> {
    max_items: usize,
    max_item_bytes: usize,
    max_bytes: usize,
    held: Mutex<Held<T>>,
}

struct Held<T> {
    items: Vec<(T, usize)>,
    bytes: usize,
}

impl<T> Stash<T> {
    /// A stash of at most `max_items` items, none over `max_item_bytes`, `max_bytes` in all.
    #[must_use]
    pub const fn new(max_items: usize, max_item_bytes: usize, max_bytes: usize) -> Self {
        Self {
            max_items,
            max_item_bytes,
            max_bytes,
            held: Mutex::new(Held {
                items: Vec::new(),
                bytes: 0,
            }),
        }
    }

    /// The item put back last.
    pub fn take(&self) -> Option<T> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let (item, size) = held.items.pop()?;
        held.bytes -= size;
        Some(item)
    }

    /// Keep `item`, which holds `size` bytes of memory, unless a bound would be exceeded.
    pub fn put(&self, item: T, size: usize) {
        if size == 0 || size > self.max_item_bytes {
            return;
        }
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if held.items.len() < self.max_items && held.bytes + size <= self.max_bytes {
            held.bytes += size;
            held.items.push((item, size));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_item_put_back_last() {
        let stash = Stash::new(4, 10, 100);
        stash.put("a", 1);
        stash.put("b", 1);
        assert_eq!(stash.take(), Some("b"));
        assert_eq!(stash.take(), Some("a"));
        assert_eq!(stash.take(), None);
    }

    #[test]
    fn drops_an_item_over_a_bound() {
        let stash = Stash::new(2, 10, 15);
        stash.put("empty", 0);
        stash.put("large", 11);
        stash.put("a", 8);
        stash.put("over the total", 8);
        stash.put("b", 7);
        stash.put("over the count", 0);
        assert_eq!(stash.take(), Some("b"));
        assert_eq!(stash.take(), Some("a"));
        assert_eq!(stash.take(), None);
    }

    #[test]
    fn taking_frees_room_in_the_total() {
        let stash = Stash::new(4, 10, 10);
        stash.put("a", 10);
        assert_eq!(stash.take(), Some("a"));
        stash.put("b", 10);
        assert_eq!(stash.take(), Some("b"));
    }
}

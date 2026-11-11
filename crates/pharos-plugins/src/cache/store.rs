use std::{
    collections::HashMap,
    hash::{BuildHasherDefault, Hasher},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use pharos_proto::{Class, Message, Name, Type};

#[derive(Default)]
struct ShardHasher(u64);
impl Hasher for ShardHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = self.0.wrapping_mul(257).wrapping_add(u64::from(*byte));
        }
    }
    fn write_u64(&mut self, value: u64) {
        // Keys in a shard share their low byte, so mix it before bucket selection.
        self.0 = value.rotate_right(8).wrapping_mul(0x9e3779b97f4a7c15);
    }
}

type Items = HashMap<u64, Item, BuildHasherDefault<ShardHasher>>;

struct Shard {
    items: Items,
    random: u64,
}

pub(super) struct Store {
    shards: [Mutex<Shard>; 256],
    capacity: usize,
    len: AtomicUsize,
}

struct Item {
    name: Name,
    qtype: Type,
    qclass: Class,
    wire: Box<[u8]>,
    ttl_offsets: Box<[usize]>,
    ttl: u32,
    stored: Instant,
    hits: i64,
    last_hit: Option<Instant>,
    refreshing: bool,
    retry_after: Option<Instant>,
    answering: bool,
    last_known_good: Option<Box<Item>>,
}

#[derive(Clone, Copy)]
pub(super) struct Hit {
    pub stale: bool,
    pub refresh: Option<Instant>,
    pub generation: Instant,
}

impl Store {
    pub(super) fn new(capacity: i64) -> Self {
        let capacity = usize::try_from(capacity / 256).unwrap_or(0).max(4);
        Self {
            shards: std::array::from_fn(|index| {
                Mutex::new(Shard {
                    items: Items::default(),
                    random: (index as u64).wrapping_add(1),
                })
            }),
            capacity,
            len: AtomicUsize::new(0),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    pub(super) fn is_current(&self, key: u64, stored: Instant) -> bool {
        self.shards[key as usize & 255]
            .lock()
            .unwrap()
            .items
            .get(&key)
            .is_some_and(|item| item.stored == stored)
    }

    pub(super) fn insert(
        &self,
        key: u64,
        response: &Message<'_>,
        ttl: u32,
        preserve_positive: bool,
        preserve_frequency: bool,
    ) -> Option<bool> {
        let mut item = Item::new(response, ttl)?;
        let mut shard = self.shards[key as usize & 255].lock().unwrap();
        let previous = shard.items.remove(&key);
        let exists = previous.is_some();
        if let Some(mut previous) = previous {
            if preserve_frequency {
                item.hits = previous.hits;
                item.last_hit = previous.last_hit;
            }
            if preserve_positive && !item.answering {
                item.last_known_good = if previous.answering {
                    Some(Box::new(previous))
                } else {
                    previous.last_known_good.take()
                };
            }
        }
        let mut evicted = false;
        if shard.items.len() >= self.capacity && !exists {
            let mut random = shard.random;
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            shard.random = random;
            let index = (random as usize) % shard.items.len();
            if let Some(old) = shard.items.keys().nth(index).copied() {
                shard.items.remove(&old);
                evicted = true;
            }
        }
        shard.items.insert(key, item);
        if !exists && !evicted {
            self.len.fetch_add(1, Ordering::Relaxed);
        }
        Some(evicted)
    }

    pub(super) fn serve(
        &self,
        key: u64,
        query: &Message<'_>,
        output: &mut Vec<u8>,
        config: &super::setup::Config,
        answering_only: bool,
        can_grow: bool,
    ) -> Option<Hit> {
        let mut shard = self.shards[key as usize & 255].lock().unwrap();
        let item = shard.items.get_mut(&key)?;
        let generation = item.stored;
        let question = query.questions().next()?;
        let item = if answering_only && !item.answering {
            item.last_known_good.as_deref_mut()?
        } else {
            item
        };
        if question.name != item.name
            || question.qtype != item.qtype
            || question.qclass != item.qclass
        {
            return None;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(item.stored).as_secs();
        // RFC 8767 §5: limit serving expired data to the configured maximum stale interval.
        let stale = elapsed >= u64::from(item.ttl);
        if stale
            && (config.stale.is_zero()
                || Duration::from_secs(elapsed - u64::from(item.ttl)) >= config.stale)
        {
            return None;
        }
        if output.capacity() < item.wire.len() {
            if !can_grow {
                return None;
            }
            output.reserve(item.wire.len().saturating_sub(output.len()));
        }
        let ttl = if stale && !config.stale_ttl.is_zero() {
            config.stale_ttl.as_secs() as u32
        } else if config.keepttl {
            item.ttl
        } else if stale {
            0
        } else {
            // RFC 2308 §6: decrement the TTL of cached negative answers by their cache age.
            item.ttl - elapsed as u32
        };
        output.clear();
        output.extend_from_slice(&item.wire);
        output[..2].copy_from_slice(&query.id().to_be_bytes());
        let original = u16::from_be_bytes([output[2], output[3]]);
        let mut flags = 0x8000 | (original & 0x04af) | (query.flags() & 0x0110);
        // RFC 6840 §5.8: only signal AD when the query requested AD or DO.
        if !query.ad() && !query.opt().is_some_and(|opt| opt.dnssec_ok()) {
            flags &= !0x20;
        }
        output[2..4].copy_from_slice(&flags.to_be_bytes());
        let mut position = 12;
        for label in question.name.labels() {
            position += 1;
            output[position..position + label.len()].copy_from_slice(label);
            position += label.len();
        }
        for &offset in &item.ttl_offsets {
            output[offset..offset + 4].copy_from_slice(&ttl.to_be_bytes());
        }
        if !stale && config.prefetch_amount > 0 {
            let window = Duration::from_nanos(config.prefetch_duration.max(0) as u64);
            item.hits = if config.prefetch_duration < 0
                || item
                    .last_hit
                    .is_none_or(|last| now.duration_since(last) > window)
            {
                1
            } else {
                item.hits.saturating_add(1)
            };
            item.last_hit = Some(now);
        }
        let threshold = (u64::from(item.ttl) * config.prefetch_percentage as u64).div_ceil(100);
        let wanted = stale
            || (config.prefetch_amount > 0
                && item.hits >= config.prefetch_amount
                && u64::from(item.ttl) - elapsed <= threshold);
        let refresh =
            if wanted && !item.refreshing && item.retry_after.is_none_or(|retry| now >= retry) {
                item.refreshing = true;
                Some(item.stored)
            } else {
                None
            };
        Some(Hit {
            stale,
            refresh,
            generation,
        })
    }

    pub(super) fn finish_refresh(
        &self,
        key: u64,
        stored: Instant,
        recheck: Duration,
        success: bool,
    ) {
        let mut shard = self.shards[key as usize & 255]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let item = shard.items.get_mut(&key).and_then(|item| {
            if item.stored == stored {
                Some(item)
            } else {
                item.last_known_good
                    .as_deref_mut()
                    .filter(|old| old.stored == stored)
            }
        });
        if let Some(item) = item {
            item.refreshing = false;
            item.retry_after = if success || recheck.is_zero() {
                None
            } else {
                Instant::now().checked_add(recheck)
            };
        }
    }

    pub(super) fn remove_if_stored(&self, key: u64, stored: Instant) -> bool {
        let mut shard = self.shards[key as usize & 255].lock().unwrap();
        if shard
            .items
            .get(&key)
            .is_some_and(|item| item.stored == stored)
        {
            shard.items.remove(&key);
            self.len.fetch_sub(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

impl Item {
    fn new(response: &Message<'_>, ttl: u32) -> Option<Self> {
        if response.question_count() != 1 {
            return None;
        }
        let question = response.questions().next()?;
        // shortcut: compressed Questions and non-final OPTs need safe re-encoding before caching.
        let raw_len: usize = question
            .name
            .labels()
            .map(|label| label.len() + 1)
            .sum::<usize>()
            + 1;
        if question.name.wire_len() != raw_len {
            return None;
        }
        let mut end = response
            .answers()
            .chain(response.authorities())
            .chain(response.additionals())
            .last()
            .map_or(12 + raw_len + 4, |rr| rr.rdata_offset + rr.rdata.len());
        if let Some(opt) = response.additionals().find(|rr| rr.rtype == Type::OPT) {
            let opt_end = opt.rdata_offset + opt.rdata.len();
            if response.additionals().last()?.rdata_offset != opt.rdata_offset {
                return None;
            }
            end = opt.ttl_offset - 4 - opt.name.wire_len();
            if opt_end > response.as_wire().len() {
                return None;
            }
        }
        let ttl_offsets: Box<[_]> = response
            .answers()
            .chain(response.authorities())
            .chain(response.additionals())
            .filter(|rr| rr.rtype != Type::OPT)
            .map(|rr| rr.ttl_offset)
            .collect();
        let mut wire = response.as_wire()[..end].to_vec();
        if response.opt().is_some() {
            let count = response.additional_count() - 1;
            wire[10..12].copy_from_slice(&count.to_be_bytes());
        }
        Some(Self {
            name: question.name.to_name(),
            qtype: question.qtype,
            qclass: question.qclass,
            wire: wire.into_boxed_slice(),
            ttl_offsets,
            ttl,
            stored: Instant::now(),
            hits: 0,
            last_hit: None,
            refreshing: false,
            retry_after: None,
            answering: super::answers_question(response),
            last_known_good: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ShardHasher;
    use std::{collections::HashSet, hash::Hasher};

    #[test]
    fn map_hash_keeps_bucket_entropy_within_one_shard() {
        let buckets = (0..256_u64)
            .map(|index| {
                let mut hash = ShardHasher::default();
                hash.write_u64((index << 8) | 7);
                hash.finish() & 255
            })
            .collect::<HashSet<_>>();
        assert_eq!(buckets.len(), 256);
    }
}

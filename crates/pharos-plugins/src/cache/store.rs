use std::{
    collections::HashMap,
    hash::{BuildHasherDefault, Hasher},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use pharos_proto::{Class, Message, Name, Rcode, Type};

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
    keys: Vec<u64>,
    random: u64,
    wire_bytes: usize,
}

impl Shard {
    // RFC 9520 §3.2: keep bounded eviction and removal in constant expected time.
    fn remove(&mut self, key: u64) -> Option<Item> {
        let item = self.items.remove(&key)?;
        // CoreDNS cache: account for both the current and retained positive Response.
        self.wire_bytes -= item.wire_bytes();
        self.keys.swap_remove(item.slot);
        if let Some(moved) = self.keys.get(item.slot) {
            self.items.get_mut(moved).unwrap().slot = item.slot;
        }
        Some(item)
    }
}

// RFC 9520 §3.2: Bound cached resolution failures by configured cache capacity.
pub(super) struct Store {
    shards: Box<[Mutex<Shard>]>,
    capacity: usize,
    len: AtomicUsize,
}

pub(super) struct Item {
    slot: usize,
    name: Name,
    qtype: Type,
    qclass: Class,
    nxdomain: bool,
    negative: bool,
    failure: bool,
    wire: Box<[u8]>,
    ttl_offsets: Box<[u32]>,
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
    pub key: u64,
    pub stale: bool,
    pub refresh: Option<Instant>,
    pub generation: Instant,
}

impl Store {
    pub(super) fn new(capacity: i64) -> Self {
        let capacity = usize::try_from(capacity / 256).unwrap_or(0).max(4);
        Self {
            shards: (0..256)
                .map(|index| {
                    Mutex::new(Shard {
                        items: Items::default(),
                        keys: Vec::new(),
                        random: (index as u64).wrapping_add(1),
                        wire_bytes: 0,
                    })
                })
                .collect(),
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

    pub(super) fn next_failure_ttl(&self, key: u64, base: u32) -> u32 {
        let shard = self.shards[key as usize & 255].lock().unwrap();
        let previous = shard.items.get(&key).filter(|item| item.failure);
        // RFC 9520 §3.2: Exponentially increase repeated failure caching, capped at 5 minutes.
        previous
            // RFC 9520 §3.2: Treat failures within two TTLs as persistent; reset after that local window.
            .filter(|item| item.stored.elapsed() < Duration::from_secs(u64::from(item.ttl) * 2))
            .map_or(base, |item| item.ttl.saturating_mul(2).max(base))
            .min(300)
    }

    #[cfg(test)]
    pub(super) fn insert(
        &self,
        key: u64,
        response: &Message<'_>,
        ttl: u32,
        preserve_positive: bool,
        preserve_frequency: bool,
    ) -> Option<bool> {
        self.insert_prepared(
            key,
            Item::new(response, ttl)?,
            preserve_positive,
            preserve_frequency,
        )
        .map(|evictions| evictions > 0)
    }

    // RFC 2181 §5.4: replace a complete cached Response; never merge data from separate Responses.
    pub(super) fn insert_prepared(
        &self,
        key: u64,
        mut item: Item,
        preserve_positive: bool,
        preserve_frequency: bool,
    ) -> Option<usize> {
        let mut shard = self.shards[key as usize & 255].lock().unwrap();
        // CoreDNS cache: supplement entry-count capacity with 4 KiB of wire per shard entry.
        let budget = self.capacity.saturating_mul(4096);
        let retained = shard
            .items
            .get(&key)
            .filter(|_| preserve_positive && !item.answering);
        let retained_bytes = retained.map_or(0, |previous| {
            if previous.answering {
                previous.wire.len()
            } else {
                previous
                    .last_known_good
                    .as_ref()
                    .map_or(0, |good| good.wire.len())
            }
        });
        // CoreDNS cache: reject an entry that cannot fit without discarding its retained positive Response.
        if item.wire.len() + retained_bytes > budget {
            return None;
        }
        let previous = shard.items.remove(&key);
        let exists = previous.is_some();
        if let Some(mut previous) = previous {
            shard.wire_bytes -= previous.wire_bytes();
            item.slot = previous.slot;
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
        // CoreDNS cache: replace in place before eviction, preserving the key's slot.
        let item_bytes = item.wire_bytes();
        let mut pending = Some(item);
        if exists {
            shard.wire_bytes += item_bytes;
            shard.items.insert(key, pending.take().unwrap());
        }
        let mut evictions = 0;
        // RFC 9520 §3.2: bound each shard by both entry count and retained wire bytes.
        while shard.items.len() + usize::from(!exists) > self.capacity
            || shard.wire_bytes + if exists { 0 } else { item_bytes } > budget
        {
            let mut random = shard.random;
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            shard.random = random;
            // CoreDNS cache: retain the newly admitted Response while choosing a random victim.
            let mut index = (random as usize) % (shard.items.len() - usize::from(exists));
            if exists && index >= shard.items[&key].slot {
                index += 1;
            }
            let old = shard.keys[index];
            shard.remove(old);
            evictions += 1;
        }
        // RFC 9520 §3.2: index each cache key once for bounded random eviction.
        if let Some(mut item) = pending {
            item.slot = shard.keys.len();
            shard.keys.push(key);
            shard.wire_bytes += item_bytes;
            shard.items.insert(key, item);
        }
        if evictions > 0 {
            self.len.fetch_sub(evictions, Ordering::Relaxed);
        }
        if !exists {
            self.len.fetch_add(1, Ordering::Relaxed);
        }
        Some(evictions)
    }

    pub(super) fn serve(
        &self,
        keys: super::CacheKeys,
        query: &Message<'_>,
        output: &mut Vec<u8>,
        config: &super::setup::Config,
        answering_only: bool,
        can_grow: bool,
    ) -> Option<Hit> {
        let key = keys.exact;
        let alternate_key = keys.allow_nxdomain.then_some(keys.nxdomain);
        debug_assert!(alternate_key.is_none_or(|alternate| alternate & 255 == key & 255));
        let mut shard = self.shards[key as usize & 255].lock().unwrap();
        let (item_key, item) = match shard.items.get_mut(&key) {
            Some(item) => (key, item),
            None => {
                let alternate_key = alternate_key?;
                (alternate_key, shard.items.get_mut(&alternate_key)?)
            }
        };
        let generation = item.stored;
        let question = query.questions().next()?;
        let item = if answering_only && !item.answering {
            item.last_known_good.as_deref_mut()?
        } else {
            item
        };
        if question.name != item.name
            || (!item.nxdomain && question.qtype != item.qtype)
            || question.qclass != item.qclass
        {
            return None;
        }
        // RFC 8020 §2: Cached denials expire at their TTL.
        let now = Instant::now();
        let elapsed = now.duration_since(item.stored).as_secs();
        // RFC 8767 §5: limit serving expired data to the configured maximum stale interval.
        let stale = elapsed >= u64::from(item.ttl);
        // RFC 9520 §3.2 caps failure caching at 5 minutes; do not extend it by serving stale.
        if stale && item.failure {
            return None;
        }
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
        // RFC 8767 §4: Set the response TTL for served stale records.
        output.clear();
        // RFC 5155 §9.1: Retain complete NSEC3 proof sets in cached responses.
        output.extend_from_slice(&item.wire);
        // RFC 1035 §4.1.1: Copy the query ID into the response.
        output[..2].copy_from_slice(&query.id().to_be_bytes());
        let original = u16::from_be_bytes([output[2], output[3]]);
        // RFC 6604 §2.2: Retain upstream AD only for authenticated response data.
        let mut flags = 0x8000 | (original & 0x04af) | (query.flags() & 0x0110);
        // RFC 6840 §5.8: only signal AD when the query requested AD or DO.
        if !query.ad() && !keys.dnssec_ok {
            flags &= !0x20;
        }
        output[2..4].copy_from_slice(&flags.to_be_bytes());
        let mut position = 12;
        for label in question.name.labels() {
            position += 1;
            output[position..position + label.len()].copy_from_slice(label);
            position += label.len();
        }
        // RFC 2308 §5: Reused NXDOMAIN entries echo the current QTYPE.
        output[position + 1..position + 3].copy_from_slice(&question.qtype.0.to_be_bytes());
        for &offset in &item.ttl_offsets {
            let offset = offset as usize;
            // RFC 2181 §5.2: Read the normalized RRset TTL from cached wire data.
            let record_ttl = u32::from_be_bytes([
                output[offset],
                output[offset + 1],
                output[offset + 2],
                output[offset + 3],
            ]);
            let ttl = if stale {
                // RFC 8767 §4: Stale records always carry a positive TTL.
                config.stale_ttl.as_secs().max(1) as u32
            } else if config.keepttl && !item.negative {
                record_ttl
            } else {
                // RFC 2308 §6: Age each cached RRset TTL by cache time.
                record_ttl.saturating_sub(elapsed as u32)
            };
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
            key: item_key,
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
            shard.remove(key);
            self.len.fetch_sub(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

impl Item {
    fn wire_bytes(&self) -> usize {
        // CoreDNS cache: retained positive Responses consume the same wire budget.
        self.wire.len()
            + self
                .last_known_good
                .as_ref()
                .map_or(0, |good| good.wire.len())
    }

    // RFC 2181 §5.4.1: Preserve sections so additional data cannot become an answer.
    pub(super) fn new(response: &Message<'_>, ttl: u32) -> Option<Self> {
        if response.question_count() != 1 {
            return None;
        }
        let question = response.questions().next()?;
        // RFC 2930 §3: TKEY transactions are transient and must not enter the cache.
        if question.qtype == Type::TKEY || super::has_record_type(response, Type::TKEY) {
            return None;
        }
        // shortcut: compressed Questions need safe re-encoding before caching.
        let raw_len: usize = question
            .name
            .labels()
            .map(|label| label.len() + 1)
            .sum::<usize>()
            + 1;
        if question.name.wire_len() != raw_len {
            return None;
        }
        let end = response
            .authorities()
            .last()
            .or_else(|| response.answers().last())
            .map_or(12 + raw_len + 4, |rr| rr.rdata_offset + rr.rdata.len());
        // RFC 2181 §5.4.1: Cache only Answer and Authority data, never untrusted Additional data.
        let ttl_offsets: Box<[u32]> = response
            .answers()
            .chain(response.authorities())
            .map(|rr| u32::try_from(rr.ttl_offset).ok())
            .collect::<Option<Vec<_>>>()?
            .into_boxed_slice();
        // RFC 2181 §5.4.1: Drop Additional records by ending cached wire after Authority.
        let mut wire = response.as_wire()[..end].to_vec();
        wire[10..12].copy_from_slice(&0_u16.to_be_bytes());
        Some(Self {
            slot: 0,
            name: question.name.to_name(),
            qtype: question.qtype,
            qclass: question.qclass,
            nxdomain: response.rcode() == Rcode::NXDOMAIN,
            negative: response.rcode() == Rcode::NXDOMAIN || !super::answers_question(response),
            failure: super::is_resolution_failure(response.rcode()),
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
mod tests;

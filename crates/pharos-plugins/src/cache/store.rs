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
}

impl Shard {
    // RFC 9520 §3.2: keep bounded eviction and removal in constant expected time.
    fn remove(&mut self, key: u64) -> Option<Item> {
        let item = self.items.remove(&key)?;
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
        Some(self.insert_prepared(
            key,
            Item::new(response, ttl)?,
            preserve_positive,
            preserve_frequency,
        ))
    }

    // RFC 2181 §5.4: replace a complete cached Response; never merge data from separate Responses.
    pub(super) fn insert_prepared(
        &self,
        key: u64,
        mut item: Item,
        preserve_positive: bool,
        preserve_frequency: bool,
    ) -> bool {
        let mut shard = self.shards[key as usize & 255].lock().unwrap();
        let previous = shard.items.remove(&key);
        let exists = previous.is_some();
        if let Some(mut previous) = previous {
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
        let mut evicted = false;
        // RFC 9520 §3.2: evict entries when a bounded cache shard reaches capacity.
        if shard.items.len() >= self.capacity && !exists {
            let mut random = shard.random;
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            shard.random = random;
            let index = (random as usize) % shard.items.len();
            let old = shard.keys[index];
            shard.remove(old);
            evicted = true;
        }
        // RFC 9520 §3.2: index each cache key once for bounded random eviction.
        if !exists {
            item.slot = shard.keys.len();
            shard.keys.push(key);
        }
        shard.items.insert(key, item);
        if !exists && !evicted {
            self.len.fetch_add(1, Ordering::Relaxed);
        }
        evicted
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
mod tests {
    use super::{ShardHasher, Store};
    use pharos_corefile::{Cursor, lex};
    use pharos_proto::{Class, Message, MessageBuilder, NameRef, Section, Type};
    use std::{
        collections::HashSet,
        hash::Hasher,
        time::{Duration, Instant},
    };

    fn message(qtype: Type, flags: u16, negative_soa: bool) -> Vec<u8> {
        let name = NameRef::parse(b"\x01x\0", 0).unwrap();
        let mut wire = Vec::with_capacity(128);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, flags).unwrap();
        builder.question(name, qtype, Class::IN).unwrap();
        if flags & 0x000f == 0 && !negative_soa && qtype != Type::TKEY {
            builder
                .record(Section::Answer, name, qtype, Class::IN, 30, &[192, 0, 2, 1])
                .unwrap();
        }
        if negative_soa {
            builder
                .record(
                    Section::Authority,
                    name,
                    Type::SOA,
                    Class::IN,
                    30,
                    b"\0\0\0\0\0\x01\0\0\0\x02\0\0\0\x03\0\0\0\x04\0\0\0\x03",
                )
                .unwrap();
        }
        let _ = builder.finish();
        wire
    }

    fn config(text: &str) -> super::super::setup::Config {
        let tokens = lex("Corefile", text);
        super::super::setup::parse(&mut Cursor::new("Corefile", &tokens), &["."]).unwrap()
    }

    fn keys(query: &Message<'_>) -> super::super::CacheKeys {
        super::super::cache_keys(query, query.opt())
    }

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

    #[test]
    fn cached_item_stays_within_the_entry_size_budget() {
        assert!(std::mem::size_of::<super::Item>() <= 160);
    }

    #[test]
    fn eviction_tracks_keys_across_replacement_and_removal() {
        let wire = message(Type::A, 0x8000, false);
        let response = Message::parse(&wire).unwrap();
        let store = Store::new(1024);
        let mut keys = vec![0, 256, 512, 768];
        for &key in &keys {
            assert_eq!(store.insert(key, &response, 30, false, false), Some(false));
        }
        assert_eq!(store.insert(256, &response, 30, false, false), Some(false));
        let stored = store.shards[0].lock().unwrap().items[&512].stored;
        assert!(store.remove_if_stored(512, stored));
        keys.swap_remove(2);
        assert_eq!(store.insert(1024, &response, 30, false, false), Some(false));
        keys.push(1024);
        let mut random = 1_u64;
        // RFC 9520 §3.2: bounded eviction retains exactly the non-evicted entries.
        for index in 5..25 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            keys.swap_remove(random as usize % keys.len());
            let key = index * 256;
            keys.push(key);
            assert_eq!(store.insert(key, &response, 30, false, false), Some(true));
            assert_eq!(store.len(), 4);
            let shard = store.shards[0].lock().unwrap();
            assert_eq!(shard.items.len(), keys.len());
            assert!(keys.iter().all(|key| shard.items.contains_key(key)));
        }
    }

    #[test]
    fn stale_response_ttl_never_zero() {
        let query_wire = message(Type::A, 0x0100, false);
        let query = Message::parse(&query_wire).unwrap();
        let response_wire = message(Type::A, 0x8000, false);
        let response = Message::parse(&response_wire).unwrap();
        let store = Store::new(1024);
        let key = keys(&query).exact;
        store.insert(key, &response, 0, false, false).unwrap();
        let mut output = Vec::with_capacity(128);
        store
            .serve(
                keys(&query),
                &query,
                &mut output,
                &config("cache {\nserve_stale 1h immediate 0\n}"),
                false,
                true,
            )
            .unwrap();
        let hit = Message::parse(&output).unwrap();
        assert_eq!(hit.answers().next().unwrap().ttl, 1);
    }

    #[test]
    fn keepttl_still_ages_negative_soa_ttl() {
        let query_wire = message(Type::A, 0x0100, false);
        let query = Message::parse(&query_wire).unwrap();
        let response_wire = message(Type::A, 0x8003, true);
        let response = Message::parse(&response_wire).unwrap();
        let store = Store::new(1024);
        let key = keys(&query).exact;
        store.insert(key, &response, 30, false, false).unwrap();
        store.shards[key as usize & 255]
            .lock()
            .unwrap()
            .items
            .get_mut(&key)
            .unwrap()
            .stored = Instant::now() - Duration::from_secs(4);
        let mut output = Vec::with_capacity(128);
        store
            .serve(
                keys(&query),
                &query,
                &mut output,
                &config("cache {\nkeepttl\n}"),
                false,
                true,
            )
            .unwrap();
        let hit = Message::parse(&output).unwrap();
        assert_eq!(hit.authorities().next().unwrap().ttl, 26);
    }

    #[test]
    fn nxdomain_hit_rewrites_question_qtype() {
        let query_a_wire = message(Type::A, 0x0100, false);
        let query_aaaa_wire = message(Type::AAAA, 0x0100, false);
        let response_wire = message(Type::A, 0x8003, true);
        let query_a = Message::parse(&query_a_wire).unwrap();
        let query_aaaa = Message::parse(&query_aaaa_wire).unwrap();
        let response = Message::parse(&response_wire).unwrap();
        let a_keys = keys(&query_a);
        let query_keys = keys(&query_aaaa);
        let store = Store::new(1024);
        store
            .insert(a_keys.nxdomain, &response, 30, false, false)
            .unwrap();
        let mut output = Vec::with_capacity(128);
        store
            .serve(
                super::super::CacheKeys {
                    allow_nxdomain: true,
                    ..query_keys
                },
                &query_aaaa,
                &mut output,
                &config("cache"),
                false,
                true,
            )
            .unwrap();
        assert_eq!(
            Message::parse(&output)
                .unwrap()
                .questions()
                .next()
                .unwrap()
                .qtype,
            Type::AAAA
        );
    }

    #[test]
    fn failure_ttl_backs_off_exponentially_to_five_minutes() {
        let response_wire = message(Type::A, 0x8002, false);
        let response = Message::parse(&response_wire).unwrap();
        let store = Store::new(1024);
        store.insert(3, &response, 5, false, false).unwrap();
        assert_eq!(store.next_failure_ttl(3, 5), 10);
        store.insert(3, &response, 10, false, false).unwrap();
        assert_eq!(store.next_failure_ttl(3, 5), 20);
        store.insert(3, &response, 300, false, false).unwrap();
        assert_eq!(store.next_failure_ttl(3, 5), 300);
    }

    #[test]
    fn refused_entries_use_failure_backoff() {
        let response_wire = message(Type::A, 0x8005, false);
        let response = Message::parse(&response_wire).unwrap();
        let store = Store::new(1024);
        store.insert(4, &response, 5, false, false).unwrap();
        assert_eq!(store.next_failure_ttl(4, 5), 10);
    }

    #[test]
    fn expired_failures_are_not_served_stale() {
        let query_wire = message(Type::A, 0x0100, false);
        let response_wire = message(Type::A, 0x8002, false);
        let query = Message::parse(&query_wire).unwrap();
        let response = Message::parse(&response_wire).unwrap();
        let store = Store::new(1024);
        let key = keys(&query).exact;
        store.insert(key, &response, 0, false, false).unwrap();
        let mut output = Vec::with_capacity(128);
        assert!(
            store
                .serve(
                    keys(&query),
                    &query,
                    &mut output,
                    &config("cache {\nserve_stale 1h\n}"),
                    false,
                    true,
                )
                .is_none()
        );
    }

    #[test]
    fn tkey_response_is_not_cacheable() {
        let name = NameRef::parse(b"\x01x\0", 0).unwrap();
        let mut wire = Vec::with_capacity(64);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x8000).unwrap();
        builder.question(name, Type::A, Class::IN).unwrap();
        builder
            .record(Section::Answer, name, Type::TKEY, Class::IN, 30, &[])
            .unwrap();
        let _ = builder.finish();
        let response = Message::parse(&wire).unwrap();
        assert!(super::Item::new(&response, 30).is_none());
    }
}

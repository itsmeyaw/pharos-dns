use std::{
    collections::HashMap,
    hash::{BuildHasherDefault, Hasher},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use pharos_proto::{Class, Message, Name, Type};

#[derive(Default)]
struct IdentityHasher(u64);
impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = self.0.wrapping_mul(257).wrapping_add(u64::from(*byte));
        }
    }
    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

type Items = HashMap<u64, Item, BuildHasherDefault<IdentityHasher>>;

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

    pub(super) fn insert(&self, key: u64, response: &Message<'_>, ttl: u32) -> Option<bool> {
        let Some(item) = Item::new(response, ttl) else {
            return None;
        };
        let mut shard = self.shards[key as usize & 255].lock().unwrap();
        let exists = shard.items.contains_key(&key);
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
        keep_ttl: bool,
    ) -> bool {
        let shard = self.shards[key as usize & 255].lock().unwrap();
        let Some(item) = shard.items.get(&key) else {
            return false;
        };
        let Some(question) = query.questions().next() else {
            return false;
        };
        if question.name != item.name
            || question.qtype != item.qtype
            || question.qclass != item.qclass
        {
            return false;
        }
        let elapsed = item.stored.elapsed().as_secs();
        if elapsed >= u64::from(item.ttl) || output.capacity() < item.wire.len() {
            return false;
        }
        let ttl = if keep_ttl {
            item.ttl
        } else {
            item.ttl - elapsed as u32
        };
        output.clear();
        output.extend_from_slice(&item.wire);
        output[..2].copy_from_slice(&query.id().to_be_bytes());
        let original = u16::from_be_bytes([output[2], output[3]]);
        let mut flags = 0x8000 | (original & 0x04af) | (query.flags() & 0x0110);
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
        true
    }
}

impl Item {
    fn new(response: &Message<'_>, ttl: u32) -> Option<Self> {
        if response.question_count() != 1 {
            return None;
        }
        let question = response.questions().next()?;
        // A compressed Question cannot be recased without moving compression targets.
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
        })
    }
}

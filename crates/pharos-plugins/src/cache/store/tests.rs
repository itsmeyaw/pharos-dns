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
fn byte_budget_evicts_before_entry_capacity() {
    let name = NameRef::parse(b"\x01x\0", 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 8192, 1, 0x8000).unwrap();
    builder.question(name, Type::TXT, Class::IN).unwrap();
    builder
        .record(Section::Answer, name, Type::TXT, Class::IN, 30, &[0; 5000])
        .unwrap();
    let _ = builder.finish();
    let response = Message::parse(&wire).unwrap();
    let store = Store::new(1024);
    assert_eq!(store.insert(0, &response, 30, false, false), Some(false));
    assert_eq!(store.insert(256, &response, 30, false, false), Some(false));
    assert_eq!(store.insert(512, &response, 30, false, false), Some(false));
    assert_eq!(store.insert(768, &response, 30, false, false), Some(true));
    assert_eq!(store.len(), 3);
}

#[test]
fn retained_positive_counts_toward_byte_budget() {
    let name = NameRef::parse(b"\x01x\0", 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 8192, 1, 0x8000).unwrap();
    builder.question(name, Type::TXT, Class::IN).unwrap();
    builder
        .record(Section::Answer, name, Type::TXT, Class::IN, 30, &[0; 5000])
        .unwrap();
    let _ = builder.finish();
    let response = Message::parse(&wire).unwrap();
    let failure_wire = message(Type::TXT, 0x8002, false);
    let failure = Message::parse(&failure_wire).unwrap();
    let store = Store::new(1024);
    for key in [0, 256, 512] {
        assert_eq!(store.insert(key, &response, 30, false, false), Some(false));
    }
    assert_eq!(store.insert(0, &failure, 30, true, false), Some(false));
    assert_eq!(store.insert(768, &response, 30, false, false), Some(true));
    assert_eq!(store.len(), 3);
}

#[test]
fn replacement_and_removal_release_wire_budget() {
    let name = NameRef::parse(b"\x01x\0", 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 8192, 1, 0x8000).unwrap();
    builder.question(name, Type::TXT, Class::IN).unwrap();
    builder
        .record(Section::Answer, name, Type::TXT, Class::IN, 30, &[0; 5000])
        .unwrap();
    let _ = builder.finish();
    let response = Message::parse(&wire).unwrap();
    let small_wire = message(Type::TXT, 0x8000, false);
    let small = Message::parse(&small_wire).unwrap();
    let store = Store::new(1024);
    for key in [0, 256, 512] {
        assert_eq!(store.insert(key, &response, 30, false, false), Some(false));
    }
    assert_eq!(store.insert(0, &small, 30, false, false), Some(false));
    assert_eq!(store.insert(768, &response, 30, false, false), Some(false));
    let stored = store.shards[0].lock().unwrap().items[&256].stored;
    assert!(store.remove_if_stored(256, stored));
    assert_eq!(store.insert(1024, &response, 30, false, false), Some(false));
    assert_eq!(store.len(), 4);
}

#[test]
fn response_larger_than_shard_budget_preserves_existing_entry() {
    let name = NameRef::parse(b"\x01x\0", 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 32768, 1, 0x8000).unwrap();
    builder.question(name, Type::TXT, Class::IN).unwrap();
    builder
        .record(Section::Answer, name, Type::TXT, Class::IN, 30, &[0; 16384])
        .unwrap();
    let _ = builder.finish();
    let response = Message::parse(&wire).unwrap();
    let old_wire = message(Type::TXT, 0x8000, false);
    let old = Message::parse(&old_wire).unwrap();
    let store = Store::new(1024);
    assert_eq!(store.insert(0, &old, 30, false, false), Some(false));
    assert_eq!(store.insert(0, &response, 30, false, false), None);
    assert_eq!(store.len(), 1);
}

#[test]
fn replacing_response_can_evict_multiple_entries() {
    let name = NameRef::parse(b"\x01x\0", 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 16384, 1, 0x8000).unwrap();
    builder.question(name, Type::TXT, Class::IN).unwrap();
    builder
        .record(Section::Answer, name, Type::TXT, Class::IN, 30, &[0; 5000])
        .unwrap();
    let _ = builder.finish();
    let response = Message::parse(&wire).unwrap();
    let mut large_wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut large_wire, 16384, 1, 0x8000).unwrap();
    builder.question(name, Type::TXT, Class::IN).unwrap();
    builder
        .record(Section::Answer, name, Type::TXT, Class::IN, 30, &[0; 12000])
        .unwrap();
    let _ = builder.finish();
    let large = Message::parse(&large_wire).unwrap();
    let store = Store::new(1024);
    for key in [0, 256, 512] {
        assert_eq!(store.insert(key, &response, 30, false, false), Some(false));
    }
    let item = super::Item::new(&large, 30).unwrap();
    assert_eq!(store.insert_prepared(0, item, false, false), Some(2));
    assert_eq!(store.len(), 1);
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
fn expired_failure_backoff_resets_after_a_quiet_period() {
    let query_wire = message(Type::A, 0x0100, false);
    let query = Message::parse(&query_wire).unwrap();
    let response_wire = message(Type::A, 0x8002, false);
    let response = Message::parse(&response_wire).unwrap();
    let store = Store::new(1024);
    let key = keys(&query).exact;
    // RFC 9520 §3.2: Back off persistent failures; the two-TTL reset window is a local policy.
    for (ttl, age, expected) in [(5, 6, 10), (5, 10, 5), (300, 301, 300), (300, 604800, 5)] {
        store.insert(key, &response, ttl, false, false).unwrap();
        store.shards[key as usize & 255]
            .lock()
            .unwrap()
            .items
            .get_mut(&key)
            .unwrap()
            .stored = Instant::now() - Duration::from_secs(age);
        let mut output = Vec::with_capacity(128);
        assert!(
            store
                .serve(
                    keys(&query),
                    &query,
                    &mut output,
                    &config("cache"),
                    false,
                    true
                )
                .is_none()
        );
        assert_eq!(store.next_failure_ttl(key, 5), expected);
    }
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

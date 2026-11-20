use super::{CacheEntry, SigCache};

#[test]
fn poisoned_signature_cache_reports_plugin_panic() {
    use pharos_corefile::{configure, parse};
    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
    use pharos_server::{Context, Error, Metadata, Protocol, Transport};

    let mut chain = configure::<crate::Chain>(
        &parse("Corefile", "miek.nl {\n dnssec\n}").unwrap(),
        crate::directives(),
    )
    .unwrap();
    let dnssec = chain[0].config.dnssec.as_mut().unwrap();
    let _ = std::panic::catch_unwind(|| {
        let _guard = dnssec.cache.lock().unwrap();
        panic!("poison cache");
    });
    let domain: Name = "miek.nl.".parse().unwrap();
    let name = NameRef::parse(domain.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    builder.question(name, Type::A, Class::IN).unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(dnssec.sign_response(&mut cx), Err(Error::PluginPanic));
}

#[test]
fn signature_cache_separates_original_ttls() {
    use pharos_corefile::{configure, parse};
    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type};
    use pharos_server::{Context, Metadata, Protocol, Transport};

    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl {{\n dnssec {{\n key file {base}\n }}\n}}");
    let mut chain =
        configure::<crate::Chain>(&parse("Corefile", &text).unwrap(), crate::directives()).unwrap();
    let dnssec = chain[0].config.dnssec.as_mut().unwrap();
    let domain: Name = "miek.nl.".parse().unwrap();
    let name = NameRef::parse(domain.as_wire(), 0).unwrap();
    let mut query = Vec::new();
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
    builder.question(name, Type::A, Class::IN).unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let mut first = Vec::new();
    for (ttl, expected_entries) in [(120, 1), (60, 2), (120, 2)] {
        let mut builder = MessageBuilder::new(cx.response, 512, 1, 0x8400).unwrap();
        builder.question(name, Type::A, Class::IN).unwrap();
        builder
            .record(
                Section::Answer,
                name,
                Type::A,
                Class::IN,
                ttl,
                &[127, 0, 0, 1],
            )
            .unwrap();
        let _ = builder.finish();
        dnssec.sign_response(&mut cx).unwrap();
        let message = Message::parse(cx.response).unwrap();
        let sig = message
            .answers()
            .find(|rr| rr.rtype == Type::RRSIG)
            .unwrap();
        assert_eq!(sig.ttl, ttl);
        assert!(
            matches!(sig.data().unwrap(), Rdata::Rrsig { original_ttl, .. } if original_ttl == ttl)
        );
        assert_eq!(dnssec.cache.lock().unwrap().map.len(), expected_entries);
        if first.is_empty() {
            first = cx.response.clone();
        } else if ttl == 120 {
            assert_eq!(*cx.response, first);
        }
    }
}

#[test]
fn empty_response_does_not_evict_a_signed_response() {
    use pharos_corefile::{configure, parse};
    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
    use pharos_server::{Context, Metadata, Protocol, Transport};

    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl {{\n dnssec {{\n key file {base}\n }}\n}}");
    let mut chain =
        configure::<crate::Chain>(&parse("Corefile", &text).unwrap(), crate::directives()).unwrap();
    let dnssec = chain[0].config.dnssec.as_mut().unwrap();
    dnssec.capacity = 1;
    let domain: Name = "miek.nl.".parse().unwrap();
    let name = NameRef::parse(domain.as_wire(), 0).unwrap();
    let mut query = Vec::new();
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
    builder.question(name, Type::A, Class::IN).unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    for answer in [true, false] {
        let mut builder = MessageBuilder::new(cx.response, 512, 1, 0x8400).unwrap();
        builder.question(name, Type::A, Class::IN).unwrap();
        if answer {
            builder
                .record(
                    Section::Answer,
                    name,
                    Type::A,
                    Class::IN,
                    60,
                    &[127, 0, 0, 1],
                )
                .unwrap();
        }
        let _ = builder.finish();
        dnssec.sign_response(&mut cx).unwrap();
    }
    let cache = dnssec.cache.lock().unwrap();
    assert_eq!(cache.map.len(), 1);
    let cached = Message::parse(&cache.map.values().next().unwrap().wire).unwrap();
    assert!(cached.answers().any(|rr| rr.rtype == Type::RRSIG));
}

fn entry(len: usize, sets: usize) -> CacheEntry {
    CacheEntry {
        wire: vec![0; len],
        max_size: 512,
        expires: 0,
        inception: 0,
        sets,
    }
}

#[test]
fn cache_evicts_to_stay_within_byte_budget_for_max_size_responses() {
    use super::CACHE_BYTES;
    let mut cache = SigCache::default();
    for i in 0..(2 * CACHE_BYTES / 65_535) as u32 {
        assert!(cache.insert(&i.to_be_bytes(), entry(65_535, 2), usize::MAX));
        assert!(cache.bytes <= CACHE_BYTES);
    }
    assert_eq!(cache.sets, 2 * cache.map.len());
    assert!(cache.map.len() >= CACHE_BYTES / (65_535 + 256) - 1);
}

#[test]
fn cache_tracks_sets_on_replace_and_rejects_entries_over_budget() {
    use super::CACHE_BYTES;
    let mut cache = SigCache::default();
    assert!(cache.insert(b"a", entry(10, 3), 4));
    assert!(cache.insert(b"a", entry(20, 1), 4));
    assert_eq!((cache.map.len(), cache.sets), (1, 1));
    assert!(!cache.insert(b"b", entry(CACHE_BYTES, 1), 4));
    assert_eq!((cache.map.len(), cache.sets), (1, 1));
    for key in [b"c", b"d", b"e", b"f"] {
        cache.insert(key, entry(1, 1), 4);
    }
    assert_eq!((cache.map.len(), cache.sets), (4, 4));
}

#[test]
fn cache_expires_after_six_days_and_checks_buffer_limit() {
    let entry = CacheEntry {
        wire: Vec::new(),
        max_size: 512,
        expires: 6 * 86400,
        inception: 0,
        sets: 1,
    };
    assert!(entry.valid(6 * 86400 - 1, 512));
    assert!(entry.valid(6 * 86400, 512));
    assert!(!entry.valid(6 * 86400 + 1, 512));
    assert!(!entry.valid(1, 1232));
}

// CoreDNS plugin/dnssec/cache_test.go TestCacheNotValidYet: validate at now plus two days.
#[test]
fn cache_rejects_signatures_not_valid_at_refresh_horizon() {
    let entry = CacheEntry {
        wire: Vec::new(),
        max_size: 512,
        expires: 15 * 86400,
        inception: 9 * 86400 - 3 * 3600,
        sets: 1,
    };
    assert!(!entry.valid(0, 512));
    assert!(entry.valid(7 * 86400, 512));
}

#[test]
fn cache_inception_comparison_wraps_at_u32_boundary() {
    let signed = u32::MAX as u64 - 86400;
    let entry = CacheEntry {
        wire: Vec::new(),
        max_size: 512,
        expires: signed + 6 * 86400,
        inception: (signed - 3 * 3600) as u32,
        sets: 1,
    };
    assert!(!entry.valid(signed - 9 * 86400, 512));
    assert!(entry.valid(signed, 512));
    assert!(entry.valid(signed + 2 * 86400, 512));
}

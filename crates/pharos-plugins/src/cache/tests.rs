use super::*;
use pharos_proto::{Class, MessageBuilder};

fn query(qtype: Type) -> Vec<u8> {
    let name = NameRef::parse(b"\x01x\0", 0).unwrap();
    let mut wire = Vec::with_capacity(64);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
    builder.question(name, qtype, Class::IN).unwrap();
    let _ = builder.finish();
    wire
}

#[test]
fn unrelated_shard_insert_does_not_wait_for_another_writer() {
    let tokens = pharos_corefile::lex("Corefile", "cache");
    let cache = Cache::parse(
        &mut pharos_corefile::Cursor::new("Corefile", &tokens),
        &[".".into()],
    )
    .unwrap();
    let wire = query(Type::A);
    let response = Message::parse(&wire).unwrap();
    let guard = cache.lock_writes(0);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let result = cache.insert_response(1, &response, 30, false, None);
            sender.send(result).unwrap();
        });
        let result = receiver.recv_timeout(std::time::Duration::from_secs(2));
        drop(guard);
        assert_eq!(result.unwrap(), Some(false));
    });
}

#[test]
fn cache_keys_separate_exact_qtype_and_shared_nxdomain_shard() {
    let a_wire = query(Type::A);
    let aaaa_wire = query(Type::AAAA);
    let a = Message::parse(&a_wire).unwrap();
    let aaaa = Message::parse(&aaaa_wire).unwrap();
    let a_keys = cache_keys(&a, a.opt());
    let aaaa_keys = cache_keys(&aaaa, aaaa.opt());
    assert_eq!(a_keys.nxdomain, aaaa_keys.nxdomain);
    assert_ne!(a_keys.exact, aaaa_keys.exact);
    assert_eq!(a_keys.exact & 255, a_keys.nxdomain & 255);
}

#[test]
fn explicit_wildcard_names_are_detected() {
    let wildcard = NameRef::parse(b"\x01*\x07example\x03org\0", 0).unwrap();
    let ordinary = NameRef::parse(b"\x01x\x07example\x03org\0", 0).unwrap();
    assert!(has_explicit_wildcard(wildcard));
    assert!(!has_explicit_wildcard(ordinary));
}

#[test]
fn ecs_query_is_detected_for_conservative_cache_bypass() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\x01\x01x\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\0\0\0\x0b\0\x08\0\x07\0\x01\x18\0\xc0\0\x02";
    assert!(has_client_subnet(Message::parse(wire).unwrap().opt()));
    assert!(!has_client_subnet(
        Message::parse(&query(Type::A)).unwrap().opt()
    ));
}

#[test]
fn negative_ttl_is_not_raised_to_positive_minimum() {
    assert_eq!(bound_ttl(1, true, 5, 100), 1);
    assert_eq!(bound_ttl(1, false, 5, 100), 5);
}

#[test]
fn expired_signature_caps_the_positive_ttl_floor() {
    let ttl = bound_ttl(0, false, 5, 100);
    assert_eq!(cap_ttl_at_signature(ttl, 0), 0);
    assert_eq!(cap_ttl_at_signature(ttl, 2), 2);
}

#[test]
fn cache_ttl_cap_is_one_week() {
    assert_eq!(cached_maximum(u64::MAX), MAX_CACHED_TTL);
}

#[test]
fn cache_ttl_ends_at_rrsig_expiration() {
    assert_eq!(signature_ttl(1_040, 1_000), 40);
    assert_eq!(signature_ttl(990, 1_000), 0);
    assert_eq!(signature_ttl(10, u32::MAX - 9), 20);
}

#[test]
fn refused_is_a_cacheable_resolution_failure() {
    assert!(is_resolution_failure(Rcode::REFUSED));
    assert!(is_resolution_failure(Rcode::SERVFAIL));
    assert!(!is_resolution_failure(Rcode::FORMERR));
}

#[test]
fn nodata_without_soa_is_not_cacheable() {
    let name = NameRef::parse(b"\x01x\0", 0).unwrap();
    let mut wire = Vec::with_capacity(64);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x8000).unwrap();
    builder.question(name, Type::A, Class::IN).unwrap();
    let _ = builder.finish();
    let response = Message::parse(&wire).unwrap();
    assert!(is_soa_less_nodata(&response, false, false));
}

#![forbid(unsafe_code)]

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{Action, Outcome, Protocol, finish_outcome};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn edns_finalization_preserves_existing_options_without_allocating() {
    let name: Name = "example.test.".parse().unwrap();
    let name = NameRef::parse(name.as_wire(), 0).unwrap();
    let root = NameRef::parse(&[0], 0).unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x0100).unwrap();
    builder.question(name, Type::A, Class::IN).unwrap();
    builder
        .record(
            Section::Additional,
            root,
            Type::OPT,
            Class(1232),
            0x8000,
            &[],
        )
        .unwrap();
    let _ = builder.finish();
    let query = Message::parse(&query).unwrap();
    let mut source = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut source, 512, 1, 0x8180).unwrap();
    builder.question(name, Type::A, Class::IN).unwrap();
    builder
        .record(
            Section::Additional,
            root,
            Type::OPT,
            Class(4096),
            0,
            &[0xfd, 0xe9, 0, 2, 0xc0, 1],
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(1232);
    let before = GLOBAL.stats();
    for _ in 0..100 {
        response.clear();
        response.extend_from_slice(&source);
        assert_eq!(
            finish_outcome(
                query,
                Protocol::Udp,
                Outcome::Response,
                &mut response,
                |_| panic!("unexpected error")
            ),
            Action::Respond
        );
        let opt = Message::parse(&response).unwrap().opt().unwrap();
        assert_eq!(opt.udp_payload_size(), 1232);
        assert!(opt.dnssec_ok());
        assert_eq!(opt.options().as_bytes(), &[0xfd, 0xe9, 0, 2, 0xc0, 1]);
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
}

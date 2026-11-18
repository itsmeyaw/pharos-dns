#![forbid(unsafe_code)]

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{Action, Outcome, Protocol, finish_outcome};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;

// The allocator counters are process-wide, so parallel tests would count the harness and each other.
#[test]
fn outcome_finalization_does_not_allocate() {
    edns_finalization_preserves_existing_options_without_allocating();
    edns_ecs_selection_does_not_allocate();
    edns_finalization_preserves_large_options_without_allocating();
    truncating_contiguous_rrsets_does_not_allocate();
}

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

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
        assert_eq!(opt.udp_payload_size(), 4096);
        assert!(opt.dnssec_ok());
        assert_eq!(opt.options().as_bytes(), &[0xfd, 0xe9, 0, 2, 0xc0, 1]);
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
}

// RFC 7871 §7.2.2: ECS presence follows the Query regardless of the upstream Response.
fn edns_ecs_selection_does_not_allocate() {
    let name: Name = "example.test.".parse().unwrap();
    let name = NameRef::parse(name.as_wire(), 0).unwrap();
    let root = NameRef::parse(&[0], 0).unwrap();
    let ecs = [0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2];
    for (query_ecs, upstream_ecs, upstream_opt) in [
        (false, false, false),
        (true, false, false),
        (false, false, true),
        (false, true, true),
        (true, false, true),
        (true, true, true),
    ] {
        let mut query_wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query_wire, 512, 1, 0x0100).unwrap();
        builder.question(name, Type::A, Class::IN).unwrap();
        builder
            .record(
                Section::Additional,
                root,
                Type::OPT,
                Class(1232),
                0,
                if query_ecs { &ecs } else { &[] },
            )
            .unwrap();
        let _ = builder.finish();
        let query = Message::parse(&query_wire).unwrap();
        let mut response = Vec::with_capacity(1232);
        let mut builder = MessageBuilder::new(&mut response, 1232, 1, 0x8180).unwrap();
        builder.question(name, Type::A, Class::IN).unwrap();
        if upstream_opt {
            builder
                .record(
                    Section::Additional,
                    root,
                    Type::OPT,
                    Class(4096),
                    0,
                    if upstream_ecs { &ecs } else { &[] },
                )
                .unwrap();
        }
        let _ = builder.finish();
        let before = GLOBAL.stats();
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
        let record = Message::parse(&response)
            .unwrap()
            .additionals()
            .next()
            .unwrap();
        assert_eq!(record.rdata, if query_ecs { &ecs[..] } else { &[] });
        assert_eq!(record.rdata_offset + record.rdata.len(), response.len());
        let after = GLOBAL.stats();
        assert_eq!(after.allocations - before.allocations, 0);
        assert_eq!(after.reallocations - before.reallocations, 0);
    }
}

// RFC 6891 §6.1.2: Large OPT RDATA remains intact when the Response uses TCP.
fn edns_finalization_preserves_large_options_without_allocating() {
    let name: Name = "example.test.".parse().unwrap();
    let name = NameRef::parse(name.as_wire(), 0).unwrap();
    let root = NameRef::parse(&[0], 0).unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x0100).unwrap();
    builder.question(name, Type::A, Class::IN).unwrap();
    builder
        .record(Section::Additional, root, Type::OPT, Class(1232), 0, &[])
        .unwrap();
    let _ = builder.finish();
    let query = Message::parse(&query).unwrap();
    for len in [508_u16, 509, 4092, 4093, 5000] {
        let mut options = vec![0xfd, 0xe9];
        options.extend_from_slice(&len.to_be_bytes());
        options.resize(4 + usize::from(len), 42);
        let mut response = Vec::with_capacity(65535);
        let mut builder = MessageBuilder::new(&mut response, 65535, 1, 0x8180).unwrap();
        builder.question(name, Type::A, Class::IN).unwrap();
        builder
            .record(
                Section::Additional,
                root,
                Type::OPT,
                Class(4096),
                0,
                &options,
            )
            .unwrap();
        let _ = builder.finish();
        let before = GLOBAL.stats();
        assert_eq!(
            finish_outcome(
                query,
                Protocol::Tcp,
                Outcome::Response,
                &mut response,
                |_| panic!("unexpected error")
            ),
            Action::Respond
        );
        let opt = Message::parse(&response).unwrap().opt().unwrap();
        assert_eq!(opt.options().as_bytes(), options);
        let after = GLOBAL.stats();
        assert_eq!(after.allocations - before.allocations, 0);
        assert_eq!(after.reallocations - before.reallocations, 0);
    }
}

fn truncating_contiguous_rrsets_does_not_allocate() {
    let question: Name = "q.test.".parse().unwrap();
    let question = NameRef::parse(question.as_wire(), 0).unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x0100).unwrap();
    builder.question(question, Type::A, Class::IN).unwrap();
    let _ = builder.finish();
    let query = Message::parse(&query).unwrap();
    let mut source = Vec::with_capacity(4096);
    let mut builder = MessageBuilder::new(&mut source, 4096, 1, 0x8180).unwrap();
    builder.question(question, Type::A, Class::IN).unwrap();
    for label in *b"abcd" {
        let wire = [1, label, 0];
        let name = NameRef::parse(&wire, 0).unwrap();
        for _ in 0..2 {
            builder
                .record(Section::Answer, name, Type::TXT, Class::IN, 10, &[7; 100])
                .unwrap();
        }
    }
    let _ = builder.finish();
    let mut response = Vec::with_capacity(4096);
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
        let message = Message::parse(&response).unwrap();
        assert!(message.tc());
        assert_eq!(message.answer_count(), 4);
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
}

#![forbid(unsafe_code)]

use std::alloc::System;

use pharos_proto::{Class, Message, MessageBuilder, NameRef, Section, Type};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

// One test in its own process prevents unrelated test threads from contaminating counts.
#[test]
fn parse_and_reused_response_buffer_do_not_allocate() {
    let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\0\x00\x01\x00\x01";
    let name = NameRef::parse(query, 12).unwrap();
    let mut wire = Vec::with_capacity(512);
    let region = Region::new(GLOBAL);
    let parsed = Message::parse(query).unwrap();
    std::hint::black_box(parsed.questions().next().unwrap());
    let mut builder = MessageBuilder::new(&mut wire, 512, 0x1234, 0x8180).unwrap();
    builder.question(name, Type(1), Class(1)).unwrap();
    for i in 0..5 {
        builder
            .record(
                Section::Answer,
                name,
                Type(1),
                Class(1),
                60,
                &[192, 0, 2, i],
            )
            .unwrap();
    }
    std::hint::black_box(builder.finish());
    let allocations = region.change();
    assert_eq!(allocations.allocations, 0);
    assert_eq!(allocations.reallocations, 0);
}

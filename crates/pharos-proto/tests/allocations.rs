#![forbid(unsafe_code)]

use std::alloc::System;

use pharos_proto::{Class, Message, MessageBuilder, NameRef, Rdata, Section, Type};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

struct Sink;
impl std::fmt::Write for Sink {
    fn write_str(&mut self, _: &str) -> std::fmt::Result {
        Ok(())
    }
}

// One test in its own process prevents unrelated test threads from contaminating counts.
#[test]
fn parse_and_reused_response_buffer_do_not_allocate() {
    let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\0\x00\x01\x00\x01";
    let name = NameRef::parse(query, 12).unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut tsig_wire = Vec::with_capacity(512);
    let mut tsig_builder = MessageBuilder::new(&mut tsig_wire, 512, 0, 0).unwrap();
    tsig_builder
        .record(
            Section::Additional,
            name,
            Type::TSIG,
            Class::ANY,
            0,
            &[0; 17],
        )
        .unwrap();
    let _ = tsig_builder.finish();
    let region = Region::new(GLOBAL);
    let parsed = Message::parse(query).unwrap();
    std::hint::black_box(parsed.questions().next().unwrap());
    let mut builder = MessageBuilder::new(&mut wire, 512, 0x1234, 0x8180).unwrap();
    let opt = b"\0\0\x29\x02\x00\0\0\0\0\0\0";
    builder.reserve(opt.len()).unwrap();
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
    for (rtype, prefix) in [
        (Type::SRV, &[0, 1, 0, 2, 0, 53][..]),
        (Type::NAPTR, &b"\x00\x01\x00\x02\x01s\x01u\x00"[..]),
    ] {
        builder
            .record_with(Section::Answer, name, rtype, Class::IN, 60, |writer| {
                writer.write_bytes(prefix)?;
                writer.write_name(name)
            })
            .unwrap();
    }
    let response = builder.finish_with_opt(opt).unwrap();
    for record in Message::parse(response).unwrap().answers() {
        std::hint::black_box(record.data().unwrap());
    }
    for (rtype, bytes) in [
        (Type::DS, &b"\0\0\x08\x02\xff"[..]),
        (Type::CDS, &b"\0\0\x08\x02\xff"[..]),
        (Type::DNSKEY, &b"\x01\0\x03\x08\xff"[..]),
        (Type::CDNSKEY, &b"\x01\0\x03\x08\xff"[..]),
        (Type::RRSIG, &[0; 19][..]),
        (Type::NSEC, &b"\0\0\x01\x40"[..]),
        (Type::NSEC3, &b"\x01\0\0\0\0\0\0\x01\x40"[..]),
        (Type::NSEC3PARAM, &b"\x01\0\0\0\0"[..]),
        (
            Type::SVCB,
            &b"\0\x01\0\0\x01\0\x03\x02h2\0\x03\0\x02\x01\xbb"[..],
        ),
        (Type::HTTPS, &b"\0\x01\0\0\x07\0\x02/x"[..]),
        (Type::TLSA, &b"\x03\x01\x01\xff"[..]),
        (Type::SSHFP, &b"\x01\x02\xff"[..]),
        (
            Type::ZONEMD,
            &b"\0\0\0\x01\x01\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"[..],
        ),
        (Type::TSIG, &[0; 17][..]),
    ] {
        let data = Rdata::parse(rtype, bytes).unwrap();
        if let Some(params) = data.svc_params() {
            for pair in params.iter() {
                std::hint::black_box(pair);
            }
        }
        std::hint::black_box(data);
    }
    let record = Message::parse(&tsig_wire)
        .unwrap()
        .additionals()
        .next()
        .unwrap();
    let display = record.display_tsig().unwrap();
    std::fmt::write(&mut Sink, format_args!("{display}")).unwrap();
    let allocations = region.change();
    assert_eq!(allocations.allocations, 0);
    assert_eq!(allocations.reallocations, 0);
}

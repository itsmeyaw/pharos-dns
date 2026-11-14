#![forbid(unsafe_code)]

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use pharos_proto::{Class, Message, MessageBuilder, NameRef, Section, Type};
use pharos_server::{Action, Outcome, Protocol, finish_outcome};

fn outcome_benchmarks(c: &mut Criterion) {
    let query_wire = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x01a\0\0\x01\0\x01";
    let mut edns_wire = query_wire.to_vec();
    edns_wire[11] = 1;
    edns_wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0]);
    let query = Message::parse(query_wire).unwrap();
    let edns_query = Message::parse(&edns_wire).unwrap();
    let name = NameRef::parse(query_wire, 12).unwrap();
    let mut response = Vec::with_capacity(2048);
    let mut builder = MessageBuilder::new(&mut response, 2048, 0x1234, 0x8180).unwrap();
    builder.question(name, Type::A, Class::IN).unwrap();
    for _ in 0..8 {
        builder
            .record(Section::Answer, name, Type::TXT, Class::IN, 10, &[42; 150])
            .unwrap();
    }
    let _ = builder.finish();

    for (label, query, truncated) in [
        ("outcome/truncate_udp", query, true),
        ("outcome/scrub_edns_tcp", edns_query, false),
    ] {
        // TCP avoids truncation while still exercising EDNS scrubbing.
        let protocol = if truncated {
            Protocol::Udp
        } else {
            Protocol::Tcp
        };
        let mut check = response.clone();
        assert_eq!(
            finish_outcome(query, protocol, Outcome::Response, &mut check, |_| panic!()),
            Action::Respond
        );
        let result = Message::parse(&check).unwrap();
        // RFC 1035 §4.2.1: Truncated UDP responses set TC.
        assert_eq!(result.tc(), truncated);
        assert_eq!(result.answer_count(), if truncated { 3 } else { 8 });
        assert_eq!(result.opt().is_some(), !truncated);
        c.bench_function(label, |b| {
            b.iter_batched_ref(
                || {
                    let mut wire = Vec::with_capacity(2048);
                    wire.extend_from_slice(&response);
                    wire
                },
                |wire| {
                    black_box(finish_outcome(
                        black_box(query),
                        protocol,
                        Outcome::Response,
                        wire,
                        |_| panic!(),
                    ))
                },
                BatchSize::LargeInput,
            )
        });
    }
}

criterion_group!(benches, outcome_benchmarks);
criterion_main!(benches);

use criterion::{Criterion, criterion_group, criterion_main};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
use std::hint::black_box;

fn message_benchmarks(criterion: &mut Criterion) {
    let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\0\x00\x01\x00\x01";
    criterion.bench_function("message/parse_query", |bencher| {
        bencher.iter(|| Message::parse(black_box(query)).unwrap())
    });
    let large = large_response();
    criterion.bench_function("message/parse_walk_large_benign_response", |bencher| {
        bencher.iter(|| {
            let message = Message::parse(black_box(&large)).unwrap();
            black_box(message.answers().count())
        })
    });
    let adversarial = pointer_chain_message(32);
    assert!(Message::parse(&adversarial).is_ok());
    criterion.bench_function(
        "message/parse_walk_adversarial_8160_pointer_hops",
        |bencher| {
            bencher.iter(|| {
                let message = Message::parse(black_box(&adversarial)).unwrap();
                black_box(message.additionals().count())
            })
        },
    );
    let name = NameRef::parse(query, 12).unwrap();
    let mut wire = Vec::with_capacity(512);
    criterion.bench_function("message/build_five_a", |bencher| {
        bencher.iter(|| {
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
            black_box(builder.finish());
        })
    });
    let owners: Vec<Name> = (0..100)
        .map(|i| format!("host{i}.service.example.com.").parse().unwrap())
        .collect();
    let mut large_wire = Vec::with_capacity(8192);
    criterion.bench_function("message/build_large_distinct_owners", |bencher| {
        bencher.iter(|| {
            let mut builder = MessageBuilder::new(&mut large_wire, 8192, 0x1234, 0x8180).unwrap();
            for owner in &owners {
                builder
                    .record(
                        Section::Answer,
                        owner.as_name_ref(),
                        Type::A,
                        Class::IN,
                        60,
                        &[192, 0, 2, 1],
                    )
                    .unwrap();
            }
            black_box(builder.finish());
        });
    });
}

fn large_response() -> Vec<u8> {
    let name = NameRef::parse(b"\x01a\0", 0).unwrap();
    let mut wire = Vec::with_capacity(usize::from(u16::MAX));
    let mut builder =
        MessageBuilder::new(&mut wire, usize::from(u16::MAX), 0x1234, 0x8180).unwrap();
    builder.question(name, Type::A, Class::IN).unwrap();
    for _ in 0..4000 {
        assert!(
            builder
                .record(
                    Section::Answer,
                    name,
                    Type::A,
                    Class::IN,
                    60,
                    &[192, 0, 2, 1],
                )
                .unwrap()
        );
    }
    let _ = builder.finish();
    wire
}

fn pointer_chain_message(repeated_names: usize) -> Vec<u8> {
    let additional_count = u16::try_from(repeated_names + 1).unwrap();
    let mut wire = Vec::with_capacity(1024);
    wire.extend_from_slice(&[0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0]);
    wire.extend_from_slice(&additional_count.to_be_bytes());
    wire.extend_from_slice(b"\x01a\0\0\x01\0\x01");
    wire.push(0); // Root owner for an opaque RDATA record that seeds backward pointers.
    wire.extend_from_slice(&65000_u16.to_be_bytes());
    wire.extend_from_slice(&Class::IN.0.to_be_bytes());
    wire.extend_from_slice(&0_u32.to_be_bytes());
    let rdata_len_offset = wire.len();
    wire.extend_from_slice(&[0, 0]);
    let rdata_offset = wire.len();
    wire.extend_from_slice(b"\x01a\0");
    let mut target = rdata_offset;
    for _ in 0..254 {
        let pointer = wire.len();
        wire.extend_from_slice(&[0xc0 | (target >> 8) as u8, target as u8]);
        target = pointer;
    }
    let rdata_len = u16::try_from(wire.len() - rdata_offset).unwrap();
    wire[rdata_len_offset..rdata_len_offset + 2].copy_from_slice(&rdata_len.to_be_bytes());
    for _ in 0..repeated_names {
        wire.extend_from_slice(&[0xc0 | (target >> 8) as u8, target as u8]);
        wire.extend_from_slice(&65000_u16.to_be_bytes());
        wire.extend_from_slice(&Class::IN.0.to_be_bytes());
        wire.extend_from_slice(&0_u32.to_be_bytes());
        wire.extend_from_slice(&[0, 0]);
    }
    wire
}

criterion_group!(benches, message_benchmarks);
criterion_main!(benches);

use criterion::{Criterion, criterion_group, criterion_main};
use pharos_proto::{Class, Message, MessageBuilder, NameRef, Section, Type};
use std::hint::black_box;

fn message_benchmarks(criterion: &mut Criterion) {
    let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\0\x00\x01\x00\x01";
    criterion.bench_function("message/parse_query", |bencher| {
        bencher.iter(|| Message::parse(black_box(query)).unwrap())
    });
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
}
criterion_group!(benches, message_benchmarks);
criterion_main!(benches);

mod common_hickory;
use common_hickory::*;
use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::Message as HMessage;
use hickory_proto::rr::RData;
use pharos_proto::{Class, Message, MessageBuilder, NameRef, Rdata, Section, Type};
use std::hint::black_box;

fn compare(c: &mut Criterion) {
    let response = pharos_response();
    let hname = hickory_name();
    assert_eq!(HMessage::from_vec(&response).unwrap().answers.len(), 5);

    c.bench_function("pharos/parse_query", |b| {
        b.iter(|| Message::parse(black_box(QUERY)).unwrap())
    });
    c.bench_function("hickory/parse_query", |b| {
        b.iter(|| HMessage::from_vec(black_box(QUERY)).unwrap())
    });

    c.bench_function("pharos/parse_response_walk", |b| {
        b.iter(|| {
            let m = Message::parse(black_box(&response)).unwrap();
            let mut sum = 0u32;
            for rr in m.answers() {
                if let Ok(Rdata::A(ip)) = rr.data() {
                    sum += u32::from(ip);
                }
            }
            sum
        })
    });
    c.bench_function("hickory/parse_response_walk", |b| {
        b.iter(|| {
            let m = HMessage::from_vec(black_box(&response)).unwrap();
            let mut sum = 0u32;
            for rr in &m.answers {
                if let RData::A(ip) = &rr.data {
                    sum += u32::from(ip.0);
                }
            }
            sum
        })
    });

    c.bench_function("pharos/forward_roundtrip", |b| {
        let mut out = Vec::with_capacity(512);
        b.iter(|| {
            let m = Message::parse(black_box(&response)).unwrap();
            m.with_ad().copy_wire(&mut out);
            black_box(&out);
        })
    });
    c.bench_function("hickory/forward_roundtrip", |b| {
        b.iter(|| {
            let mut m = HMessage::from_vec(black_box(&response)).unwrap();
            m.metadata.authentic_data = true;
            black_box(m.to_vec().unwrap())
        })
    });

    let name = NameRef::parse(QUERY, 12).unwrap();
    let mut wire = Vec::with_capacity(512);
    c.bench_function("pharos/build_five_a", |b| {
        b.iter(|| {
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
    c.bench_function("hickory/build_five_a_and_encode", |b| {
        b.iter(|| black_box(hickory_response(black_box(&hname)).to_vec().unwrap()))
    });
}

criterion_group!(benches, compare);
criterion_main!(benches);

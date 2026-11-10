#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use std::{hint::black_box, time::Duration};

use criterion::{Criterion, criterion_group, criterion_main};
use pharos_plugins::log_format::{COMMON_LOG_FORMAT, Format};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

fn formatting(c: &mut Criterion) {
    let wire = b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
    let domain: Name = ".".parse().unwrap();
    let mut response = wire.to_vec();
    response[2] = 0x81;
    let mut slots = [];
    let context = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let format = Format::compile(COMMON_LOG_FORMAT);
    let mut buffer = String::with_capacity(512);
    c.bench_function("log/common", |b| {
        b.iter(|| {
            buffer.clear();
            format.format(
                &mut buffer,
                black_box(&context),
                Outcome::Response,
                Duration::from_micros(123),
            );
            black_box(&buffer);
        })
    });
}

criterion_group!(benches, formatting);
criterion_main!(benches);

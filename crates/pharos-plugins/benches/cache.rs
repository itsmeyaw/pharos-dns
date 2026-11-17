#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use std::{
    future::Future,
    hint::black_box,
    task::{Context, Poll, Waker},
};

use criterion::{Criterion, criterion_group, criterion_main};
use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::Message;
use pharos_server::{Action, Handler, Protocol};

fn run(future: impl Future<Output = Action>) -> Action {
    match std::pin::pin!(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("cache hit must be ready immediately"),
    }
}

fn cache_hit(c: &mut Criterion) {
    let blocks = parse(
        "Corefile",
        ".:0 {\n cache {\n success 1024 3600 3600\n }\n whoami\n}",
    )
    .unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
    let peer = "127.0.0.1:1001".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        run(server.handle(query, peer, Protocol::Udp, &mut response)),
        Action::Respond
    );
    let mut dispatch = || {
        run(server.handle(
            black_box(query),
            peer,
            Protocol::Udp,
            black_box(&mut response),
        ))
    };
    c.bench_function("cache/routed_hit", |b| b.iter(|| black_box(dispatch())));
    assert_eq!(Message::parse(&response).unwrap().additional_count(), 2);
}

fn cache_miss_churn(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache/miss_churn");
    for capacity in [1024_u32, 65_536, 1_000_000] {
        let corefile = format!(
            ".:0 {{\n cache {{\n success {capacity} 3600 3600\n }}\n template IN A {{\n answer \"{{{{ .Name }}}} 3600 IN A 192.0.2.1\"\n additional \"{{{{ .Name }}}} 3600 IN A 192.0.2.2\"\n }}\n}}"
        );
        let blocks = parse("Corefile", &corefile).unwrap();
        let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
        let (_, server) = servers.drain().next().unwrap();
        let mut query =
            *b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x0800000000\x07example\x03com\0\0\x01\0\x01";
        let peer = "127.0.0.1:1001".parse().unwrap();
        let mut response = Vec::with_capacity(65535);
        let mut id = 1_u32;
        assert_eq!(
            run(server.handle(&query, peer, Protocol::Udp, &mut response)),
            Action::Respond
        );
        assert_eq!(Message::parse(&response).unwrap().additional_count(), 1);
        assert_eq!(
            run(server.handle(&query, peer, Protocol::Udp, &mut response)),
            Action::Respond
        );
        assert_eq!(Message::parse(&response).unwrap().additional_count(), 0);
        // RFC 1034 §5.1: use distinct names to exercise cache misses and eviction.
        let mut dispatch = || {
            for (digit, byte) in query[13..21].iter_mut().enumerate() {
                *byte = b"0123456789abcdef"[((id >> (28 - digit * 4)) & 15) as usize];
            }
            id = id.wrapping_add(1);
            assert_eq!(
                run(server.handle(&query, peer, Protocol::Udp, &mut response)),
                Action::Respond
            );
        };
        for _ in 0..capacity * 2 {
            dispatch();
        }
        group.bench_function(capacity.to_string(), |b| b.iter(&mut dispatch));
    }
    group.finish();
}

criterion_group!(benches, cache_hit, cache_miss_churn);
criterion_main!(benches);

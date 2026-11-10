#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use std::{
    future::Future,
    hint::black_box,
    task::{Context as TaskContext, Poll, Waker},
};

use criterion::{Criterion, criterion_group, criterion_main};
use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

fn run(future: impl Future<Output = Outcome>) -> Outcome {
    match std::pin::pin!(future)
        .as_mut()
        .poll(&mut TaskContext::from_waker(Waker::noop()))
    {
        Poll::Ready(outcome) => outcome,
        Poll::Pending => panic!("whoami should be ready immediately"),
    }
}

fn chain_benchmarks(c: &mut Criterion) {
    let blocks = parse("Corefile", ". {\n whoami\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let chain = &configured[0].config;
    let wire = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
    let query = Message::parse(wire).unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let client = "127.0.0.1:1234".parse().unwrap();
    let local = "127.0.0.1:53".parse().unwrap();
    let mut dispatch = || {
        let mut slots = [None; 18];
        let mut context = Context {
            query,
            client,
            local,
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        run(black_box(chain).serve(black_box(&mut context)))
    };
    assert_eq!(dispatch(), Outcome::Response);
    c.bench_function("chain/whoami", |b| b.iter(|| black_box(dispatch())));
    assert_eq!(Message::parse(&response).unwrap().additional_count(), 2);
}

criterion_group!(benches, chain_benchmarks);
criterion_main!(benches);

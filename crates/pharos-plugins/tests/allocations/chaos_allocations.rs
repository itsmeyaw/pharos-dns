#![forbid(unsafe_code)]
#![cfg(feature = "plugin-chaos")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::{
    alloc::System,
    future::Future,
    task::{Context as TaskContext, Poll, Waker},
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn chaos_responses_do_not_allocate_per_query() {
    let blocks = parse("Corefile", ". {\n chaos v1 Alice Bob\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let domain: Name = ".".parse().unwrap();
    for wire in [
        &b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03"[..],
        &b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x07authors\x04bind\0\0\x10\0\x03"[..],
        &b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x08hostname\x04bind\0\0\x10\0\x03"[..],
    ] {
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
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
        let region = Region::new(GLOBAL);
        let future = configured[0].config.serve(&mut cx);
        let mut future = std::pin::pin!(future);
        let result = future
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()));
        let stats = region.change();
        assert_eq!(result, Poll::Ready(Outcome::Response));
        assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    }
}

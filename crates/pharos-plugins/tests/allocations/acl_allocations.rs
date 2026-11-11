#![forbid(unsafe_code)]
#![cfg(feature = "plugin-acl")]

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

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn acl_block_does_not_allocate_per_query() {
    if crate::run_isolated("acl::acl_allocations::acl_block_does_not_allocate_per_query") {
        return;
    }
    let blocks = parse("Corefile", ". {\n acl {\n  block\n }\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let wire = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
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

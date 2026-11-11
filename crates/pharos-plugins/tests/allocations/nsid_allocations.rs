#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-nsid", feature = "plugin-whoami"))]

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
fn requested_nsid_does_not_allocate_per_query() {
    let _serial = crate::serial();
    if crate::run_isolated("nsid::nsid_allocations::requested_nsid_does_not_allocate_per_query") {
        return;
    }
    let blocks = parse("Corefile", ". {\n nsid NSID\n whoami\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let wire = [
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 4, 0, 3,
        0, 0,
    ];
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut context = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:53".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let region = Region::new(GLOBAL);
    let future = configured[0].config.serve(&mut context);
    let mut future = std::pin::pin!(future);
    let result = future
        .as_mut()
        .poll(&mut TaskContext::from_waker(Waker::noop()));
    let stats = region.change();
    assert_eq!(result, Poll::Ready(Outcome::Response));
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
}

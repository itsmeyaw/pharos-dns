#![forbid(unsafe_code)]
#![cfg(feature = "plugin-transfer")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::{
    alloc::System,
    future::Future,
    task::{Context as TaskContext, Poll, Waker},
};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

struct NextDrop;
impl Next for NextDrop {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Drop
    }
}

#[test]
fn ordinary_query_does_not_allocate() {
    if crate::run_isolated("transfer::cases::ordinary_query_does_not_allocate") {
        return;
    }
    let blocks = parse("Corefile", ". {\n transfer {\n to 192.0.2.1\n }\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let wire = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    let axfr = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 252, 0, 1];
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
    {
        let region = Region::new(GLOBAL);
        let future = configured[0]
            .config
            .transfer
            .as_ref()
            .unwrap()
            .serve(&mut cx, NextDrop);
        let mut future = std::pin::pin!(future);
        let outcome = future
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()));
        let stats = region.change();
        assert_eq!(outcome, Poll::Ready(Outcome::Drop));
        assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    }

    cx.query = Message::parse(&axfr).unwrap();
    cx.protocol = Protocol::Tcp;
    let region = Region::new(GLOBAL);
    let future = configured[0]
        .config
        .transfer
        .as_ref()
        .unwrap()
        .serve(&mut cx, NextDrop);
    let mut future = std::pin::pin!(future);
    let outcome = future
        .as_mut()
        .poll(&mut TaskContext::from_waker(Waker::noop()));
    let stats = region.change();
    assert_eq!(
        outcome,
        Poll::Ready(Outcome::Unanswered(pharos_proto::Rcode::REFUSED))
    );
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
}

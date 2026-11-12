#![cfg(feature = "plugin-erratic")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
use stats_alloc::Region;
use std::{
    future::Future,
    task::{Context as TaskContext, Poll, Waker},
};

#[test]
fn ordinary_answers_and_drops_do_not_allocate() {
    if crate::run_isolated("erratic::cases::ordinary_answers_and_drops_do_not_allocate") {
        return;
    }
    let blocks = parse("Corefile", ". {\n erratic\n}").unwrap();
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
    for expected in [Outcome::Drop, Outcome::Response] {
        let region = Region::new(crate::GLOBAL);
        let future = configured[0].config.serve(&mut cx);
        let mut future = std::pin::pin!(future);
        let result = future
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()));
        let stats = region.change();
        assert_eq!(result, Poll::Ready(expected));
        assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    }
}

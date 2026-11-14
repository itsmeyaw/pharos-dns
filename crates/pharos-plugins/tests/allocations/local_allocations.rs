#![forbid(unsafe_code)]
#![cfg(feature = "plugin-local")]

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
fn local_responses_do_not_allocate_per_query() {
    if crate::run_isolated("local::local_allocations::local_responses_do_not_allocate_per_query") {
        return;
    }
    let blocks = parse("Corefile", ". {\n local\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let domain: Name = ".".parse().unwrap();
    for wire in [
        // RFC 1035 §4.1.2: Each question carries QNAME, QTYPE, and QCLASS.
        &b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01a\x09localhost\0\0\x01\0\x01"[..],
        &b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x011\x010\x010\x03127\x07in-addr\x04arpa\0\0\x0c\0\x01"[..],
        &b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x012\x010\x010\x03127\x07in-addr\x04arpa\0\0\x0c\0\x01"[..],
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
    local_debug_logging_does_not_allocate_per_query();
}

fn local_debug_logging_does_not_allocate_per_query() {
    let blocks = parse("Corefile", ". {\n local\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let domain: Name = ".".parse().unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01a\x09localhost\0\0\x01\0\x01";
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
    pharos_server::logging::set_debug_enabled(true);
    for round in 0..2 {
        let region = Region::new(GLOBAL);
        let future = configured[0].config.serve(&mut cx);
        let mut future = std::pin::pin!(future);
        let result = future
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()));
        let stats = region.change();
        assert_eq!(result, Poll::Ready(Outcome::Response));
        if round == 1 {
            assert_eq!((stats.allocations, stats.reallocations), (0, 0));
        }
    }
    pharos_server::logging::set_debug_enabled(false);
}

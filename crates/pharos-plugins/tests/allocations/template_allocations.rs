#![cfg(feature = "plugin-template")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region};
use std::{
    future::Future,
    task::{Context as TaskContext, Poll, Waker},
};

fn measure(corefile: &str) -> (Poll<Outcome>, stats_alloc::Stats) {
    let blocks = parse("Corefile", corefile).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\0\0\x01\0\x01";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut context = Context {
        query: Message::parse(wire).unwrap(),
        client: "192.0.2.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    let future = configured[0].config.serve(&mut context);
    let mut future = std::pin::pin!(future);
    let outcome = future
        .as_mut()
        .poll(&mut TaskContext::from_waker(Waker::noop()));
    (outcome, region.change())
}

#[test]
#[cfg(feature = "plugin-whoami")]
fn unmatched_and_fallthrough_queries_do_not_allocate() {
    if crate::run_isolated("template::cases::unmatched_and_fallthrough_queries_do_not_allocate") {
        return;
    }
    for directive in [
        "template IN A other {\n answer \"{{ .Name }} 60 IN A 192.0.2.1\"\n}",
        "template IN AAAA example {\n answer \"{{ .Name }} 60 IN A 192.0.2.1\"\n}",
        "template IN A example {\n match ^nomatch$\n fallthrough\n}",
        "template IN A example {\n expr false\n fallthrough\n}",
        "template IN A example {\n match ^(?P<host>[a-z]+)[.]example[.]$\n var host group('host')\n expr host == 'no'\n fallthrough\n}",
    ] {
        let corefile = format!(". {{\n {directive}\n whoami\n}}");
        let (outcome, stats) = measure(&corefile);
        assert_eq!(outcome, Poll::Ready(Outcome::Response), "{directive}");
        assert_eq!(
            (stats.allocations, stats.reallocations),
            (0, 0),
            "{directive}"
        );
    }
}

#[test]
fn matched_zone_record_allocations_are_bounded() {
    if crate::run_isolated("template::cases::matched_zone_record_allocations_are_bounded") {
        return;
    }
    let corefile =
        ". {\n template IN A example {\n answer \"{{ .Name }} 60 IN A 192.0.2.1\"\n }\n}";
    let (outcome, stats) = measure(corefile);
    assert_eq!(outcome, Poll::Ready(Outcome::Response));
    assert!(stats.allocations + stats.reallocations <= 100, "{stats:?}");
    assert!(stats.bytes_allocated <= 262_144, "{stats:?}");
}

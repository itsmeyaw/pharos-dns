#![cfg(all(feature = "plugin-view", feature = "plugin-hosts"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::Message;
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region};

#[tokio::test(flavor = "current_thread")]
async fn filtered_routing_does_not_allocate() {
    if crate::run_isolated("view::cases::filtered_routing_does_not_allocate") {
        return;
    }
    let text = ".:53 {\n view first {\n  expr name() == 'example.com.' && type() == 'A'\n }\n hosts {\n  192.0.2.1 example.com other.com\n }\n}\n.:53 {\n hosts {\n  192.0.2.2 example.com other.com\n }\n}";
    let blocks = parse("Corefile", text).unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    let wire =
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let unmatched =
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05other\x03com\x00\x00\x01\x00\x01";
    let peer = "127.0.0.1:1234".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server
            .handle(wire, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    for _ in 0..100 {
        assert_eq!(
            server
                .handle(wire, peer, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
        assert_eq!(
            server
                .handle(unmatched, peer, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
        assert_eq!(
            Message::parse(&response)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rdata,
            [192, 0, 2, 2]
        );
    }
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
}

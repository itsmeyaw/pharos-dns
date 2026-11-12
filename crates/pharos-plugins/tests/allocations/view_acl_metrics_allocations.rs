#![cfg(all(feature = "plugin-view", feature = "plugin-acl"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region};

#[tokio::test(flavor = "current_thread")]
async fn routed_acl_metrics_do_not_allocate() {
    if crate::run_isolated("view::acl_metrics::routed_acl_metrics_do_not_allocate") {
        return;
    }
    let blocks = parse(
        "Corefile",
        "example.org:53 {\n view child {\n  expr true\n }\n}\norg:53 {\n acl {\n  filter\n }\n}",
    )
    .unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    // RFC 4034 §5: DS is queried at the delegation owner name.
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x07example\x03org\0\0\x2b\0\x01";
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
    }
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
}

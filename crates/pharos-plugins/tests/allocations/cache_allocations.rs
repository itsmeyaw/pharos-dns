#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-cache", feature = "plugin-whoami"))]

use std::alloc::System;

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Message, Rdata};
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn warmed_routed_cache_hit_has_no_allocations() {
    if crate::run_isolated("cache::cache_allocations::warmed_routed_cache_hit_has_no_allocations") {
        return;
    }
    crate::on_allocation_stack(warmed_routed_cache_hit);
}

async fn warmed_routed_cache_hit() {
    let blocks = parse(
        "Corefile",
        ".:0 {\n cache {\n success 1024 3600 3600\n }\n whoami\n}",
    )
    .unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
    let first = "127.0.0.1:1001".parse().unwrap();
    let second = "127.0.0.1:1002".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(query, first, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    let before = GLOBAL.stats();
    for _ in 0..100 {
        assert_eq!(
            server
                .handle(query, second, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    let answer = Message::parse(&response).unwrap();
    let port = answer.additionals().find_map(|rr| match rr.data().ok()? {
        Rdata::Srv { port, .. } => Some(port),
        _ => None,
    });
    assert_eq!(port, Some(1001), "response must come from the warmed cache");
}

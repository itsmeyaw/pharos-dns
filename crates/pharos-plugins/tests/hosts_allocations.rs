#![forbid(unsafe_code)]
#![cfg(feature = "plugin-hosts")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::Message;
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[tokio::test(flavor = "current_thread")]
async fn routed_hosts_hit_has_no_allocations() {
    let blocks = parse(
        "Corefile",
        ".:0 {\n hosts /nonexistent {\n 192.0.2.1 www.example.com\n }\n}",
    )
    .unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
    let client = "127.0.0.1:1001".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(query, client, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    let before = GLOBAL.stats();
    for _ in 0..100 {
        assert_eq!(
            server
                .handle(query, client, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    assert_eq!(Message::parse(&response).unwrap().answer_count(), 1);
}

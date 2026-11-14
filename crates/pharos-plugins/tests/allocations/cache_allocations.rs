#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-cache", feature = "plugin-template"))]

use std::alloc::System;

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Message, Rdata};
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[tokio::test]
async fn warmed_routed_cache_hit_has_no_allocations() {
    if crate::run_isolated("cache::cache_allocations::warmed_routed_cache_hit_has_no_allocations") {
        return;
    }
    warmed_routed_cache_hit().await;
}

async fn warmed_routed_cache_hit() {
    let blocks = parse(
        "Corefile",
        ".:0 {\n cache {\n success 1024 3600 3600\n }\n template IN A {\n answer \"{{ .Name }} 60 IN A {{ .Remote }}\"\n }\n}",
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
    let port = answer.answers().find_map(|rr| match rr.data().ok()? {
        Rdata::A(address) if !address.is_unspecified() => {
            Some(1000 + u16::from(address.octets()[3]))
        }
        Rdata::A(_) => Some(0),
        _ => None,
    });
    assert_eq!(port, Some(1001), "response must come from the warmed cache");
}

#[tokio::test]
async fn warmed_nxdomain_cross_qtype_hit_has_no_allocations() {
    if crate::run_isolated(
        "cache::cache_allocations::warmed_nxdomain_cross_qtype_hit_has_no_allocations",
    ) {
        return;
    }
    let blocks = parse(
        "Corefile",
        ".:0 {\n cache {\n denial 1024 300 5\n }\n template IN A {\n rcode NXDOMAIN\n authority \"example.com. 30 IN SOA ns.example.com. hostmaster.example.com. (1 60 60 60 60)\"\n }\n}",
    )
    .unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let query_a = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
    let query_aaaa = b"\x12\x35\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x1c\0\x01";
    let peer = "127.0.0.1:1001".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(query_a, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    let before = GLOBAL.stats();
    for _ in 0..100 {
        assert_eq!(
            server
                .handle(query_aaaa, peer, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.rcode(), pharos_proto::Rcode::NXDOMAIN);
    assert_eq!(
        response.questions().next().unwrap().qtype,
        pharos_proto::Type::AAAA
    );
}

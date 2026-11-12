#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-hosts", feature = "plugin-loadbalance"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Action, Handler, Phase, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn routed_shuffled_hosts_hit_has_no_allocations() {
    if crate::run_isolated(
        "loadbalance::loadbalance_allocations::routed_shuffled_hosts_hit_has_no_allocations",
    ) {
        return;
    }
    crate::on_allocation_stack(routed_shuffled_hosts_hit);
}

async fn routed_shuffled_hosts_hit() {
    let path =
        std::env::temp_dir().join(format!("pharos-hosts-allocations-{}", std::process::id()));
    std::fs::write(
        &path,
        "192.0.2.1 www.example.com\n192.0.2.2 www.example.com\n192.0.2.3 www.example.com\n2001:db8::1 www.example.com\n",
    )
    .unwrap();
    let text = format!(
        ".:0 {{\n loadbalance\n hosts {} {{\n reload 0\n }}\n}}",
        path.display()
    );
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, lifecycle) =
        servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let mut queries = Vec::new();
    for (name, kind) in [
        ("www.example.com.", Type::A),
        ("www.example.com.", Type::AAAA),
        ("www.example.com.", Type::TXT),
        ("1.2.0.192.in-addr.arpa.", Type::PTR),
    ] {
        let name: Name = name.parse().unwrap();
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x0100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        let _ = builder.finish();
        queries.push(query);
    }
    let client = "127.0.0.1:1001".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    for query in &queries {
        assert_eq!(
            server
                .handle(query, client, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
    }
    let before = GLOBAL.stats();
    for _ in 0..100 {
        for query in &queries {
            assert_eq!(
                server
                    .handle(query, client, Protocol::Udp, &mut response)
                    .await,
                Action::Respond
            );
        }
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    assert!(Message::parse(&response).is_ok());
    lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_file(path).unwrap();
}

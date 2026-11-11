#![forbid(unsafe_code)]
#![cfg(feature = "plugin-loadbalance")]

#[path = "../support/loadbalance_fixtures.rs"]
mod fixtures;

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::Message;
use pharos_server::{
    Action, Context, Handler, ListenerKey, Next, Outcome, Plugin, Protocol, Router, Server,
    Transport,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

struct Reply<'a>(&'a [u8]);
impl Next for Reply<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        cx.response.clear();
        cx.response.extend_from_slice(self.0);
        Outcome::Response
    }
}

struct Routed {
    chain: Chain,
    wire: Vec<u8>,
}
impl pharos_server::Chain for Routed {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.chain
            .loadbalance
            .as_ref()
            .unwrap()
            .serve(cx, Reply(&self.wire))
            .await
    }
    fn is_empty(&self) -> bool {
        false
    }
    fn metrics_enabled(&self) -> bool {
        false
    }
}

#[tokio::test(flavor = "current_thread")]
async fn routed_compressed_cname_shuffle_has_no_allocations() {
    let _serial = crate::serial();
    if crate::run_isolated(
        "loadbalance::loadbalance_cname_allocations::routed_compressed_cname_shuffle_has_no_allocations",
    ) {
        return;
    }
    let blocks = parse("Corefile", ".:53 {\n loadbalance\n}").unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        key,
        ".".parse().unwrap(),
        Some(Routed {
            chain,
            wire: fixtures::cdn_response(),
        }),
        vec![],
    );
    let server = Server::new(router, key);
    let query = fixtures::cdn_query();
    let client = "127.0.0.1:1001".parse().unwrap();
    let mut output = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(&query, client, Protocol::Udp, &mut output)
            .await,
        Action::Respond
    );
    let before = GLOBAL.stats();
    let mut first_addresses = 0u8;
    for _ in 0..100 {
        assert_eq!(
            server
                .handle(&query, client, Protocol::Udp, &mut output)
                .await,
            Action::Respond
        );
        let message = Message::parse(&output).unwrap();
        let address = message.answers().nth(1).unwrap().rdata[3];
        first_addresses |= 1 << address;
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    assert!(
        first_addresses.count_ones() > 1,
        "CNAME-compressed addresses were not shuffled"
    );
    assert!(
        Message::parse(&output)
            .unwrap()
            .answers()
            .skip(1)
            .all(|rr| rr.name.to_string() == "cdn.example.net.")
    );
}

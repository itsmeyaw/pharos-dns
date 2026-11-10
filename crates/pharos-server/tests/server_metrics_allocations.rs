#![forbid(unsafe_code)]

use std::alloc::System;

use pharos_proto::Rcode;
use pharos_server::{
    Chain, Context, Handler, ListenerKey, Outcome, Protocol, Router, Server, Transport,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

struct Refuse;
impl Chain for Refuse {
    async fn serve(&self, _: &mut Context<'_>) -> Outcome {
        Outcome::Unanswered(Rcode::REFUSED)
    }
    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test(flavor = "current_thread")]
async fn server_records_queries_without_allocating() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(Refuse), vec![]);
    let server = Server::new(router, key);
    let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
    let peer = "127.0.0.1:1234".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    server
        .handle(&query, peer, Protocol::Udp, &mut response)
        .await;
    let before = GLOBAL.stats();
    for _ in 0..100 {
        server
            .handle(&query, peer, Protocol::Udp, &mut response)
            .await;
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
}

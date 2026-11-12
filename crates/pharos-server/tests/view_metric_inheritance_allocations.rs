#![forbid(unsafe_code)]

use std::alloc::System;

use pharos_proto::Rcode;
use pharos_server::{
    Chain, Context, Handler, ListenerKey, Outcome, Protocol, Router, Server, Transport,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

struct View(&'static str, bool);

impl Chain for View {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        if self.1 {
            assert!(
                cx.metadata
                    .insert(pharos_server::metrics::WRITER_METADATA, "test")
            );
        }
        Outcome::Unanswered(Rcode::REFUSED)
    }
    fn is_empty(&self) -> bool {
        false
    }
    fn has_view(&self) -> bool {
        !self.0.is_empty()
    }
    fn view_name(&self) -> &str {
        self.0
    }
    fn visit_enabled(&self, visit: &mut dyn FnMut(&'static str)) {
        visit("test");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn inherited_request_and_writer_metrics_allocate_nothing() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    for writer in [false, true] {
        let mut router = Router::default();
        router.add(
            key,
            "example.org.".parse().unwrap(),
            Some(View("child", false)),
            vec![],
        );
        router.add(key, "org.".parse().unwrap(), Some(View("", writer)), vec![]);
        let server = Server::new(router, key);
        let wire = [
            0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
            b'o', b'r', b'g', 0, 0, 43, 0, 1,
        ];
        let peer = "127.0.0.1:1234".parse().unwrap();
        let mut response = Vec::with_capacity(512);
        let before = GLOBAL.stats();
        for _ in 0..100 {
            server
                .handle(&wire, peer, Protocol::Udp, &mut response)
                .await;
        }
        let after = GLOBAL.stats();
        assert_eq!(after.allocations - before.allocations, 0);
        assert_eq!(after.reallocations - before.reallocations, 0);
    }
}

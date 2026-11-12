#![forbid(unsafe_code)]

use pharos_proto::Rcode;
use pharos_server::{
    Chain, Context, Handler, ListenerKey, Outcome, Protocol, Router, Server, Transport,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::{alloc::System, sync::Arc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

struct View(Arc<str>);
impl Chain for View {
    async fn serve(&self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(Rcode::REFUSED)
    }
    fn is_empty(&self) -> bool {
        false
    }
    fn has_view(&self) -> bool {
        true
    }
    fn view_name(&self) -> &str {
        &self.0
    }
    fn has_metadata_collector(&self) -> bool {
        true
    }
    fn collect_metadata(&self, cx: &mut Context<'_, '_>) {
        cx.metadata.set_view_name(Arc::clone(&self.0));
    }
    fn matches_view(&self, cx: &Context<'_, '_>) -> bool {
        cx.metadata.get("view/name") == Some(self.0.as_ref())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn view_routing_and_shared_metadata_do_not_allocate() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        key,
        ".".parse().unwrap(),
        Some(View("x".repeat(2048).into())),
        vec![],
    );
    let server = Server::new(router, key);
    let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
    let peer = "127.0.0.1:1234".parse().unwrap();
    let mut response = Vec::with_capacity(512);
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

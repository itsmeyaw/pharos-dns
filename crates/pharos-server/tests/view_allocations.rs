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

struct CutView {
    name: Arc<str>,
    rcode: Rcode,
}

impl Chain for CutView {
    async fn serve(&self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(self.rcode)
    }
    fn is_empty(&self) -> bool {
        false
    }
    fn has_view(&self) -> bool {
        true
    }
    fn view_name(&self) -> &str {
        &self.name
    }
    fn has_metadata_collector(&self) -> bool {
        true
    }
    fn collect_metadata(&self, cx: &mut Context<'_, '_>) {
        cx.metadata.set_view_name(Arc::clone(&self.name));
    }
    fn matches_view(&self, cx: &Context<'_, '_>) -> bool {
        cx.metadata.get("view/name") == Some(self.name.as_ref())
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

#[tokio::test(flavor = "current_thread")]
async fn ds_zone_cut_routing_does_not_allocate() {
    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};

    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut parent_router = Router::default();
    parent_router.add(
        key,
        "org.".parse().unwrap(),
        Some(CutView {
            name: Arc::from("parent"),
            rcode: Rcode::NOTAUTH,
        }),
        vec![],
    );
    parent_router.add(
        key,
        "example.org.".parse().unwrap(),
        Some(CutView {
            name: Arc::from("child"),
            rcode: Rcode::REFUSED,
        }),
        vec![],
    );
    let parent_server = Server::new(parent_router, key);

    let mut child_router = Router::default();
    child_router.add(
        key,
        "example.org.".parse().unwrap(),
        Some(CutView {
            name: Arc::from("child"),
            rcode: Rcode::REFUSED,
        }),
        vec![],
    );
    let child_server = Server::new(child_router, key);

    let name: Name = "example.org.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x0100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::DS,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let peer = "127.0.0.1:1234".parse().unwrap();
    let mut parent_response = Vec::with_capacity(512);
    let mut child_response = Vec::with_capacity(512);

    for _ in 0..2 {
        parent_server
            .handle(&query, peer, Protocol::Udp, &mut parent_response)
            .await;
        child_server
            .handle(&query, peer, Protocol::Udp, &mut child_response)
            .await;
    }
    assert_eq!(
        Message::parse(&parent_response).unwrap().rcode(),
        Rcode::NOTAUTH
    );
    assert_eq!(
        Message::parse(&child_response).unwrap().rcode(),
        Rcode::REFUSED
    );

    let before = GLOBAL.stats();
    for _ in 0..100 {
        parent_server
            .handle(&query, peer, Protocol::Udp, &mut parent_response)
            .await;
        child_server
            .handle(&query, peer, Protocol::Udp, &mut child_response)
            .await;
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
}

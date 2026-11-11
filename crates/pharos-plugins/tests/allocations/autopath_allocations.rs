#![forbid(unsafe_code)]
#![cfg(feature = "plugin-autopath")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::{
    alloc::System,
    future::Future,
    task::{Context as TaskContext, Poll, Waker},
};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

struct Answer<'a>(Option<&'a Name>);
impl Next for Answer<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        if let Some(owner) = self.0 {
            b.record(
                Section::Answer,
                NameRef::parse(owner.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
                60,
                &[1, 2, 3, 4],
            )
            .unwrap();
        }
        let _ = b.finish();
        Outcome::Response
    }
}

#[test]
fn autopath_without_self_lookup_does_not_allocate() {
    if crate::run_isolated(
        "autopath::autopath_allocations::autopath_without_self_lookup_does_not_allocate",
    ) {
        return;
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/autopath-search.conf"
    );
    let config = format!(".:53 {{\n autopath {path}\n}}");
    let configured =
        configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap();
    let plugin = configured[0].config.autopath.as_ref().unwrap();
    let root: Name = ".".parse().unwrap();
    let alias: Name = "other.example.org.".parse().unwrap();
    for (name, owner) in [
        ("outside.example.com.", None),
        ("inside.example.org.", None),
        ("inside.example.org.", Some(&alias)),
    ] {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let region = Region::new(GLOBAL);
        let mut future = std::pin::pin!(plugin.serve(&mut cx, Answer(owner)));
        let result = future
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()));
        let stats = region.change();
        assert_eq!(result, Poll::Ready(Outcome::Response));
        assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    }
}

#![forbid(unsafe_code)]
#![cfg(feature = "plugin-siit")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{
    Action, Context, Handler, Metadata, Next, Outcome, Plugin, Protocol, Transport,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::{
    alloc::System,
    future::Future,
    sync::Arc,
    task::{Context as TaskContext, Poll, Waker},
};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

struct Answer {
    rcode: u16,
    a: bool,
    truncated: bool,
}
impl Next for Answer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(
            cx.response,
            512,
            cx.query.id(),
            0x8100 | self.rcode | if self.truncated { 0x200 } else { 0 },
        )
        .unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        if self.a {
            builder
                .record(
                    Section::Answer,
                    q.name,
                    Type::A,
                    Class::IN,
                    60,
                    &[192, 0, 2, 1],
                )
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

#[test]
fn siit_non_synthesis_paths_do_not_allocate() {
    if crate::run_isolated("siit::siit_allocations::siit_non_synthesis_paths_do_not_allocate") {
        return;
    }
    let configured =
        configure::<Chain>(&parse("Corefile", ". {\n siit\n}").unwrap(), directives()).unwrap();
    let plugin = configured[0].config.siit.as_ref().unwrap();
    let name: Name = "example.org.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    for (typ, class, rcode, a, truncated) in [
        (Type::AAAA, Class::IN, 0, false, false),
        (Type::A, Class::CH, 0, false, false),
        (Type::A, Class::IN, 3, false, false),
        (Type::A, Class::IN, 0, true, false),
        (Type::A, Class::IN, 0, false, true),
    ] {
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(NameRef::parse(name.as_wire(), 0).unwrap(), typ, class)
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
        let future = plugin.serve(
            &mut cx,
            Answer {
                rcode,
                a,
                truncated,
            },
        );
        let mut future = std::pin::pin!(future);
        let result = future
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()));
        let stats = region.change();
        assert_eq!(result, Poll::Ready(Outcome::Response));
        assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    }
}

#[cfg(feature = "plugin-hosts")]
#[test]
fn siit_synthesis_self_lookup_does_not_allocate_once_warmed() {
    if crate::run_isolated(
        "siit::siit_allocations::siit_synthesis_self_lookup_does_not_allocate_once_warmed",
    ) {
        return;
    }
    let config =
        ".:53 {\n siit\n hosts /nonexistent {\n  64:ff9b::8.8.8.1 mapped.example\n  ttl 60\n }\n}";
    let blocks = parse("Corefile", config).unwrap();
    let (mut listeners, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = Arc::new(listeners.drain().next().unwrap().1);
    let name: Name = "mapped.example.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 42, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let peer = "[::1]:1234".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let run = |response: &mut Vec<u8>| {
        let future = Handler::handle_shared(&server, &wire, peer, Protocol::Udp, response);
        let mut future = std::pin::pin!(future);
        future
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()))
    };
    assert_eq!(run(&mut response), Poll::Ready(Action::Respond));
    let region = Region::new(GLOBAL);
    for _ in 0..100 {
        assert_eq!(run(&mut response), Poll::Ready(Action::Respond));
    }
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    let message = Message::parse(&response).unwrap();
    let answer = message.answers().next().unwrap();
    assert_eq!((answer.rtype, answer.rdata), (Type::A, &[8, 8, 8, 1][..]));
}

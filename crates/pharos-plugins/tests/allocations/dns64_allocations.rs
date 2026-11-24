#![forbid(unsafe_code)]
#![cfg(feature = "plugin-dns64")]

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
    aaaa: bool,
}
impl Next for Answer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut builder =
            MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8100 | self.rcode).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        if self.aaaa {
            builder
                .record(Section::Answer, q.name, Type::AAAA, Class::IN, 60, &[0; 16])
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

#[test]
fn dns64_non_synthesis_paths_do_not_allocate() {
    if crate::run_isolated("dns64::dns64_allocations::dns64_non_synthesis_paths_do_not_allocate") {
        return;
    }
    let blocks = parse("Corefile", ". {\n dns64\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let plugin = configured[0].config.dns64.as_ref().unwrap();
    let name: Name = "example.org.".parse().unwrap();
    let domain: Name = ".".parse().unwrap();
    for (client, qtype, rcode, aaaa) in [
        ("127.0.0.1:1", Type::AAAA, 0, false),
        ("[::1]:1", Type::A, 0, false),
        ("[::1]:1", Type::AAAA, 0, true),
        ("[::1]:1", Type::AAAA, 3, false),
    ] {
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: client.parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let region = Region::new(GLOBAL);
        let future = plugin.serve(&mut cx, Answer { rcode, aaaa });
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
fn dns64_synthesis_self_lookup_does_not_allocate_once_warmed() {
    if crate::run_isolated(
        "dns64::dns64_allocations::dns64_synthesis_self_lookup_does_not_allocate_once_warmed",
    ) {
        return;
    }
    let config =
        ".:53 {\n dns64\n hosts /nonexistent {\n  64.64.64.64 example.org\n  ttl 60\n }\n}";
    let blocks = parse("Corefile", config).unwrap();
    let (mut listeners, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = Arc::new(listeners.drain().next().unwrap().1);
    let name: Name = "example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 42, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::AAAA,
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
    assert_eq!(answer.rtype, Type::AAAA);
    assert_eq!(
        answer.rdata,
        "64:ff9b::4040:4040"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
    );
}

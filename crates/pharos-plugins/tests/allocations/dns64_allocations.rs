#![forbid(unsafe_code)]
#![cfg(feature = "plugin-dns64")]
#![recursion_limit = "512"]

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

#[global_allocator]
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

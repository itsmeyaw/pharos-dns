#![forbid(unsafe_code)]
#![cfg(feature = "plugin-rewrite")]
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
struct Answer;
impl Next for Answer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record(
            Section::Answer,
            q.name,
            Type::A,
            Class::IN,
            5,
            &[127, 0, 0, 1],
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

#[test]
fn rewrite_non_regex_rules_do_not_allocate() {
    for (rule, incoming) in [
        ("rewrite type A AAAA", "example."),
        ("rewrite class IN CH", "example."),
        ("rewrite ttl example. 10", "example."),
        ("rewrite rcode example. SERVFAIL NOERROR", "example."),
        ("rewrite name example. internal.", "example."),
        ("rewrite name suffix .example. .internal.", "www.example."),
        (
            "rewrite name suffix .example. .internal. answer auto",
            "www.example.",
        ),
        ("rewrite name prefix www api", "www.example."),
        ("rewrite name substring example internal", "www.example."),
        ("rewrite name other. internal.", "example."),
        ("rewrite cname old.example. new.example.", "example."),
        ("rewrite edns0 local set 0xffee abcd", "example."),
        ("rewrite edns0 local append 0xffee abcd", "example."),
        ("rewrite edns0 local replace 0xffee abcd", "example."),
        ("rewrite edns0 local unset 0xffee", "example."),
        ("rewrite edns0 nsid set", "example."),
        ("rewrite edns0 subnet set 24 56", "example."),
    ] {
        let config = format!(".:53 {{\n {rule}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = incoming.parse().unwrap();
        let root: Name = ".".parse().unwrap();
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
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let region = Region::new(GLOBAL);
        let future = chain.rewrite.as_ref().unwrap().serve(&mut cx, Answer);
        let mut future = std::pin::pin!(future);
        let outcome = future
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()));
        let stats = region.change();
        assert_eq!(outcome, Poll::Ready(Outcome::Response), "{rule}");
        assert_eq!((stats.allocations, stats.reallocations), (0, 0), "{rule}");
    }
}

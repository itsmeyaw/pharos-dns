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
struct WaitForever;
impl Next for WaitForever {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        std::future::pending().await
    }
}
struct DropNext;
impl Next for DropNext {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Drop
    }
}
struct FailNext;
impl Next for FailNext {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL)
    }
}
struct QuestionOnly;
impl Next for QuestionOnly {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8000).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}
struct OtherCname<'a>(&'a Name);
impl Next for OtherCname<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        builder
            .record_with(
                Section::Answer,
                q.name,
                Type::CNAME,
                Class::IN,
                30,
                |writer| writer.write_name(NameRef::parse(self.0.as_wire(), 0).unwrap()),
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}
impl Next for Answer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let query = cx.query;
        let q = query.questions().next().unwrap();
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
        if let Some(opt) = query.opt() {
            b.record(
                Section::Additional,
                NameRef::parse(&[0], 0).unwrap(),
                Type::OPT,
                Class(opt.udp_payload_size()),
                0,
                opt.options().as_bytes(),
            )
            .unwrap();
        }
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
        ("rewrite edns0 local set 0xffee abcd revert", "example."),
        ("rewrite edns0 nsid set revert", "example."),
        ("rewrite edns0 subnet set 24 56 revert", "example."),
        ("rewrite edns0 local append 0xffee abcd", "example."),
        ("rewrite edns0 local replace 0xffee abcd", "example."),
        ("rewrite edns0 local unset 0xffee", "example."),
        ("rewrite edns0 nsid set", "example."),
        ("rewrite edns0 subnet set 24 56", "example."),
        ("rewrite edns0 local set 0xffee {qname}", "example."),
        ("rewrite edns0 local set 0xffee {qtype}", "example."),
        ("rewrite edns0 local set 0xffee {client_ip}", "example."),
        ("rewrite edns0 local set 0xffee {client_port}", "example."),
        ("rewrite edns0 local set 0xffee {server_ip}", "example."),
        ("rewrite edns0 local set 0xffee {server_port}", "example."),
        ("rewrite edns0 local set 0xffee {protocol}", "example."),
        ("rewrite edns0 local set 0xffee {test/label}", "example."),
        (
            "rewrite continue edns0 local set 0xffee {test/label}\n rewrite edns0 local replace 0xffee new revert",
            "example.",
        ),
        ("rewrite edns0 local set 0xffee {missing/label}", "example."),
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
        let mut slots = [None];
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
        assert!(cx.metadata.insert("test/label", "Team-A"));
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

    let config = ".:53 {\n rewrite edns0 local set 0xffee abcd\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let plugin = chain.rewrite.as_ref().unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let root: Name = ".".parse().unwrap();
    let mut first_response = Vec::with_capacity(512);
    let mut second_response = Vec::with_capacity(512);
    let mut first_slots = [];
    let mut second_slots = [];
    let mut first = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut first_slots),
        response: &mut first_response,
        max_response_size: 512,
    };
    let mut second = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut second_slots),
        response: &mut second_response,
        max_response_size: 512,
    };
    let mut first_future = Box::pin(plugin.serve(&mut first, WaitForever));
    let mut second_future = Box::pin(plugin.serve(&mut second, DropNext));
    let region = Region::new(GLOBAL);
    let mut task = TaskContext::from_waker(Waker::noop());
    assert_eq!(first_future.as_mut().poll(&mut task), Poll::Pending);
    assert_eq!(second_future.as_mut().poll(&mut task), Poll::Pending);
    drop(first_future);
    assert_eq!(
        second_future.as_mut().poll(&mut task),
        Poll::Ready(Outcome::Drop)
    );
    let stats = region.change();
    assert_eq!(
        (stats.allocations, stats.reallocations),
        (0, 0),
        "contended EDNS scratch"
    );
    drop(second_future);
    let region = Region::new(GLOBAL);
    let future = plugin.serve(&mut second, FailNext);
    let mut future = std::pin::pin!(future);
    assert_eq!(
        future.as_mut().poll(&mut task),
        Poll::Ready(Outcome::Response)
    );
    let stats = region.change();
    assert_eq!(
        (stats.allocations, stats.reallocations),
        (0, 0),
        "EDNS unanswered response"
    );
    let long = "long-long-long-long-long-long-long-long.example.";
    let config = format!(".:53 {{\n rewrite name {long} x.\n}}");
    let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = long.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(32);
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
    {
        let region = Region::new(GLOBAL);
        let future = chain.rewrite.as_ref().unwrap().serve(&mut cx, QuestionOnly);
        let mut future = std::pin::pin!(future);
        let outcome = future.as_mut().poll(&mut task);
        let stats = region.change();
        assert_eq!(
            outcome,
            Poll::Ready(Outcome::Error(pharos_server::Error::ResponseBufferTooSmall))
        );
        assert_eq!(
            (stats.allocations, stats.reallocations),
            (0, 0),
            "undersized UDP buffer"
        );
    }
    cx.protocol = Protocol::Tcp;
    cx.query = Message::parse(&wire).unwrap();
    let region = Region::new(GLOBAL);
    let future = chain.rewrite.as_ref().unwrap().serve(&mut cx, QuestionOnly);
    let mut future = std::pin::pin!(future);
    assert_eq!(
        future.as_mut().poll(&mut task),
        Poll::Ready(Outcome::Response)
    );
    let stats = region.change();
    assert_eq!(
        stats.allocations + stats.reallocations,
        1,
        "TCP buffer grows once"
    );
    let config = ".:53 {\n rewrite cname old.example. new.example.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let target: Name = "other.example.".parse().unwrap();
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
    let future = chain
        .rewrite
        .as_ref()
        .unwrap()
        .serve(&mut cx, OtherCname(&target));
    let mut future = std::pin::pin!(future);
    assert_eq!(
        future.as_mut().poll(&mut task),
        Poll::Ready(Outcome::Response)
    );
    let stats = region.change();
    assert_eq!(
        (stats.allocations, stats.reallocations),
        (0, 0),
        "non-matching CNAME target"
    );
}

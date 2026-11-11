#![forbid(unsafe_code)]
#![cfg(feature = "plugin-rewrite")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct Answer;
impl Next for Answer {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
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

struct Unanswered(Rcode);
impl Next for Unanswered {
    async fn run(self, _: &mut Context<'_>) -> Outcome {
        Outcome::Unanswered(self.0)
    }
}

struct InspectQuestion(Type, Class);
impl Next for InspectQuestion {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        assert_eq!((q.qtype, q.qclass), (self.0, self.1));
        let mut copy = Vec::with_capacity(512);
        cx.query.copy_wire(&mut copy);
        let parsed = Message::parse(&copy).unwrap();
        let copied = parsed.questions().next().unwrap();
        assert_eq!((copied.qtype, copied.qclass), (self.0, self.1));
        Outcome::Drop
    }
}

struct AliasedAnswer;
impl Next for AliasedAnswer {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        assert_eq!(q.name.to_string(), "internal.example.");
        let owner: Name = "alias.internal.example.".parse().unwrap();
        let target: Name = "other.internal.example.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record_with(
            Section::Answer,
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::CNAME,
            Class::IN,
            60,
            |writer| writer.write_name(NameRef::parse(target.as_wire(), 0).unwrap()),
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

#[tokio::test]
async fn coredns_exact_auto_rewrites_subdomain_owners_and_values() {
    let config = ".:53 {\n rewrite name example.com. internal.example.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.com.".parse().unwrap();
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
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, AliasedAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    let rr = message.answers().next().unwrap();
    assert_eq!(rr.name.to_string(), "alias.example.com.");
    let pharos_proto::Rdata::Cname(target) = rr.data().unwrap() else {
        panic!("expected CNAME")
    };
    assert_eq!(target.to_string(), "other.example.com.");
}

#[tokio::test]
async fn coredns_type_and_class_rewrite_question() {
    for (rules, expected_type, expected_class) in [
        ("rewrite type A AAAA", Type::AAAA, Class::IN),
        ("rewrite type AAAA HINFO", Type::A, Class::IN),
        ("rewrite class IN CH", Type::A, Class::CH),
        (
            "rewrite continue type A AAAA\n rewrite class IN CH",
            Type::AAAA,
            Class::CH,
        ),
    ] {
        let config = format!(".:53 {{\n {rules}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
        let root: Name = ".".parse().unwrap();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, InspectQuestion(expected_type, expected_class))
                .await,
            Outcome::Drop
        );
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_test.go.
#[tokio::test]
async fn coredns_exact_name_rewrites_query_and_auto_reverts_response() {
    let config = ".:53 {\n rewrite name example.com. internal.example.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.com.".parse().unwrap();
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
    assert_eq!(
        chain.rewrite.as_ref().unwrap().serve(&mut cx, Answer).await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(
        message.questions().next().unwrap().name.to_string(),
        "example.com."
    );
    assert_eq!(
        message.answers().next().unwrap().name.to_string(),
        "example.com."
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rcode_test.go.
#[tokio::test]
async fn coredns_rcode_rewrites_unanswered_response() {
    for code in [
        Rcode::FORMERR,
        Rcode::SERVFAIL,
        Rcode::REFUSED,
        Rcode::NOTIMP,
    ] {
        let text = format!(".:53 {{\n rewrite rcode example. {} NOERROR\n}}", code.0);
        let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "example.".parse().unwrap();
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
        let outcome = chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, Unanswered(code))
            .await;
        assert!(
            outcome == Outcome::Unanswered(Rcode::NOERROR)
                || (outcome == Outcome::Response
                    && Message::parse(cx.response).unwrap().rcode() == Rcode::NOERROR)
        );
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/ttl_test.go.
#[tokio::test]
async fn coredns_ttl_exact_and_ranges() {
    for (rule, name, ttl) in [
        ("rewrite ttl srv1.coredns.rocks 1", "srv1.coredns.rocks.", 1),
        (
            "rewrite ttl range.example.com. 30-300",
            "range.example.com.",
            30,
        ),
        ("rewrite ttl ceil.example.com. -11", "ceil.example.com.", 5),
        (
            "rewrite ttl floor.example.com. 10-",
            "floor.example.com.",
            10,
        ),
        ("rewrite ttl other.example. 1", "example.com.", 5),
        (
            "rewrite ttl exact srv15.coredns.rocks 15",
            "srv15.coredns.rocks.",
            15,
        ),
        ("rewrite ttl prefix srv30 30", "srv30.coredns.rocks.", 30),
        (
            "rewrite ttl suffix 45.coredns.rocks 45",
            "srv45.coredns.rocks.",
            45,
        ),
        ("rewrite ttl substring rv50 50", "srv50.coredns.rocks.", 50),
        (
            r"rewrite ttl regex (srv10)\.(coredns)\.(rocks) 10",
            "srv10.coredns.rocks.",
            10,
        ),
    ] {
        let config = format!(".:53 {{\n {rule}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = name.parse().unwrap();
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
        assert_eq!(
            chain.rewrite.as_ref().unwrap().serve(&mut cx, Answer).await,
            Outcome::Response
        );
        assert_eq!(
            Message::parse(cx.response)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .ttl,
            ttl,
            "{rule}"
        );
    }
}

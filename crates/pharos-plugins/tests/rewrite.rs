#![forbid(unsafe_code)]
#![cfg(feature = "plugin-rewrite")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct AliasChain(pharos_plugins::rewrite::Rewrite, &'static str);
impl pharos_server::Chain for AliasChain {
    async fn serve(&self, cx: &mut Context<'_>) -> Outcome {
        self.0.serve(cx, AliasBackend(self.1)).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}
struct AliasBackend(&'static str);
impl Next for AliasBackend {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let original = q.name.to_string() == "alias.example.";
        let target: Name = "old.example.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        if original {
            b.record_with(Section::Answer, q.name, Type::CNAME, Class::IN, 30, |w| {
                w.write_name(NameRef::parse(target.as_wire(), 0).unwrap())
            })
            .unwrap();
        } else {
            assert_eq!(q.name.to_string(), self.0);
            b.record(
                Section::Answer,
                q.name,
                Type::A,
                Class::IN,
                60,
                &[192, 0, 2, 1],
            )
            .unwrap();
        }
        let _ = b.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/cname_target_test.go.
#[tokio::test]
async fn coredns_cname_rewrite_follows_target_through_self_lookup() {
    for (rule, expected) in [
        ("rewrite cname old.example. new.example.", "new.example."),
        ("rewrite cname suffix .example. .other.", "old.other."),
        ("rewrite cname prefix old new", "new.example."),
        ("rewrite cname substring ld.ex k.ex", "ok.example."),
        (
            r"rewrite cname regex (.*)\.example\. {1}.other.",
            "old.other.",
        ),
    ] {
        let config = format!(".:53 {{\n {rule}\n}}");
        let mut chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let key = pharos_server::ListenerKey {
            transport: Transport::Dns,
            address: "127.0.0.1:53".parse().unwrap(),
        };
        let mut router = pharos_server::Router::default();
        router.add(
            key,
            ".".parse().unwrap(),
            Some(AliasChain(chain.rewrite.take().unwrap(), expected)),
            vec![],
        );
        let server = pharos_server::Server::new(router, key);
        let name: Name = "alias.example.".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            pharos_server::Handler::handle(
                &server,
                &wire,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
            pharos_server::Action::Respond
        );
        let message = Message::parse(&response).unwrap();
        let mut answers = message.answers();
        let pharos_proto::Rdata::Cname(target) = answers.next().unwrap().data().unwrap() else {
            panic!("expected CNAME")
        };
        assert_eq!(target.to_string(), expected);
        let answer = answers.next().unwrap();
        assert_eq!(answer.name.to_string(), expected);
        assert_eq!(answer.rdata, &[192, 0, 2, 1]);
    }
}

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

struct InspectName(&'static str);
impl Next for InspectName {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        assert_eq!(
            cx.query.questions().next().unwrap().name.to_string(),
            self.0
        );
        Outcome::Drop
    }
}

struct ExpectNameAnswer(&'static str);
impl Next for ExpectNameAnswer {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        assert_eq!(
            cx.query.questions().next().unwrap().name.to_string(),
            self.0
        );
        Answer.run(cx).await
    }
}

#[tokio::test]
async fn coredns_continue_applies_and_reverts_names_in_order() {
    let config = ".:53 {\n rewrite continue name a.example. b.example.\n rewrite name b.example. c.example.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "a.example.".parse().unwrap();
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
            .serve(&mut cx, ExpectNameAnswer("c.example."))
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(
        message.questions().next().unwrap().name.to_string(),
        "a.example."
    );
    assert_eq!(
        message.answers().next().unwrap().name.to_string(),
        "a.example."
    );
}

#[tokio::test]
async fn coredns_ttl_rule_matches_name_rewritten_by_previous_rule() {
    let config =
        ".:53 {\n rewrite continue name a.example. b.example.\n rewrite ttl b.example. 30\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "a.example.".parse().unwrap();
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
            .serve(&mut cx, ExpectNameAnswer("b.example."))
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(message.answers().next().unwrap().ttl, 30);
}

#[tokio::test]
async fn coredns_non_regex_name_rewrite_modes() {
    for (rule, incoming, expected) in [
        (
            "rewrite name prefix ftp web",
            "ftp.example.",
            "web.example.",
        ),
        (
            "rewrite name suffix .schmoogle.com. .google.com.",
            "www.schmoogle.com.",
            "www.google.com.",
        ),
        (
            "rewrite name substring service.us-west-1.example.org service.us-west-1.consul",
            "ftp.service.us-west-1.example.org.",
            "ftp.service.us-west-1.consul.",
        ),
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
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, InspectName(expected))
                .await,
            Outcome::Drop,
            "{rule}"
        );
    }
}

#[tokio::test]
async fn coredns_regex_name_capture_rewrite() {
    let config = r".:53 {
 rewrite name regex (.*)-(us-west-1)\.example\.org {1}.service.{2}.consul
}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "ftp-us-west-1.example.org.".parse().unwrap();
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
            .serve(&mut cx, InspectName("ftp.service.us-west-1.consul."))
            .await,
        Outcome::Drop
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_metadata_test.go.
#[tokio::test]
async fn coredns_regex_name_metadata_and_missing_labels() {
    let config = r".:53 {
 rewrite name regex ^([^.]+)\.example\.$ {1}.{kubernetes/client-namespace}.svc.cluster.local. metadata
}";
    for (value, expected) in [
        (Some("Team-A"), "web.team-a.svc.cluster.local."),
        (None, "web.example."),
    ] {
        let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "web.example.".parse().unwrap();
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
        if let Some(value) = value {
            cx.metadata.insert("kubernetes/client-namespace", value);
        }
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, InspectName(expected))
                .await,
            Outcome::Drop
        );
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

struct SuffixAnswer;
impl Next for SuffixAnswer {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        assert_eq!(q.name.to_string(), "www.internal.");
        let owner: Name = "other.internal.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record(
            Section::Answer,
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
            60,
            &[127, 0, 0, 1],
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

struct ChainedSuffixAnswer;
impl Next for ChainedSuffixAnswer {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        assert_eq!(q.name.to_string(), "www.c.");
        let owner: Name = "other.c.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record(
            Section::Answer,
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
            60,
            &[127, 0, 0, 1],
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

#[tokio::test]
async fn coredns_continue_reverts_each_suffix_rule_in_reverse() {
    let config = ".:53 {\n rewrite continue name suffix .a. .b. answer auto\n rewrite name suffix .b. .c. answer auto\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "www.a.".parse().unwrap();
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
            .serve(&mut cx, ChainedSuffixAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(
        message.questions().next().unwrap().name.to_string(),
        "www.a."
    );
    assert_eq!(
        message.answers().next().unwrap().name.to_string(),
        "other.a."
    );
}

#[tokio::test]
async fn coredns_suffix_answer_auto_rewrites_entire_suffix() {
    let config = ".:53 {\n rewrite name suffix .external. .internal. answer auto\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "www.external.".parse().unwrap();
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
            .serve(&mut cx, SuffixAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(
        message.questions().next().unwrap().name.to_string(),
        "www.external."
    );
    assert_eq!(
        message.answers().next().unwrap().name.to_string(),
        "other.external."
    );
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
async fn coredns_explicit_answer_name_and_value_rules() {
    let config = r".:53 {
 rewrite name exact example.com. internal.example. answer name (.*)\.internal\.example\. {1}.external.test. answer value (.*)\.internal\.example\. {1}.external.test.
}";
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
    assert_eq!(rr.name.to_string(), "alias.external.test.");
    let pharos_proto::Rdata::Cname(target) = rr.data().unwrap() else {
        panic!("expected CNAME")
    };
    assert_eq!(target.to_string(), "other.external.test.");
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

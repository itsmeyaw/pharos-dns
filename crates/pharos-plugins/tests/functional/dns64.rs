#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-dns64", feature = "plugin-hosts"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{
    Action, Context, Error, Handler, Metadata, Next, Outcome, Plugin, Protocol, Transport,
};
use std::net::Ipv6Addr;

struct ScriptedChain {
    dns64: pharos_plugins::dns64::Dns64,
    initial_rcode: u16,
    initial_aa_ra: u16,
    initial_soa: bool,
    initial_cname: bool,
    initial_aaaa: InitialAaaa,
    fallback_rcode: u16,
    fallback_answers: bool,
    truncated: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InitialAaaa {
    None,
    MappedOnly,
    UsableAndMapped,
}

impl pharos_server::Chain for ScriptedChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.dns64.serve(cx, ScriptedNext(self)).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}

struct ScriptedNext<'a>(&'a ScriptedChain);
impl Next for ScriptedNext<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let fallback = q.qtype == Type::A;
        let code = if fallback {
            self.0.fallback_rcode
        } else {
            self.0.initial_rcode
        };
        let flags = 0x8100
            | if fallback {
                self.0.initial_aa_ra ^ 0x0480
            } else {
                self.0.initial_aa_ra
            }
            | code
            | if fallback && self.0.truncated {
                0x0200
            } else {
                0
            };
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), flags).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        if !fallback
            && matches!(
                self.0.initial_aaaa,
                InitialAaaa::MappedOnly | InitialAaaa::UsableAndMapped
            )
        {
            let mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 42];
            builder
                .record(Section::Answer, q.name, Type::AAAA, Class::IN, 60, &mapped)
                .unwrap();
        }
        if !fallback && self.0.initial_aaaa == InitialAaaa::UsableAndMapped {
            let usable = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            builder
                .record(Section::Answer, q.name, Type::AAAA, Class::IN, 60, &usable)
                .unwrap();
        }
        if !fallback && self.0.initial_cname {
            let target: Name = "missing.example.net.".parse().unwrap();
            builder
                .record(
                    Section::Answer,
                    q.name,
                    Type::CNAME,
                    q.qclass,
                    30,
                    target.as_wire(),
                )
                .unwrap();
        }
        if fallback && self.0.fallback_answers {
            builder
                .record(
                    Section::Answer,
                    q.name,
                    Type::A,
                    Class::IN,
                    60,
                    &[8, 8, 8, 42],
                )
                .unwrap();
            builder
                .record(
                    Section::Answer,
                    q.name,
                    Type::A,
                    Class::IN,
                    5000,
                    &[8, 8, 8, 43],
                )
                .unwrap();
        }
        if (!fallback && self.0.initial_soa) || (fallback && !self.0.fallback_answers) {
            // RFC 1035 §3.3.13: MNAME, RNAME and five unsigned 32-bit fields.
            let soa = [0u8; 22];
            builder
                .record(
                    Section::Authority,
                    q.name,
                    Type::SOA,
                    Class::IN,
                    if fallback { 3600 } else { 70 },
                    &soa,
                )
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS TestDNS64 and TestDNS64FallbackError.
#[tokio::test]
async fn coredns_dns64_fallback_rcodes_soa_ttl_and_truncation() {
    for (
        initial,
        soa,
        fallback,
        answers,
        truncated,
        role_flags,
        expected_code,
        expected_ttls,
        initial_aaaa,
        translate_all,
    ) in [
        (
            0,
            true,
            0,
            true,
            false,
            0x0480,
            0,
            vec![60, 70],
            InitialAaaa::None,
            false,
        ),
        (
            5,
            false,
            0,
            true,
            false,
            0x0480,
            0,
            vec![60, 600],
            InitialAaaa::None,
            false,
        ),
        (
            0,
            true,
            0,
            true,
            true,
            0x0480,
            0,
            vec![60, 70],
            InitialAaaa::None,
            false,
        ),
        (
            0,
            true,
            0,
            true,
            false,
            0,
            0,
            vec![60, 70],
            InitialAaaa::None,
            false,
        ),
        (
            0,
            true,
            0,
            false,
            false,
            0x0480,
            0,
            vec![],
            InitialAaaa::None,
            false,
        ),
        (
            0,
            false,
            2,
            false,
            false,
            0x0480,
            2,
            vec![],
            InitialAaaa::None,
            false,
        ),
        (
            0,
            false,
            5,
            false,
            false,
            0x0480,
            5,
            vec![],
            InitialAaaa::None,
            false,
        ),
        (
            0,
            false,
            1,
            false,
            false,
            0x0480,
            1,
            vec![],
            InitialAaaa::None,
            false,
        ),
        (
            0,
            false,
            3,
            false,
            false,
            0x0480,
            3,
            vec![],
            InitialAaaa::None,
            false,
        ),
        (
            0,
            false,
            4,
            false,
            false,
            0x0480,
            4,
            vec![],
            InitialAaaa::None,
            false,
        ),
        (
            0,
            true,
            0,
            true,
            false,
            0x0480,
            0,
            vec![60, 70],
            InitialAaaa::MappedOnly,
            false,
        ),
        (
            0,
            true,
            0,
            true,
            false,
            0x0480,
            0,
            vec![60],
            InitialAaaa::UsableAndMapped,
            false,
        ),
        (
            0,
            true,
            0,
            false,
            false,
            0x0480,
            0,
            vec![],
            InitialAaaa::MappedOnly,
            true,
        ),
    ] {
        let config = if translate_all {
            ".:53 {\n dns64 {\n  translate_all\n }\n}"
        } else {
            ".:53 {\n dns64\n}"
        };
        let blocks = parse("Corefile", config).unwrap();
        let mut chain = configure::<Chain>(&blocks, directives())
            .unwrap()
            .remove(0)
            .config;
        let scripted = ScriptedChain {
            dns64: chain.dns64.take().unwrap(),
            initial_rcode: initial,
            initial_aa_ra: role_flags,
            initial_soa: soa,
            initial_cname: false,
            initial_aaaa,
            fallback_rcode: fallback,
            fallback_answers: answers,
            truncated,
        };
        let key = pharos_server::ListenerKey {
            transport: Transport::Dns,
            address: "127.0.0.1:53".parse().unwrap(),
        };
        let mut router = pharos_server::Router::default();
        router.add(key, ".".parse().unwrap(), Some(scripted), vec![]);
        let server = pharos_server::Server::new(router, key);
        let name: Name = "example.com.".parse().unwrap();
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
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    &wire,
                    "[::1]:1234".parse().unwrap(),
                    Protocol::Udp,
                    &mut response
                )
                .await,
            Action::Respond
        );
        let message = Message::parse(&response).unwrap();
        assert_eq!(message.id(), 42);
        assert_eq!(message.questions().next().unwrap().qtype, Type::AAAA);
        assert_eq!(message.rcode(), Rcode(expected_code));
        assert_eq!(message.tc(), truncated);
        assert_eq!(message.flags() & 0x0480, role_flags);
        assert_eq!(
            message.answers().map(|rr| rr.ttl).collect::<Vec<_>>(),
            expected_ttls
        );
        if answers {
            assert!(message.answers().all(|rr| rr.rtype == Type::AAAA));
        } else if soa && fallback == 0 {
            assert_eq!(message.authorities().next().unwrap().ttl, 70);
        } else {
            assert_eq!(message.authorities().next().unwrap().ttl, 3600);
        }
    }
}

#[tokio::test]
async fn nxdomain_with_cname_does_not_trigger_dns64_synthesis() {
    let blocks = parse("Corefile", ".:53 {\n dns64\n}").unwrap();
    let mut config = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let chain = ScriptedChain {
        dns64: config.dns64.take().unwrap(),
        initial_rcode: 3,
        initial_aa_ra: 0,
        initial_soa: false,
        initial_cname: true,
        initial_aaaa: InitialAaaa::None,
        fallback_rcode: 0,
        fallback_answers: true,
        truncated: false,
    };
    let key = pharos_server::ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = pharos_server::Router::default();
    router.add(key, ".".parse().unwrap(), Some(chain), vec![]);
    let server = pharos_server::Server::new(router, key);
    let name: Name = "alias.example.org.".parse().unwrap();
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
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server
            .handle(
                &wire,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await,
        Action::Respond
    );
    let message = Message::parse(&response).unwrap();
    // RFC 6604 §3: NXDOMAIN may accompany a CNAME chain to a nonexistent target.
    assert_eq!(message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(
        message
            .answers()
            .filter(|rr| rr.rtype == Type::CNAME)
            .count(),
        1
    );
    assert_eq!(
        message
            .answers()
            .filter(|rr| rr.rtype == Type::AAAA)
            .count(),
        0
    );
}

struct FakeNext {
    rcode: u16,
    has_aaaa: bool,
}

struct ExpiredNx;
impl Next for ExpiredNx {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8103).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        let sig = b"\0\x02\x08\0\0\0\0\x3c\0\0\0\x96\0\0\0\x32\0\x01\0";
        builder
            .record(Section::Authority, q.name, Type::RRSIG, Class::IN, 60, sig)
            .unwrap();
        builder
            .record(
                Section::Additional,
                NameRef::parse(&[0], 0).unwrap(),
                Type::OPT,
                Class(1232),
                0x8000,
                &[],
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

#[tokio::test]
async fn expired_signed_nxdomain_does_not_trigger_dns64_synthesis() {
    let blocks = parse("Corefile", ". {\n dns64\n}").unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let domain: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 42, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(domain.as_wire(), 0).unwrap(),
            Type::AAAA,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "[::1]:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .dns64
            .as_ref()
            .unwrap()
            .serve(&mut cx, ExpiredNx)
            .await,
        Outcome::Response
    );
    let response = Message::parse(cx.response).unwrap();
    // RFC 6147 §5.1.2: RCODE NXDOMAIN remains a name error even with an expired RRSIG.
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    assert_eq!(response.authorities().next().unwrap().rtype, Type::RRSIG);
}

struct MixedAaaa;
impl Next for MixedAaaa {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let question = cx.query.questions().next().unwrap();
        let mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1];
        let usable: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::AAAA,
                Class::IN,
                60,
                &mapped,
            )
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::AAAA,
                Class::IN,
                60,
                &usable.octets(),
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

#[tokio::test]
async fn dns64_does_not_return_ipv4_mapped_aaaa() {
    let blocks = parse("Corefile", ".:53 {\n dns64\n}").unwrap();
    let config = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.com.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
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
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "[::1]:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        config
            .dns64
            .as_ref()
            .unwrap()
            .serve(&mut cx, MixedAaaa)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(message.answer_count(), 1);
    let usable: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert_eq!(message.answers().next().unwrap().rdata, &usable.octets());
}

impl Next for FakeNext {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut builder =
            MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8100 | self.rcode).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        if self.has_aaaa {
            builder
                .record(Section::Answer, q.name, Type::AAAA, Class::IN, 60, &[0; 16])
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS TestRequestShouldIntercept and TestResponseShould.
#[tokio::test]
async fn coredns_dns64_interception_cases() {
    for (settings, client, typ, class, rcode, aaaa, synthesize) in [
        ("", "[::1]:1", Type::AAAA, Class::IN, 0, false, true),
        (
            "allow_ipv4",
            "127.0.0.1:1",
            Type::AAAA,
            Class::IN,
            0,
            false,
            true,
        ),
        ("", "127.0.0.1:1", Type::AAAA, Class::IN, 0, false, false),
        ("", "[::1]:1", Type::A, Class::IN, 0, false, false),
        ("", "[::1]:1", Type::AAAA, Class::CH, 0, false, false),
        ("", "[::1]:1", Type::AAAA, Class::IN, 0, true, false),
        ("", "[::1]:1", Type::AAAA, Class::IN, 4, false, true),
        ("", "[::1]:1", Type::AAAA, Class::IN, 3, false, false),
        (
            "translate_all",
            "[::1]:1",
            Type::AAAA,
            Class::IN,
            0,
            true,
            true,
        ),
    ] {
        let text = format!(".:53 {{\n dns64 {{\n {settings}\n }}\n}}");
        let blocks = parse("Corefile", &text).unwrap();
        let chain = configure::<Chain>(&blocks, directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "example.org.".parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 42, 0x100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), typ, class)
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
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let outcome = chain
            .dns64
            .as_ref()
            .unwrap()
            .serve(
                &mut cx,
                FakeNext {
                    rcode,
                    has_aaaa: aaaa,
                },
            )
            .await;
        assert_eq!(
            outcome,
            if synthesize {
                Outcome::Error(Error::SelfLookupUnavailable)
            } else {
                Outcome::Response
            },
            "{settings} {client} {typ} {class} {rcode} {aaaa}"
        );
        if !synthesize {
            assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode(rcode));
        }
    }
}

// Derived from CoreDNS v1.15.0 plugin/dns64/dns64_test.go, TestTo6.
#[tokio::test]
async fn coredns_dns64_synthesizes_prefixes_through_self_lookup() {
    synthesizes_prefixes_through_self_lookup().await;
}

#[test]
fn dns64_rejects_invalid_well_known_prefix_lengths_and_reserved_octet() {
    for prefix in [
        "64:ff9b::/32",
        "64:ff9b:0:0:1::/32",
        "64:ff9b::/64",
        "2001:db8:0:0:100::/96",
    ] {
        let config = format!(".:53 {{\n dns64 {prefix}\n}}");
        let blocks = parse("Corefile", &config).unwrap();
        assert!(
            configure::<Chain>(&blocks, directives()).is_err(),
            "{prefix}"
        );
    }
}

async fn synthesizes_prefixes_through_self_lookup() {
    for (prefix, expected) in [
        ("64:ff9b::/96", "64:ff9b::4040:4040"),
        ("2001:db8:0:0::/64", "2001:db8:0:0:40:4040:4000:0"),
        ("2001:db8:0:40::/56", "2001:db8:0:40:40:4040::"),
        ("64::/32", "64:0:4040:4040::"),
    ] {
        let config = format!(
            ".:53 {{\n dns64 {prefix}\n hosts /nonexistent {{\n  64.64.64.64 example.org\n  ttl 60\n }}\n}}"
        );
        let blocks = parse("Corefile", &config).unwrap();
        let (mut listeners, _) =
            servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
        let (_, server) = listeners.drain().next().unwrap();
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
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    &wire,
                    "[::1]:1234".parse().unwrap(),
                    Protocol::Udp,
                    &mut response
                )
                .await,
            Action::Respond
        );
        let message = Message::parse(&response).unwrap();
        let answer = message.answers().next().expect(prefix);
        assert_eq!(answer.rtype, Type::AAAA, "{prefix}");
        assert_eq!(
            answer.rdata,
            expected.parse::<Ipv6Addr>().unwrap().octets(),
            "{prefix}"
        );
        assert_eq!(answer.ttl, 60);
        let mut metrics = String::new();
        server.metrics().encode(&mut metrics);
        assert!(
            metrics.contains("pharos_dns64_requests_translated_total{server=\"dns://:53\"} 1"),
            "{metrics}"
        );
    }
}

#[tokio::test]
async fn well_known_prefix_does_not_synthesize_non_global_ipv4() {
    let config = ".:53 {\n dns64\n hosts /nonexistent {\n  192.0.2.1 example.org\n  ttl 60\n }\n}";
    let blocks = parse("Corefile", config).unwrap();
    let (mut listeners, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = listeners.drain().next().unwrap();
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
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(
                &wire,
                "[::1]:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await,
        Action::Respond
    );
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(message.answers().count(), 0);
}

struct ChasingDns64(pharos_plugins::dns64::Dns64);
impl pharos_server::Chain for ChasingDns64 {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, Dns64Backend).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}
struct Dns64Backend;
impl Next for Dns64Backend {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let question = cx.query.questions().next().unwrap();
        let name = question.name.to_string();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        if name == "alias.example." && question.qtype == Type::A {
            let target: Name = "target.example.".parse().unwrap();
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::CNAME,
                    Class::IN,
                    60,
                    target.as_wire(),
                )
                .unwrap();
        } else if name == "target.example." && question.qtype == Type::A {
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::A,
                    Class::IN,
                    60,
                    &[8, 8, 8, 1],
                )
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

#[tokio::test]
async fn dns64_follows_a_lookup_cname_to_terminal_address() {
    let blocks = parse("Corefile", ".:53 {\n dns64\n}").unwrap();
    let mut config = configure::<Chain>(&blocks, directives())
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
        Some(ChasingDns64(config.dns64.take().unwrap())),
        vec![],
    );
    let server = pharos_server::Server::new(router, key);
    let name: Name = "alias.example.".parse().unwrap();
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
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(
                &wire,
                "[::1]:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await,
        Action::Respond
    );
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.answer_count(), 2);
    assert!(message.answers().any(|rr| rr.rtype == Type::CNAME));
    let aaaa = message.answers().find(|rr| rr.rtype == Type::AAAA).unwrap();
    assert_eq!(
        aaaa.rdata,
        &[0, 100, 255, 155, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 1]
    );
}

struct CyclicDns64(pharos_plugins::dns64::Dns64);
impl pharos_server::Chain for CyclicDns64 {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, CnameCycleBackend).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}
struct CnameCycleBackend;
impl Next for CnameCycleBackend {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let question = cx.query.questions().next().unwrap();
        let name = question.name.to_string();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        if question.qtype == Type::A {
            let target: Name = if name == "alias.example." {
                "target.example.".parse().unwrap()
            } else {
                "alias.example.".parse().unwrap()
            };
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::CNAME,
                    Class::IN,
                    60,
                    target.as_wire(),
                )
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

#[tokio::test]
async fn dns64_cname_cycle_returns_server_error_at_the_hop_limit() {
    let blocks = parse("Corefile", ".:53 {\n dns64\n}").unwrap();
    let mut config = configure::<Chain>(&blocks, directives())
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
        Some(CyclicDns64(config.dns64.take().unwrap())),
        vec![],
    );
    let server = pharos_server::Server::new(router, key);
    let name: Name = "alias.example.".parse().unwrap();
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
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(
                &wire,
                "[::1]:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
}

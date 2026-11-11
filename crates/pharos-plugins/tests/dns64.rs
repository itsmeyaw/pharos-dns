#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-dns64", feature = "plugin-hosts"))]
#![recursion_limit = "512"]

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
    initial_soa: bool,
    fallback_rcode: u16,
    fallback_answers: bool,
    truncated: bool,
}

impl pharos_server::Chain for ScriptedChain {
    async fn serve(&self, cx: &mut Context<'_>) -> Outcome {
        self.dns64.serve(cx, ScriptedNext(self)).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}

struct ScriptedNext<'a>(&'a ScriptedChain);
impl Next for ScriptedNext<'_> {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let fallback = q.qtype == Type::A;
        let code = if fallback {
            self.0.fallback_rcode
        } else {
            self.0.initial_rcode
        };
        let flags = 0x8100
            | code
            | if fallback && self.0.truncated {
                0x0200
            } else {
                0
            };
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), flags).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        if fallback && self.0.fallback_answers {
            builder
                .record(
                    Section::Answer,
                    q.name,
                    Type::A,
                    Class::IN,
                    60,
                    &[192, 0, 2, 42],
                )
                .unwrap();
            builder
                .record(
                    Section::Answer,
                    q.name,
                    Type::A,
                    Class::IN,
                    5000,
                    &[192, 0, 2, 43],
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
    for (initial, soa, fallback, answers, truncated, expected_code, expected_ttls) in [
        (0, true, 0, true, false, 0, vec![60, 70]),
        (5, false, 0, true, false, 0, vec![60, 600]),
        (0, true, 0, true, true, 0, vec![60, 70]),
        (0, true, 0, false, false, 0, vec![]),
        (0, false, 2, false, false, 2, vec![]),
        (0, false, 5, false, false, 5, vec![]),
        (0, false, 1, false, false, 1, vec![]),
        (0, false, 3, false, false, 3, vec![]),
        (0, false, 4, false, false, 4, vec![]),
    ] {
        let blocks = parse("Corefile", ".:53 {\n dns64\n}").unwrap();
        let mut chain = configure::<Chain>(&blocks, directives())
            .unwrap()
            .remove(0)
            .config;
        let scripted = ScriptedChain {
            dns64: chain.dns64.take().unwrap(),
            initial_rcode: initial,
            initial_soa: soa,
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
        assert_eq!(
            message.answers().map(|rr| rr.ttl).collect::<Vec<_>>(),
            expected_ttls
        );
        if answers {
            assert!(message.answers().all(|rr| rr.rtype == Type::AAAA));
        } else {
            assert_eq!(message.authorities().next().unwrap().ttl, 3600);
        }
    }
}

struct FakeNext {
    rcode: u16,
    has_aaaa: bool,
}

impl Next for FakeNext {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
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
    for (prefix, expected) in [
        ("64:ff9b::/96", "64:ff9b::4040:4040"),
        ("64:ff9b::/64", "64:ff9b::40:4040:4000:0"),
        ("64:ff9b::/56", "64:ff9b:0:40:40:4040::"),
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

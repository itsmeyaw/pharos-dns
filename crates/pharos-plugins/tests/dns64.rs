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
    }
}

#![forbid(unsafe_code)]
#![cfg(feature = "plugin-siit")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Action, Context, Handler, Next, Outcome, Plugin, Protocol, Transport};

struct Scripted {
    siit: pharos_plugins::siit::Siit,
    initial: u16,
    initial_tc: bool,
    initial_a: bool,
    secondary: u16,
    addresses: Vec<std::net::Ipv6Addr>,
}

impl pharos_server::Chain for Scripted {
    async fn serve(&self, cx: &mut Context<'_>) -> Outcome {
        self.siit.serve(cx, Backend(self)).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}
struct Backend<'a>(&'a Scripted);
impl Next for Backend<'_> {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let secondary = q.qtype == Type::AAAA;
        let code = if secondary {
            self.0.secondary
        } else {
            self.0.initial
        };
        let flags = 0x8580
            | code
            | if !secondary && self.0.initial_tc {
                0x200
            } else {
                0
            };
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), flags).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        if secondary {
            for addr in &self.0.addresses {
                b.record(
                    Section::Answer,
                    q.name,
                    Type::AAAA,
                    Class::IN,
                    5000,
                    &addr.octets(),
                )
                .unwrap();
            }
        } else if self.0.initial_a {
            b.record(
                Section::Answer,
                q.name,
                Type::A,
                Class::IN,
                60,
                &[127, 0, 0, 1],
            )
            .unwrap();
        } else {
            b.record(
                Section::Authority,
                q.name,
                Type::SOA,
                Class::IN,
                70,
                &[0; 22],
            )
            .unwrap();
        }
        let _ = b.finish();
        Outcome::Response
    }
}

async fn query(
    settings: &str,
    initial: u16,
    initial_tc: bool,
    initial_a: bool,
    secondary: u16,
    addresses: &[&str],
) -> Vec<u8> {
    let text = format!(".:53 {{\n siit {{\n {settings}\n }}\n}}");
    let mut chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let scripted = Scripted {
        siit: chain.siit.take().unwrap(),
        initial,
        initial_tc,
        initial_a,
        secondary,
        addresses: addresses.iter().map(|s| s.parse().unwrap()).collect(),
    };
    let key = pharos_server::ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = pharos_server::Router::default();
    router.add(key, ".".parse().unwrap(), Some(scripted), vec![]);
    let server = pharos_server::Server::new(router, key);
    let name: Name = "example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 42, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
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
    response
}

// Derived from CoreDNS v1.15.0 plugin/siit/siit_test.go.
#[tokio::test]
async fn coredns_siit_translation_fallback_and_eam() {
    let wire = query(
        "eam 203.0.113.9 64:ff9b::192.0.2.1",
        0,
        false,
        false,
        0,
        &["2001:db8::1", "64:ff9b::192.0.2.1", "64:ff9b::192.0.2.42"],
    )
    .await;
    let m = Message::parse(&wire).unwrap();
    assert_eq!(m.id(), 42);
    assert_eq!(m.questions().next().unwrap().qtype, Type::A);
    let answers = m.answers().collect::<Vec<_>>();
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0].rdata, &[203, 0, 113, 9]);
    assert_eq!(answers[1].rdata, &[192, 0, 2, 42]);
    assert!(answers.iter().all(|rr| rr.rtype == Type::A && rr.ttl == 70));
    assert_eq!(m.flags() & 0x0420, 0x0400);

    for (initial, tc, a, secondary, addresses, expected_code, expected_answers) in [
        (3, false, false, 0, vec!["64:ff9b::192.0.2.1"], 3, 0),
        (0, true, false, 0, vec!["64:ff9b::192.0.2.1"], 0, 0),
        (0, false, true, 0, vec!["64:ff9b::192.0.2.1"], 0, 1),
        (0, false, false, 0, vec!["2001:db8::1"], 0, 0),
        (0, false, false, 2, vec![], 2, 0),
        (0, false, false, 3, vec![], 3, 0),
    ] {
        let wire = query("", initial, tc, a, secondary, &addresses).await;
        let m = Message::parse(&wire).unwrap();
        assert_eq!(m.rcode(), Rcode(expected_code));
        assert_eq!(m.answers().count(), expected_answers);
        assert_eq!(m.tc(), tc);
        assert_eq!(m.questions().next().unwrap().qtype, Type::A);
    }
}

// RFC 6052 §2.2 Table 1: independent address mapping vectors.
#[tokio::test]
async fn siit_rfc6052_vectors() {
    for (prefix, address) in [
        ("2001:db8::/32", "2001:db8:c000:221::"),
        ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
        ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
        ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
        ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::"),
        ("2001:db8:122:344::/96", "2001:db8:122:344::192.0.2.33"),
    ] {
        let wire = query(
            &format!("ipv6_prefix {prefix}"),
            0,
            false,
            false,
            0,
            &[address],
        )
        .await;
        let m = Message::parse(&wire).unwrap();
        assert_eq!(
            m.answers().next().unwrap().rdata,
            &[192, 0, 2, 33],
            "{prefix}"
        );
    }
}

#[cfg(feature = "plugin-hosts")]
#[tokio::test]
async fn siit_metrics_count_translations_only() {
    let config = ".:53 {\n siit\n hosts /nonexistent {\n  64:ff9b::192.0.2.1 mapped.example\n  2001:db8::1 unmapped.example\n  ttl 60\n }\n}";
    let (mut listeners, _) = pharos_plugins::servers(
        configure::<Chain>(&parse("Corefile", config).unwrap(), directives()).unwrap(),
    )
    .unwrap();
    let (_, server) = listeners.drain().next().unwrap();
    for host in ["mapped.example.", "unmapped.example."] {
        let name: Name = host.parse().unwrap();
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
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    &wire,
                    "127.0.0.1:1234".parse().unwrap(),
                    Protocol::Udp,
                    &mut response
                )
                .await,
            Action::Respond
        );
    }
    let mut metrics = String::new();
    server.metrics().encode(&mut metrics);
    assert!(
        metrics.contains("pharos_siit_requests_translated_total{server=\"dns://:53\"} 1"),
        "{metrics}"
    );
}

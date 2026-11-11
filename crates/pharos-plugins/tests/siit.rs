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
    secondary_flags: u16,
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
        let flags = 0x8120
            | if secondary {
                self.0.secondary_flags
            } else {
                0x0480
            }
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
            if code & 0xf != 0 {
                b.record(
                    Section::Authority,
                    q.name,
                    Type::SOA,
                    Class::IN,
                    3600,
                    &[0; 22],
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
        } else if self.0.initial == 0 {
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
    secondary_flags: u16,
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
        secondary_flags,
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
        0x0480,
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
    assert_eq!(m.flags() & 0x04a0, 0x0480);

    for (initial, tc, a, secondary, addresses, expected_code, expected_answers) in [
        (3, false, false, 0, vec!["64:ff9b::192.0.2.1"], 3, 0),
        (0, true, false, 0, vec!["64:ff9b::192.0.2.1"], 0, 0),
        (0, false, true, 0, vec!["64:ff9b::192.0.2.1"], 0, 1),
        (0, false, false, 0, vec!["2001:db8::1"], 0, 0),
        (0, false, false, 0, vec![], 0, 0),
        (0, false, false, 2, vec![], 2, 0),
        (0, false, false, 3, vec![], 3, 0),
    ] {
        let wire = query("", initial, tc, a, secondary, 0x0480, &addresses).await;
        let m = Message::parse(&wire).unwrap();
        assert_eq!(m.rcode(), Rcode(expected_code));
        assert_eq!(m.answers().count(), expected_answers);
        assert_eq!(m.tc(), tc);
        assert_eq!(m.questions().next().unwrap().qtype, Type::A);
        if secondary == 2 || secondary == 3 {
            assert_eq!(m.authorities().next().unwrap().ttl, 3600);
            assert_eq!(m.flags() & 0x0480, 0x0480);
        }
    }
    for initial in [2, 5] {
        let wire = query(
            "",
            initial,
            false,
            false,
            0,
            0x0480,
            &["64:ff9b::192.0.2.1"],
        )
        .await;
        assert_eq!(
            Message::parse(&wire).unwrap().answers().next().unwrap().ttl,
            600
        );
    }
    for flags in [0, 0x80, 0x400, 0x480] {
        let wire = query("", 0, false, false, 0, flags, &["64:ff9b::192.0.2.1"]).await;
        assert_eq!(Message::parse(&wire).unwrap().flags() & 0x4a0, flags);
    }
    let wire = query("", 0, false, false, 0x200, 0x0480, &["64:ff9b::192.0.2.1"]).await;
    assert!(Message::parse(&wire).unwrap().tc());
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
            0x0480,
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
    let wire = query(
        "ipv6_prefix 2001:db8:122:344::/64",
        0,
        false,
        false,
        0,
        0x0480,
        &["2001:db8:122:344:ffc0:2:2100:0"],
    )
    .await;
    assert_eq!(Message::parse(&wire).unwrap().answers().count(), 0);
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

// Derived from CoreDNS TestSIITDNS64NoRecursion.
#[cfg(feature = "plugin-dns64")]
#[tokio::test]
async fn siit_dns64_self_lookup_does_not_recurse() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Both {
        dns64: pharos_plugins::dns64::Dns64,
        siit: pharos_plugins::siit::Siit,
        calls: std::sync::Arc<AtomicUsize>,
    }
    struct RunSiit<'a>(&'a Both);
    struct Empty<'a>(&'a Both);
    impl pharos_server::Chain for Both {
        async fn serve(&self, cx: &mut Context<'_>) -> Outcome {
            self.dns64.serve(cx, RunSiit(self)).await
        }
        fn is_empty(&self) -> bool {
            false
        }
    }
    impl Next for RunSiit<'_> {
        async fn run(self, cx: &mut Context<'_>) -> Outcome {
            self.0.siit.serve(cx, Empty(self.0)).await
        }
    }
    impl Next for Empty<'_> {
        async fn run(self, cx: &mut Context<'_>) -> Outcome {
            self.0.calls.fetch_add(1, Ordering::Relaxed);
            let q = cx.query.questions().next().unwrap();
            let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8100).unwrap();
            b.question(q.name, q.qtype, q.qclass).unwrap();
            let _ = b.finish();
            Outcome::Response
        }
    }
    for (client, options) in [("[::1]:1234", ""), ("127.0.0.1:1234", "allow_ipv4")] {
        let config = format!(".:53 {{\n dns64 {{\n {options}\n }}\n siit\n}}");
        let mut chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let both = Both {
            dns64: chain.dns64.take().unwrap(),
            siit: chain.siit.take().unwrap(),
            calls: calls.clone(),
        };
        let key = pharos_server::ListenerKey {
            transport: Transport::Dns,
            address: "127.0.0.1:53".parse().unwrap(),
        };
        let mut router = pharos_server::Router::default();
        router.add(key, ".".parse().unwrap(), Some(both), vec![]);
        let server = pharos_server::Server::new(router, key);
        let name: Name = "example.org.".parse().unwrap();
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
            server
                .handle(&wire, client.parse().unwrap(), Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
        assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode(0));
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }
}

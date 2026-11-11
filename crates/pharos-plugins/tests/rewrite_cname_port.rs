#![forbid(unsafe_code)]
#![cfg(feature = "plugin-rewrite")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type};
use pharos_server::{
    Context, Handler, ListenerKey, Next, Outcome, Plugin, Protocol, Router, Server, Transport,
};

struct Case {
    question: &'static str,
    qtype: Type,
    aliases: &'static [(&'static str, &'static str, u32)],
    target: &'static str,
    lookup_alias: Option<(&'static str, &'static str, u32)>,
    addresses: &'static [&'static str],
    ttl: u32,
    truncated: bool,
}

struct Scripted {
    rewrite: pharos_plugins::rewrite::Rewrite,
    case: Case,
}
impl pharos_server::Chain for Scripted {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.rewrite.serve(cx, Backend(&self.case)).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}
struct Backend<'a>(&'a Case);
impl Next for Backend<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let lookup = q.name.to_string() != self.0.question;
        let mut builder = MessageBuilder::new(
            cx.response,
            512,
            cx.query.id(),
            if lookup && self.0.truncated {
                0x8380
            } else {
                0x8180
            },
        )
        .unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        if lookup {
            assert_eq!(q.name.to_string(), self.0.target);
            if let Some((owner, target, ttl)) = self.0.lookup_alias {
                cname(&mut builder, owner, target, ttl);
            }
            let owner = self
                .0
                .lookup_alias
                .map_or(self.0.target, |(_, target, _)| target);
            let owner: Name = owner.parse().unwrap();
            for address in self.0.addresses {
                let data = address.parse::<std::net::IpAddr>().unwrap();
                match data {
                    std::net::IpAddr::V4(ip) => builder
                        .record(
                            Section::Answer,
                            NameRef::parse(owner.as_wire(), 0).unwrap(),
                            Type::A,
                            Class::IN,
                            self.0.ttl,
                            &ip.octets(),
                        )
                        .unwrap(),
                    std::net::IpAddr::V6(ip) => builder
                        .record(
                            Section::Answer,
                            NameRef::parse(owner.as_wire(), 0).unwrap(),
                            Type::AAAA,
                            Class::IN,
                            self.0.ttl,
                            &ip.octets(),
                        )
                        .unwrap(),
                };
            }
        } else {
            for (owner, target, ttl) in self.0.aliases {
                cname(&mut builder, owner, target, *ttl);
            }
            if !self.0.truncated {
                let owner: Name = self.0.aliases.last().unwrap().1.parse().unwrap();
                let data: &[u8] = if self.0.qtype == Type::A {
                    &[1, 2, 3, 4]
                } else {
                    &[0; 16]
                };
                builder
                    .record(
                        Section::Answer,
                        NameRef::parse(owner.as_wire(), 0).unwrap(),
                        self.0.qtype,
                        Class::IN,
                        5,
                        data,
                    )
                    .unwrap();
            }
        }
        let _ = builder.finish();
        Outcome::Response
    }
}
fn cname(builder: &mut MessageBuilder<'_>, owner: &str, target: &str, ttl: u32) {
    let owner: Name = owner.parse().unwrap();
    let target: Name = target.parse().unwrap();
    builder
        .record_with(
            Section::Answer,
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::CNAME,
            Class::IN,
            ttl,
            |w| w.write_name(NameRef::parse(target.as_wire(), 0).unwrap()),
        )
        .unwrap();
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/cname_target_test.go TestCNameTargetRewrite.
#[tokio::test]
async fn coredns_cname_target_rows() {
    let config = r".:53 {
 rewrite continue cname exact def.example.com xyz.example.com
 rewrite continue cname prefix chat.openai.com bard.google.com
 rewrite continue cname suffix uvw. xyz.
 rewrite continue cname substring efgh zzzz.www
 rewrite continue cname regex (.*)\.web\.(.*)\.site\. {1}.webapp.{2}.org.
 rewrite continue cname exact music.truncated.spotify.com. music.truncated.spotify.com.
 rewrite continue cname suffix prod. staging.
}";
    let cases = [
        Case {
            question: "abc.example.com.",
            qtype: Type::A,
            aliases: &[("abc.example.com.", "def.example.com.", 5)],
            target: "xyz.example.com.",
            lookup_alias: None,
            addresses: &["3.4.5.6"],
            ttl: 3600,
            truncated: false,
        },
        Case {
            question: "abc.example.com.",
            qtype: Type::AAAA,
            aliases: &[("abc.example.com.", "def.example.com.", 5)],
            target: "xyz.example.com.",
            lookup_alias: None,
            addresses: &["3a01:7e00::f03c:91ff:fe79:234c"],
            ttl: 3600,
            truncated: false,
        },
        Case {
            question: "chat.openai.com.",
            qtype: Type::A,
            aliases: &[(
                "chat.openai.com.",
                "chat.openai.com.cdn.cloudflare.net.",
                20,
            )],
            target: "bard.google.com.cdn.cloudflare.net.",
            lookup_alias: None,
            addresses: &["9.7.2.1"],
            ttl: 1800,
            truncated: false,
        },
        Case {
            question: "coredns.io.",
            qtype: Type::A,
            aliases: &[("coredns.io.", "www.hosting.uvw.", 100)],
            target: "www.hosting.xyz.",
            lookup_alias: None,
            addresses: &["20.30.40.50"],
            ttl: 500,
            truncated: false,
        },
        Case {
            question: "core.dns.rocks.",
            qtype: Type::A,
            aliases: &[("core.dns.rocks.", "abcd.efgh.pqrst.", 200)],
            target: "abcd.zzzz.www.pqrst.",
            lookup_alias: None,
            addresses: &["101.20.5.1", "101.20.5.2"],
            ttl: 120,
            truncated: false,
        },
        Case {
            question: "order.service.eu.",
            qtype: Type::A,
            aliases: &[("order.service.eu.", "orders.web.eu.site.", 200)],
            target: "orders.webapp.eu.org.",
            lookup_alias: None,
            addresses: &["20.0.0.9"],
            ttl: 120,
            truncated: false,
        },
        Case {
            question: "music.spotify.com.",
            qtype: Type::A,
            aliases: &[("music.spotify.com.", "music.truncated.spotify.com.", 200)],
            target: "music.truncated.spotify.com.",
            lookup_alias: None,
            addresses: &["10.1.0.9"],
            ttl: 120,
            truncated: true,
        },
        Case {
            question: "cname-chain.org.",
            qtype: Type::A,
            aliases: &[
                ("cname-chain.org.", "intermediate-1.com.", 200),
                ("intermediate-1.com.", "intermediate-2.prod.", 200),
                ("intermediate-2.prod.", "final.prod.net.", 200),
            ],
            target: "intermediate-2.staging.",
            lookup_alias: Some(("intermediate-2.staging.", "final.staging.net.", 200)),
            addresses: &["5.6.7.8"],
            ttl: 120,
            truncated: false,
        },
    ];
    for case in cases {
        let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let key = ListenerKey {
            transport: Transport::Dns,
            address: "127.0.0.1:53".parse().unwrap(),
        };
        let mut router = Router::default();
        let question = case.question;
        let qtype = case.qtype;
        let aliases = case.aliases;
        let target = case.target;
        let expected_lookup_alias = case.lookup_alias;
        let expected_addresses = case.addresses;
        let ttl = case.ttl;
        let truncated = case.truncated;
        router.add(
            key,
            ".".parse().unwrap(),
            Some(Scripted {
                rewrite: chain.rewrite.take().unwrap(),
                case,
            }),
            vec![],
        );
        let server = Server::new(router, key);
        let name: Name = question.parse().unwrap();
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    &query,
                    "127.0.0.1:1234".parse().unwrap(),
                    Protocol::Udp,
                    &mut response
                )
                .await,
            pharos_server::Action::Respond,
            "{question}"
        );
        let response = Message::parse(&response).unwrap();
        assert_eq!(response.tc(), truncated, "{question}");
        let mut records = response.answers();
        let retained = if question == "cname-chain.org." { 2 } else { 1 };
        for (index, (owner, original, expected_ttl)) in aliases.iter().take(retained).enumerate() {
            let record = records.next().unwrap();
            assert_eq!(record.name.to_string(), *owner);
            assert_eq!(record.ttl, *expected_ttl);
            let Rdata::Cname(value) = record.data().unwrap() else {
                panic!("expected CNAME")
            };
            assert_eq!(
                value.to_string(),
                if index + 1 == retained {
                    target
                } else {
                    original
                }
            );
        }
        if let Some((owner, alias_target, expected_ttl)) = expected_lookup_alias {
            let record = records.next().unwrap();
            assert_eq!(record.name.to_string(), owner);
            assert_eq!(record.ttl, expected_ttl);
            let Rdata::Cname(value) = record.data().unwrap() else {
                panic!("expected CNAME")
            };
            assert_eq!(value.to_string(), alias_target);
        }
        for address in expected_addresses {
            let record = records.next().unwrap();
            assert_eq!(record.ttl, ttl);
            let expected: std::net::IpAddr = address.parse().unwrap();
            match (record.data().unwrap(), expected) {
                (Rdata::A(actual), std::net::IpAddr::V4(expected)) => assert_eq!(actual, expected),
                (Rdata::Aaaa(actual), std::net::IpAddr::V6(expected)) => {
                    assert_eq!(actual, expected)
                }
                _ => panic!("address type mismatch"),
            }
        }
        assert!(records.next().is_none());
    }
}

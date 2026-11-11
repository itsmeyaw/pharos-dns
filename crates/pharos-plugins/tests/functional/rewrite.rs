#![forbid(unsafe_code)]
#![cfg(feature = "plugin-rewrite")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct AliasChain(pharos_plugins::rewrite::Rewrite, &'static str);
impl pharos_server::Chain for AliasChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, AliasBackend(self.1)).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}

struct LoopChain {
    rewrite: pharos_plugins::rewrite::Rewrite,
    visits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

struct TruncatedAliasChain(pharos_plugins::rewrite::Rewrite);
impl pharos_server::Chain for TruncatedAliasChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, TruncatedAliasBackend).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}

struct MultiAliasChain(pharos_plugins::rewrite::Rewrite);
impl pharos_server::Chain for MultiAliasChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, MultiAliasBackend).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}

struct EdnsAliasChain(pharos_plugins::rewrite::Rewrite);
impl pharos_server::Chain for EdnsAliasChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        if cx.query.questions().next().unwrap().name.to_string() == "new.example." {
            assert!(
                cx.query
                    .opt()
                    .is_some_and(|opt| opt.options().iter().any(|option| matches!(
                        option,
                        pharos_proto::EdnsOption::Unknown {
                            code: 0xffee,
                            data: b"abcd"
                        }
                    )))
            );
        }
        self.0.serve(cx, EdnsAliasBackend).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}
struct EdnsAliasBackend;
impl Next for EdnsAliasBackend {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        assert!(
            cx.query
                .opt()
                .unwrap()
                .options()
                .iter()
                .any(|option| matches!(
                    option,
                    pharos_proto::EdnsOption::Unknown {
                        code: 0xffee,
                        data: b"abcd"
                    }
                ))
        );
        AliasBackend("new.example.").run(cx).await
    }
}

#[tokio::test]
async fn cname_self_lookup_preserves_rewritten_edns_options() {
    let config = ".:53 {\n rewrite continue edns0 local set 0xffee abcd\n rewrite cname old.example. new.example.\n}";
    let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
        Some(EdnsAliasChain(chain.rewrite.take().unwrap())),
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
    let response = Message::parse(&response).unwrap();
    let pharos_proto::Rdata::Cname(target) = response.answers().next().unwrap().data().unwrap()
    else {
        panic!("expected CNAME")
    };
    assert_eq!(target.to_string(), "new.example.");
    assert_eq!(response.answers().count(), 2);
}

struct AuthorityAliasChain(pharos_plugins::rewrite::Rewrite);
impl pharos_server::Chain for AuthorityAliasChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, AuthorityAliasBackend).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}
struct AuthorityAliasBackend;
impl Next for AuthorityAliasBackend {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let original = q.name.to_string() == "alias.example.";
        let target: Name = "old.example.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        if original {
            b.record_with(
                Section::Authority,
                q.name,
                Type::CNAME,
                Class::IN,
                30,
                |w| w.write_name(NameRef::parse(target.as_wire(), 0).unwrap()),
            )
            .unwrap();
        } else {
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

#[tokio::test]
async fn coredns_cname_rule_also_visits_authority_records() {
    let config = ".:53 {\n rewrite cname old.example. new.example.\n}";
    let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
        Some(AuthorityAliasChain(chain.rewrite.take().unwrap())),
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
    let response = Message::parse(&response).unwrap();
    assert_eq!(
        response.answers().next().unwrap().name.to_string(),
        "new.example."
    );
    assert_eq!(response.authorities().next().unwrap().rtype, Type::CNAME);
}
struct MultiAliasBackend;
impl Next for MultiAliasBackend {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let original = q.name.to_string() == "alias.example.";
        let hop: Name = "hop.example.".parse().unwrap();
        let old: Name = "old.example.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        if original {
            b.record_with(Section::Answer, q.name, Type::CNAME, Class::IN, 30, |w| {
                w.write_name(NameRef::parse(hop.as_wire(), 0).unwrap())
            })
            .unwrap();
            b.record_with(
                Section::Answer,
                NameRef::parse(hop.as_wire(), 0).unwrap(),
                Type::CNAME,
                Class::IN,
                40,
                |w| w.write_name(NameRef::parse(old.as_wire(), 0).unwrap()),
            )
            .unwrap();
            b.record(
                Section::Answer,
                NameRef::parse(old.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
                50,
                &[192, 0, 2, 99],
            )
            .unwrap();
        } else {
            assert_eq!(q.name.to_string(), "new.example.");
            let address = if q.qtype == Type::AAAA {
                &b"\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x01"[..]
            } else {
                &b"\xc0\0\x02\x01"[..]
            };
            b.record(Section::Answer, q.name, q.qtype, Class::IN, 60, address)
                .unwrap();
        }
        let _ = b.finish();
        Outcome::Response
    }
}

#[tokio::test]
async fn coredns_cname_chain_keeps_prior_aliases_and_query_type() {
    let config = ".:53 {\n rewrite cname old.example. new.example.\n}";
    let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
        Some(MultiAliasChain(chain.rewrite.take().unwrap())),
        vec![],
    );
    let server = pharos_server::Server::new(router, key);
    let name: Name = "alias.example.".parse().unwrap();
    for qtype in [Type::A, Type::AAAA] {
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
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
        let pharos_proto::Rdata::Cname(first) = answers.next().unwrap().data().unwrap() else {
            panic!("expected CNAME")
        };
        assert_eq!(first.to_string(), "hop.example.");
        let pharos_proto::Rdata::Cname(second) = answers.next().unwrap().data().unwrap() else {
            panic!("expected CNAME")
        };
        assert_eq!(second.to_string(), "new.example.");
        let address = answers.next().unwrap();
        assert_eq!(address.rtype, qtype);
        assert_eq!(address.name.to_string(), "new.example.");
        assert!(answers.next().is_none());
    }
}
struct TruncatedAliasBackend;
impl Next for TruncatedAliasBackend {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let target = cx.query.questions().next().unwrap().name.to_string() == "new.example.";
        let result = AliasBackend("new.example.").run(cx).await;
        if target {
            cx.response[2] |= 0x02;
        }
        result
    }
}

#[tokio::test]
async fn coredns_cname_rewrite_propagates_lookup_truncation() {
    let config = ".:53 {\n rewrite cname old.example. new.example.\n}";
    let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
        Some(TruncatedAliasChain(chain.rewrite.take().unwrap())),
        vec![],
    );
    let server = std::sync::Arc::new(pharos_server::Server::new(router, key));
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
        pharos_server::Handler::handle_shared(
            &server,
            &wire,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response
        )
        .await,
        pharos_server::Action::Respond
    );
    assert!(Message::parse(&response).unwrap().tc());
}
impl pharos_server::Chain for LoopChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.rewrite.serve(cx, LoopBackend(&self.visits)).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}
struct LoopBackend<'a>(&'a std::sync::atomic::AtomicUsize);
impl Next for LoopBackend<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let q = cx.query.questions().next().unwrap();
        let target: Name = "loop.example.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record_with(Section::Answer, q.name, Type::CNAME, Class::IN, 30, |w| {
            w.write_name(NameRef::parse(target.as_wire(), 0).unwrap())
        })
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/cname_target_test.go.
#[tokio::test]
async fn coredns_cname_loop_stops_after_nine_lookups() {
    let config = ".:53 {\n rewrite cname loop.example. target.example.\n}";
    let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let visits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let key = pharos_server::ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = pharos_server::Router::default();
    router.add(
        key,
        ".".parse().unwrap(),
        Some(LoopChain {
            rewrite: chain.rewrite.take().unwrap(),
            visits: std::sync::Arc::clone(&visits),
        }),
        vec![],
    );
    let server = std::sync::Arc::new(pharos_server::Server::new(router, key));
    let name: Name = "victim.example.".parse().unwrap();
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
        pharos_server::Handler::handle_shared(
            &server,
            &wire,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response
        )
        .await,
        pharos_server::Action::Respond
    );
    assert_eq!(visits.load(std::sync::atomic::Ordering::Relaxed), 10);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOERROR);
}

#[tokio::test]
async fn coredns_cname_lookup_failure_keeps_original_answer() {
    let config = ".:53 {\n rewrite cname old.example. new.example.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "alias.example.".parse().unwrap();
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
            .serve(&mut cx, AliasBackend("new.example."))
            .await,
        Outcome::Response
    );
    let response = Message::parse(cx.response).unwrap();
    let pharos_proto::Rdata::Cname(target) = response.answers().next().unwrap().data().unwrap()
    else {
        panic!("expected CNAME")
    };
    assert_eq!(target.to_string(), "old.example.");
}
struct AliasBackend(&'static str);
impl Next for AliasBackend {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
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
        ("rewrite cname OLD.EXAMPLE NEW.EXAMPLE", "new.example."),
        (
            "rewrite continue cname old.example. new.example.\n rewrite cname missing.example. unused.example.",
            "new.example.",
        ),
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

struct TtlFixture {
    ttl: u32,
    count: usize,
    kind: Type,
}

struct ReverterFixture {
    owner: &'static str,
    kind: Type,
    count: usize,
}

struct RemapFixture;
impl Next for RemapFixture {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        for value in [
            "example.com.",
            "sub.example.com.",
            "a.b.example.com.",
            "notexample.com.",
            "example.net.",
            "com.",
        ] {
            let owner: Name = value.parse().unwrap();
            builder
                .record(
                    Section::Answer,
                    NameRef::parse(owner.as_wire(), 0).unwrap(),
                    Type::A,
                    Class::IN,
                    5,
                    &[127, 0, 0, 1],
                )
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_test.go TestRemapStringRewriter.
#[tokio::test]
async fn coredns_remap_name_boundary_rows() {
    let config = ".:53 {\n rewrite name example.org. example.com.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.org.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
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
            .serve(&mut cx, RemapFixture)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    let actual: Vec<_> = message
        .answers()
        .map(|record| record.name.to_string())
        .collect();
    assert_eq!(
        actual,
        [
            "example.org.",
            "sub.example.org.",
            "a.b.example.org.",
            "notexample.com.",
            "example.net.",
            "com."
        ]
    );
}
impl Next for ReverterFixture {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        assert_eq!(q.name.to_string(), "dns.core.rocks.");
        let owner: Name = self.owner.parse().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        for index in 0..self.count {
            if self.kind == Type::SRV {
                let target: Name = "srv1.dns.core.rocks.".parse().unwrap();
                builder
                    .record_with(
                        Section::Answer,
                        NameRef::parse(owner.as_wire(), 0).unwrap(),
                        Type::SRV,
                        Class::IN,
                        5,
                        |w| {
                            w.write_bytes(&[0, 0, 0, 100, 0, 100])?;
                            w.write_name(NameRef::parse(target.as_wire(), 0).unwrap())
                        },
                    )
                    .unwrap();
            } else {
                let data: &[u8] = if self.kind == Type::HINFO {
                    b"\x08INTEL-64\x08RHEL 7.4"
                } else if index == 0 {
                    &[10, 0, 0, 1]
                } else {
                    &[10, 0, 0, 2]
                };
                builder
                    .record(
                        Section::Answer,
                        NameRef::parse(owner.as_wire(), 0).unwrap(),
                        self.kind,
                        Class::IN,
                        5,
                        data,
                    )
                    .unwrap();
            }
        }
        let raw = Message::parse(builder.finish()).unwrap();
        assert_eq!(
            raw.questions().next().unwrap().name.to_string(),
            "dns.core.rocks."
        );
        assert_eq!(raw.answers().count(), self.count);
        for record in raw.answers() {
            assert_eq!(
                (record.name.to_string().as_str(), record.rtype),
                (self.owner, self.kind)
            );
        }
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go TestResponseReverter.
#[tokio::test]
async fn coredns_response_reverter_rows() {
    for mode in ["stop", "continue"] {
        for (kind, owner, count) in [
            (Type::A, "dns.core.rocks.", 1),
            (Type::SRV, "dns.core.rocks.", 1),
            (Type::A, "core.dns.rocks.", 1),
            (Type::SRV, "core.dns.rocks.", 1),
            (Type::HINFO, "core.dns.rocks.", 1),
            (Type::A, "dns.core.rocks.", 2),
        ] {
            let config = format!(
                r".:53 {{
 rewrite {mode} name regex (core)\.(dns)\.(rocks) {{2}}.{{1}}.{{3}} answer name (dns)\.(core)\.(rocks) {{2}}.{{1}}.{{3}}
}}"
            );
            let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
                .unwrap()
                .remove(0)
                .config;
            let name: Name = "core.dns.rocks.".parse().unwrap();
            let root: Name = ".".parse().unwrap();
            let mut wire = Vec::with_capacity(512);
            let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
            builder
                .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
                .unwrap();
            let _ = builder.finish();
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
                    .serve(&mut cx, ReverterFixture { owner, kind, count })
                    .await,
                Outcome::Response
            );
            let response = Message::parse(cx.response).unwrap();
            let q = response.questions().next().unwrap();
            assert_eq!(
                (q.name.to_string().as_str(), q.qtype),
                ("core.dns.rocks.", kind)
            );
            assert_eq!(response.answers().count(), count);
            for rr in response.answers() {
                assert_eq!(rr.name.to_string(), "core.dns.rocks.");
                assert_eq!(rr.rtype, kind);
                if let pharos_proto::Rdata::Srv { target, .. } = rr.data().unwrap() {
                    assert_eq!(target.to_string(), "srv1.dns.core.rocks.");
                }
            }
        }
    }
}
impl Next for TtlFixture {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        for index in 0..self.count {
            if self.kind == Type::SRV {
                builder
                    .record_with(
                        Section::Answer,
                        q.name,
                        Type::SRV,
                        Class::IN,
                        self.ttl,
                        |w| {
                            w.write_bytes(&[0, 0, 0, 100, 0, 100])?;
                            w.write_name(q.name)
                        },
                    )
                    .unwrap();
            } else {
                let data: &[u8] = if self.kind == Type::HINFO {
                    b"\x08INTEL-64\x08RHEL 7.5"
                } else if index == 0 {
                    &[10, 0, 0, 1]
                } else {
                    &[10, 0, 0, 2]
                };
                builder
                    .record(
                        Section::Answer,
                        q.name,
                        self.kind,
                        Class::IN,
                        self.ttl,
                        data,
                    )
                    .unwrap();
            }
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/ttl_test.go TestTtlRewrite.
#[tokio::test]
async fn coredns_ttl_answer_rows() {
    for (rule, name, kind, before, after, count) in [
        (
            "srv1.coredns.rocks 1",
            "srv1.coredns.rocks.",
            Type::A,
            5,
            1,
            1,
        ),
        (
            "exact srv15.coredns.rocks 15",
            "srv15.coredns.rocks.",
            Type::A,
            5,
            15,
            1,
        ),
        ("prefix srv30 30", "srv30.coredns.rocks.", Type::A, 5, 30, 1),
        (
            "suffix 45.coredns.rocks 45",
            "srv45.coredns.rocks.",
            Type::A,
            5,
            45,
            1,
        ),
        (
            "substring rv50 50",
            "srv50.coredns.rocks.",
            Type::A,
            5,
            50,
            1,
        ),
        (
            r"regex (srv10)\.(coredns)\.(rocks) 10",
            "srv10.coredns.rocks.",
            Type::A,
            5,
            10,
            1,
        ),
        (
            "srv1.coredns.rocks 1",
            "xmpp.coredns.rocks.",
            Type::SRV,
            5,
            5,
            1,
        ),
        (
            "exact srv15.coredns.rocks 15",
            "srv15.coredns.rocks.",
            Type::HINFO,
            5,
            15,
            1,
        ),
        (
            r"regex (srv20)\.(coredns)\.(rocks) 20",
            "srv20.coredns.rocks.",
            Type::A,
            5,
            20,
            2,
        ),
        (
            "range.example.com. 30-300",
            "range.example.com.",
            Type::A,
            5,
            30,
            1,
        ),
        (
            "range.example.com. 30-300",
            "range.example.com.",
            Type::A,
            55,
            55,
            1,
        ),
        (
            "range.example.com. 30-300",
            "range.example.com.",
            Type::A,
            500,
            300,
            1,
        ),
        (
            "ceil.example.com. -11",
            "ceil.example.com.",
            Type::A,
            5,
            5,
            1,
        ),
        (
            "ceil.example.com. -11",
            "ceil.example.com.",
            Type::A,
            15,
            11,
            1,
        ),
        (
            "floor.example.com. 5-",
            "floor.example.com.",
            Type::A,
            0,
            5,
            1,
        ),
        (
            "floor.example.com. 5-",
            "floor.example.com.",
            Type::A,
            30,
            30,
            1,
        ),
    ] {
        let config = format!(".:53 {{\n rewrite ttl {rule}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = name.parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        let _ = builder.finish();
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
                .serve(
                    &mut cx,
                    TtlFixture {
                        ttl: before,
                        count,
                        kind
                    }
                )
                .await,
            Outcome::Response,
            "{rule}"
        );
        let message = Message::parse(cx.response).unwrap();
        assert_eq!(message.answers().count(), count);
        for record in message.answers() {
            assert_eq!(record.ttl, after, "{rule}");
        }
    }
}

struct Unanswered(Rcode);
impl Next for Unanswered {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(self.0)
    }
}

struct EmptyServfail;
impl Next for EmptyServfail {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let question = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8182).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rcode_test.go TestRCodeRewriteEmptyResponse.
#[tokio::test]
async fn coredns_rcode_rewrites_empty_response() {
    let config = ".:53 {\n rewrite rcode example. SERVFAIL NOERROR\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
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
            .serve(&mut cx, EmptyServfail)
            .await,
        Outcome::Response
    );
    assert_eq!(Message::parse(cx.response).unwrap().rcode(), Rcode::NOERROR);
}

struct RcodeChain(pharos_plugins::rewrite::Rewrite);
impl pharos_server::Chain for RcodeChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, Unanswered(Rcode::SERVFAIL)).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}

struct RewriteAnswerChain(pharos_plugins::rewrite::Rewrite);
impl pharos_server::Chain for RewriteAnswerChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, Answer).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn edns_rewrite_does_not_add_opt_for_non_edns_client() {
    let config = ".:53 {\n rewrite edns0 local set 0xffee abcd\n}";
    let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
        Some(RewriteAnswerChain(chain.rewrite.take().unwrap())),
        vec![],
    );
    let server = pharos_server::Server::new(router, key);
    let name: Name = "example.".parse().unwrap();
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
    // RFC 6891 §7: a non-EDNS Query must not receive an OPT record.
    assert!(Message::parse(&response).unwrap().opt().is_none());
}

#[tokio::test]
async fn coredns_rcode_rewrite_returns_a_response_for_unanswered_success() {
    let config = ".:53 {\n rewrite rcode example. SERVFAIL NOERROR\n}";
    let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
        Some(RcodeChain(chain.rewrite.take().unwrap())),
        vec![],
    );
    let server = pharos_server::Server::new(router, key);
    let name: Name = "example.".parse().unwrap();
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
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.question_count(), 1);
}

#[tokio::test]
async fn coredns_edns_revert_survives_unanswered_error_response() {
    for (config, expected) in [
        (
            ".:53 {\n rewrite edns0 local set 0xffee new revert\n}",
            &b"\xff\xee\0\x03old"[..],
        ),
        (
            ".:53 {\n rewrite continue edns0 local set 0xffee new\n}",
            &b"\xff\xee\0\x03new"[..],
        ),
    ] {
        let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
            Some(RcodeChain(chain.rewrite.take().unwrap())),
            vec![],
        );
        let server = pharos_server::Server::new(router, key);
        let name: Name = "example.".parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let original = b"\xff\xee\0\x03old";
        let mut wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        b.record(
            Section::Additional,
            NameRef::parse(root.as_wire(), 0).unwrap(),
            Type::OPT,
            Class(1232),
            0,
            original,
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
        let response = Message::parse(&response).unwrap();
        assert_eq!(response.rcode(), Rcode::SERVFAIL);
        assert_eq!(response.opt().unwrap().options().as_bytes(), expected);
    }
}

struct InspectQuestion(Type, Class);
impl Next for InspectQuestion {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
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

struct InspectFullQuestion(&'static str, Type, Class);
impl Next for InspectFullQuestion {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        assert_eq!(
            (q.name.to_string().as_str(), q.qtype, q.qclass),
            (self.0, self.1, self.2)
        );
        Outcome::Drop
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestRewrite.
#[tokio::test]
async fn coredns_chained_rule_question_rows() {
    let config = r".:53 {
 rewrite name from.nl. to.nl.
 rewrite name regex (core)\.(dns)\.(rocks)\.(nl) {2}.{1}.{3}.{4} answer name (dns)\.(core)\.(rocks)\.(nl) {2}.{1}.{3}.{4}
 rewrite name exact from.exact.nl. to.nl.
 rewrite name prefix prefix to
 rewrite name suffix .suffix. .nl.
 rewrite name substring from.substring to
 rewrite name regex (f.*m)\.regex\.(nl) to.{2}
 rewrite continue name regex consul\.(rocks) core.dns.{1}
 rewrite name core.dns.rocks to.nl.
 rewrite continue class HS CH
 rewrite class CH IN
 rewrite type ANY HINFO
}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    for (incoming, from_type, from_class, expected, to_type, to_class) in [
        ("from.nl.", Type::A, Class::IN, "to.nl.", Type::A, Class::IN),
        ("a.nl.", Type::A, Class::IN, "a.nl.", Type::A, Class::IN),
        ("a.nl.", Type::A, Class::CH, "a.nl.", Type::A, Class::IN),
        (
            "a.nl.",
            Type::ANY,
            Class::IN,
            "a.nl.",
            Type::HINFO,
            Class::IN,
        ),
        (
            "from.nl.",
            Type::ANY,
            Class::IN,
            "to.nl.",
            Type::ANY,
            Class::IN,
        ),
        (
            "from.exact.nl.",
            Type::A,
            Class::IN,
            "to.nl.",
            Type::A,
            Class::IN,
        ),
        (
            "prefix.nl.",
            Type::A,
            Class::IN,
            "to.nl.",
            Type::A,
            Class::IN,
        ),
        (
            "to.suffix.",
            Type::A,
            Class::IN,
            "to.nl.",
            Type::A,
            Class::IN,
        ),
        (
            "from.substring.nl.",
            Type::A,
            Class::IN,
            "to.nl.",
            Type::A,
            Class::IN,
        ),
        (
            "from.regex.nl.",
            Type::A,
            Class::IN,
            "to.nl.",
            Type::A,
            Class::IN,
        ),
        (
            "consul.rocks.",
            Type::A,
            Class::IN,
            "to.nl.",
            Type::A,
            Class::IN,
        ),
        ("a.nl.", Type::ANY, Class::CH, "a.nl.", Type::ANY, Class::IN),
        ("a.nl.", Type::ANY, Class::HS, "a.nl.", Type::ANY, Class::IN),
        (
            "core.dns.rocks.nl.",
            Type::A,
            Class::IN,
            "dns.core.rocks.nl.",
            Type::A,
            Class::IN,
        ),
    ] {
        let name: Name = incoming.parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                from_type,
                from_class,
            )
            .unwrap();
        let _ = builder.finish();
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
                .serve(&mut cx, InspectFullQuestion(expected, to_type, to_class))
                .await,
            Outcome::Drop,
            "{incoming}"
        );
    }
}

struct InspectLocalOption;
impl Next for InspectLocalOption {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let opt = cx.query.opt().expect("rewrite created OPT");
        assert!(opt.options().iter().any(|option| matches!(
            option,
            pharos_proto::EdnsOption::Unknown {
                code: 0xffee,
                data: b"abcd"
            }
        )));
        Outcome::Drop
    }
}

struct InspectOptionBytes(&'static [u8]);
impl Next for InspectOptionBytes {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(cx.query.opt().unwrap().options().as_bytes(), self.0);
        Outcome::Drop
    }
}

#[tokio::test]
async fn coredns_edns_local_append_replace_and_unset() {
    let initial = b"\xff\xee\0\x01a";
    for (rule, input, expected) in [
        (
            "rewrite edns0 local append 0xffee b",
            &initial[..],
            &b"\xff\xee\0\x01a\xff\xee\0\x01b"[..],
        ),
        (
            "rewrite edns0 local append 0xffee {qname}",
            &initial[..],
            &initial[..],
        ),
        (
            "rewrite edns0 nsid append",
            &b"\0\x03\0\x03old"[..],
            &b"\0\x03\0\x03old\0\x03\0\0"[..],
        ),
        (
            "rewrite edns0 subnet append 24 56",
            &b"\0\x08\0\x04\0\x01\0\0"[..],
            &b"\0\x08\0\x04\0\x01\0\0"[..],
        ),
        (
            "rewrite edns0 local replace 0xffee b",
            &initial[..],
            &b"\xff\xee\0\x01b"[..],
        ),
        ("rewrite edns0 local replace 0xffee b", &b""[..], &b""[..]),
        ("rewrite edns0 local unset 0xffee", &initial[..], &b""[..]),
        ("rewrite edns0 local unset 0xffee", &b""[..], &b""[..]),
        (
            "rewrite edns0 local unset 0xffee",
            &b"\xff\xee\0\x03\xab\xcd\xef"[..],
            &b""[..],
        ),
        (
            "rewrite edns0 local unset 0xffed",
            &b"\xff\xee\0\x03\xab\xcd\xef"[..],
            &b"\xff\xee\0\x03\xab\xcd\xef"[..],
        ),
        (
            "rewrite edns0 local unset 0xffed",
            &initial[..],
            &initial[..],
        ),
        ("rewrite edns0 nsid unset", &b"\0\x03\0\0"[..], &b""[..]),
        ("rewrite edns0 nsid unset", &b""[..], &b""[..]),
        (
            "rewrite edns0 subnet unset",
            &b"\0\x08\0\x04\0\x01\0\0"[..],
            &b""[..],
        ),
        ("rewrite edns0 subnet unset", &b""[..], &b""[..]),
        (
            "rewrite edns0 nsid unset",
            &b"\xff\xee\0\x06foobar\0\x03\0\0"[..],
            &b"\xff\xee\0\x06foobar"[..],
        ),
        (
            "rewrite edns0 local unset 0xffee",
            &b"\xff\xee\0\x06foobar\0\x03\0\0"[..],
            &b"\0\x03\0\0"[..],
        ),
        (
            "rewrite edns0 subnet unset",
            &b"\xff\xee\0\x06foobar\0\x03\0\0"[..],
            &b"\xff\xee\0\x06foobar\0\x03\0\0"[..],
        ),
        (
            "rewrite edns0 local set 0xffee 0xabcdef",
            &b""[..],
            &b"\xff\xee\0\x03\xab\xcd\xef"[..],
        ),
        (
            "rewrite edns0 local append 0xffee abcdefghijklmnop",
            &b""[..],
            &b"\xff\xee\0\x10abcdefghijklmnop"[..],
        ),
        ("rewrite edns0 nsid set", &b""[..], &b"\0\x03\0\0"[..]),
        ("rewrite edns0 nsid append", &b""[..], &b"\0\x03\0\0"[..]),
        ("rewrite edns0 nsid replace", &b""[..], &b""[..]),
    ] {
        let config = format!(".:53 {{\n {rule}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
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
        b.record(
            Section::Additional,
            NameRef::parse(root.as_wire(), 0).unwrap(),
            Type::OPT,
            Class(4096),
            0,
            input,
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
                .serve(&mut cx, InspectOptionBytes(expected))
                .await,
            Outcome::Drop,
            "{rule}"
        );
    }
}

#[tokio::test]
async fn coredns_local_rule_does_not_replace_typed_nsid() {
    for (config, expected) in [
        (
            ".:53 {\n rewrite edns0 local set 3 abcd\n}",
            &b"\0\x03\0\x03old\0\x03\0\x04abcd"[..],
        ),
        (
            ".:53 {\n rewrite continue edns0 local set 3 abcd\n rewrite edns0 nsid set\n}",
            &b"\0\x03\0\0\0\x03\0\x04abcd"[..],
        ),
    ] {
        let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
        b.record(
            Section::Additional,
            NameRef::parse(root.as_wire(), 0).unwrap(),
            Type::OPT,
            Class(4096),
            0,
            b"\0\x03\0\x03old",
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
                .serve(&mut cx, InspectOptionBytes(expected))
                .await,
            Outcome::Drop
        );
    }
}

#[tokio::test]
async fn coredns_ignored_edns_replace_does_not_stop_later_rules() {
    let config = ".:53 {\n rewrite edns0 local replace 0xffee data\n rewrite ttl example. 30\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
    assert_eq!(
        chain.rewrite.as_ref().unwrap().serve(&mut cx, Answer).await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(message.answers().next().unwrap().ttl, 30);
}

#[tokio::test]
async fn coredns_ignored_edns_replace_does_not_block_name_reversion() {
    let config =
        ".:53 {\n rewrite edns0 local replace 0xffee data\n rewrite name a.example. b.example.\n}";
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
    assert_eq!(
        message.answers().next().unwrap().name.to_string(),
        "a.example."
    );
}

#[tokio::test]
async fn coredns_edns_nsid_and_subnet_rewrite() {
    for (rule, expected) in [
        ("rewrite edns0 nsid set", &b"\0\x03\0\0"[..]),
        (
            "rewrite edns0 subnet set 24 56",
            &b"\0\x08\0\x07\0\x01\x18\0\xc0\0\x02"[..],
        ),
        (
            "rewrite edns0 subnet set 25 57",
            &b"\0\x08\0\x08\0\x01\x19\0\xc0\0\x02\x80"[..],
        ),
    ] {
        let config = format!(".:53 {{\n {rule}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
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
            client: "192.0.2.129:1234".parse().unwrap(),
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
                .serve(&mut cx, InspectOptionBytes(expected))
                .await,
            Outcome::Drop,
            "{rule}"
        );
    }
}

#[tokio::test]
async fn coredns_edns_subnet_uses_ipv6_prefix_and_masks_host_bits() {
    let config = ".:53 {\n rewrite edns0 subnet set 24 56\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
        client: "[2001:db8:abcd:1234::1]:1234".parse().unwrap(),
        local: "[::1]:53".parse().unwrap(),
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
            .serve(
                &mut cx,
                InspectOptionBytes(b"\0\x08\0\x0b\0\x02\x38\0\x20\x01\x0d\xb8\xab\xcd\x12")
            )
            .await,
        Outcome::Drop
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestRewriteEDNS0Subnet.
#[tokio::test]
async fn coredns_edns_subnet_prefix_rows() {
    for (rule, client, expected) in [
        (
            "24 56",
            "10.240.0.1:40212",
            &b"\0\x08\0\x07\0\x01\x18\0\x0a\xf0\0"[..],
        ),
        (
            "32 56",
            "10.240.0.1:40212",
            &b"\0\x08\0\x08\0\x01\x20\0\x0a\xf0\0\x01"[..],
        ),
        ("0 56", "10.240.0.1:40212", &b"\0\x08\0\x04\0\x01\0\0"[..]),
        (
            "24 56",
            "[fe80::42:ff:feca:4c65]:40212",
            &b"\0\x08\0\x0b\0\x02\x38\0\xfe\x80\0\0\0\0\0"[..],
        ),
        (
            "24 128",
            "[fe80::42:ff:feca:4c65]:40212",
            &b"\0\x08\0\x14\0\x02\x80\0\xfe\x80\0\0\0\0\0\0\0\x42\0\xff\xfe\xca\x4c\x65"[..],
        ),
        (
            "24 0",
            "[fe80::42:ff:feca:4c65]:40212",
            &b"\0\x08\0\x04\0\x02\0\0"[..],
        ),
    ] {
        let config = format!(".:53 {{\n rewrite edns0 subnet set {rule}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "example.com.".parse().unwrap();
        let root: Name = ".".parse().unwrap();
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
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, InspectOptionBytes(expected))
                .await,
            Outcome::Drop,
            "{rule} {client}"
        );
    }
}

struct InspectMaybeOptions(Option<&'static [u8]>);
impl Next for InspectMaybeOptions {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(cx.query.opt().map(|opt| opt.options().as_bytes()), self.0);
        Outcome::Drop
    }
}

struct MutateMetadataAnswer;
impl Next for MutateMetadataAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        cx.metadata.insert("test/value", "new");
        Answer.run(cx).await
    }
}

struct MutateMetadataEcho;
impl Next for MutateMetadataEcho {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        cx.metadata.insert("test/value", "changed");
        EchoOptions.run(cx).await
    }
}

#[tokio::test]
async fn edns_revert_uses_metadata_from_query_phase() {
    let config = ".:53 {\n rewrite continue edns0 local set 0xffee {test/value}\n rewrite edns0 local replace 0xffee new revert\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
    b.record(
        Section::Additional,
        NameRef::parse(root.as_wire(), 0).unwrap(),
        Type::OPT,
        Class(4096),
        0,
        &[],
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
    cx.metadata.insert("test/value", "old");
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, MutateMetadataEcho)
            .await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(cx.response)
            .unwrap()
            .opt()
            .unwrap()
            .options()
            .as_bytes(),
        b"\xff\xee\0\x03old"
    );
}

#[tokio::test]
async fn edns_revert_replays_the_original_metadata_name() {
    let config = r".:53 {
 rewrite continue name regex ^([^.]+)\.example\.$ {1}.{test/value}. metadata
 rewrite continue edns0 local set 0xffee {qname}
 rewrite edns0 local replace 0xffee new revert
}";
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
    b.record(
        Section::Additional,
        NameRef::parse(root.as_wire(), 0).unwrap(),
        Type::OPT,
        Class(4096),
        0,
        &[],
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
    cx.metadata.insert("test/value", "old");
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, MutateMetadataEcho)
            .await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(cx.response)
            .unwrap()
            .opt()
            .unwrap()
            .options()
            .as_bytes(),
        b"\xff\xee\0\x08web.old."
    );
}

#[tokio::test]
async fn metadata_name_reversion_uses_value_from_the_query_phase() {
    let config = r".:53 {
 rewrite name regex ^([^.]+)\.example\.$ {1}.{test/value}. metadata answer auto
}";
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
    cx.metadata.insert("test/value", "old");
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, MutateMetadataAnswer)
            .await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(cx.response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .name
            .to_string(),
        "web.example."
    );
}

struct EchoOptions;
impl Next for EchoOptions {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let query = cx.query;
        let q = query.questions().next().unwrap();
        let opt = query.opt().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record(
            Section::Additional,
            NameRef::parse(&[0], 0).unwrap(),
            Type::OPT,
            Class(opt.udp_payload_size()),
            0,
            opt.options().as_bytes(),
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

struct MultiAnswerEcho;
impl Next for MultiAnswerEcho {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let query = cx.query;
        let q = query.questions().next().unwrap();
        let opt = query.opt().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        for ip in [[192, 0, 2, 1], [192, 0, 2, 2]] {
            b.record(Section::Answer, q.name, Type::A, Class::IN, 30, &ip)
                .unwrap();
        }
        b.record(
            Section::Additional,
            NameRef::parse(&[0], 0).unwrap(),
            Type::OPT,
            Class(opt.udp_payload_size()),
            0,
            opt.options().as_bytes(),
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

#[tokio::test]
async fn coredns_edns_reverter_applies_once_for_each_response_record() {
    let config = ".:53 {\n rewrite edns0 local append 0xffee c revert\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
    b.record(
        Section::Additional,
        NameRef::parse(root.as_wire(), 0).unwrap(),
        Type::OPT,
        Class(4096),
        0,
        b"\xff\xee\0\x01a\xff\xee\0\x01b",
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
            .serve(&mut cx, MultiAnswerEcho)
            .await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(cx.response)
            .unwrap()
            .opt()
            .unwrap()
            .options()
            .as_bytes(),
        b""
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/edns0_test.go.
#[tokio::test]
async fn coredns_edns_revert_restores_original_or_removes_injected_option() {
    for original in [&b""[..], &b"\xff\xee\0\x03old"[..]] {
        let config = ".:53 {\n rewrite edns0 local set 0xffee new revert\n}";
        let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
        b.record(
            Section::Additional,
            NameRef::parse(root.as_wire(), 0).unwrap(),
            Type::OPT,
            Class(4096),
            0,
            original,
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
                .serve(&mut cx, EchoOptions)
                .await,
            Outcome::Response
        );
        let response = Message::parse(cx.response).unwrap();
        assert_eq!(response.opt().unwrap().options().as_bytes(), original);
    }
}

#[tokio::test]
async fn coredns_edns_revert_restores_previous_rewrite_value() {
    let config = ".:53 {\n rewrite continue edns0 local set 0xffee abcd\n rewrite edns0 local replace 0xffee bcde revert\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
    b.record(
        Section::Additional,
        NameRef::parse(root.as_wire(), 0).unwrap(),
        Type::OPT,
        Class(4096),
        0,
        &[],
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
            .serve(&mut cx, EchoOptions)
            .await,
        Outcome::Response
    );
    let response = Message::parse(cx.response).unwrap();
    assert_eq!(
        response.opt().unwrap().options().as_bytes(),
        b"\xff\xee\0\x04abcd"
    );
}

#[tokio::test]
async fn coredns_edns_revert_applies_when_next_omits_opt() {
    let config = ".:53 {\n rewrite continue edns0 local set 0xffee abcd\n rewrite edns0 local replace 0xffee bcde revert\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
    b.record(
        Section::Additional,
        NameRef::parse(root.as_wire(), 0).unwrap(),
        Type::OPT,
        Class(4096),
        0,
        &[],
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
    let response = Message::parse(cx.response).unwrap();
    assert_eq!(
        response.opt().unwrap().options().as_bytes(),
        b"\xff\xee\0\x04abcd"
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestRewriteEDNS0LocalVariable.
#[tokio::test]
async fn coredns_edns_local_variables_and_metadata() {
    for (variable, value, expected) in [
        ("qname", None, Some(&b"\xff\xee\0\x0cexample.com."[..])),
        ("qtype", None, Some(&b"\xff\xee\0\x02\0\x01"[..])),
        (
            "client_ip",
            None,
            Some(&b"\xff\xee\0\x04\x0a\xf0\0\x01"[..]),
        ),
        ("client_port", None, Some(&b"\xff\xee\0\x02\x9d\x14"[..])),
        ("server_ip", None, Some(&b"\xff\xee\0\x04\x7f\0\0\x01"[..])),
        ("server_port", None, Some(&b"\xff\xee\0\x02\0\x35"[..])),
        ("protocol", None, Some(&b"\xff\xee\0\x03udp"[..])),
        (
            "test/label",
            Some("my-value"),
            Some(&b"\xff\xee\0\x08my-value"[..]),
        ),
        ("test/label", None, None),
        ("test/empty", Some(""), None),
        ("test/does-not-exist", None, None),
    ] {
        let config = format!(".:53 {{\n rewrite edns0 local set 0xffee {{{variable}}}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
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
        let mut slots = [None];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "10.240.0.1:40212".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        if let Some(value) = value {
            cx.metadata.insert(variable, value);
        }
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, InspectMaybeOptions(expected))
                .await,
            Outcome::Drop,
            "{variable}"
        );
    }
}

struct WaitForever;
impl Next for WaitForever {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        std::future::pending().await
    }
}

#[test]
fn edns_buffer_is_released_when_a_query_is_cancelled() {
    use std::{
        future::Future,
        task::{Context as TaskContext, Poll, Waker},
    };
    let config = ".:53 {\n rewrite edns0 local set 0xffee abcd\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let plugin = chain.rewrite.as_ref().unwrap();
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
    let mut first_response = Vec::with_capacity(512);
    let mut second_response = Vec::with_capacity(512);
    let mut first_slots = [];
    let mut second_slots = [];
    let mut first = Context {
        query: Message::parse(&wire).unwrap(),
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
        query: Message::parse(&wire).unwrap(),
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
    let mut second_future = Box::pin(plugin.serve(&mut second, InspectLocalOption));
    let mut task = TaskContext::from_waker(Waker::noop());
    assert_eq!(first_future.as_mut().poll(&mut task), Poll::Pending);
    assert_eq!(second_future.as_mut().poll(&mut task), Poll::Pending);
    drop(first_future);
    assert_eq!(
        second_future.as_mut().poll(&mut task),
        Poll::Ready(Outcome::Drop)
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go.
#[tokio::test]
async fn coredns_edns_local_set_reaches_next_without_original_opt() {
    let config = ".:53 {\n rewrite edns0 local set 0xffee abcd\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, InspectLocalOption)
            .await,
        Outcome::Drop
    );
    assert!(cx.query.opt().is_none());
}

struct InspectName(&'static str);
impl Next for InspectName {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(
            cx.query.questions().next().unwrap().name.to_string(),
            self.0
        );
        Outcome::Drop
    }
}

struct ExpectNameAnswer(&'static str);
impl Next for ExpectNameAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(
            cx.query.questions().next().unwrap().name.to_string(),
            self.0
        );
        Answer.run(cx).await
    }
}

struct NoQuestionAnswer;
impl Next for NoQuestionAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
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

struct EmptyResponse;
impl Next for EmptyResponse {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go TestResponseReverterWriteMsgNilResponse.
#[tokio::test]
async fn coredns_reverter_rejects_missing_response_without_panicking() {
    let config = ".:53 {\n rewrite ttl example.org. 30\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.org.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
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
    assert!(matches!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, EmptyResponse)
            .await,
        Outcome::Error(_)
    ));
}

struct TtlPointerAnswer;
impl Next for TtlPointerAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        cx.response.extend_from_slice(b"\0\x01\x81\x80\0\x01\0\x02\0\0\0\0\0\0\x01\0\x01\0\0\x01\0\x01\0\0\0\x3c\0\x04\x7f\0\0\x01\xc0\x16\0\x01\0\x01\0\0\0\x3c\0\x04\x7f\0\0\x02");
        Outcome::Response
    }
}

struct RcodePointerAnswer;
impl Next for RcodePointerAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        cx.response.extend_from_slice(b"\0\x01\x80\x02\0\x01\0\x01\0\0\0\0\0\0\x01\0\x01\xc0\x03\0\x01\0\x01\0\0\0\x3c\0\x04\x7f\0\0\x01");
        Outcome::Response
    }
}

struct ServfailWithOpt;
impl Next for ServfailWithOpt {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8182).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record(
            Section::Additional,
            NameRef::parse(&[0], 0).unwrap(),
            Type::OPT,
            Class(1232),
            0x8000,
            &[],
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

#[tokio::test]
async fn coredns_rcode_rewrite_updates_extended_opt_code() {
    for (target, code) in [("BADCOOKIE", Rcode::BADCOOKIE), ("FORMERR", Rcode::FORMERR)] {
        let config = format!(".:53 {{\n rewrite rcode example. SERVFAIL {target}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
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
        b.record(
            Section::Additional,
            NameRef::parse(root.as_wire(), 0).unwrap(),
            Type::OPT,
            Class(1232),
            0x8000,
            &[],
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
                .serve(&mut cx, ServfailWithOpt)
                .await,
            Outcome::Response
        );
        let response = Message::parse(cx.response).unwrap();
        assert_eq!(response.rcode(), code);
        assert!(response.opt().unwrap().dnssec_ok());
    }
}

#[tokio::test]
async fn rcode_rewrite_preserves_names_compressed_against_old_header() {
    let config = ".:53 {\n rewrite rcode . SERVFAIL NOERROR\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\0\0\x01\0\x01";
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
            .serve(&mut cx, RcodePointerAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(
        message.answers().next().unwrap().name.to_string(),
        r"\000\001."
    );
}

#[tokio::test]
async fn ttl_rewrite_preserves_names_compressed_against_old_ttl() {
    let config = ".:53 {\n rewrite ttl . 16777216\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\0\0\x01\0\x01";
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
            .serve(&mut cx, TtlPointerAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    for rr in message.answers() {
        assert_eq!(rr.name.to_string(), ".");
        assert_eq!(rr.ttl, 16777216);
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go.
#[tokio::test]
async fn coredns_reverter_restores_a_missing_question() {
    let config = ".:53 {\n rewrite ttl example. 30\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, NoQuestionAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(
        message.questions().next().unwrap().name.to_string(),
        "example."
    );
    assert_eq!(message.answers().next().unwrap().ttl, 30);
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go TestResponseReverterRestoresMissingQuestion.
#[tokio::test]
async fn coredns_reverter_restores_missing_question_and_answer_name() {
    let config = ".:53 {\n rewrite name suffix .example.org .example.net answer auto\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "service.example.org.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
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
            .serve(&mut cx, NoQuestionAnswer)
            .await,
        Outcome::Response
    );
    let response = Message::parse(cx.response).unwrap();
    let question = response.questions().next().unwrap();
    assert_eq!(
        (question.name.to_string().as_str(), question.qtype),
        ("service.example.org.", Type::A)
    );
    assert_eq!(
        response.answers().next().unwrap().name.to_string(),
        "service.example.org."
    );
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
async fn coredns_response_rules_restore_the_original_question_type() {
    let config = ".:53 {\n rewrite continue type A AAAA\n rewrite ttl example. 30\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
    assert_eq!(
        chain.rewrite.as_ref().unwrap().serve(&mut cx, Answer).await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    assert_eq!(message.questions().next().unwrap().qtype, Type::A);
    assert_eq!(message.answers().next().unwrap().ttl, 30);
}

#[tokio::test]
async fn coredns_non_regex_name_rewrite_modes() {
    for (rule, incoming, expected) in [
        (
            "rewrite name prefix foo bar",
            "foo.example.com.",
            "bar.example.com.",
        ),
        (
            "rewrite name prefix foo. bar.",
            "foo.example.com.",
            "bar.example.com.",
        ),
        (
            "rewrite name suffix com org",
            "foo.example.com.",
            "foo.example.org.",
        ),
        (
            "rewrite name suffix .com .org",
            "foo.example.com.",
            "foo.example.org.",
        ),
        (
            "rewrite name suffix .ingress.coredns.rocks nginx.coredns.rocks",
            "coredns.ingress.coredns.rocks.",
            "corednsnginx.coredns.rocks.",
        ),
        (
            "rewrite name prefix foo bar",
            "coredns.foo.",
            "coredns.foo.",
        ),
        (
            "rewrite name prefix foo bar.",
            "coredns.foo.",
            "coredns.foo.",
        ),
        (
            "rewrite name suffix com org",
            "com.coredns.",
            "com.coredns.",
        ),
        (
            "rewrite name suffix com org.",
            "com.coredns.",
            "com.coredns.",
        ),
        (
            "rewrite name substring service svc",
            "com.coredns.",
            "com.coredns.",
        ),
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

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_test.go answer tables.
#[tokio::test]
async fn coredns_name_answer_rows() {
    for (rule, incoming, rewritten, answer) in [
        (
            "prefix foo bar",
            "coredns.foo.",
            "coredns.foo.",
            "coredns.foo.",
        ),
        (
            "prefix foo bar.",
            "coredns.foo.",
            "coredns.foo.",
            "coredns.foo.",
        ),
        (
            "suffix com org",
            "com.coredns.",
            "com.coredns.",
            "com.coredns.",
        ),
        (
            "suffix com org.",
            "com.coredns.",
            "com.coredns.",
            "com.coredns.",
        ),
        (
            "substring service svc",
            "com.coredns.",
            "com.coredns.",
            "com.coredns.",
        ),
        ("prefix prefix to", "prefix.nl.", "to.nl.", "to.nl."),
        ("suffix .suffix. .nl.", "to.suffix.", "to.nl.", "to.nl."),
        (
            "substring from.substring to",
            "from.substring.nl.",
            "to.nl.",
            "to.nl.",
        ),
        (
            r"regex (f.*m)\.regex\.(nl) to.{2}",
            "from.regex.nl.",
            "to.nl.",
            "to.nl.",
        ),
        (
            "prefix foo bar",
            "foo.example.com.",
            "bar.example.com.",
            "bar.example.com.",
        ),
        (
            "prefix foo. bar.",
            "foo.example.com.",
            "bar.example.com.",
            "bar.example.com.",
        ),
        (
            "suffix com org",
            "foo.example.com.",
            "foo.example.org.",
            "foo.example.org.",
        ),
        (
            "suffix .com .org",
            "foo.example.com.",
            "foo.example.org.",
            "foo.example.org.",
        ),
        (
            "suffix .ingress.coredns.rocks nginx.coredns.rocks",
            "coredns.ingress.coredns.rocks.",
            "corednsnginx.coredns.rocks.",
            "corednsnginx.coredns.rocks.",
        ),
        (
            "prefix foo bar answer auto",
            "foo.example.com.",
            "bar.example.com.",
            "foo.example.com.",
        ),
        (
            "prefix foo. bar. answer auto",
            "foo.example.com.",
            "bar.example.com.",
            "foo.example.com.",
        ),
        (
            "suffix com org answer auto",
            "foo.example.com.",
            "foo.example.org.",
            "foo.example.com.",
        ),
        (
            "suffix .com .org answer auto",
            "foo.example.com.",
            "foo.example.org.",
            "foo.example.com.",
        ),
        (
            "suffix .ingress.coredns.rocks nginx.coredns.rocks answer auto",
            "coredns.ingress.coredns.rocks.",
            "corednsnginx.coredns.rocks.",
            "coredns.ingress.coredns.rocks.",
        ),
        (
            "exact coredns.rocks service.consul answer auto",
            "coredns.rocks.",
            "service.consul.",
            "coredns.rocks.",
        ),
        (
            "exact coredns.rocks. service.consul. answer auto",
            "coredns.rocks.",
            "service.consul.",
            "coredns.rocks.",
        ),
        (
            "exact coredns.rocks service.consul",
            "coredns.rocks.",
            "service.consul.",
            "coredns.rocks.",
        ),
        (
            "exact coredns.rocks. service.consul.",
            "coredns.rocks.",
            "service.consul.",
            "coredns.rocks.",
        ),
        (
            "exact coredns.org. service.consul.",
            "coredns.rocks.",
            "coredns.rocks.",
            "coredns.rocks.",
        ),
        (
            "regex (.*).coredns.rocks {1}.coredns.maps answer auto",
            "foo.coredns.rocks.",
            "foo.coredns.maps.",
            "foo.coredns.rocks.",
        ),
        (
            "regex (.*).coredns.rocks {1}.coredns.maps answer name (.*).coredns.maps {1}.coredns.works",
            "foo.coredns.rocks.",
            "foo.coredns.maps.",
            "foo.coredns.works.",
        ),
        (
            "regex (.*).coredns.rocks {1}.coredns.maps",
            "foo.coredns.rocks.",
            "foo.coredns.maps.",
            "foo.coredns.maps.",
        ),
    ] {
        let config = format!(".:53 {{\n rewrite name {rule}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = incoming.parse().unwrap();
        let root: Name = ".".parse().unwrap();
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
                .serve(&mut cx, ExpectNameAnswer(rewritten))
                .await,
            Outcome::Response,
            "{rule}"
        );
        let response = Message::parse(cx.response).unwrap();
        assert_eq!(
            response.answers().next().unwrap().name.to_string(),
            answer,
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
        (Some(""), "web.example."),
        (
            Some("{1}.{test/Other}"),
            "web.{1}.{test/other}.svc.cluster.local.",
        ),
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

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_metadata_test.go TestRegexNameMetadataValues.
#[tokio::test]
async fn coredns_metadata_replacement_rows() {
    for (replacement, value, expected) in [
        (
            "{1}.{test/Team}.EXAMPLE.",
            Some("Team-A"),
            "web.team-a.example.",
        ),
        ("{0}{test/Team}.", Some("suffix"), "web.example.suffix."),
        (
            "{1}.{test/Team}.",
            Some("{1}.{test/Other}"),
            "web.{1}.{test/other}.",
        ),
        ("{1}.{test/Team}.", None, "web.example."),
        ("{1}.{test/Team}.", Some(""), "web.example."),
        (
            "{1}.{test/Team}.{test/Missing}.",
            Some("present"),
            "web.example.",
        ),
    ] {
        let config = format!(
            r".:53 {{
 rewrite name regex ^([^.]+)\.example\.$ {replacement} metadata
}}"
        );
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "web.example.".parse().unwrap();
        let root: Name = ".".parse().unwrap();
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
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 2];
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
            cx.metadata.insert("test/Team", value);
        }
        cx.metadata.insert("test/Other", "must-not-expand");
        assert_eq!(
            chain
                .rewrite
                .as_ref()
                .unwrap()
                .serve(&mut cx, InspectName(expected))
                .await,
            Outcome::Drop,
            "{replacement}"
        );
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_metadata_test.go TestRegexNameMetadataSkippedAndInvalid.
#[tokio::test]
async fn coredns_metadata_skip_and_invalid_rows() {
    let config = r".:53 {
 rewrite name regex ^([^.]+)\.example\.$ {1}.{test/value}. metadata answer auto
 rewrite name exact web.example. fallback.example.
}";
    for (incoming, value, expected) in [
        ("web.example.", String::new(), Some("fallback.example.")),
        ("other.test.", "unused".to_owned(), Some("other.test.")),
        ("web.example.", "invalid..name".to_owned(), None),
        ("web.example.", "a".repeat(64), None),
    ] {
        let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = incoming.parse().unwrap();
        let root: Name = ".".parse().unwrap();
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
        cx.metadata.insert("test/value", &value);
        let outcome = chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, InspectName(expected.unwrap_or("must-not-run")))
            .await;
        if expected.is_some() {
            assert_eq!(outcome, Outcome::Drop);
        } else {
            assert!(matches!(outcome, Outcome::Error(_)));
            assert_eq!(
                cx.query.questions().next().unwrap().name.to_string(),
                incoming
            );
        }
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_metadata_test.go TestRegexNameMetadataLegacyLiteral.
#[tokio::test]
async fn coredns_legacy_regex_keeps_metadata_label_literal() {
    let config = r".:53 {
 rewrite name regex ^(.*)\.$ {1}.{test/Value}.
}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
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
    cx.metadata.insert("test/value", "changed");
    assert_eq!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, InspectName("example.{test/value}."))
            .await,
        Outcome::Drop
    );
}

struct ConcurrentMetadataAnswer(String);
impl Next for ConcurrentMetadataAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(
            cx.query.questions().next().unwrap().name.to_string(),
            self.0
        );
        tokio::task::yield_now().await;
        let q = cx.query.questions().next().unwrap();
        let target: Name = format!("child.{}", self.0).parse().unwrap();
        let target = NameRef::parse(target.as_wire(), 0).unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        builder
            .record_with(Section::Answer, q.name, Type::CNAME, Class::IN, 30, |w| {
                w.write_name(target)
            })
            .unwrap();
        builder
            .record(
                Section::Answer,
                target,
                Type::A,
                Class::IN,
                30,
                &[192, 0, 2, 1],
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_metadata_test.go TestRegexNameMetadataConcurrentResponses.
#[tokio::test]
async fn coredns_metadata_rewrites_are_per_query_when_concurrent() {
    let config = r".:53 {
 rewrite name regex ^([^.]+)\.example\.$ {1}.{test/namespace}.svc.cluster.local. metadata answer auto
}";
    let mut chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let plugin = std::sync::Arc::new(chain.rewrite.take().unwrap());
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..32 {
        let plugin = std::sync::Arc::clone(&plugin);
        tasks.spawn(async move {
            let namespace = format!("team-{index}");
            let rewritten = format!("web.{namespace}.svc.cluster.local.");
            let name: Name = "web.example.".parse().unwrap();
            let root: Name = ".".parse().unwrap();
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
            cx.metadata.insert("test/namespace", &namespace);
            assert_eq!(
                plugin
                    .serve(&mut cx, ConcurrentMetadataAnswer(rewritten))
                    .await,
                Outcome::Response
            );
            let response = Message::parse(cx.response).unwrap();
            assert_eq!(
                response.questions().next().unwrap().name.to_string(),
                "web.example."
            );
            let mut answers = response.answers();
            let first = answers.next().unwrap();
            assert_eq!(first.name.to_string(), "web.example.");
            let pharos_proto::Rdata::Cname(target) = first.data().unwrap() else {
                panic!("expected CNAME")
            };
            assert_eq!(target.to_string(), "child.web.example.");
            assert_eq!(
                answers.next().unwrap().name.to_string(),
                "child.web.example."
            );
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
}

#[tokio::test]
async fn coredns_invalid_metadata_name_restores_original_question() {
    let config = r".:53 {
 rewrite continue name a.example. b.example.
 rewrite name regex ^([^.]+)\.example\.$ {1}.{test/value}. metadata
}";
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
    cx.metadata.insert("test/value", "invalid..name");
    assert!(matches!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, InspectName("must-not-run"))
            .await,
        Outcome::Error(_)
    ));
    assert_eq!(
        cx.query.questions().next().unwrap().name.to_string(),
        "a.example."
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_test.go TestRewriteIllegalName.
#[tokio::test]
async fn coredns_illegal_exact_name_is_not_forwarded() {
    let config = ".:53 {\n rewrite name example.org. example..org.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "example.org.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
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
    assert!(matches!(
        chain
            .rewrite
            .as_ref()
            .unwrap()
            .serve(&mut cx, InspectName("must-not-run"))
            .await,
        Outcome::Error(_)
    ));
    assert_eq!(
        cx.query.questions().next().unwrap().name.to_string(),
        "example.org."
    );
}

struct AliasedAnswer;
impl Next for AliasedAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
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

struct ValueAnswer<'a> {
    data: pharos_proto::Rdata<'a>,
    extra_owner: NameRef<'a>,
}
impl Next for ValueAnswer<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        assert_eq!(q.name.to_string(), "my.cluster.local.");
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record_with(
            Section::Answer,
            q.name,
            self.data.rtype(),
            Class::IN,
            60,
            |w| self.data.write(w),
        )
        .unwrap();
        b.record(
            Section::Additional,
            self.extra_owner,
            Type::A,
            Class::IN,
            60,
            &[192, 0, 2, 1],
        )
        .unwrap();
        let raw = Message::parse(b.finish()).unwrap();
        assert_eq!(
            raw.questions().next().unwrap().name.to_string(),
            "my.cluster.local."
        );
        assert_eq!(raw.answers().next().unwrap().data().unwrap(), self.data);
        assert_eq!(raw.additionals().next().unwrap().name, self.extra_owner);
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go valueTests.
#[tokio::test]
async fn coredns_answer_value_rewrites_name_bearing_record_types() {
    use pharos_proto::Rdata;
    let target: Name = "target.cluster.local.".parse().unwrap();
    let hostmaster: Name = "admin.cluster.local.".parse().unwrap();
    let target_ref = NameRef::parse(target.as_wire(), 0).unwrap();
    let hostmaster_ref = NameRef::parse(hostmaster.as_wire(), 0).unwrap();
    for data in [
        Rdata::Cname(target_ref),
        Rdata::Dname(target_ref),
        Rdata::Ns(target_ref),
        Rdata::Ptr(target_ref),
        Rdata::Mx {
            preference: 1,
            exchange: target_ref,
        },
        Rdata::Srv {
            priority: 0,
            weight: 100,
            port: 100,
            target: target_ref,
        },
        Rdata::Soa {
            mname: target_ref,
            rname: hostmaster_ref,
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        },
        Rdata::Naptr {
            order: 100,
            preference: 10,
            flags: b"S",
            services: b"SIP+D2U",
            regexp: b"",
            replacement: target_ref,
        },
    ] {
        for rules in [
            r"rewrite name regex (.*)\.domain\.uk {1}.cluster.local answer name (.*)\.cluster\.local {1}.domain.uk answer value (.*)\.cluster\.local {1}.domain.uk",
            r"rewrite continue name regex (.*)\.domain\.uk {1}.cluster.local answer name (.*)\.cluster\.local {1}.domain.uk answer value (.*)\.cluster\.local {1}.domain.uk",
            r"rewrite name suffix .domain.uk .cluster.local answer auto answer value (.*)\.cluster\.local {1}.domain.uk",
            "rewrite continue name suffix .domain.uk .domain.us answer auto\n rewrite name suffix .domain.us .cluster.local answer auto",
        ] {
            let config = format!(".:53 {{\n {rules}\n}}");
            let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
                .unwrap()
                .remove(0)
                .config;
            let name: Name = "my.domain.uk.".parse().unwrap();
            let root: Name = ".".parse().unwrap();
            let mut wire = Vec::with_capacity(512);
            let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
            b.question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                data.rtype(),
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
                    .serve(
                        &mut cx,
                        ValueAnswer {
                            data,
                            extra_owner: target_ref
                        }
                    )
                    .await,
                Outcome::Response
            );
            let response = Message::parse(cx.response).unwrap();
            let answer = response.answers().next().unwrap().data().unwrap();
            let target = match answer {
                Rdata::Cname(value)
                | Rdata::Dname(value)
                | Rdata::Ns(value)
                | Rdata::Ptr(value) => value,
                Rdata::Mx { exchange, .. } => exchange,
                Rdata::Srv { target, .. } => target,
                Rdata::Soa { mname, rname, .. } => {
                    assert_eq!(rname.to_string(), "admin.cluster.local.");
                    mname
                }
                Rdata::Naptr { replacement, .. } => replacement,
                _ => panic!("unexpected record"),
            };
            assert_eq!(target.to_string(), "target.domain.uk.");
            assert_eq!(
                response.additionals().next().unwrap().name.to_string(),
                "target.domain.uk."
            );
        }
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go valueTests.
#[tokio::test]
async fn coredns_response_value_fixture_rows() {
    use pharos_proto::Rdata;
    let srv: Name = "srv1.my.cluster.local.".parse().unwrap();
    let cname: Name = "cname.cluster.local.".parse().unwrap();
    let dname: Name = "dname.cluster.local.".parse().unwrap();
    let mx: Name = "mx1.cluster.local.".parse().unwrap();
    let ns: Name = "ns1.cluster.local.".parse().unwrap();
    let admin: Name = "admin.cluster.local.".parse().unwrap();
    let naptr: Name = "_sip._udp.cluster.local.".parse().unwrap();
    fn borrow(name: &Name) -> NameRef<'_> {
        NameRef::parse(name.as_wire(), 0).unwrap()
    }
    let cases = [
        (
            Type::SRV,
            Rdata::Srv {
                priority: 0,
                weight: 100,
                port: 100,
                target: borrow(&srv),
            },
            borrow(&srv),
            "srv1.my.domain.uk.",
            "srv1.my.domain.uk.",
        ),
        (
            Type::ANY,
            Rdata::Cname(borrow(&cname)),
            borrow(&cname),
            "cname.domain.uk.",
            "cname.domain.uk.",
        ),
        (
            Type::ANY,
            Rdata::Dname(borrow(&dname)),
            borrow(&dname),
            "dname.domain.uk.",
            "dname.domain.uk.",
        ),
        (
            Type::MX,
            Rdata::Mx {
                preference: 1,
                exchange: borrow(&mx),
            },
            borrow(&mx),
            "mx1.domain.uk.",
            "mx1.domain.uk.",
        ),
        (
            Type::ANY,
            Rdata::Ns(borrow(&ns)),
            borrow(&ns),
            "ns1.domain.uk.",
            "ns1.domain.uk.",
        ),
        (
            Type::SOA,
            Rdata::Soa {
                mname: borrow(&ns),
                rname: borrow(&admin),
                serial: 1502165581,
                refresh: 14400,
                retry: 3600,
                expire: 604800,
                minimum: 14400,
            },
            borrow(&ns),
            "ns1.domain.uk.",
            "ns1.domain.uk.",
        ),
        (
            Type::NAPTR,
            Rdata::Naptr {
                order: 100,
                preference: 10,
                flags: b"S",
                services: b"SIP+D2U",
                regexp: b"!^.*$!sip:customer-service@example.com!",
                replacement: borrow(&naptr),
            },
            borrow(&ns),
            "_sip._udp.domain.uk.",
            "ns1.domain.uk.",
        ),
    ];
    for rules in [
        r"rewrite name regex (.*)\.domain\.uk {1}.cluster.local answer name (.*)\.cluster\.local {1}.domain.uk answer value (.*)\.cluster\.local {1}.domain.uk",
        r"rewrite continue name regex (.*)\.domain\.uk {1}.cluster.local answer name (.*)\.cluster\.local {1}.domain.uk answer value (.*)\.cluster\.local {1}.domain.uk",
        r"rewrite name suffix .domain.uk .cluster.local answer auto answer value (.*)\.cluster\.local {1}.domain.uk",
        "rewrite continue name suffix .domain.uk .domain.us answer auto\n rewrite name suffix .domain.us .cluster.local answer auto",
    ] {
        let config = format!(".:53 {{\n {rules}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        for (qtype, data, extra_owner, expected_value, expected_extra) in cases {
            let name: Name = "my.domain.uk.".parse().unwrap();
            let root: Name = ".".parse().unwrap();
            let mut wire = Vec::with_capacity(512);
            let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
            builder
                .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
                .unwrap();
            let _ = builder.finish();
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
                    .serve(&mut cx, ValueAnswer { data, extra_owner })
                    .await,
                Outcome::Response,
                "{rules} {qtype}"
            );
            let message = Message::parse(cx.response).unwrap();
            let question = message.questions().next().unwrap();
            assert_eq!(
                (question.name.to_string().as_str(), question.qtype),
                ("my.domain.uk.", qtype)
            );
            let answer = message.answers().next().unwrap();
            assert_eq!(answer.rtype, data.rtype());
            let value = match answer.data().unwrap() {
                Rdata::Cname(value) | Rdata::Dname(value) | Rdata::Ns(value) => value,
                Rdata::Mx { exchange, .. } => exchange,
                Rdata::Srv { target, .. } => target,
                Rdata::Soa { mname, .. } => mname,
                Rdata::Naptr { replacement, .. } => replacement,
                _ => panic!("unexpected record"),
            };
            assert_eq!(value.to_string(), expected_value);
            assert_eq!(
                message.additionals().next().unwrap().name.to_string(),
                expected_extra
            );
        }
    }
}

struct DnameAnswer;
impl Next for DnameAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let target: Name = "other.internal.example.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record_with(Section::Answer, q.name, Type::DNAME, Class::IN, 60, |w| {
            w.write_uncompressed_name(NameRef::parse(target.as_wire(), 0).unwrap())
        })
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go.
#[tokio::test]
async fn coredns_auto_rewrites_dname_values() {
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
            .serve(&mut cx, DnameAnswer)
            .await,
        Outcome::Response
    );
    let message = Message::parse(cx.response).unwrap();
    let rr = message.answers().next().unwrap();
    assert_eq!(
        NameRef::parse(rr.rdata, 0).unwrap().to_string(),
        "other.example.com."
    );
}

struct SuffixAnswer;
impl Next for SuffixAnswer {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
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
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
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
async fn invalid_answer_replacement_does_not_silently_preserve_old_name() {
    let config = r".:53 {
 rewrite name exact example. internal. answer name (.*)internal\. {1}bad..name.
}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
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
    assert!(matches!(
        chain.rewrite.as_ref().unwrap().serve(&mut cx, Answer).await,
        Outcome::Error(_)
    ));
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

#[tokio::test]
async fn coredns_auto_rewrite_keeps_question_case_but_lowercases_answer() {
    let config = ".:53 {\n rewrite name foo.example. internal.example.\n}";
    let chain = configure::<Chain>(&parse("Corefile", config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "FoO.Example.".parse().unwrap();
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
    let response = Message::parse(cx.response).unwrap();
    assert_eq!(
        response.questions().next().unwrap().name.to_string(),
        "FoO.Example."
    );
    assert_eq!(
        response.answers().next().unwrap().name.to_string(),
        "foo.example."
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rcode_test.go.
#[tokio::test]
async fn coredns_rcode_rewrites_unanswered_response() {
    for mode in ["stop", "continue"] {
        for code in [
            Rcode::FORMERR,
            Rcode::SERVFAIL,
            Rcode::REFUSED,
            Rcode::NOTIMP,
        ] {
            let text = format!(
                ".:53 {{\n rewrite {mode} rcode example. {} NOERROR\n}}",
                code.0
            );
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
            assert_eq!(outcome, Outcome::Response, "{mode} {code}");
            assert_eq!(Message::parse(cx.response).unwrap().rcode(), Rcode::NOERROR);
        }
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

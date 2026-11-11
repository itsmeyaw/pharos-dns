#![forbid(unsafe_code)]
#![cfg(feature = "plugin-autopath")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Section, Type};
use pharos_server::{
    Action, Context, Handler, ListenerKey, Metadata, Next, Outcome, Plugin, Protocol, Router,
    Server, Transport,
};

struct Scripted(pharos_plugins::autopath::AutoPath);
impl pharos_server::Chain for Scripted {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, Backend).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}
struct Backend;
impl Next for Backend {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let name = q.name.to_string();
        if name == "c.bar.com." {
            return Outcome::Drop;
        }
        let success = name == "b.com." || name == "a.example.com.";
        let mut b = MessageBuilder::new(
            cx.response,
            512,
            cx.query.id(),
            if success { 0x8180 } else { 0x8183 },
        )
        .unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        if success {
            b.record(
                Section::Answer,
                q.name,
                Type::A,
                Class::IN,
                3600,
                &[127, 0, 0, 53],
            )
            .unwrap();
        }
        let _ = b.finish();
        Outcome::Response
    }
}

struct Alias;
impl Next for Alias {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let owner: Name = "other.example.org.".parse().unwrap();
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record(
            Section::Answer,
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
            33,
            &[1, 2, 3, 4],
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

struct DropFirst(pharos_plugins::autopath::AutoPath);
impl pharos_server::Chain for DropFirst {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, DropFirstBackend).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}
struct DropFirstBackend;
impl Next for DropFirstBackend {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        if q.name.to_string() != "x.example.com." {
            return Outcome::Drop;
        }
        let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8180).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record(
            Section::Answer,
            q.name,
            Type::A,
            Class::IN,
            60,
            &[1, 2, 3, 4],
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

struct NoAnswer(
    pharos_plugins::autopath::AutoPath,
    bool,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
);
impl pharos_server::Chain for NoAnswer {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.serve(cx, NoAnswerBackend(self.1, &self.2)).await
    }
    fn is_empty(&self) -> bool {
        false
    }
}
struct NoAnswerBackend<'a>(bool, &'a std::sync::atomic::AtomicUsize);
impl Next for NoAnswerBackend<'_> {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        self.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.0 {
            Outcome::Drop
        } else {
            Outcome::Unanswered(Rcode::SERVFAIL)
        }
    }
}

// Derived from CoreDNS TestAutoPathNoAnswer and TestAutoPathNilMsgFromNext.
#[tokio::test]
async fn coredns_unwritten_replies_keep_the_first_outcome() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/autopath-search.conf"
    );
    let config = format!(".:53 {{\n autopath {path}\n}}");
    for drop in [true, false] {
        let mut chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let key = ListenerKey {
            transport: Transport::Dns,
            address: "127.0.0.1:53".parse().unwrap(),
        };
        let mut router = Router::default();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        router.add(
            key,
            ".".parse().unwrap(),
            Some(NoAnswer(
                chain.autopath.take().unwrap(),
                drop,
                calls.clone(),
            )),
            vec![],
        );
        let server = Server::new(router, key);
        let name: Name = "c.example.org.".parse().unwrap();
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
        let action = server
            .handle(
                &wire,
                "127.0.0.1:1".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await;
        if drop {
            assert_eq!(action, Action::Drop);
        } else {
            assert_eq!(action, Action::Respond);
            assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 4);
    }
}

// Derived from CoreDNS TestInSearchPath; equal first suffix fails TrimZone.
#[tokio::test]
async fn coredns_first_search_suffix_membership() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/autopath-kubernetes-search.conf"
    );
    let config = format!(".:53 {{\n autopath {path}\n}}");
    let blocks = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap();
    let plugin = blocks[0].config.autopath.as_ref().unwrap();
    let root: Name = ".".parse().unwrap();
    for (name, expected) in [
        ("google.com.", Outcome::Response),
        (
            "default.svc.cluster.local.",
            Outcome::Error(pharos_server::Error::InvalidQuery),
        ),
        (
            "a.default.svc.cluster.local.",
            Outcome::Error(pharos_server::Error::SelfLookupUnavailable),
        ),
        ("a.b.svc.cluster.local.", Outcome::Response),
    ] {
        let name: Name = name.parse().unwrap();
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
            client: "127.0.0.1:1".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(plugin.serve(&mut cx, Backend).await, expected);
    }
}

#[tokio::test]
async fn coredns_search_continues_after_unwritten_first_reply() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/autopath-search.conf"
    );
    let config = format!(".:53 {{\n autopath {path}\n}}");
    let mut chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        key,
        ".".parse().unwrap(),
        Some(DropFirst(chain.autopath.take().unwrap())),
        vec![],
    );
    let server = Server::new(router, key);
    let name: Name = "x.example.org.".parse().unwrap();
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
            .handle(
                &wire,
                "127.0.0.1:1".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().answers().count(), 2);
}

#[tokio::test]
async fn coredns_first_success_with_different_owner_adds_cname() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/autopath-search.conf"
    );
    let config = format!(".:53 {{\n autopath {path}\n}}");
    let blocks = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap();
    let plugin = blocks[0].config.autopath.as_ref().unwrap();
    let root: Name = ".".parse().unwrap();
    let name: Name = "a.example.org.".parse().unwrap();
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
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(plugin.serve(&mut cx, Alias).await, Outcome::Response);
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.answers().count(), 2);
    let first = response.answers().next().unwrap();
    assert_eq!(first.ttl, 33);
    let Rdata::Cname(target) = first.data().unwrap() else {
        panic!("expected CNAME")
    };
    assert_eq!(target.to_string(), "other.example.org.");
}

// Derived from CoreDNS v1.15.0 plugin/autopath/autopath_test.go.
#[tokio::test]
async fn coredns_autopath_search_and_passthrough() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/autopath-search.conf"
    );
    let config = format!(".:53 {{\n autopath {path}\n}}");
    let mut chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        key,
        ".".parse().unwrap(),
        Some(Scripted(chain.autopath.take().unwrap())),
        vec![],
    );
    let server = Server::new(router, key);
    for (query, expected, answer_count) in [
        ("b.example.org.", Rcode::NOERROR, 2),
        ("a.example.com.", Rcode::NOERROR, 1),
        ("x.example.org.", Rcode::NXDOMAIN, 0),
    ] {
        let name: Name = query.parse().unwrap();
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
                    "127.0.0.1:1234".parse().unwrap(),
                    Protocol::Udp,
                    &mut response
                )
                .await,
            Action::Respond
        );
        let m = Message::parse(&response).unwrap();
        assert_eq!(m.rcode(), expected, "{query}");
        assert_eq!(m.questions().next().unwrap().name.to_string(), query);
        assert_eq!(m.answers().count(), answer_count, "{query}");
        if answer_count == 2 {
            let rr = m.answers().next().unwrap();
            assert_eq!(rr.name.to_string(), query);
            assert_eq!(rr.ttl, 3600);
            let Rdata::Cname(target) = rr.data().unwrap() else {
                panic!("expected CNAME")
            };
            assert_eq!(target.to_string(), "b.com.");
        }
    }
}

#[cfg(feature = "plugin-whoami")]
#[tokio::test]
async fn autopath_counts_non_nxdomain_search_responses() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/autopath-search.conf"
    );
    let config = format!(".:53 {{\n autopath {path}\n whoami\n}}");
    let (mut listeners, _) = pharos_plugins::servers(
        configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap(),
    )
    .unwrap();
    let (_, server) = listeners.drain().next().unwrap();
    for query in ["inside.example.org.", "outside.example.com."] {
        let name: Name = query.parse().unwrap();
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
    let mut output = String::new();
    server.metrics().encode(&mut output);
    assert!(
        output.contains("pharos_autopath_success_total{server=\"dns://:53\"} 1"),
        "{output}"
    );
}

#![forbid(unsafe_code)]
#![cfg(feature = "plugin-autopath")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Section, Type};
use pharos_server::{
    Action, Context, Handler, ListenerKey, Next, Outcome, Plugin, Protocol, Router, Server,
    Transport,
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

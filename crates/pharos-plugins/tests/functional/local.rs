#![forbid(unsafe_code)]
#![cfg(feature = "plugin-local")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

fn configured(text: &str) -> Result<Chain, String> {
    let blocks = parse("Corefile", &format!(".:53 {{\n{text}\n}}")).map_err(|e| e.to_string())?;
    Ok(configure::<Chain>(&blocks, directives())
        .map_err(|e| e.to_string())?
        .remove(0)
        .config)
}

struct NextDrop;
impl Next for NextDrop {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Drop
    }
}

async fn query(chain: &Chain, name: &str, qtype: Type) -> (Outcome, Vec<u8>) {
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 123, 0x0110).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
        .unwrap();
    let _ = builder.finish();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let outcome = chain.local.as_ref().unwrap().serve(&mut cx, NextDrop).await;
    (outcome, response)
}

#[test]
fn coredns_setup_cases() {
    for text in [
        "local",
        "local {\n}",
        "local {\n localhost_prefix on\n}",
        "local {\n localhost_prefix off\n}",
        "local {\n localhost_prefix off\n localhost_prefix on\n}",
    ] {
        assert!(configured(text).is_ok(), "{text}");
    }
    for text in [
        "local example.org",
        "local {\n foo\n}",
        "local {\n localhost_prefix maybe\n}",
        "local {\n localhost_prefix\n}",
        "local {\n localhost_prefix on off\n}",
    ] {
        assert!(configured(text).is_err(), "{text}");
    }
}

#[tokio::test]
async fn coredns_local_cases() {
    let chain = configured("local").unwrap();
    for (name, qtype, rcode, answer, authority) in [
        (
            "localhost.",
            Type::A,
            Rcode::NOERROR,
            Some(("localhost.", Type::A)),
            None,
        ),
        (
            "localHOst.",
            Type::A,
            Rcode::NOERROR,
            Some(("localHOst.", Type::A)),
            None,
        ),
        (
            "localhost.",
            Type::AAAA,
            Rcode::NOERROR,
            Some(("localhost.", Type::AAAA)),
            None,
        ),
        (
            "localhost.",
            Type::NS,
            Rcode::NOERROR,
            Some(("localhost.", Type::NS)),
            None,
        ),
        (
            "localhost.",
            Type::SOA,
            Rcode::NOERROR,
            Some(("localhost.", Type::SOA)),
            None,
        ),
        (
            "127.in-addr.arpa.",
            Type::A,
            Rcode::NOERROR,
            None,
            Some("127.in-addr.arpa."),
        ),
        (
            "localhost.",
            Type::MX,
            Rcode::NOERROR,
            None,
            Some("localhost."),
        ),
        (
            "a.localhost.",
            Type::A,
            Rcode::NOERROR,
            Some(("a.localhost.", Type::A)),
            None,
        ),
        (
            "a.localhost.",
            Type::AAAA,
            Rcode::NOERROR,
            Some(("a.localhost.", Type::AAAA)),
            None,
        ),
        (
            "a.localhost.",
            Type::MX,
            Rcode::NOERROR,
            None,
            Some("a.localhost."),
        ),
        (
            "1.0.0.127.in-addr.arpa.",
            Type::PTR,
            Rcode::NOERROR,
            Some(("1.0.0.127.in-addr.arpa.", Type::PTR)),
            None,
        ),
        (
            "1.0.0.127.in-addr.arpa.",
            Type::MX,
            Rcode::NOERROR,
            None,
            Some("127.in-addr.arpa."),
        ),
        (
            "2.0.0.127.in-addr.arpa.",
            Type::PTR,
            Rcode::NXDOMAIN,
            None,
            Some("127.in-addr.arpa."),
        ),
        (
            "x.0.in-addr.arpa.",
            Type::A,
            Rcode::NXDOMAIN,
            None,
            Some("0.in-addr.arpa."),
        ),
        (
            "x.255.in-addr.arpa.",
            Type::AAAA,
            Rcode::NXDOMAIN,
            None,
            Some("255.in-addr.arpa."),
        ),
    ] {
        let (outcome, wire) = query(&chain, name, qtype).await;
        assert_eq!(outcome, Outcome::Response, "{name}");
        let msg = Message::parse(&wire).unwrap();
        assert_eq!(
            (msg.id(), msg.flags() & 0xfff0, msg.rcode()),
            (123, 0x8110, rcode),
            "{name}"
        );
        let rr = msg.answers().next();
        assert_eq!(
            rr.map(|r| (r.name.to_string(), r.rtype)),
            answer.map(|(n, t)| (n.to_owned(), t)),
            "{name}"
        );
        let rr = msg.authorities().next();
        assert_eq!(
            rr.map(|r| (r.name.to_string(), r.rtype)),
            authority.map(|n| (n.to_owned(), Type::SOA)),
            "{name}"
        );
        for rr in msg.answers().chain(msg.authorities()) {
            assert_eq!((rr.class, rr.ttl), (Class::IN, 604800));
        }
    }
}

#[tokio::test]
async fn coredns_localhost_prefix_and_next() {
    let on = configured("local").unwrap();
    let off = configured("local {\n localhost_prefix off\n}").unwrap();
    for name in ["localhost.example.net.", "LOCALHOST.Example.net."] {
        assert_eq!(query(&on, name, Type::A).await.0, Outcome::Response);
        assert_eq!(query(&off, name, Type::A).await.0, Outcome::Drop);
    }
    for name in ["a.localhost.", "a.LOCALHOST."] {
        assert_eq!(query(&off, name, Type::AAAA).await.0, Outcome::Response);
    }
    for name in [
        "example.net.",
        "notlocalhost.",
        "notlocalhost.example.net.",
        "1.ip6.arpa.",
    ] {
        assert_eq!(query(&on, name, Type::A).await.0, Outcome::Drop);
    }
}

#[tokio::test]
async fn counter_is_shared_by_server_blocks_and_excludes_apex_and_reverse() {
    use pharos_plugins::servers_with_registry;
    use pharos_server::{Action, Handler, metrics::Registry};

    let source = ".:53 {\n local\n}\nexample.net:53 {\n local\n}";
    let blocks = parse("Corefile", source).unwrap();
    let registry = Registry::new("test", "test", "test");
    let (servers, _) = servers_with_registry(
        configure::<Chain>(&blocks, directives()).unwrap(),
        registry.clone(),
    )
    .unwrap();
    let server = servers.values().next().unwrap();
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(text.contains("pharos_local_localhost_requests_total 0\n"));
    for name in [
        "localhost.",
        "1.0.0.127.in-addr.arpa.",
        "a.localhost.",
        "localhost.example.net.",
    ] {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
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
    text.clear();
    registry.encode(&mut text);
    assert!(text.contains("# TYPE pharos_local_localhost_requests_total counter\n"));
    assert!(
        text.contains("pharos_local_localhost_requests_total 2\n"),
        "{text}"
    );
}

#![forbid(unsafe_code)]
#![cfg(feature = "plugin-chaos")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
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

async fn query(chain: &Chain, name: &str, qtype: Type, class: Class) -> (Outcome, Vec<u8>) {
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 123, 0x0110).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, class)
        .unwrap();
    let _ = builder.finish();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
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
    let outcome = chain.chaos.as_ref().unwrap().serve(&mut cx, NextDrop).await;
    (outcome, response)
}

#[test]
fn coredns_setup_cases() {
    for directive in [
        "chaos",
        "chaos v2",
        "chaos v3 \"Miek Gieben\"",
        "chaos {\n}",
        "chaos v2\nchaos v3",
    ] {
        assert!(configured(directive).is_ok(), "{directive}");
    }
    assert!(configured("chaos v2 {\n unknown\n}").is_err());
}

#[tokio::test]
async fn coredns_txt_and_next_cases() {
    let chain = configured("chaos CoreDNS-001 \"Miek Gieben\" Alice Alice").unwrap();
    for (name, expected) in [
        ("version.bind.", vec!["CoreDNS-001"]),
        ("VeRsIoN.SeRvEr.", vec!["CoreDNS-001"]),
        ("authors.bind.", vec!["Alice", "Miek Gieben"]),
    ] {
        let (outcome, wire) = query(&chain, name, Type::TXT, Class::CH).await;
        assert_eq!(outcome, Outcome::Response);
        let msg = Message::parse(&wire).unwrap();
        assert_eq!((msg.id(), msg.flags()), (123, 0x8110));
        let mut values = msg
            .answers()
            .map(|rr| {
                assert_eq!((rr.rtype, rr.class, rr.ttl), (Type::TXT, Class::CH, 0));
                assert_eq!(rr.name.to_string(), name);
                std::str::from_utf8(&rr.rdata[1..]).unwrap().to_owned()
            })
            .collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, expected);
    }
    for (name, qtype, class) in [
        ("authors.bind.", Type::SRV, Class::CH),
        ("version.bind.", Type::TXT, Class::IN),
        ("unknown.bind.", Type::TXT, Class::CH),
        ("sub.version.bind.", Type::TXT, Class::CH),
    ] {
        assert_eq!(query(&chain, name, qtype, class).await.0, Outcome::Drop);
    }
}

#[tokio::test]
async fn hostname_aliases_and_default_identity() {
    let chain = configured("chaos").unwrap();
    let expected = format!("Pharos-{}", env!("CARGO_PKG_VERSION"));
    let (_, wire) = query(&chain, "version.bind.", Type::TXT, Class::CH).await;
    assert_eq!(
        &Message::parse(&wire)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata[1..],
        expected.as_bytes()
    );
    let (_, wire) = query(&chain, "authors.bind.", Type::TXT, Class::CH).await;
    assert_eq!(
        &Message::parse(&wire)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata[1..],
        b"itsmeyaw"
    );
    let (_, a) = query(&chain, "hostname.bind.", Type::TXT, Class::CH).await;
    let (_, b) = query(&chain, "id.server.", Type::TXT, Class::CH).await;
    assert_eq!(
        Message::parse(&a).unwrap().answers().next().unwrap().rdata,
        Message::parse(&b).unwrap().answers().next().unwrap().rdata
    );
}

#[tokio::test]
async fn coredns_trims_and_deduplicates_setup_values() {
    let long = "x".repeat(260);
    let single = configured(&format!("chaos {long}")).unwrap();
    let (_, wire) = query(&single, "version.bind.", Type::TXT, Class::CH).await;
    let answer = Message::parse(&wire).unwrap().answers().next().unwrap();
    assert_eq!(answer.rdata.len(), 256);
    assert_eq!(answer.rdata[0], 255);

    let chain = configured(&format!("chaos v2 {long} {long} {}", "y".repeat(260))).unwrap();
    let (_, wire) = query(&chain, "authors.bind.", Type::TXT, Class::CH).await;
    let message = Message::parse(&wire).unwrap();
    assert_eq!(message.answer_count(), 1);
    assert!(message.tc());

    let chain = configured(&format!("chaos {long} author")).unwrap();
    assert!(matches!(
        query(&chain, "version.bind.", Type::TXT, Class::CH).await.0,
        Outcome::Error(_)
    ));
}

#[cfg(feature = "plugin-whoami")]
#[tokio::test]
async fn chaos_enables_non_in_for_all_blocks_on_listener() {
    use pharos_plugins::servers;
    use pharos_server::{Action, Handler};
    let source = "version.bind:53 {\n chaos v1 author\n}\nother.example:53 {\n whoami\n}";
    let blocks = parse("Corefile", source).unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    for name in ["version.bind.", "other.example."] {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::TXT,
                Class::CH,
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
        assert_eq!(
            Message::parse(&response).unwrap().rcode(),
            pharos_proto::Rcode::NOERROR
        );
    }
}

#[tokio::test]
async fn authors_are_shuffled_without_losing_records() {
    let authors = (0..20).map(|i| format!("author{i:02}")).collect::<Vec<_>>();
    let chain = configured(&format!("chaos v1 {}", authors.join(" "))).unwrap();
    let (_, wire) = query(&chain, "authors.bind.", Type::TXT, Class::CH).await;
    let message = Message::parse(&wire).unwrap();
    let order = message
        .answers()
        .map(|rr| std::str::from_utf8(&rr.rdata[1..]).unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut sorted = order.clone();
    sorted.sort();
    assert_eq!(sorted, authors);
}

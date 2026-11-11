#![forbid(unsafe_code)]
#![cfg(feature = "plugin-hosts")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

#[tokio::test]
async fn inline_answers_nodata_and_fallthrough() {
    let text = ".:53 {\n hosts /nonexistent example.org {\n 192.0.2.1 one.example.org\n ::1 two.example.org\n ttl 60\n fallthrough\n }\n whoami\n}";
    let blocks = parse("Corefile", text).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let root: Name = ".".parse().unwrap();
    for (name, kind, answers, additional) in [
        ("ONE.example.org.", Type::A, 1, 0),
        ("one.example.org.", Type::AAAA, 0, 0),
        ("one.example.org.", Type::TXT, 0, 0),
        ("two.example.org.", Type::AAAA, 1, 0),
        ("1.2.0.192.in-addr.arpa.", Type::PTR, 1, 0),
        ("2.2.0.192.in-addr.arpa.", Type::PTR, 0, 2),
        ("absent.example.org.", Type::A, 0, 2),
        ("outside.test.", Type::A, 0, 2),
    ] {
        let name: Name = name.parse().unwrap();
        let name_ref = NameRef::parse(name.as_wire(), 0).unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
        builder.question(name_ref, kind, Class::IN).unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
        let mut context = Context {
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
            configured[0].config.serve(&mut context).await,
            Outcome::Response
        );
        let response = Message::parse(&response).unwrap();
        assert!(response.aa());
        assert_eq!(response.answer_count(), answers);
        assert_eq!(response.additional_count(), additional);
        if answers > 0 {
            assert_eq!(response.answers().next().unwrap().ttl, 60);
        }
    }
}

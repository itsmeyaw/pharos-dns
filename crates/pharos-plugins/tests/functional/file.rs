#![forbid(unsafe_code)]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

#[tokio::test]
async fn serves_zone_and_negative_answers() {
    let zonefile = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/file/example.zone");
    let corefile = format!("example.org:53 {{\n file {zonefile}\n}}");
    let blocks = parse("Corefile", &corefile).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let domain: Name = "example.org.".parse().unwrap();
    for (name, kind, rcode, answers, authorities) in [
        ("www.example.org.", Type::A, Rcode::NOERROR, 1, 1),
        ("www.example.org.", Type::AAAA, Rcode::NOERROR, 0, 1),
        ("missing.example.org.", Type::A, Rcode::NXDOMAIN, 0, 1),
    ] {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
        builder.question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN).unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
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
        assert_eq!(configured[0].config.serve(&mut cx).await, Outcome::Response);
        let response = Message::parse(&response).unwrap();
        assert!(response.aa());
        assert_eq!(response.rcode(), rcode);
        assert_eq!(response.answer_count(), answers);
        assert_eq!(response.authority_count(), authorities);
    }
}

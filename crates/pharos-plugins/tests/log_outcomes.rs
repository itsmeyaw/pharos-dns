#![cfg(feature = "plugin-log")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct Answer<'a>(Outcome, &'a [u8]);
impl Next for Answer<'_> {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        cx.response.extend_from_slice(self.1);
        self.0
    }
}

#[tokio::test]
async fn expired_dnssec_signature_is_an_error_class() {
    let blocks = parse("Corefile", ". {\n log {\n class denial\n }\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let log = configured[0].config.log.as_ref().unwrap();
    let root = NameRef::parse(&[0], 0).unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x8000).unwrap();
    builder.reserve(11).unwrap();
    let mut signature = [0; 19];
    signature[11] = 1;
    builder
        .record(Section::Answer, root, Type::RRSIG, Class::IN, 0, &signature)
        .unwrap();
    let opt = [0, 0, 41, 2, 0, 0, 0, 0x80, 0, 0, 0];
    builder.finish_with_opt(&opt).unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 4];
    let mut cx = Context {
        query: Message::parse(&[0; 12]).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    log.serve(&mut cx, Answer(Outcome::Response, &wire)).await;
    assert_eq!(cx.metadata.get("log/type"), Some("OTHERERROR"));
    assert_eq!(cx.metadata.get("log/class"), Some("error"));
}

#[tokio::test]
async fn matching_rule_classifies_next_outcome_without_changing_it() {
    let blocks = parse("Corefile", ". {\n log example.org {\n class success\n }\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let log = configured[0].config.log.as_ref().unwrap();
    let domain: Name = ".".parse().unwrap();
    let query = b"\x00\x01\x01\x00\x00\x01\0\0\0\0\0\0\x03www\x07example\x03org\0\0\x01\0\x01";
    for (outcome, wire, kind, class) in [
        (Outcome::Drop, &b""[..], "OTHERERROR", "error"),
        (
            Outcome::Unanswered(Rcode::SERVFAIL),
            &b""[..],
            "SERVERERROR",
            "error",
        ),
        (
            Outcome::Response,
            &b"\0\x01\x80\x03\0\0\0\0\0\0\0\0"[..],
            "NXDOMAIN",
            "denial",
        ),
        (
            Outcome::Response,
            &b"\0\x01\x80\0\0\0\0\0\0\0\0\0"[..],
            "NOERROR",
            "success",
        ),
    ] {
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 4];
        let mut cx = Context {
            query: Message::parse(query).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(log.serve(&mut cx, Answer(outcome, wire)).await, outcome);
        assert_eq!(cx.metadata.get("log/type"), Some(kind));
        assert_eq!(cx.metadata.get("log/class"), Some(class));
        assert_eq!(cx.response, wire);
    }
}

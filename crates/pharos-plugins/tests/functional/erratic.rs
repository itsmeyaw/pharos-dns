use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Context, Metadata, Outcome, Protocol, Readiness, Transport};

#[test]
fn coredns_setup_cases() {
    for (directive, valid) in [
        ("erratic", true),
        ("erratic {\n drop\n}", true),
        ("erratic {\n drop 2\n delay 3 1ms\n}", true),
        ("erratic {\n truncate 2\n delay 3 1ms\n}", true),
        ("erratic {\n drop 3\n delay\n}", true),
        ("erratic {\n drop 3\n truncate\n}", true),
        ("erratic {\n drop -1\n}", false),
        ("erratic {\n delay -1\n}", false),
        ("erratic {\n delay 1 2 4\n}", false),
        ("erratic {\n delay 15.a\n}", false),
        ("erratic {\n delay 3 bla\n}", false),
        ("erratic {\n truncate 15.a\n}", false),
        ("erratic {\n something-else\n}", false),
    ] {
        let blocks = parse("Corefile", &format!(".:53 {{\n {directive}\n}}")).unwrap();
        assert_eq!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            valid,
            "{directive}"
        );
    }
}

#[tokio::test]
async fn coredns_drop_answers_and_readiness() {
    let blocks = parse("Corefile", ".:53 {\n erratic\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let chain = &configured[0].config;
    let erratic = chain.erratic.as_ref().unwrap();
    assert!(!erratic.ready());
    for (kind, expected, ready) in [
        (Type::A, Outcome::Drop, false),
        (Type::A, Outcome::Response, false),
        (Type::AAAA, Outcome::Drop, true),
        (Type::HINFO, Outcome::Unanswered(Rcode::SERVFAIL), true),
        (Type::A, Outcome::Drop, false),
    ] {
        let name: Name = "Example.org.".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 42, 0x0110).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut context = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &name,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(chain.serve(&mut context).await, expected);
        assert_eq!(erratic.ready(), ready);
        if expected == Outcome::Response {
            let reply = Message::parse(&response).unwrap();
            assert!(reply.aa() && reply.rd() && reply.cd());
            let answer = reply.answers().next().unwrap();
            assert_eq!(answer.name.to_string(), "Example.org.");
            assert_eq!(answer.rdata, [192, 0, 2, 53]);
        }
    }
}

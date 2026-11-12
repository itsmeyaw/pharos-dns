#![cfg(feature = "plugin-erratic")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Context, Metadata, Outcome, Protocol, Readiness, Transport};

#[cfg(feature = "plugin-autopath")]
#[test]
fn erratic_is_an_autopath_provider() {
    let blocks = parse("Corefile", ".:53 {\n autopath @erratic\n erratic\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    assert!(pharos_plugins::servers(configured).is_ok());
}

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
        ("erratic {\n large extra\n}", false),
        ("erratic {\n large drop 0\n}", true),
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
        let _ = builder.finish();
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

#[tokio::test]
async fn coredns_axfr_complete_and_truncated() {
    for (options, count) in [("drop 0", 6), ("truncate 2", 5)] {
        let blocks = parse(
            "Corefile",
            &format!(".:53 {{\n erratic {{\n {options}\n }}\n}}"),
        )
        .unwrap();
        let configured = configure::<Chain>(&blocks, directives()).unwrap();
        let name: Name = "example.org.".parse().unwrap();
        let mut query_wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query_wire, 512, 42, 0x0100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::AXFR,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(65535);
        let mut slots = [];
        let mut context = Context {
            query: Message::parse(&query_wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Tcp,
            domain: &name,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 65535,
        };
        let Outcome::Stream(mut stream) = configured[0].config.serve(&mut context).await else {
            panic!("expected stream")
        };
        assert!(stream.next(&mut response).unwrap());
        let message = Message::parse(&response).unwrap();
        assert!(message.aa() && !message.tc());
        assert_eq!(message.answer_count(), count);
        let types: Vec<_> = message.answers().map(|rr| rr.rtype).collect();
        assert_eq!(
            &types[..5],
            &[Type::SOA, Type::NS, Type::NS, Type::AAAA, Type::AAAA]
        );
        if count == 6 {
            assert_eq!(types[5], Type::SOA);
        }
        assert!(!stream.next(&mut response).unwrap());
    }
}

#[tokio::test]
async fn coredns_root_axfr_writes_no_message() {
    let blocks = parse("Corefile", ". {\n erratic {\n drop 0\n }\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let wire = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 252, 0, 1];
    let name: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let mut slots = [];
    let mut context = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Tcp,
        domain: &name,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 65535,
    };
    let Outcome::Stream(mut stream) = configured[0].config.serve(&mut context).await else {
        panic!("expected stream")
    };
    assert!(!stream.next(&mut response).unwrap());
}

#[tokio::test]
async fn coredns_truncate_bitmask_and_large_answers() {
    let blocks = parse("Corefile", ".:53 {\n erratic {\n truncate 2\n large\n }\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let name: Name = "example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 42, 0x0100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(65535);
    let mut slots = [];
    let mut context = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Tcp,
        domain: &name,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 65535,
    };
    for truncated in [true, true, false, false, true, true] {
        assert_eq!(
            configured[0].config.serve(&mut context).await,
            Outcome::Response
        );
        let reply = Message::parse(context.response).unwrap();
        assert_eq!(reply.tc(), truncated);
        assert_eq!(reply.answer_count(), 30);
    }
}

#[tokio::test]
async fn delayed_query_does_not_block_other_queries() {
    let blocks = parse("Corefile", ". {\n erratic {\n delay 2 100ms\n }\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let chain = &configured[0].config;
    let wire = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    let name: Name = ".".parse().unwrap();
    let mut first_response = Vec::with_capacity(512);
    let mut second_response = Vec::with_capacity(512);
    let mut first_slots = [];
    let mut second_slots = [];
    let context = |response, slots| Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &name,
        metadata: Metadata::new(slots),
        response,
        max_response_size: 512,
    };
    let mut first = context(&mut first_response, &mut first_slots);
    let mut second = context(&mut second_response, &mut second_slots);
    let delayed = chain.serve(&mut first);
    tokio::pin!(delayed);
    tokio::select! {
        _ = &mut delayed => panic!("first Query should be delayed"),
        _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
    }
    assert_eq!(chain.serve(&mut second).await, Outcome::Response);
    assert_eq!(delayed.await, Outcome::Response);
}

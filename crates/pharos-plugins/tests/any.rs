#![forbid(unsafe_code)]
#![cfg(feature = "plugin-any")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

fn configured(text: &str) -> Result<Chain, String> {
    let source = format!(".:53 {{\n{text}\n}}");
    let blocks = parse("Corefile", &source).map_err(|e| e.to_string())?;
    let mut blocks = configure::<Chain>(&blocks, directives()).map_err(|e| e.to_string())?;
    Ok(blocks.remove(0).config)
}

#[test]
fn coredns_setup_accepts_any() {
    assert!(configured("any").is_ok());
}

#[test]
fn coredns_setup_rejects_arguments_and_block_options() {
    assert!(configured("any example.org").is_err());
    assert!(configured("any {\n foo\n}").is_err());
    assert!(configured("any {\n}").is_ok());
    assert!(configured("any\nany").is_ok());
}

struct NextOutcome(Outcome);

impl Next for NextOutcome {
    async fn run(self, _: &mut Context<'_>) -> Outcome {
        self.0
    }
}

#[tokio::test]
async fn coredns_any_synthesizes_hinfo() {
    let chain = configured("any").unwrap();
    let name: Name = "ExAmple.org.".parse().unwrap();
    let name_ref = NameRef::parse(name.as_wire(), 0).unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 0x1234, 0x0110).unwrap();
    builder.question(name_ref, Type::ANY, Class::CH).unwrap();
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
    assert_eq!(
        chain
            .any
            .as_ref()
            .unwrap()
            .serve(&mut cx, NextOutcome(Outcome::Drop))
            .await,
        Outcome::Response
    );
    let message = Message::parse(&response).unwrap();
    assert_eq!((message.id(), message.flags()), (0x1234, 0x8110));
    assert_eq!(
        (
            message.question_count(),
            message.answer_count(),
            message.authority_count(),
            message.additional_count()
        ),
        (1, 1, 0, 0)
    );
    let question = message.questions().next().unwrap();
    assert_eq!(
        (question.name.to_string(), question.qtype, question.qclass),
        ("ExAmple.org.".into(), Type::ANY, Class::CH)
    );
    let answer = message.answers().next().unwrap();
    assert_eq!(
        (
            answer.name.to_string(),
            answer.rtype,
            answer.class,
            answer.ttl
        ),
        ("ExAmple.org.".into(), Type::HINFO, Class::IN, 8482)
    );
    assert_eq!(answer.rdata, b"\x0dANY obsoleted\x0cSee RFC 8482");
}

#[tokio::test]
async fn coredns_non_any_queries_pass_next_outcomes_unchanged() {
    let chain = configured("any").unwrap();
    let name: Name = "example.org.".parse().unwrap();
    let name_ref = NameRef::parse(name.as_wire(), 0).unwrap();
    let domain: Name = ".".parse().unwrap();
    for qtype in [Type::A, Type::AAAA, Type::MX, Type::TXT, Type::CNAME] {
        for outcome in [
            Outcome::Drop,
            Outcome::Unanswered(pharos_proto::Rcode::REFUSED),
            Outcome::Error(pharos_server::Error::NoNextPlugin),
        ] {
            let mut wire = Vec::with_capacity(512);
            let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
            builder.question(name_ref, qtype, Class::IN).unwrap();
            let _ = builder.finish();
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
            assert_eq!(
                chain
                    .any
                    .as_ref()
                    .unwrap()
                    .serve(&mut cx, NextOutcome(outcome))
                    .await,
                outcome,
                "{qtype:?}"
            );
        }
    }
}

#[tokio::test]
async fn any_checks_buffer_capacity_and_preserves_opcode_rules() {
    let chain = configured("any").unwrap();
    let wire = [0, 7, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 1];
    let domain: Name = ".".parse().unwrap();
    for (protocol, capacity) in [(Protocol::Udp, 0), (Protocol::Tcp, 0), (Protocol::Udp, 512)] {
        let mut response = Vec::with_capacity(capacity);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let outcome = chain
            .any
            .as_ref()
            .unwrap()
            .serve(&mut cx, NextOutcome(Outcome::Drop))
            .await;
        if protocol == Protocol::Udp && capacity == 0 {
            assert_eq!(
                outcome,
                Outcome::Error(pharos_server::Error::ResponseBufferTooSmall)
            );
        } else {
            assert_eq!(outcome, Outcome::Response);
            assert_eq!(Message::parse(&response).unwrap().flags(), 0xa800);
        }
    }
}

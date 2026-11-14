#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Section, Type};
use pharos_server::{
    Action, Chain, Context, Error, Handler, ListenerKey, Outcome, Protocol, Router, Server,
    Transport,
};

enum TestPlugin {
    Cname(&'static str),
    Address,
}

impl Chain for TestPlugin {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        let question = cx.query.questions().next().unwrap();
        let target: Name;
        let captured = match self {
            Self::Cname(name) => {
                target = name.parse().unwrap();
                match cx.self_lookup(&target, question.qtype).await {
                    Ok(wire) => {
                        if Message::parse(&wire).unwrap().rcode() != Rcode::NOERROR {
                            return Outcome::Error(Error::InvalidQuery);
                        }
                        Some(wire)
                    }
                    Err(error) => return Outcome::Error(error),
                }
            }
            Self::Address => {
                target = ".".parse().unwrap();
                None
            }
        };
        let mut builder = MessageBuilder::new(cx.response, 65535, cx.query.id(), 0x8400).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        if let Some(wire) = &captured {
            let target = NameRef::parse(target.as_wire(), 0).unwrap();
            builder
                .record_with(
                    Section::Answer,
                    question.name,
                    Type::CNAME,
                    Class::IN,
                    60,
                    |writer| writer.write_name(target),
                )
                .unwrap();
            for answer in Message::parse(wire).unwrap().answers() {
                let data = answer.data().unwrap();
                builder
                    .record_with(
                        Section::Answer,
                        answer.name,
                        answer.rtype,
                        answer.class,
                        answer.ttl,
                        |writer| data.write(writer),
                    )
                    .unwrap();
            }
        } else {
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::A,
                    Class::IN,
                    60,
                    &[192, 0, 2, 42],
                )
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
    fn is_empty(&self) -> bool {
        false
    }
}

fn server(looping: bool) -> Server<TestPlugin> {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        key,
        "example.".parse().unwrap(),
        Some(TestPlugin::Cname("b.other.")),
        vec![],
    );
    router.add(
        key,
        "other.".parse().unwrap(),
        Some(if looping {
            TestPlugin::Cname("a.example.")
        } else {
            TestPlugin::Address
        }),
        vec![],
    );
    Server::new(router, key)
}

async fn lookup(looping: bool) -> Vec<u8> {
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x01a\x07example\0\0\x01\0\x01";
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server(looping)
            .handle(
                query,
                "192.0.2.10:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
        Action::Respond
    );
    response
}

// RFC 1034 §4.3.2: Copy a CNAME into the answer and restart lookup at its canonical name.
#[tokio::test]
async fn cname_chases_into_another_server_block() {
    let wire = lookup(false).await;
    let response = Message::parse(&wire).unwrap();
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let answers = response.answers().collect::<Vec<_>>();
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0].name.to_string(), "a.example.");
    // RFC 1035 §3.3.1: CNAME RDATA names the canonical name as a domain name.
    assert!(
        matches!(answers[0].data().unwrap(), Rdata::Cname(target) if target.to_string() == "b.other.")
    );
    assert_eq!(answers[1].name.to_string(), "b.other.");
    assert_eq!(answers[1].rdata, [192, 0, 2, 42]);
}

// RFC 1034 §3.6.2: Follow CNAME chains and signal CNAME loops as errors.
#[tokio::test]
async fn cname_loop_returns_servfail() {
    let wire = lookup(true).await;
    let response = Message::parse(&wire).unwrap();
    assert_eq!(response.rcode(), Rcode::SERVFAIL);
    assert_eq!(response.answer_count(), 0);
}

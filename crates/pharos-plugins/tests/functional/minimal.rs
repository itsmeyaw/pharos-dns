#![forbid(unsafe_code)]
#![cfg(feature = "plugin-minimal")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

fn configured(text: &str) -> Result<Chain, String> {
    let blocks =
        parse("Corefile", &format!(".:53 {{\n{text}\n}}")).map_err(|error| error.to_string())?;
    Ok(configure::<Chain>(&blocks, directives())
        .map_err(|error| error.to_string())?
        .remove(0)
        .config)
}

#[test]
fn coredns_setup_cases() {
    for directive in ["minimal", "minimal\nminimal"] {
        assert!(configured(directive).is_ok(), "{directive}");
    }
    for directive in [
        "minimal example.org",
        "minimal x y",
        "minimal {}",
        "minimal {\n ignored\n}",
        "minimal {\n}",
    ] {
        assert!(configured(directive).is_err(), "{directive}");
    }
}

fn response(
    flags: u16,
    qtype: Type,
    answer: bool,
    authority: Option<Type>,
    do_bit: bool,
    expired: bool,
) -> Vec<u8> {
    let mut wire = Vec::with_capacity(512);
    let root = NameRef::parse(&[0], 0).unwrap();
    let mut builder = MessageBuilder::new(&mut wire, 512, 7, flags).unwrap();
    builder.question(root, qtype, Class::IN).unwrap();
    if answer {
        builder
            .record(
                Section::Answer,
                root,
                Type::A,
                Class::IN,
                293,
                &[142, 250, 76, 46],
            )
            .unwrap();
    }
    if let Some(rtype) = authority {
        builder
            .record(Section::Authority, root, rtype, Class::IN, 60, &[0])
            .unwrap();
    }
    builder
        .record(
            Section::Additional,
            root,
            Type::A,
            Class::IN,
            60,
            &[192, 0, 2, 1],
        )
        .unwrap();
    if expired {
        let sig = b"\0\x02\x08\0\0\0\0\x3c\0\0\0\x96\0\0\0\x32\0\x01\0";
        builder
            .record(Section::Additional, root, Type::RRSIG, Class::IN, 60, sig)
            .unwrap();
    }
    if do_bit {
        builder
            .record(
                Section::Additional,
                root,
                Type::OPT,
                Class(1232),
                0x8000,
                &[],
            )
            .unwrap();
    }
    let _ = builder.finish();
    wire
}

struct Reply<'a> {
    wire: &'a [u8],
    outcome: Outcome,
}

impl Next for Reply<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        cx.response.extend_from_slice(self.wire);
        self.outcome
    }
}

#[tokio::test]
async fn coredns_minimization_and_response_types() {
    let chain = configured("minimal").unwrap();
    let query = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    let domain: Name = ".".parse().unwrap();
    for (flags, qtype, answer, authority, do_bit, expired, strip) in [
        (0x8000, Type::A, true, None, false, false, true),
        (0x8000, Type::A, true, Some(Type::NS), true, false, true),
        (0x8000, Type::A, false, Some(Type::NS), false, false, false),
        (0x8000, Type::A, false, Some(Type::SOA), false, false, false),
        (0x8003, Type::A, false, Some(Type::SOA), false, false, false),
        (0x8003, Type::A, true, Some(Type::NS), false, false, false),
        (0x8002, Type::A, true, Some(Type::NS), false, false, false),
        (0x8005, Type::A, true, Some(Type::NS), false, false, false),
        (0x8000, Type::A, false, None, false, false, true),
        (0xa000, Type::A, true, Some(Type::NS), false, false, false),
        (0xa800, Type::A, true, Some(Type::NS), false, false, false),
        (
            0x8000,
            Type::AXFR,
            true,
            Some(Type::NS),
            false,
            false,
            false,
        ),
        (0x8000, Type::A, true, Some(Type::NS), true, true, false),
        (0x8000, Type::A, true, Some(Type::NS), false, true, true),
    ] {
        let original = response(flags, qtype, answer, authority, do_bit, expired);
        let mut wire = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut wire,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .minimal
                .as_ref()
                .unwrap()
                .serve(
                    &mut cx,
                    Reply {
                        wire: &original,
                        outcome: Outcome::Response
                    }
                )
                .await,
            Outcome::Response
        );
        let result = Message::parse(cx.response).unwrap();
        assert_eq!(result.answer_count(), u16::from(answer));
        if answer {
            let record = result.answers().next().unwrap();
            assert_eq!(
                (record.rtype, record.class, record.ttl, record.rdata),
                (Type::A, Class::IN, 293, &[142, 250, 76, 46][..])
            );
        }
        assert_eq!(
            result.authority_count(),
            if strip {
                0
            } else {
                u16::from(authority.is_some())
            },
            "flags={flags:x}"
        );
        assert_eq!(
            result.additional_count(),
            if strip {
                0
            } else {
                1 + u16::from(expired) + u16::from(do_bit)
            },
            "flags={flags:x}"
        );
        if !strip {
            assert_eq!(*cx.response, original);
        }
        assert_eq!(result.id(), 7);
        assert_eq!(result.flags(), flags);
    }
}

#[tokio::test]
async fn message_less_and_error_outcomes_are_preserved() {
    let chain = configured("minimal").unwrap();
    let query = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    let domain: Name = ".".parse().unwrap();
    for outcome in [
        Outcome::Drop,
        Outcome::Unanswered(Rcode::REFUSED),
        Outcome::Error(pharos_server::Error::NoNextPlugin),
    ] {
        let mut wire = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut wire,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .minimal
                .as_ref()
                .unwrap()
                .serve(&mut cx, Reply { wire: &[], outcome })
                .await,
            outcome
        );
        assert!(cx.response.is_empty());
    }
}

#[tokio::test]
async fn header_compressed_question_is_left_unchanged() {
    let chain = configured("minimal").unwrap();
    let query = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    let original = [
        0, 1, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0xc0, 10, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 60, 0,
        4, 192, 0, 2, 1,
    ];
    Message::parse(&original).unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut wire,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .minimal
            .as_ref()
            .unwrap()
            .serve(
                &mut cx,
                Reply {
                    wire: &original,
                    outcome: Outcome::Response
                }
            )
            .await,
        Outcome::Response
    );
    assert_eq!(cx.response.as_slice(), original);
}

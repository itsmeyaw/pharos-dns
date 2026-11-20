use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct QueryDnskeyReply;

impl Next for QueryDnskeyReply {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let question = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8400).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::DNSKEY,
                question.qclass,
                300,
                &[0, 1, 3, 13, 1],
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

#[test]
fn explicit_nxname_query_gets_formerr() {
    let domain: Name = "example.org.".parse().unwrap();
    let name = NameRef::parse(domain.as_wire(), 0).unwrap();
    let mut query = Vec::new();
    let mut builder = MessageBuilder::new(&mut query, 512, 7, 0x0110).unwrap();
    builder.question(name, Type::NXNAME, Class::IN).unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    super::nxname_formerr(&mut cx).unwrap();
    let reply = Message::parse(cx.response).unwrap();
    assert_eq!(reply.rcode(), Rcode::FORMERR);
    assert_eq!(reply.id(), 7);
    assert_eq!(reply.flags() & 0x0010, 0);
    assert_eq!(reply.answers().count(), 0);
}

// RFC 1035 §3.2.5: Explicit QCLASS CH must not receive an IN DNSKEY RRset.
#[tokio::test]
async fn non_in_dnskey_query_passes_through_without_in_records() {
    let key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let corefile = format!("miek.nl {{\n dnssec {{\n key file {key}\n }}\n}}");
    let mut chain = pharos_corefile::configure::<crate::Chain>(
        &pharos_corefile::parse("Corefile", &corefile).unwrap(),
        crate::directives(),
    )
    .unwrap();
    let dnssec = chain[0].config.dnssec.take().unwrap();

    let domain: Name = "miek.nl.".parse().unwrap();
    let name = NameRef::parse(domain.as_wire(), 0).unwrap();
    let mut query = Vec::new();
    let mut builder = MessageBuilder::new(&mut query, 512, 9, 0x0100).unwrap();
    builder.question(name, Type::DNSKEY, Class::CH).unwrap();
    builder
        .record(
            Section::Additional,
            NameRef::parse(&[0], 0).unwrap(),
            Type::OPT,
            Class(1232),
            0x8000,
            &[],
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };

    assert_eq!(
        dnssec.serve(&mut cx, QueryDnskeyReply).await,
        Outcome::Response
    );
    let reply = Message::parse(cx.response).unwrap();
    let answers: Vec<_> = reply.answers().collect();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].class, Class::CH);
    assert!(!answers.iter().any(|rr| rr.rtype == Type::RRSIG));
}

// RFC 1035 §3.2.3: QCLASS=ANY selects DNSKEY data in any class.
#[tokio::test]
async fn qclass_any_dnskey_intercepts_signed_zone_key() {
    let key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let corefile = format!("miek.nl {{\n dnssec {{\n key file {key}\n }}\n}}");
    let mut chain = pharos_corefile::configure::<crate::Chain>(
        &pharos_corefile::parse("Corefile", &corefile).unwrap(),
        crate::directives(),
    )
    .unwrap();
    let dnssec = chain[0].config.dnssec.take().unwrap();

    let domain: Name = "miek.nl.".parse().unwrap();
    let name = NameRef::parse(domain.as_wire(), 0).unwrap();
    let mut query = Vec::new();
    let mut builder = MessageBuilder::new(&mut query, 512, 10, 0x0100).unwrap();
    builder.question(name, Type::DNSKEY, Class::ANY).unwrap();
    builder
        .record(
            Section::Additional,
            NameRef::parse(&[0], 0).unwrap(),
            Type::OPT,
            Class(1232),
            0x8000,
            &[],
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };

    assert_eq!(
        dnssec.serve(&mut cx, QueryDnskeyReply).await,
        Outcome::Response
    );
    let reply = Message::parse(cx.response).unwrap();
    assert!(
        reply
            .answers()
            .any(|rr| rr.rtype == Type::DNSKEY && rr.class == Class::IN)
    );
    assert!(
        reply
            .answers()
            .any(|rr| rr.rtype == Type::RRSIG && rr.class == Class::IN)
    );
}

#![cfg(all(feature = "plugin-dnssec", feature = "plugin-whoami"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::{Action, Handler, Protocol};

#[tokio::test(flavor = "current_thread")]
async fn no_do_and_warmed_signature_hits_do_not_allocate() {
    if crate::run_isolated("dnssec::cases::no_do_and_warmed_signature_hits_do_not_allocate") {
        return;
    }
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl:0 {{\n dnssec {{\n key file {base}\n }}\n whoami\n}}");
    let (mut servers, _) =
        servers(configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap())
            .unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let unsigned = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x03www\x04miek\x02nl\0\0\x01\0\x01";
    let dnskey = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x04miek\x02nl\0\0\x30\0\x01";
    let signed = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\x01\x03www\x04miek\x02nl\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\x80\0\0\0";
    let signed_dnskey = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\x01\x04miek\x02nl\0\0\x30\0\x01\0\0\x29\x04\xd0\0\0\x80\0\0\0";
    let peer = "127.0.0.1:1001".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    for query in [
        unsigned.as_slice(),
        dnskey.as_slice(),
        signed.as_slice(),
        signed_dnskey.as_slice(),
    ] {
        assert_eq!(
            server
                .handle(query, peer, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
        if query == signed {
            let message = pharos_proto::Message::parse(&response).unwrap();
            assert!(
                message
                    .additionals()
                    .any(|rr| rr.rtype == pharos_proto::Type::RRSIG)
            );
        }
        if query == signed_dnskey {
            let message = pharos_proto::Message::parse(&response).unwrap();
            assert!(
                message
                    .answers()
                    .any(|rr| rr.rtype == pharos_proto::Type::RRSIG)
            );
        }
        let before = crate::GLOBAL.stats();
        for _ in 0..100 {
            assert_eq!(
                server
                    .handle(query, peer, Protocol::Udp, &mut response)
                    .await,
                Action::Respond
            );
        }
        let after = crate::GLOBAL.stats();
        assert_eq!(after.allocations - before.allocations, 0);
        assert_eq!(after.reallocations - before.reallocations, 0);
    }
}

struct Negative;
impl pharos_server::Next for Negative {
    async fn run(self, cx: &mut pharos_server::Context<'_, '_>) -> pharos_server::Outcome {
        use pharos_proto::{Class, MessageBuilder, NameRef, Section, Type};
        let question = cx.query.questions().next().unwrap();
        let mut builder =
            MessageBuilder::new(cx.response, cx.max_response_size, cx.query.id(), 0x8403).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Authority,
                NameRef::parse(cx.domain.as_wire(), 0).unwrap(),
                Type::SOA,
                Class::IN,
                60,
                &[
                    0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5,
                ],
            )
            .unwrap();
        let _ = builder.finish();
        pharos_server::Outcome::Response
    }
}

#[tokio::test(flavor = "current_thread")]
async fn warmed_black_lie_hit_does_not_allocate() {
    use pharos_proto::{Message, Name, Type};
    use pharos_server::{Context, Metadata, Outcome, Plugin, Transport};

    if crate::run_isolated("dnssec::cases::warmed_black_lie_hit_does_not_allocate") {
        return;
    }
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl {{\n dnssec {{\n key file {base}\n }}\n}}");
    let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\x01\x03www\x04miek\x02nl\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\x80\0\0\0";
    let domain: Name = "miek.nl.".parse().unwrap();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(query).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    let plugin = blocks[0].config.dnssec.as_ref().unwrap();
    assert_eq!(plugin.serve(&mut cx, Negative).await, Outcome::Response);
    assert!(
        Message::parse(cx.response)
            .unwrap()
            .authorities()
            .any(|rr| rr.rtype == Type::NSEC)
    );
    let before = crate::GLOBAL.stats();
    for _ in 0..100 {
        assert_eq!(plugin.serve(&mut cx, Negative).await, Outcome::Response);
    }
    let after = crate::GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
}

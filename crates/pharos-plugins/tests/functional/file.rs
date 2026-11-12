#![forbid(unsafe_code)]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Context, Metadata, Outcome, Phase, Protocol, Transport};

#[tokio::test]
async fn serves_zone_and_negative_answers() {
    let zonefile = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
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
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
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

#[tokio::test]
async fn serves_aliases_wildcards_and_referrals() {
    let zonefile = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let corefile = format!("example.org:53 {{\n file {zonefile}\n}}");
    let blocks = parse("Corefile", &corefile).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let domain: Name = "example.org.".parse().unwrap();
    for (name, aa, answers, authority, additional) in [
        ("alias.example.org.", true, 2, 1, 0),
        ("foo.wild.example.org.", true, 1, 1, 0),
        ("foo.child.example.org.", false, 0, 1, 1),
        ("empty.example.org.", true, 0, 1, 0),
    ] {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
            )
            .unwrap();
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
        assert_eq!(response.rcode(), Rcode::NOERROR, "{name}");
        assert_eq!(response.aa(), aa, "{name}");
        assert_eq!(response.answer_count(), answers, "{name}");
        assert_eq!(response.authority_count(), authority, "{name}");
        assert_eq!(response.additional_count(), additional, "{name}");
    }
}

#[tokio::test]
async fn reload_replaces_only_changed_serial() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-reload-test.zone");
    let original = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    ))
    .unwrap();
    std::fs::write(&path, &original).unwrap();
    let corefile = format!(
        "example.org:53 {{\n file {} {{\n reload 10ms\n }}\n}}",
        path.display()
    );
    let blocks = parse("Corefile", &corefile).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let chain = &configured[0].config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    std::fs::write(
        &path,
        original
            .replace(" 1 7200", " 2 7200")
            .replace("192.0.2.1", "192.0.2.9"),
    )
    .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let name: Name = "www.example.org.".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
        let mut cx = Context {
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
        assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
        let response = Message::parse(&response).unwrap();
        if response.answers().next().unwrap().rdata == [192, 0, 2, 9] {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "Zone did not reload");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_file(path).unwrap();
}

#[cfg(feature = "plugin-transfer")]
#[test]
fn axfr_and_current_ixfr_have_soa_framing() {
    use pharos_plugins::transfer::{TransferRequest, Transferer};
    let zonefile = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let corefile = format!("example.org:53 {{\n file {zonefile}\n}}");
    let blocks = parse("Corefile", &corefile).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let plugin = configured[0].config.file.as_ref().unwrap();
    let apex: Name = "example.org.".parse().unwrap();
    for (kind, serial, expected) in [(Type::AXFR, 0, 2), (Type::IXFR, 1, 1)] {
        let mut stream = plugin
            .transfer(TransferRequest {
                zone: NameRef::parse(apex.as_wire(), 0).unwrap(),
                serial,
                id: 1,
                flags: 0,
                protocol: Protocol::Tcp,
                qtype: kind,
                qclass: Class::IN,
            })
            .unwrap()
            .unwrap();
        let mut wire = Vec::with_capacity(65535);
        let mut types = Vec::new();
        while stream.next(&mut wire).unwrap() {
            let message = Message::parse(&wire).unwrap();
            types.extend(message.answers().map(|record| record.rtype));
        }
        assert_eq!(types.first(), Some(&Type::SOA));
        assert_eq!(types.last(), Some(&Type::SOA));
        assert_eq!(
            types.iter().filter(|kind| **kind == Type::SOA).count(),
            expected
        );
    }
}

#[tokio::test]
async fn dnssec_ok_serves_rrsigs_and_nsec_denial() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/signed.zone"
    );
    let corefile = format!("example.org:53 {{\n file {path}\n}}");
    let blocks = parse("Corefile", &corefile).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    for (name, kind, expected_answer, expected_authority) in [
        (
            "www.example.org.",
            Type::A,
            vec![Type::A, Type::RRSIG],
            vec![Type::NS, Type::RRSIG],
        ),
        (
            "www.example.org.",
            Type::AAAA,
            vec![],
            vec![Type::SOA, Type::RRSIG, Type::NSEC, Type::RRSIG],
        ),
        (
            "missing.example.org.",
            Type::A,
            vec![],
            vec![Type::SOA, Type::RRSIG, Type::NSEC, Type::RRSIG],
        ),
    ] {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::with_capacity(1232);
        let mut builder = MessageBuilder::new(&mut wire, 1232, 1, 0x0100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        builder
            .record(
                pharos_proto::Section::Additional,
                NameRef::parse(&[0], 0).unwrap(),
                Type::OPT,
                Class(1232),
                0x8000,
                &[],
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(1232);
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &name,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 1232,
        };
        assert_eq!(configured[0].config.serve(&mut cx).await, Outcome::Response);
        let response = Message::parse(&response).unwrap();
        assert_eq!(
            response.answers().map(|rr| rr.rtype).collect::<Vec<_>>(),
            expected_answer
        );
        assert_eq!(
            response
                .authorities()
                .map(|rr| rr.rtype)
                .collect::<Vec<_>>(),
            expected_authority
        );
    }
}

#[tokio::test]
async fn external_alias_preserves_target_rcode_and_truncation() {
    use pharos_server::{Action, Handler, ListenerKey, Router, Server};
    use std::sync::Arc;
    enum Route {
        File(Box<Chain>),
        Target,
    }
    impl pharos_server::Chain for Route {
        async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
            match self {
                Self::File(chain) => chain.serve(cx).await,
                Self::Target => {
                    let question = cx.query.questions().next().unwrap();
                    let mut builder =
                        MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8202).unwrap();
                    builder
                        .question(question.name, question.qtype, question.qclass)
                        .unwrap();
                    let _ = builder.finish();
                    Outcome::Response
                }
            }
        }
        fn is_empty(&self) -> bool {
            false
        }
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let config = format!("example.org:53 {{\n file {path}\n}}");
    let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        key,
        "example.org.".parse().unwrap(),
        Some(Route::File(Box::new(chain))),
        vec![],
    );
    router.add(
        key,
        "outside.test.".parse().unwrap(),
        Some(Route::Target),
        vec![],
    );
    let server = Arc::new(Server::new(router, key));
    let name: Name = "external.example.org.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x0100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut wire = Vec::with_capacity(65535);
    assert_eq!(
        Handler::handle_shared(
            &server,
            &query,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut wire
        )
        .await,
        Action::Respond
    );
    let response = Message::parse(&wire).unwrap();
    assert_eq!(response.rcode(), Rcode::SERVFAIL);
    assert!(response.tc());
    assert_eq!(response.answer_count(), 1);
}

// Derived from CoreDNS plugin/file/nsec3_test.go.
#[test]
fn nsec3_and_nsec3param_fail_the_entire_zone_load() {
    for filename in ["nsec3.zone", "nsec3param.zone"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/file")
            .join(filename);
        let error =
            pharos_plugins::file::Zone::load("example.org.".parse().unwrap(), &path).unwrap_err();
        assert!(error.contains("NSEC3 zone is not supported"), "{error}");
    }
}

#[tokio::test]
async fn apex_ns_mx_and_srv_include_addresses() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let corefile = format!("example.org:53 {{\n file {path}\n}}");
    let configured =
        configure::<Chain>(&parse("Corefile", &corefile).unwrap(), directives()).unwrap();
    for (name, kind, authority) in [
        ("example.org.", Type::NS, 0),
        ("example.org.", Type::MX, 1),
        ("_sip._tcp.example.org.", Type::SRV, 1),
    ] {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
        let mut cx = Context {
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
        assert_eq!(configured[0].config.serve(&mut cx).await, Outcome::Response);
        let response = Message::parse(&response).unwrap();
        assert_eq!(response.authority_count(), authority);
        assert_eq!(response.additional_count(), 1);
        assert_eq!(response.additionals().next().unwrap().rtype, Type::A);
    }
}

#[cfg(feature = "plugin-transfer")]
#[tokio::test]
async fn notifies_on_startup_and_reload() {
    use pharos_plugins::servers;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-notify-test.zone");
    let original = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    ))
    .unwrap();
    std::fs::write(&path, &original).unwrap();
    let config = format!(
        "example.org:0 {{\n file {} {{\n reload 10ms\n }}\n transfer {{\n to {address}\n }}\n}}",
        path.display()
    );
    let (_, lifecycle) =
        servers(configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap())
            .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    for stage in 0..2 {
        if stage == 1 {
            std::fs::write(&path, original.replace(" 1 7200", " 2 7200")).unwrap();
        }
        let mut wire = [0; 512];
        let (len, peer) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut wire),
        )
        .await
        .unwrap()
        .unwrap();
        let notify = Message::parse(&wire[..len]).unwrap();
        assert_eq!(notify.opcode(), pharos_proto::Opcode::NOTIFY);
        assert_eq!(
            notify.questions().next().unwrap().name.to_string(),
            "example.org."
        );
        wire[2] |= 0x80;
        socket.send_to(&wire[..len], peer).await.unwrap();
    }
    lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn dname_synthesizes_alias_and_follows_target() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let corefile = format!("example.org:53 {{\n file {path}\n}}");
    let configured =
        configure::<Chain>(&parse("Corefile", &corefile).unwrap(), directives()).unwrap();
    let name: Name = "foo.old.example.org.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x0100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut wire = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &name,
        metadata: Metadata::new(&mut slots),
        response: &mut wire,
        max_response_size: 512,
    };
    assert_eq!(configured[0].config.serve(&mut cx).await, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(
        response.answers().map(|rr| rr.rtype).collect::<Vec<_>>(),
        vec![Type::DNAME, Type::CNAME, Type::A]
    );
}

#[tokio::test]
async fn alias_target_below_cut_returns_partial_answer_and_referral() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let corefile = format!("example.org:53 {{\n file {path}\n}}");
    let configured =
        configure::<Chain>(&parse("Corefile", &corefile).unwrap(), directives()).unwrap();
    let name: Name = "aliaschild.example.org.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x0100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut wire = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &name,
        metadata: Metadata::new(&mut slots),
        response: &mut wire,
        max_response_size: 512,
    };
    assert_eq!(configured[0].config.serve(&mut cx).await, Outcome::Response);
    let response = Message::parse(&wire).unwrap();
    assert!(response.aa());
    assert_eq!(
        response.answers().map(|rr| rr.rtype).collect::<Vec<_>>(),
        vec![Type::CNAME]
    );
    assert_eq!(
        response.authorities().next().unwrap().name.to_string(),
        "child.example.org."
    );
    assert_eq!(response.additionals().next().unwrap().rtype, Type::A);
}

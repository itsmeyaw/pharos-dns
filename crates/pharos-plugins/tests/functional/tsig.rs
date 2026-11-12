#![cfg(feature = "plugin-tsig")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name, Rcode, TsigAlgorithm, TsigKey};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

#[tokio::test]
async fn upstream_nsid_must_not_invalidate_tsig() {
    let blocks = parse(
        "Corefile",
        ". {\n nsid server1\n tsig {\n secret key. c2VjcmV0\n }\n whoami\n}",
    )
    .unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut wire = Vec::with_capacity(512);
    wire.extend_from_slice(&[
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, b'a', 0, 0, 1, 0, 1, 0, 0, 41, 0x04, 0xd0, 0, 0,
        0x80, 0, 0, 4, 0, 3, 0, 0,
    ]);
    key.sign(&mut wire, now, 300, None).unwrap();
    let mac = key.verify(&wire, now, None, 0).unwrap().mac;
    let query = Message::parse(&wire).unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [];
    let mut cx = Context {
        query,
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    let outcome = configured[0].config.serve(&mut cx).await;
    assert_eq!(outcome, Outcome::Response);
    let signing = cx.metadata.take_tsig_signing();
    pharos_server::finish_outcome_signed(
        query,
        Protocol::Udp,
        outcome,
        &mut response,
        signing,
        |e| panic!("{e}"),
    );
    key.verify(&response, now, Some(mac), 0).unwrap();
}

#[tokio::test]
async fn keys_are_shared_by_server_blocks_on_the_same_listener() {
    use pharos_server::{Action, Handler};
    let blocks = parse("Corefile", "one.test:53 {\n tsig {\n secret key. c2VjcmV0\n }\n whoami\n}\ntwo.test:53 {\n tsig\n whoami\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let (servers, _) = pharos_plugins::servers(configured).unwrap();
    let server = servers.values().next().unwrap();
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut wire = Vec::with_capacity(512);
    wire.extend_from_slice(&[
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b't', b'w', b'o', 4, b't', b'e', b's', b't', 0, 0,
        1, 0, 1,
    ]);
    key.sign(&mut wire, now, 300, None).unwrap();
    let mac = key.verify(&wire, now, None, 0).unwrap().mac;
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server
            .handle(
                &wire,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
        Action::Respond
    );
    key.verify(&response, now, Some(mac), 0).unwrap();
}

#[tokio::test]
async fn nonfinal_tsig_is_formerr_even_outside_domain() {
    let blocks = parse("Corefile", ". {\n tsig example.com\n whoami\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut wire = Vec::with_capacity(512);
    wire.extend_from_slice(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1]);
    key.sign(&mut wire, now, 300, None).unwrap();
    wire.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4]);
    wire[11] = 2;
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
        configured[0].config.serve(&mut cx).await,
        Outcome::Unanswered(Rcode::FORMERR)
    );
}

#[tokio::test]
async fn validated_key_is_visible_to_next_without_tsig_record() {
    struct Next;
    impl pharos_server::Next for Next {
        async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
            assert_eq!(
                pharos_plugins::tsig::validated_key_name(cx).map(|name| name.to_string()),
                Some("key.".to_owned())
            );
            assert_eq!(cx.query.additional_count(), 0);
            let mut wire = Vec::with_capacity(512);
            cx.query.copy_wire(&mut wire);
            assert_eq!(Message::parse(&wire).unwrap().additional_count(), 0);
            Outcome::Unanswered(Rcode::REFUSED)
        }
    }
    let blocks = parse("Corefile", ". {\n tsig {\n secret KEY. c2VjcmV0\n }\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut wire = Vec::with_capacity(512);
    wire.extend_from_slice(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1]);
    key.sign(&mut wire, now, 300, None).unwrap();
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
        pharos_server::Plugin::serve(configured[0].config.tsig.as_ref().unwrap(), &mut cx, Next)
            .await,
        Outcome::Unanswered(Rcode::REFUSED)
    );
}

#[tokio::test]
async fn signed_unanswered_query_gets_signed_servfail() {
    let blocks = parse("Corefile", ". {\n tsig {\n secret key. c2VjcmV0\n }\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut wire = Vec::with_capacity(512);
    wire.extend_from_slice(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1]);
    key.sign(&mut wire, now, 300, None).unwrap();
    let mac = key.verify(&wire, now, None, 0).unwrap().mac;
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
    let outcome = configured[0].config.serve(&mut cx).await;
    let signing = cx.metadata.take_tsig_signing();
    pharos_server::finish_outcome_signed(
        Message::parse(&wire).unwrap(),
        Protocol::Udp,
        outcome,
        &mut response,
        signing,
        |_| {},
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
    key.verify(&response, now, Some(mac), 0).unwrap();
}

#[tokio::test]
async fn signed_edns_response_survives_listener_finalization() {
    let blocks = parse(
        "Corefile",
        ". {\n tsig {\n secret key. c2VjcmV0\n }\n whoami\n}",
    )
    .unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut wire = Vec::with_capacity(512);
    wire.extend_from_slice(&[
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, b'a', 0, 0, 1, 0, 1, 0, 0, 41, 0x04, 0xd0, 0, 0,
        0x80, 0, 0, 0,
    ]);
    key.sign(&mut wire, now, 300, None).unwrap();
    let mac = key.verify(&wire, now, None, 0).unwrap().mac;
    let query = Message::parse(&wire).unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [];
    let mut cx = Context {
        query,
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    let outcome = configured[0].config.serve(&mut cx).await;
    let signing = cx.metadata.take_tsig_signing();
    pharos_server::finish_outcome_signed(
        query,
        Protocol::Udp,
        outcome,
        &mut response,
        signing,
        |e| panic!("{e}"),
    );
    key.verify(&response, now, Some(mac), 0).unwrap();
    assert!(Message::parse(&response).unwrap().opt().is_some());
}

#[tokio::test]
async fn unknown_key_and_bad_mac_return_tsig_errors() {
    let blocks = parse(
        "Corefile",
        ". {\n tsig {\n secret key. c2VjcmV0\n }\n whoami\n}",
    )
    .unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (name, secret, code) in [("other.", b"secret".as_slice(), 17), ("key.", b"wrong", 16)] {
        let key = TsigKey::new(name.parse().unwrap(), TsigAlgorithm::Sha256, secret);
        let mut wire = Vec::with_capacity(512);
        wire.extend_from_slice(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1]);
        key.sign(&mut wire, now, 300, None).unwrap();
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
        let outcome = configured[0].config.serve(&mut cx).await;
        let signing = cx.metadata.take_tsig_signing();
        pharos_server::finish_outcome_signed(
            Message::parse(&wire).unwrap(),
            Protocol::Udp,
            outcome,
            &mut response,
            signing,
            |e| panic!("{e}"),
        );
        assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOTAUTH);
        let tsig = pharos_proto::TsigRecord::parse(&response).unwrap();
        assert_eq!(tsig.error, code);
        assert!(tsig.mac.is_empty());
    }
}

#[tokio::test]
async fn badkey_edns_response_keeps_opt_before_tsig() {
    let blocks = parse("Corefile", ". {\n tsig\n whoami\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let key = TsigKey::new(
        "missing.".parse().unwrap(),
        TsigAlgorithm::Sha256,
        b"secret",
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut wire = Vec::with_capacity(512);
    wire.extend_from_slice(&[
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, b'a', 0, 0, 1, 0, 1, 0, 0, 41, 0x04, 0xd0, 0, 0,
        0x80, 0, 0, 0,
    ]);
    key.sign(&mut wire, now, 300, None).unwrap();
    let query = Message::parse(&wire).unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [];
    let mut cx = Context {
        query,
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    let outcome = configured[0].config.serve(&mut cx).await;
    let signing = cx.metadata.take_tsig_signing();
    pharos_server::finish_outcome_signed(
        query,
        Protocol::Udp,
        outcome,
        &mut response,
        signing,
        |e| panic!("{e}"),
    );
    let message = Message::parse(&response).unwrap();
    assert!(message.opt().is_some());
    assert_eq!(
        pharos_proto::TsigRecord::parse(&response).unwrap().error,
        17
    );
}

#[tokio::test]
async fn valid_signed_query_produces_signed_response() {
    let blocks = parse(
        "Corefile",
        ". {\n tsig {\n secret key. c2VjcmV0\n }\n whoami\n}",
    )
    .unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
    wire.reserve(512);
    key.sign(&mut wire, now, 300, None).unwrap();
    let mac = key.verify(&wire, now, None, 0).unwrap().mac;
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
    assert_eq!(configured[0].config.serve(&mut cx).await, Outcome::Response);
    let signing = cx.metadata.take_tsig_signing();
    pharos_server::finish_outcome_signed(
        Message::parse(&wire).unwrap(),
        Protocol::Udp,
        Outcome::Response,
        &mut response,
        signing,
        |e| panic!("{e}"),
    );
    key.verify(&response, now, Some(mac), 0).unwrap();
}

#[tokio::test]
async fn require_applies_only_to_matching_domains_and_types() {
    let blocks = parse(
        "Corefile",
        ". {\n tsig example.com {\n require A\n }\n whoami\n}",
    )
    .unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let domain: Name = ".".parse().unwrap();
    for (name, typ, expected) in [
        (b"example".as_slice(), 1, Rcode::REFUSED),
        (b"example", 28, Rcode::NOERROR),
        (b"other", 1, Rcode::NOERROR),
    ] {
        let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, name.len() as u8];
        wire.extend_from_slice(name);
        wire.extend_from_slice(&[3, b'c', b'o', b'm', 0, 0, typ, 0, 1]);
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
        let outcome = configured[0].config.serve(&mut cx).await;
        if expected == Rcode::REFUSED {
            assert_eq!(outcome, Outcome::Unanswered(expected));
        } else {
            assert_eq!(outcome, Outcome::Response);
            assert_eq!(Message::parse(&response).unwrap().rcode(), expected);
        }
    }
}

#[test]
fn setup_accepts_coredns_requirement_options() {
    for directive in [
        "tsig {\n secret name.key. test-key\n require all\n}",
        "tsig example.com {\n require A AAAA\n require_opcode UPDATE NOTIFY\n}",
        "tsig {\n require none\n require_opcode none\n}",
    ] {
        let source = format!(". {{\n {directive}\n}}");
        let blocks = parse("Corefile", &source).unwrap();
        assert!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            "{directive}"
        );
    }
}

#[test]
fn setup_rejects_coredns_invalid_options() {
    for directive in [
        "tsig {\n blah\n}",
        "tsig {\n secret name. too many parameters\n}",
        "tsig {\n require\n}",
        "tsig {\n require invalid-qtype\n}",
        "tsig {\n require_opcode\n}",
        "tsig {\n require_opcode INVALID\n}",
        "tsig {\n secret key. c2VjcmV0\n secret KEY c2VjcmV0\n}",
    ] {
        let source = format!(". {{\n {directive}\n}}");
        let blocks = parse("Corefile", &source).unwrap();
        assert!(
            configure::<Chain>(&blocks, directives()).is_err(),
            "{directive}"
        );
    }
}

#[tokio::test]
async fn badtime_response_is_signed_and_contains_server_time() {
    use pharos_server::{Action, Handler};
    let blocks = parse(
        "Corefile",
        ".:53 {\n tsig {\n secret key. c2VjcmV0\n }\n whoami\n}",
    )
    .unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let (servers, _) = pharos_plugins::servers(configured).unwrap();
    let server = servers.values().next().unwrap();
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut wire = Vec::with_capacity(512);
    wire.extend_from_slice(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1]);
    key.sign(&mut wire, now - 600, 300, None).unwrap();
    let mac = pharos_proto::TsigRecord::parse(&wire).unwrap().mac;
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server
            .handle(
                &wire,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
        Action::Respond
    );
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.rcode(), Rcode::NOTAUTH);
    let tsig = pharos_proto::TsigRecord::parse(&response).unwrap();
    assert_eq!(tsig.error, 18);
    assert_eq!(tsig.time_signed, now - 600);
    assert_eq!(tsig.other.len(), 6);
    assert_eq!(
        key.verify(&response, now, Some(mac), 0).unwrap_err(),
        pharos_proto::TsigError::BadTime
    );
}

#[tokio::test]
async fn accepts_all_coredns_hmac_algorithms_and_rejects_md5() {
    use pharos_server::{Action, Handler};
    let blocks = parse(
        "Corefile",
        ".:53 {\n tsig {\n secret testkey. c2VjcmV0\n }\n whoami\n}",
    )
    .unwrap();
    let (servers, _) =
        pharos_plugins::servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for algorithm in [
        TsigAlgorithm::Sha1,
        TsigAlgorithm::Sha224,
        TsigAlgorithm::Sha256,
        TsigAlgorithm::Sha384,
        TsigAlgorithm::Sha512,
    ] {
        let key = TsigKey::new("testkey.".parse().unwrap(), algorithm, b"secret");
        let mut wire = Vec::with_capacity(512);
        wire.extend_from_slice(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1]);
        key.sign(&mut wire, now, 300, None).unwrap();
        let mac = pharos_proto::TsigRecord::parse(&wire).unwrap().mac;
        let mut response = Vec::with_capacity(512);
        assert_eq!(
            server
                .handle(
                    &wire,
                    "127.0.0.1:1234".parse().unwrap(),
                    Protocol::Udp,
                    &mut response
                )
                .await,
            Action::Respond
        );
        key.verify(&response, now, Some(mac), 0).unwrap();
    }
    // CoreDNS v1.15.0 returns unsigned BADSIG for a known HMAC-MD5 key.
    let fixture = concat!(
        "c60001000001000000000001076578616d706c6503636f6d0000060001",
        "07746573746b65790000fa00ff00000000003a08686d61632d6d6435",
        "077369672d616c670372656703696e740000005f0f9043012c0010",
        "6fcce0af04e944c869df97e77a608e3dc60000000000"
    );
    let wire: Vec<u8> = fixture
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server
            .handle(
                &wire,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOTAUTH);
    let tsig = pharos_proto::TsigRecord::parse(&response).unwrap();
    assert_eq!(tsig.error, 16);
    assert!(tsig.mac.is_empty());
}

#[tokio::test]
async fn coredns_serve_dns_requirement_and_next_cases() {
    struct Next {
        signed: bool,
        extra: u16,
    }
    impl pharos_server::Next for Next {
        async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
            assert_eq!(
                pharos_plugins::tsig::validated_key_name(cx).is_some(),
                self.signed
            );
            assert_eq!(cx.query.additional_count(), self.extra);
            Outcome::Unanswered(Rcode::SERVFAIL)
        }
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let domain: Name = ".".parse().unwrap();
    for (zone, require, qtype, opcode, signed, refused, authenticated) in [
        (".", "require all", 1, 0, true, false, true),
        (".", "require all", 1, 0, false, true, false),
        ("other.", "require all", 1, 0, false, false, false),
        ("other.", "require all", 1, 0, true, false, false),
        (".", "require AXFR", 252, 0, true, false, true),
        (".", "require none", 1, 0, false, false, false),
        (".", "require none", 1, 0, true, false, true),
        (".", "require_opcode UPDATE", 6, 5, true, false, true),
        (".", "require_opcode UPDATE", 6, 5, false, true, false),
        (".", "require_opcode UPDATE", 1, 0, false, false, false),
        (".", "require_opcode NOTIFY", 6, 4, true, false, true),
        (".", "require_opcode all", 1, 0, false, true, false),
    ] {
        let source = format!(". {{\n tsig {zone} {{\n secret key. c2VjcmV0\n {require}\n }}\n}}");
        let blocks = parse("Corefile", &source).unwrap();
        let configured = configure::<Chain>(&blocks, directives()).unwrap();
        let mut wire = Vec::with_capacity(512);
        wire.extend_from_slice(&[
            0,
            1,
            opcode << 3,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            1,
            1,
            b'a',
            0,
            0,
            qtype,
            0,
            1,
            0,
            0,
            41,
            4,
            208,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        if signed {
            key.sign(&mut wire, now, 300, None).unwrap();
        }
        let mut response = Vec::with_capacity(1232);
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
            max_response_size: 1232,
        };
        let result = pharos_server::Plugin::serve(
            configured[0].config.tsig.as_ref().unwrap(),
            &mut cx,
            Next {
                signed: authenticated,
                extra: 1 + u16::from(signed && !authenticated),
            },
        )
        .await;
        assert_eq!(
            result,
            Outcome::Unanswered(if refused {
                Rcode::REFUSED
            } else {
                Rcode::SERVFAIL
            }),
            "{source}"
        );
        assert_eq!(cx.metadata.take_tsig_signing().is_some(), authenticated);
    }
}

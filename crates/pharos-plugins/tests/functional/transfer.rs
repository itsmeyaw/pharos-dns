#![forbid(unsafe_code)]
#![cfg(feature = "plugin-transfer")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, transfer::Transferer};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Protocol, Stream, Transport};

struct Provider;
impl Transferer for Provider {
    fn bind_transfer(&self, _: Option<&pharos_plugins::transfer::Transfer>) {}

    fn transfer(
        &self,
        _: Name,
        _: u32,
        _: u16,
        _: Type,
        _: Class,
    ) -> Result<Option<Stream>, pharos_server::Error> {
        Ok(Some(Stream::new(|_| Ok(false))))
    }
}

struct DropNext;
impl Next for DropNext {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Drop
    }
}

// Derived from CoreDNS v1.15.0 plugin/transfer/transfer_test.go.
#[tokio::test]
async fn transfer_acl_and_zone_selection() {
    let config = ".:53 {\n transfer example.org {\n to 127.0.0.1\n }\n}";
    let blocks = parse("Corefile", config).unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let transfer = chain.transfer.as_ref().unwrap();
    let root: Name = ".".parse().unwrap();
    for (name, kind, client, protocol, expected) in [
        ("example.org.", Type::AXFR, "127.0.0.1:42", Protocol::Tcp, 0),
        (
            "example.org.",
            Type::AXFR,
            "[::ffff:127.0.0.1]:42",
            Protocol::Tcp,
            0,
        ),
        ("example.org.", Type::AXFR, "127.0.0.2:42", Protocol::Tcp, 1),
        (
            "elsewhere.org.",
            Type::AXFR,
            "127.0.0.1:42",
            Protocol::Tcp,
            2,
        ),
        ("example.org.", Type::A, "127.0.0.1:42", Protocol::Tcp, 2),
        ("example.org.", Type::AXFR, "127.0.0.1:42", Protocol::Udp, 1),
    ] {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 3, 0).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: client.parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let outcome = transfer
            .serve_with(&mut cx, DropNext, Some(&Provider))
            .await;
        match expected {
            0 => assert!(matches!(outcome, Outcome::Stream(_))),
            1 => assert_eq!(outcome, Outcome::Unanswered(Rcode::REFUSED)),
            _ => assert_eq!(outcome, Outcome::Drop),
        }
    }
}

#[tokio::test]
async fn notify_uses_to_addresses_and_source() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let config =
        format!(".:53 {{\n transfer example.org {{\n to * {address}\n source 127.0.0.1\n }}\n}}");
    let blocks = parse("Corefile", &config).unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let responder = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
        let message = Message::parse(&wire[..len]).unwrap();
        assert_eq!(message.opcode(), pharos_proto::Opcode::NOTIFY);
        assert_eq!(
            message.questions().next().unwrap().name.to_string(),
            "example.org."
        );
        assert_eq!(peer.ip().to_string(), "127.0.0.1");
        wire[2] |= 0x80;
        socket.send_to(&wire[..len], peer).await.unwrap();
    });
    chain
        .transfer
        .unwrap()
        .notify(&"example.org.".parse().unwrap())
        .await
        .unwrap();
    responder.await.unwrap();
}

// CoreDNS compares the text of the configured host to the client's normalized IP.
#[tokio::test]
async fn acl_does_not_normalize_configured_ipv6_text() {
    let blocks = parse("Corefile", ". {\n transfer {\n to 2001:0db8::1\n }\n}").unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let wire = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 252, 0, 1];
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::new();
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "[2001:db8::1]:42".parse().unwrap(),
        local: "[::1]:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Tcp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .transfer
            .unwrap()
            .serve_with(&mut cx, DropNext, Some(&Provider))
            .await,
        Outcome::Unanswered(Rcode::REFUSED)
    );
}

// Derived from CoreDNS v1.15.0 plugin/transfer/notify_test.go, TestNotifyMultipleFailures.
#[tokio::test]
async fn notify_reports_each_secondary_failure() {
    let first = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first.local_addr().unwrap();
    let second_addr = second.local_addr().unwrap();
    let respond = |socket: tokio::net::UdpSocket| {
        tokio::spawn(async move {
            let mut wire = [0; 512];
            for _ in 0..3 {
                let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
                wire[2] |= 0x80;
                wire[3] = 5;
                socket.send_to(&wire[..len], peer).await.unwrap();
            }
        })
    };
    let first_task = respond(first);
    let second_task = respond(second);
    let config = format!(".:53 {{\n transfer {{\n to {first_addr} {second_addr}\n }}\n}}");
    let blocks = parse("Corefile", &config).unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let error = chain
        .transfer
        .unwrap()
        .notify(&"example.org.".parse().unwrap())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains(&first_addr.to_string()), "{error}");
    assert!(error.contains(&second_addr.to_string()), "{error}");
    first_task.await.unwrap();
    second_task.await.unwrap();
}

#[tokio::test]
async fn ixfr_passes_requested_serial_and_rejects_missing_soa() {
    struct SerialProvider(std::sync::atomic::AtomicU32);
    impl Transferer for SerialProvider {
        fn bind_transfer(&self, _: Option<&pharos_plugins::transfer::Transfer>) {}

        fn transfer(
            &self,
            _: Name,
            serial: u32,
            _: u16,
            _: Type,
            _: Class,
        ) -> Result<Option<Stream>, pharos_server::Error> {
            self.0.store(serial, std::sync::atomic::Ordering::Relaxed);
            Ok(Some(Stream::new(|_| Ok(false))))
        }
    }
    let blocks = parse("Corefile", ". {\n transfer {\n to *\n }\n}").unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let provider = SerialProvider(std::sync::atomic::AtomicU32::new(0));
    let zone: Name = "example.org.".parse().unwrap();
    let name = NameRef::parse(zone.as_wire(), 0).unwrap();
    for include_soa in [false, true] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
        builder.question(name, Type::IXFR, Class::IN).unwrap();
        if include_soa {
            builder
                .record_with(Section::Authority, name, Type::SOA, Class::IN, 0, |w| {
                    w.write_name(name)?;
                    w.write_name(name)?;
                    for field in [12345_u32, 7200, 1800, 86400, 300] {
                        w.write_bytes(&field.to_be_bytes())?;
                    }
                    Ok(())
                })
                .unwrap();
        }
        let _ = builder.finish();
        let mut response = Vec::new();
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:42".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Tcp,
            domain: &zone,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let result = chain
            .transfer
            .as_ref()
            .unwrap()
            .serve_with(&mut cx, DropNext, Some(&provider))
            .await;
        if include_soa {
            assert!(matches!(result, Outcome::Stream(_)));
            assert_eq!(provider.0.load(std::sync::atomic::Ordering::Relaxed), 12345);
        } else {
            assert_eq!(result, Outcome::Unanswered(Rcode::SERVFAIL));
        }
    }
}

// Derived from CoreDNS v1.15.0 plugin/transfer/select_test.go, TestZoneSelection.
#[tokio::test]
async fn most_specific_zone_controls_acl() {
    let config = ". {\n transfer example.org {\n to 192.0.2.1\n }\n transfer sub.example.org {\n to *\n }\n}";
    let blocks = parse("Corefile", config).unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let name: Name = "sub.example.org.".parse().unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::AXFR,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::new();
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:42".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Tcp,
        domain: &name,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert!(matches!(
        chain
            .transfer
            .unwrap()
            .serve_with(&mut cx, DropNext, Some(&Provider))
            .await,
        Outcome::Stream(_)
    ));
}

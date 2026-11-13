use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

#[tokio::test]
async fn serves_seed_zone() {
    let seed = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let text = format!(
        "example.org:53 {{\n dynupdate {{\n  file {seed}\n  allow key.example.org. * A\n }}\n}}"
    );
    let blocks = parse("Corefile", &text).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let domain: Name = "example.org.".parse().unwrap();
    let owner: Name = "www.example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(owner.as_wire(), 0).unwrap(),
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
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answer_count(), 1);
}

#[tokio::test]
async fn malformed_empty_a_update_is_rejected() {
    let seed = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let text = format!(
        "example.org:53 {{\n dynupdate {{\n file {seed}\n allow key.example.org. * A\n }}\n}}"
    );
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let domain: Name = "example.org.".parse().unwrap();
    let owner: Name = "new.example.org.".parse().unwrap();
    let key: Name = "key.example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x2800).unwrap();
    builder
        .question(
            NameRef::parse(domain.as_wire(), 0).unwrap(),
            Type::SOA,
            Class::IN,
        )
        .unwrap();
    builder
        .record(
            Section::Authority,
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
            60,
            &[],
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut metadata = Metadata::new(&mut slots);
    metadata.set_validated_tsig(&key);
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata,
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(configured[0].config.serve(&mut cx).await, Outcome::Response);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::FORMERR);
}

#[tokio::test]
async fn coredns_update_authentication_and_other_zone_cases() {
    let seed = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let text = format!(
        ".:53 {{\n dynupdate example.org. {{\n file {seed}\n allow key.example.org. allowed.example.org. A\n }}\n}}"
    );
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let domain: Name = ".".parse().unwrap();
    for (zone, key, owner, expected) in [
        ("other.test.", None, "allowed.example.org.", Rcode::NOTAUTH),
        ("example.org.", None, "allowed.example.org.", Rcode::REFUSED),
        (
            "example.org.",
            Some("other.example.org."),
            "allowed.example.org.",
            Rcode::REFUSED,
        ),
        (
            "example.org.",
            Some("key.example.org."),
            "blocked.example.org.",
            Rcode::REFUSED,
        ),
        (
            "example.org.",
            Some("key.example.org."),
            "allowed.example.org.",
            Rcode::NOERROR,
        ),
    ] {
        let zone: Name = zone.parse().unwrap();
        let owner: Name = owner.parse().unwrap();
        let key: Option<Name> = key.map(|key| key.parse().unwrap());
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x2800).unwrap();
        builder
            .question(
                NameRef::parse(zone.as_wire(), 0).unwrap(),
                Type::SOA,
                Class::IN,
            )
            .unwrap();
        builder
            .record(
                Section::Authority,
                NameRef::parse(owner.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
                60,
                &[192, 0, 2, 10],
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
        let mut metadata = Metadata::new(&mut slots);
        if let Some(key) = &key {
            metadata.set_validated_tsig(key);
        }
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata,
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(configured[0].config.serve(&mut cx).await, Outcome::Response);
        assert_eq!(Message::parse(&response).unwrap().rcode(), expected);
    }
}

#[test]
fn coredns_rejects_invalid_seed_zones() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynupdate-invalid-seed-{}",
            std::process::id()
        ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("seed");
    for zone in [
        "@ 60 IN NS ns.example.org.\n",
        "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n@ 60 IN SOA ns.example.org. hostmaster.example.org. 11 60 60 60 60\n",
        "@ 60 IN SOA ns.example.org. hostmaster.example.org. 0 60 60 60 60\n",
        "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\nalias 60 IN CNAME target.example.org.\nalias 60 IN A 192.0.2.20\n",
    ] {
        std::fs::write(&path, zone).unwrap();
        let text = format!(
            "example.org:53 {{\n dynupdate {{\n file {}\n allow key.example.org. * A\n }}\n}}",
            path.display()
        );
        assert!(
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).is_err(),
            "{zone}"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn duplicate_directive_does_not_create_database() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("pharos-dynupdate-duplicate-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let seed = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let database = dir.join("db");
    let text = format!(
        "example.org:53 {{\n dynupdate {{\n file {seed}\n database {}\n allow key.example.org. * A\n }}\n dynupdate {{\n file {seed}\n allow key.example.org. * A\n }}\n}}",
        database.display()
    );
    assert!(configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).is_err());
    assert!(!database.exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn authenticated_update_is_visible_to_subsequent_query() {
    let seed = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let text = format!(
        "example.org:53 {{\n dynupdate {{\n  file {seed}\n  allow key.example.org. * A\n }}\n}}"
    );
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let domain: Name = "example.org.".parse().unwrap();
    let key: Name = "key.example.org.".parse().unwrap();
    let host: Name = "new.example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x2910).unwrap();
    builder
        .question(
            NameRef::parse(domain.as_wire(), 0).unwrap(),
            Type::SOA,
            Class::IN,
        )
        .unwrap();
    builder
        .record(
            Section::Authority,
            NameRef::parse(host.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
            60,
            &[192, 0, 2, 99],
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut metadata = Metadata::new(&mut slots);
    metadata.set_validated_tsig(&key);
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata,
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(configured[0].config.serve(&mut cx).await, Outcome::Response);
    let update_response = Message::parse(&response).unwrap();
    assert_eq!(update_response.rcode(), Rcode::NOERROR);
    assert_eq!(update_response.flags() & 0x0110, 0);
    wire.clear();
    let mut builder = MessageBuilder::new(&mut wire, 512, 2, 0).unwrap();
    builder
        .question(
            NameRef::parse(host.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
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
    let answer = Message::parse(&response).unwrap();
    assert_eq!(answer.rcode(), Rcode::NOERROR);
    assert_eq!(answer.answers().next().unwrap().rdata, &[192, 0, 2, 99]);
    #[cfg(feature = "plugin-transfer")]
    {
        use pharos_plugins::transfer::{TransferRequest, Transferer};
        let plugin = configured[0].config.dynupdate.as_ref().unwrap();
        let mut stream = plugin
            .transfer(TransferRequest {
                zone: NameRef::parse(domain.as_wire(), 0).unwrap(),
                serial: 0,
                id: 3,
                flags: 0,
                protocol: Protocol::Tcp,
                qtype: Type::AXFR,
                qclass: Class::IN,
            })
            .unwrap()
            .unwrap();
        let mut wire = Vec::with_capacity(65535);
        let mut found = false;
        while stream.next(&mut wire).unwrap() {
            let message = Message::parse(&wire).unwrap();
            found |= message
                .answers()
                .any(|rr| rr.name == host && rr.rdata == [192, 0, 2, 99]);
        }
        assert!(found);
    }
}

#[cfg(all(feature = "plugin-tsig", feature = "plugin-cache"))]
#[tokio::test]
async fn signed_update_bypasses_negative_cache_through_listener() {
    use pharos_proto::{TsigAlgorithm, TsigKey};
    use pharos_server::{Action, Handler};
    let seed = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let text = format!(
        "example.org:53 {{\n cache\n tsig {{\n  secret key.example.org. c2VjcmV0\n  require_opcode UPDATE\n }}\n dynupdate {{\n  file {seed}\n  allow key.example.org. * A\n }}\n}}"
    );
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let (servers, _) = pharos_plugins::servers(configured).unwrap();
    let server = servers.values().next().unwrap();
    let zone: Name = "example.org.".parse().unwrap();
    let host: Name = "new.example.org.".parse().unwrap();
    let key = TsigKey::new(
        "key.example.org.".parse().unwrap(),
        TsigAlgorithm::Sha256,
        b"secret",
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(host.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let peer = "127.0.0.1:1234".parse().unwrap();
    assert_eq!(
        Box::pin(server.handle(&query, peer, Protocol::Udp, &mut response)).await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NXDOMAIN);
    let mut update = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut update, 512, 2, 0x2800).unwrap();
    builder
        .question(
            NameRef::parse(zone.as_wire(), 0).unwrap(),
            Type::SOA,
            Class::IN,
        )
        .unwrap();
    builder
        .record(
            Section::Authority,
            NameRef::parse(host.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
            60,
            &[192, 0, 2, 99],
        )
        .unwrap();
    let _ = builder.finish();
    key.sign(&mut update, now, 300, None).unwrap();
    let mac = key.verify(&update, now, None, 0).unwrap().mac;
    assert_eq!(
        Box::pin(server.handle(&update, peer, Protocol::Udp, &mut response)).await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOERROR);
    key.verify(&response, now, Some(mac), 0).unwrap();
    assert_eq!(
        Box::pin(server.handle(&query, peer, Protocol::Udp, &mut response)).await,
        Action::Respond
    );
    let result = Message::parse(&response).unwrap();
    assert_eq!(result.rcode(), Rcode::NOERROR);
    assert_eq!(result.answers().next().unwrap().rdata, &[192, 0, 2, 99]);
}

#[cfg(feature = "plugin-transfer")]
#[tokio::test]
async fn changed_zone_sends_notify() {
    use pharos_plugins::transfer::Transferer;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = socket.local_addr().unwrap();
    let seed = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let text = format!(
        "example.org:53 {{\n transfer {{\n  to {destination}\n }}\n dynupdate {{\n  file {seed}\n  allow key.example.org. * A\n }}\n}}"
    );
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let chain = &configured[0].config;
    chain
        .dynupdate
        .as_ref()
        .unwrap()
        .bind_transfer(chain.transfer.as_ref());
    let domain: Name = "example.org.".parse().unwrap();
    let key: Name = "key.example.org.".parse().unwrap();
    let host: Name = "new.example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x2800).unwrap();
    builder
        .question(
            NameRef::parse(domain.as_wire(), 0).unwrap(),
            Type::SOA,
            Class::IN,
        )
        .unwrap();
    builder
        .record(
            Section::Authority,
            NameRef::parse(host.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
            60,
            &[192, 0, 2, 99],
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut metadata = Metadata::new(&mut slots);
    metadata.set_validated_tsig(&key);
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata,
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    let mut packet = [0; 512];
    let (len, peer) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv_from(&mut packet),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        Message::parse(&packet[..len]).unwrap().opcode(),
        pharos_proto::Opcode::NOTIFY
    );
    packet[2] |= 0x80;
    socket.send_to(&packet[..len], peer).await.unwrap();
}

#[cfg(feature = "plugin-transfer")]
#[tokio::test]
async fn notify_coalesces_changes_while_one_is_in_flight() {
    use pharos_plugins::transfer::Transferer;
    async fn update(chain: &Chain, index: u8) {
        let domain: Name = "example.org.".parse().unwrap();
        let key: Name = "key.example.org.".parse().unwrap();
        let owner: Name = format!("host-{index}.example.org.").parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, u16::from(index), 0x2800).unwrap();
        builder
            .question(
                NameRef::parse(domain.as_wire(), 0).unwrap(),
                Type::SOA,
                Class::IN,
            )
            .unwrap();
        builder
            .record(
                Section::Authority,
                NameRef::parse(owner.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
                60,
                &[192, 0, 2, index],
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
        let mut metadata = Metadata::new(&mut slots);
        metadata.set_validated_tsig(&key);
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata,
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(Box::pin(chain.serve(&mut cx)).await, Outcome::Response);
        assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOERROR);
    }
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = socket.local_addr().unwrap();
    let seed = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let text = format!(
        "example.org:53 {{\n transfer {{\n to {destination}\n }}\n dynupdate {{\n file {seed}\n allow key.example.org. * A\n }}\n}}"
    );
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let chain = &configured[0].config;
    chain
        .dynupdate
        .as_ref()
        .unwrap()
        .bind_transfer(chain.transfer.as_ref());
    update(chain, 1).await;
    let mut first = [0; 512];
    let (len, peer) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv_from(&mut first),
    )
    .await
    .unwrap()
    .unwrap();
    update(chain, 2).await;
    update(chain, 3).await;
    let mut next = [0; 512];
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            socket.recv_from(&mut next)
        )
        .await
        .is_err()
    );
    first[2] |= 0x80;
    socket.send_to(&first[..len], peer).await.unwrap();
    let (len, peer) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv_from(&mut next),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        Message::parse(&next[..len]).unwrap().opcode(),
        pharos_proto::Opcode::NOTIFY
    );
    next[2] |= 0x80;
    socket.send_to(&next[..len], peer).await.unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            socket.recv_from(&mut next)
        )
        .await
        .is_err()
    );
}

#[cfg(feature = "plugin-file")]
#[tokio::test]
async fn coredns_external_cname_uses_self_lookup() {
    use pharos_server::{Action, Handler};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("pharos-dynamic-cname-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let seed = dir.join("seed");
    std::fs::write(&seed, "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\nalias 60 IN CNAME leaf.external.test.\n").unwrap();
    let external = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/external.zone"
    );
    let text = format!(
        ".:0 {{\n dynupdate example.org. {{\n file {}\n allow key.example.org. * A\n }}\n file {external} external.test {{\n reload 0\n }}\n}}",
        seed.display()
    );
    let (mut servers, _) = pharos_plugins::servers(
        configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap(),
    )
    .unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let owner: Name = "alias.example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        Box::pin(server.handle(
            &wire,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response
        ))
        .await,
        Action::Respond
    );
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(
        message.answers().map(|rr| rr.rtype).collect::<Vec<_>>(),
        [Type::CNAME, Type::A]
    );
    assert_eq!(message.answers().last().unwrap().rdata, [192, 0, 2, 88]);
    drop(server);
    std::fs::remove_dir_all(dir).unwrap();
}

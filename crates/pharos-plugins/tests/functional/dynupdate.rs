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

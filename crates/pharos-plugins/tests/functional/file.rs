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
    let zonefile = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/file/example.zone");
    let corefile = format!("example.org:53 {{\n file {zonefile}\n}}");
    let blocks = parse("Corefile", &corefile).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let plugin = configured[0].config.file.as_ref().unwrap();
    let apex: Name = "example.org.".parse().unwrap();
    for (kind, serial, expected) in [(Type::AXFR, 0, 2), (Type::IXFR, 1, 1)] {
        let mut stream = plugin.transfer(TransferRequest {
            zone: NameRef::parse(apex.as_wire(), 0).unwrap(), serial, id: 1, flags: 0,
            protocol: Protocol::Tcp, qtype: kind, qclass: Class::IN,
        }).unwrap().unwrap();
        let mut wire = Vec::with_capacity(65535);
        let mut types = Vec::new();
        while stream.next(&mut wire).unwrap() {
            let message = Message::parse(&wire).unwrap();
            types.extend(message.answers().map(|record| record.rtype));
        }
        assert_eq!(types.first(), Some(&Type::SOA));
        assert_eq!(types.last(), Some(&Type::SOA));
        assert_eq!(types.iter().filter(|kind| **kind == Type::SOA).count(), expected);
    }
}

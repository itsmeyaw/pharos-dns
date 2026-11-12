use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

#[test]
fn coredns_auto_setup_cases() {
    for (body, valid) in [
        ("directory /tmp", true),
        ("directory /tmp (.*) {1}\n reload 0", true),
        ("directory /tmp\n upstream 8.8.8.8", true),
        ("directory /tmp (.*)", false),
        ("directory /tmp (.*) {1} extra", false),
        ("directory /tmp abc {1}", false),
        ("directory /tmp\n fallthrough", false),
        ("directory /tmp\n reload -1s", false),
        ("directory /tmp\n reload", false),
        ("directory /tmp\n reload 0 extra", true),
    ] {
        let text = format!("example.org:53 {{\n auto {{\n {body}\n }}\n}}");
        let blocks = parse("Corefile", &text).unwrap();
        assert_eq!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            valid,
            "{body}"
        );
    }
    let large = "a".repeat(10001);
    let text = format!("example.org:53 {{\n auto {{\n directory /tmp {large} {{1}}\n }}\n}}");
    assert!(configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).is_err());
}

#[tokio::test]
async fn serves_zone_loaded_on_startup() {
    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
    use pharos_server::{Context, Metadata, Outcome, Phase, Protocol, Transport};
    let root = std::env::temp_dir().join(format!("pharos-auto-functional-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("db.example.org"),
        "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\nwww 60 IN A 192.0.2.1\n",
    )
    .unwrap();
    let text = format!(
        "example.org:53 {{\n auto {{\n directory {}\n reload 0\n }}\n}}",
        root.display()
    );
    let blocks = parse("Corefile", &text).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let chain = &configured[0].config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    let name: Name = "www.example.org.".parse().unwrap();
    let domain: Name = "example.org.".parse().unwrap();
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
    assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().next().unwrap().rdata, [192, 0, 2, 1]);
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "plugin-transfer")]
#[tokio::test]
async fn sends_notify_on_startup_and_rescan() {
    use pharos_plugins::servers;
    use pharos_proto::{Message, Opcode};
    use pharos_server::Phase;
    let root = std::env::temp_dir().join(format!("pharos-auto-notify-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("db.example.org"),
        "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\n",
    )
    .unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let receiver = tokio::spawn(async move {
        for _ in 0..2 {
            let mut wire = [0; 512];
            let (len, peer) = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                socket.recv_from(&mut wire),
            )
            .await
            .unwrap()
            .unwrap();
            let notify = Message::parse(&wire[..len]).unwrap();
            assert_eq!(notify.opcode(), Opcode::NOTIFY);
            assert_eq!(
                notify.questions().next().unwrap().name.to_string(),
                "example.org."
            );
            wire[2] |= 0x80;
            socket.send_to(&wire[..len], peer).await.unwrap();
        }
    });
    let text = format!(
        "example.org:0 {{\n auto {{\n directory {}\n reload 20ms\n }}\n transfer {{\n to {address}\n }}\n}}",
        root.display()
    );
    let (_, lifecycle) =
        servers(configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap())
            .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    receiver.await.unwrap();
    lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

#[test]
fn coredns_auto_setup_cases() {
    for (body, valid) in [
        ("directory /tmp", true),
        ("directory /tmp (.*) {1}\n reload 0", true),
        ("directory /tmp\n upstream 8.8.8.8", true),
        ("directory /tmp\n upstream", true),
        ("directory /tmp (.*) bliep\n reload 10s", true),
        ("directory /nonexistent/pharos-auto", true),
        ("directory", false),
        ("directory /tmp * {1}", false),
        ("directory /tmp\n no_reload", false),
        ("directory /tmp\n transfer to 127.0.0.1", false),
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

#[cfg(all(feature = "plugin-prometheus", feature = "plugin-whoami"))]
#[tokio::test]
async fn discovered_zones_label_metrics_and_removed_series_remain() {
    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
    use pharos_server::{Action, Handler, Phase, Protocol, metrics::Registry};
    use std::time::Duration;

    async fn query(server: &impl Handler, name: &str) -> u16 {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
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
        Message::parse(&response).unwrap().answer_count()
    }

    fn count(registry: &Registry, zone: &str) -> u64 {
        let mut text = String::new();
        registry.encode(&mut text);
        let suffix = format!("zone=\"{zone}\"}}");
        text.lines()
            .filter(|line| {
                line.starts_with("pharos_dns_requests_total{")
                    && line.contains("type=\"A\"")
                    && line.contains(&suffix)
            })
            .map(|line| line.rsplit_once(' ').unwrap().1.parse::<u64>().unwrap())
            .sum()
    }

    let root = std::env::temp_dir().join(format!("pharos-auto-metrics-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let first = root.join("db.example.org");
    for path in [
        &first,
        &root.join("db.example.net"),
        &root.join("db.sub.example.org"),
        &root.join("db.UPPER.org"),
    ] {
        std::fs::write(
            path,
            "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\nwww 60 IN A 192.0.2.1\n",
        )
        .unwrap();
    }
    let text = format!(
        ".:0 {{\n prometheus 127.0.0.1:0\n auto {{\n  directory {}\n  reload 20ms\n }}\n whoami\n}}",
        root.display()
    );
    let registry = Registry::default();
    let (mut servers, lifecycle) = pharos_plugins::servers_with_registry(
        configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap(),
        registry.clone(),
    )
    .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();
    assert_eq!(query(&server, "www.example.org.").await, 1);
    assert_eq!(query(&server, "www.example.net.").await, 1);
    assert_eq!(query(&server, "WWW.SUB.EXAMPLE.ORG.").await, 1);
    assert_eq!(query(&server, "www.upper.org.").await, 1);
    assert_eq!(query(&server, "other.test.").await, 0);
    assert_eq!(count(&registry, "example.org."), 1);
    assert_eq!(count(&registry, "example.net."), 1);
    assert_eq!(count(&registry, "sub.example.org."), 1);
    assert_eq!(count(&registry, "UPPER.org."), 1);
    assert_eq!(count(&registry, "."), 1);
    let mut metrics = String::new();
    registry.encode(&mut metrics);
    assert!(
        metrics.lines().any(
            |line| line.starts_with("pharos_dns_responses_total{plugin=\"auto\"")
                && line.contains("zone=\"example.org.\"} 1")
        ),
        "{metrics}"
    );
    assert!(
        metrics.lines().any(|line| line
            .starts_with("pharos_dns_responses_total{plugin=\"whoami\"")
            && line.contains("zone=\".\"} 1")),
        "{metrics}"
    );
    std::fs::remove_file(&first).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while query(&server, "www.example.org.").await != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let old = count(&registry, "example.org.");
    let fallback = count(&registry, ".");
    assert_eq!(query(&server, "www.example.org.").await, 0);
    assert_eq!(count(&registry, "example.org."), old);
    assert_eq!(count(&registry, "."), fallback + 1);
    std::fs::write(
        &first,
        "@ 60 IN SOA ns. hostmaster. 2 2 3 4 5\nwww 60 IN A 192.0.2.1\n",
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while query(&server, "www.example.org.").await != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let restored = count(&registry, "example.org.");
    assert!(restored > old);
    assert_eq!(query(&server, "www.example.org.").await, 1);
    assert_eq!(count(&registry, "example.org."), restored + 1);
    lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(all(
    feature = "plugin-prometheus",
    feature = "plugin-whoami",
    feature = "plugin-view"
))]
#[tokio::test]
async fn discovered_zone_metrics_preserve_inherited_view() {
    use pharos_proto::{Class, MessageBuilder, Name, NameRef, Type};
    use pharos_server::{Action, Handler, Phase, Protocol, metrics::Registry};
    let root =
        std::env::temp_dir().join(format!("pharos-auto-metrics-view-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("db.example.org"),
        "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\n",
    )
    .unwrap();
    let text = format!(
        "example.org:0 {{\n view child {{\n expr true\n }}\n prometheus 127.0.0.1:0\n whoami\n}}\norg:0 {{\n prometheus 127.0.0.1:0\n auto {{\n directory {}\n reload 0\n }}\n}}",
        root.display()
    );
    let registry = Registry::default();
    let (mut servers, lifecycle) = pharos_plugins::servers_with_registry(
        configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap(),
        registry.clone(),
    )
    .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let name: Name = "example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::DS,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
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
    let mut metrics = String::new();
    registry.encode(&mut metrics);
    assert!(metrics.contains("pharos_dns_requests_total{family=\"1\",proto=\"udp\",server=\"dns://:0\",type=\"DS\",view=\"child\",zone=\"example.org.\"} 1"), "{metrics}");
    lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "plugin-prometheus")]
#[tokio::test]
async fn discovered_zone_metrics_include_all_server_block_keys() {
    use pharos_proto::{Class, MessageBuilder, Name, NameRef, Type};
    use pharos_server::{Action, Handler, Phase, Protocol, metrics::Registry};
    let root =
        std::env::temp_dir().join(format!("pharos-auto-metrics-keys-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("db.org"),
        "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\n",
    )
    .unwrap();
    let text = format!(
        "example.org:0 org:0 {{\n prometheus 127.0.0.1:0\n auto {{\n directory {}\n reload 0\n }}\n}}",
        root.display()
    );
    let registry = Registry::default();
    let (mut servers, lifecycle) = pharos_plugins::servers_with_registry(
        configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap(),
        registry.clone(),
    )
    .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let name: Name = "example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::DS,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
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
    let mut metrics = String::new();
    registry.encode(&mut metrics);
    assert!(metrics.contains("pharos_dns_requests_total{family=\"1\",proto=\"udp\",server=\"dns://:0\",type=\"DS\",view=\"\",zone=\"example.org.\"} 1"), "{metrics}");
    lifecycle.run(Phase::Shutdown).await.unwrap();
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

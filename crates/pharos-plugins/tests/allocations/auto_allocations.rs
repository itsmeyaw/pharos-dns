use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Context, Metadata, Outcome, Phase, Protocol, Transport};
use stats_alloc::INSTRUMENTED_SYSTEM;

#[tokio::test]
async fn auto_queries_do_not_allocate() {
    if crate::run_isolated("auto_allocations::auto_queries_do_not_allocate") {
        return;
    }
    let root = std::env::temp_dir().join(format!("pharos-auto-alloc-{}", std::process::id()));
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
    let domain: Name = "example.org.".parse().unwrap();
    let name: Name = "www.example.org.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
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
        query: Message::parse(&query).unwrap(),
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
    let before = INSTRUMENTED_SYSTEM.stats();
    for _ in 0..100 {
        assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    }
    let after = INSTRUMENTED_SYSTEM.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "plugin-prometheus")]
#[tokio::test]
async fn auto_metrics_queries_do_not_allocate() {
    use pharos_server::{Action, Handler};
    if crate::run_isolated("auto_allocations::auto_metrics_queries_do_not_allocate") {
        return;
    }
    let root =
        std::env::temp_dir().join(format!("pharos-auto-metrics-alloc-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("db.example.org"),
        "@ 60 IN SOA ns. hostmaster. 1 2 3 4 5\nwww 60 IN A 192.0.2.1\n",
    )
    .unwrap();
    let text = format!(
        ".:0 {{\n prometheus 127.0.0.1:0\n auto {{\n  directory {}\n  reload 0\n }}\n}}",
        root.display()
    );
    let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let (mut servers, lifecycle) = pharos_plugins::servers(blocks).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let name: Name = "www.example.org.".parse().unwrap();
    let missing: Name = "missing.other.".parse().unwrap();
    let mut missing_query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut missing_query, 512, 2, 0).unwrap();
    builder
        .question(
            NameRef::parse(missing.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let peer = "127.0.0.1:1234".parse().unwrap();
    let first = Box::pin(server.handle(&query, peer, Protocol::Udp, &mut response));
    let before_first = INSTRUMENTED_SYSTEM.stats();
    assert_eq!(first.await, Action::Respond);
    let after_first = INSTRUMENTED_SYSTEM.stats();
    assert_eq!(after_first.allocations - before_first.allocations, 0);
    assert_eq!(after_first.reallocations - before_first.reallocations, 0);
    let before = INSTRUMENTED_SYSTEM.stats();
    for _ in 0..100 {
        assert_eq!(
            server
                .handle(&query, peer, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
        assert_eq!(
            server
                .handle(&missing_query, peer, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
    }
    let after = INSTRUMENTED_SYSTEM.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

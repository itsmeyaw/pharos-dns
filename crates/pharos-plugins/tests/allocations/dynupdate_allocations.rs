use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::INSTRUMENTED_SYSTEM;

#[tokio::test]
async fn warm_dynamic_and_unrelated_cached_queries_do_not_allocate() {
    if crate::run_isolated(
        "dynupdate_allocations::warm_dynamic_and_unrelated_cached_queries_do_not_allocate",
    ) {
        return;
    }
    let root = std::env::temp_dir().join(format!("pharos-dynupdate-alloc-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let database = root.join("database");
    let seed = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let other = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/external.zone"
    );
    let text = format!(
        ".:0 {{\n cache\n dynupdate example.org {{\n file {seed}\n database {}\n allow key.example.org. * A\n }}\n file {other} external.test {{\n reload 0\n }}\n}}",
        database.display()
    );
    let configured = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let (mut servers, _) = servers(configured).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let queries = [
        "www.example.org.",
        "missing.example.org.",
        "leaf.external.test.",
    ]
    .map(|text| {
        let name: Name = text.parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        wire
    });
    let peer = "127.0.0.1:1001".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    for (index, query) in queries.iter().enumerate() {
        assert_eq!(
            server
                .handle(query, peer, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
        assert_eq!(
            Message::parse(&response).unwrap().rcode(),
            if index == 1 {
                Rcode::NXDOMAIN
            } else {
                Rcode::NOERROR
            }
        );
    }
    let before = INSTRUMENTED_SYSTEM.stats();
    for _ in 0..100 {
        for query in &queries {
            assert_eq!(
                server
                    .handle(query, peer, Protocol::Udp, &mut response)
                    .await,
                Action::Respond
            );
        }
    }
    let after = INSTRUMENTED_SYSTEM.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    let mut metrics = String::new();
    server.metrics().encode(&mut metrics);
    assert!(
        metrics
            .contains("pharos_cache_requests_total{server=\"dns://:0\",view=\"\",zones=\".\"} 101"),
        "{metrics}"
    );
    assert!(metrics.contains("pharos_cache_hits_total{server=\"dns://:0\",type=\"success\",view=\"\",zones=\".\"} 100"), "{metrics}");
    drop(server);
    std::fs::remove_dir_all(root).unwrap();
}

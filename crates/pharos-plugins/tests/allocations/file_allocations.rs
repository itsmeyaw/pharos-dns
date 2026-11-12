#![forbid(unsafe_code)]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::INSTRUMENTED_SYSTEM;

#[tokio::test(flavor = "current_thread")]
async fn file_queries_do_not_allocate() {
    if crate::run_isolated("file_allocations::file_queries_do_not_allocate") {
        return;
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let text = format!("example.org:0 {{\n file {path} {{\n reload 0\n }}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let queries = [
        "www.example.org.",
        "alias.example.org.",
        "foo.wild.example.org.",
        "foo.child.example.org.",
        "absent.example.org.",
    ]
    .iter()
    .map(|name| {
        let name: Name = name.parse().unwrap();
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
        query
    })
    .collect::<Vec<_>>();
    let client = "127.0.0.1:1001".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    for query in &queries {
        assert_eq!(
            server
                .handle(query, client, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
    }
    let before = INSTRUMENTED_SYSTEM.stats();
    for _ in 0..100 {
        for query in &queries {
            assert_eq!(
                server
                    .handle(query, client, Protocol::Udp, &mut response)
                    .await,
                Action::Respond
            );
        }
    }
    let after = INSTRUMENTED_SYSTEM.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
}

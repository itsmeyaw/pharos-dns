#![forbid(unsafe_code)]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rdata, Type};
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
        "foo.old.example.org.",
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

#[test]
fn dname_self_lookup_allocates_and_resolves_target() {
    if crate::run_isolated("file_allocations::dname_self_lookup_allocates_and_resolves_target") {
        return;
    }
    // Debug Plugin Chain futures exceed 2 MiB; see #90.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(dname_self_lookup());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn dname_self_lookup() {
    let original = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let external = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/external.zone"
    );
    let text = format!(
        ".:0 {{\n file {original} example.org {{\n reload 0\n }}\n file {external} external.test {{\n reload 0\n }}\n}}"
    );
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let name: Name = "leaf.outside-dname.example.org.".parse().unwrap();
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
    let client = "127.0.0.1:1001".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(&query, client, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    let before = INSTRUMENTED_SYSTEM.stats();
    assert_eq!(
        server
            .handle(&query, client, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    let after = INSTRUMENTED_SYSTEM.stats();
    assert!(after.allocations > before.allocations);
    let response = Message::parse(&response).unwrap();
    assert!(response.answers().any(|record| matches!(record.data(), Ok(Rdata::A(address)) if address == std::net::Ipv4Addr::new(192, 0, 2, 88))));
}

#[cfg(feature = "plugin-metadata")]
#[test]
fn signed_wildcard_and_denial_queries_do_not_allocate() {
    if crate::run_isolated("file_allocations::signed_wildcard_and_denial_queries_do_not_allocate") {
        return;
    }
    // Debug Plugin Chain futures exceed 2 MiB; see #90.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(signed_queries());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[cfg(feature = "plugin-metadata")]
async fn signed_queries() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/dnssex-signed.zone"
    );
    let text = format!("dnssex.nl:0 {{\n metadata\n file {path} {{\n reload 0\n }}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let mut queries = Vec::new();
    for (name, kind) in [
        ("wild.dnssex.nl.", Type::TXT),
        ("wild.dnssex.nl.", Type::SRV),
        ("a.dnssex.nl.", Type::A),
    ] {
        let name: Name = name.parse().unwrap();
        let mut query = Vec::with_capacity(1232);
        let mut builder = MessageBuilder::new(&mut query, 1232, 1, 0x0100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        builder
            .record(
                pharos_proto::Section::Additional,
                NameRef::parse(&[0], 0).unwrap(),
                Type::OPT,
                Class(1232),
                0x8000,
                &[],
            )
            .unwrap();
        let _ = builder.finish();
        queries.push(query);
    }
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

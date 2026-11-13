#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-loadbalance", feature = "plugin-hosts"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Context, Metadata, Outcome, Phase, Protocol, Transport};
use std::sync::atomic::{AtomicUsize, Ordering};

fn file() -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    std::env::temp_dir().join(format!(
        "pharos-loadbalance-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn chain(path: &std::path::Path, reload: &str) -> Chain {
    let text = format!(
        ".:53 {{\n loadbalance weighted {} {{\n reload {reload}\n }}\n hosts /nonexistent {{\n 192.0.2.1 example.org\n 192.0.2.2 example.org\n 2001:db8::1 example.org\n 2001:db8::2 example.org\n reload 0\n }}\n}}",
        path.display()
    );
    let blocks = parse("Corefile", &text).unwrap();
    configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config
}

async fn top_counts(chain: &Chain, qtype: Type) -> [usize; 2] {
    let name: Name = "example.org.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut counts = [0, 0];
    for _ in 0..100 {
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        // Keep the non-measured Chain future out of the reload fixture's stack.
        assert_eq!(Box::pin(chain.serve(&mut cx)).await, Outcome::Response);
        let message = Message::parse(&response).unwrap();
        let last = *message.answers().next().unwrap().rdata.last().unwrap();
        counts[usize::from(last - 1)] += 1;
    }
    counts
}

#[tokio::test]
async fn weighted_selection_and_reload_follow_file_contents() {
    let path = file();
    std::fs::write(&path, "example.org\n192.0.2.2 255\n2001:db8::2 255\n").unwrap();
    let chain = chain(&path, "10ms");
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    assert!(top_counts(&chain, Type::A).await[1] > 90);
    assert!(top_counts(&chain, Type::AAAA).await[1] > 90);
    std::fs::write(&path, "example.org\n192.0.2.1 255\n2001:db8::1 255\n").unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    assert!(top_counts(&chain, Type::A).await[0] > 90);
    assert!(top_counts(&chain, Type::AAAA).await[0] > 90);
    std::fs::write(&path, "example.org\n192.0.2.1 0\n").unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    assert!(top_counts(&chain, Type::A).await[0] > 90);
    chain.lifecycle.run(Phase::Restart).await.unwrap();
    std::fs::write(&path, "example.org\n192.0.2.1 1\n192.0.2.2 255\n").unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    assert!(top_counts(&chain, Type::A).await[0] > 90);
    chain.lifecycle.run(Phase::RestartFailed).await.unwrap();
    assert!(top_counts(&chain, Type::A).await[1] > 90);
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn coredns_weight_file_errors_are_reported_at_startup() {
    let path = file();
    for (content, valid) in [
        ("", true),
        ("# comment\nexample.org\n192.0.2.1 10\n", true),
        ("192.0.2.1 10\n", false),
        ("example.org\n192.0.2.1\n", false),
        ("example.org\n192.0.2.999 1\n", false),
        ("example.org\n192.0.2.1 0\n", false),
        ("example.org\n192.0.2.1 +1\n", false),
        ("example.org\n192.0.2.1 256\n", false),
    ] {
        std::fs::write(&path, content).unwrap();
        let chain = chain(&path, "0");
        assert_eq!(
            chain.lifecycle.run(Phase::Startup).await.is_ok(),
            valid,
            "{content}"
        );
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    }
    std::fs::remove_file(&path).unwrap();
    assert!(
        chain(&path, "0")
            .lifecycle
            .run(Phase::Startup)
            .await
            .is_err()
    );
    let chain = chain(&path, "10ms");
    assert!(chain.lifecycle.run(Phase::Startup).await.is_ok());
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

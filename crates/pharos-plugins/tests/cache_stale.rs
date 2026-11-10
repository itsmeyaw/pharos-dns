#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-cache", feature = "plugin-whoami"))]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Message, Rdata};
use pharos_server::{Action, Handler, Protocol};
use std::time::Duration;

const QUERY: &[u8] = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";

async fn request(server: &impl Handler, port: u16) -> (u16, u32) {
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(
                QUERY,
                ([127, 0, 0, 1], port).into(),
                Protocol::Udp,
                &mut response
            )
            .await,
        Action::Respond
    );
    let message = Message::parse(&response).unwrap();
    let rr = message
        .additionals()
        .find(|rr| rr.rtype == pharos_proto::Type::SRV)
        .unwrap();
    let Rdata::Srv { port, .. } = rr.data().unwrap() else {
        panic!("not SRV")
    };
    (port, rr.ttl)
}

fn setup(options: &str) -> impl Handler {
    let text = format!(".:0 {{\n cache {{\n success 1024 2 2\n {options}\n }}\n whoami\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    servers.drain().next().unwrap().1
}

#[tokio::test]
async fn immediate_serves_stale_then_refreshes() {
    let server = setup("serve_stale 10s immediate 7s");
    assert_eq!(request(&server, 1001).await, (1001, 2));
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(request(&server, 1002).await, (1001, 7));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(request(&server, 1003).await, (0, 2));
}

#[tokio::test]
async fn verify_uses_fresh_answer() {
    let server = setup("serve_stale 10s verify");
    request(&server, 1001).await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(request(&server, 1002).await, (1002, 2));
}

#[tokio::test]
async fn popular_entry_prefetches_before_expiry() {
    let server = setup("prefetch 1 1m 90%");
    request(&server, 1001).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(request(&server, 1002).await.0, 1001);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(request(&server, 1003).await.0, 0);
}

#[cfg(feature = "plugin-forward")]
#[tokio::test]
async fn prefetched_servfail_does_not_shadow_a_valid_positive() {
    let response = prefetched_result("", 0x8082).await;
    assert_eq!(
        Message::parse(&response).unwrap().rcode(),
        pharos_proto::Rcode::NOERROR
    );
}

#[cfg(feature = "plugin-forward")]
#[tokio::test]
async fn prefer_positive_retains_last_good_answer_after_nonanswer_prefetch() {
    let response = prefetched_result(
        "serve_stale 10s\n serve_stale_policy prefer_positive",
        0x8080,
    )
    .await;
    assert_eq!(Message::parse(&response).unwrap().answer_count(), 1);
}

#[cfg(feature = "plugin-forward")]
#[tokio::test]
async fn late_stale_refresh_cannot_replace_newer_answer() {
    use pharos_proto::{Class, MessageBuilder, Section, Type};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::Notify,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let upstream = tokio::spawn({
        let (count, started, release) = (count.clone(), started.clone(), release.clone());
        async move {
            loop {
                let (mut connection, _) = listener.accept().await.unwrap();
                let (count, started, release) = (count.clone(), started.clone(), release.clone());
                tokio::spawn(async move {
                    while let Ok(len) = connection.read_u16().await {
                        let mut wire = vec![0; usize::from(len)];
                        if connection.read_exact(&mut wire).await.is_err() {
                            break;
                        }
                        let index = count.fetch_add(1, Ordering::Relaxed);
                        if index == 1 {
                            started.notify_one();
                            release.notified().await;
                        }
                        let query = Message::parse(&wire).unwrap();
                        let q = query.questions().next().unwrap();
                        let mut response = Vec::new();
                        let mut builder =
                            MessageBuilder::new(&mut response, 512, query.id(), 0x8080).unwrap();
                        builder.question(q.name, q.qtype, q.qclass).unwrap();
                        builder
                            .record(
                                Section::Answer,
                                q.name,
                                Type::A,
                                Class::IN,
                                1,
                                &[192, 0, 2, (index + 1) as u8],
                            )
                            .unwrap();
                        let _ = builder.finish();
                        if connection.write_u16(response.len() as u16).await.is_err()
                            || connection.write_all(&response).await.is_err()
                        {
                            break;
                        }
                    }
                });
            }
        }
    });
    let text = format!(
        ".:0 {{\n cache {{\n success 1024 1 0\n serve_stale 1s immediate\n }}\n forward . {address} {{\n force_tcp\n }}\n}}"
    );
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let mut response = Vec::with_capacity(65535);
    let peer = ([127, 0, 0, 1], 1001).into();
    assert_eq!(
        server
            .handle(QUERY, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        server
            .handle(QUERY, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        server
            .handle(QUERY, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    release.notify_one();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        server
            .handle(QUERY, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    assert!(
        matches!(Message::parse(&response).unwrap().answers().next().unwrap().data().unwrap(), Rdata::A(ip) if ip.octets() == [192, 0, 2, 3])
    );
    upstream.abort();
}

#[cfg(feature = "plugin-forward")]
async fn prefetched_result(options: &str, second_flags: u16) -> Vec<u8> {
    use pharos_proto::{Class, MessageBuilder, Section, Type};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, done) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        for index in 0..2 {
            let len = connection.read_u16().await.unwrap();
            let mut wire = vec![0; usize::from(len)];
            connection.read_exact(&mut wire).await.unwrap();
            let query = Message::parse(&wire).unwrap();
            let q = query.questions().next().unwrap();
            let mut response = Vec::with_capacity(512);
            let mut builder = MessageBuilder::new(
                &mut response,
                512,
                query.id(),
                if index == 0 { 0x8080 } else { second_flags },
            )
            .unwrap();
            builder.question(q.name, q.qtype, q.qclass).unwrap();
            if index == 0 {
                builder
                    .record(
                        Section::Answer,
                        q.name,
                        Type::A,
                        Class::IN,
                        2,
                        &[192, 0, 2, 1],
                    )
                    .unwrap();
            }
            let _ = builder.finish();
            connection.write_u16(response.len() as u16).await.unwrap();
            connection.write_all(&response).await.unwrap();
        }
        let _ = sent.send(());
    });
    let text = format!(
        ".:0 {{\n cache {{\n success 1024 2 0\n prefetch 1 1m 90%\n {options}\n }}\n forward . {address} {{\n force_tcp\n }}\n}}"
    );
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let mut response = Vec::with_capacity(65535);
    let peer = ([127, 0, 0, 1], 1001).into();
    assert_eq!(
        server
            .handle(QUERY, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        server
            .handle(QUERY, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    tokio::time::timeout(Duration::from_secs(2), done)
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        server
            .handle(QUERY, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    upstream.await.unwrap();
    response
}

#[tokio::test]
async fn verify_returns_stale_on_servfail() {
    use pharos_proto::{Class, MessageBuilder, Name, Section, Type};
    use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Transport};
    struct Backend(bool);
    struct Pending;
    impl Next for Pending {
        async fn run(self, _: &mut Context<'_>) -> Outcome {
            std::future::pending().await
        }
    }
    impl Next for Backend {
        async fn run(self, cx: &mut Context<'_>) -> Outcome {
            assert!(cx.query.ad(), "refresh must request authenticated data");
            if self.0 {
                return Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL);
            }
            let q = cx.query.questions().next().unwrap();
            let mut b = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8080).unwrap();
            b.question(q.name, q.qtype, q.qclass).unwrap();
            b.record(
                Section::Answer,
                q.name,
                Type::A,
                Class::IN,
                1,
                &[192, 0, 2, 1],
            )
            .unwrap();
            let _ = b.finish();
            Outcome::Response
        }
    }
    let blocks = parse(
        "Corefile",
        ".:0 {\n cache {\n success 1024 1 0\n serve_stale 10s verify\n }\n}",
    )
    .unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(QUERY).unwrap(),
        client: ([127, 0, 0, 1], 1000).into(),
        local: ([127, 0, 0, 1], 53).into(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let cache = chain.cache.as_ref().unwrap();
    assert_eq!(
        cache.serve(&mut cx, Backend(false)).await,
        Outcome::Response
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(cache.serve(&mut cx, Backend(true)).await, Outcome::Response);
    assert_eq!(
        Message::parse(cx.response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .ttl,
        0
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(10), cache.serve(&mut cx, Pending))
            .await
            .is_err()
    );
    assert_eq!(
        cache.serve(&mut cx, Backend(false)).await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(cx.response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .ttl,
        1
    );
}

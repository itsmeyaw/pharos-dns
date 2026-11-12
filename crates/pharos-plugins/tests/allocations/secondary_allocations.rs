use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{Context, Metadata, Outcome, Phase, Protocol, Transport};
use stats_alloc::INSTRUMENTED_SYSTEM;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn secondary_queries_do_not_allocate() {
    if crate::run_isolated("secondary_allocations::secondary_queries_do_not_allocate") {
        return;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let primary = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let length = socket.read_u16().await.unwrap();
        let mut query = vec![0; usize::from(length)];
        socket.read_exact(&mut query).await.unwrap();
        let query = Message::parse(&query).unwrap();
        let question = query.questions().next().unwrap();
        let mut response = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut response, 512, query.id(), 0x8400).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        let mut soa = vec![0, 0];
        for value in [1u32, 3600, 600, 86400, 60] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        builder
            .record(
                Section::Answer,
                question.name,
                Type::SOA,
                Class::IN,
                60,
                &soa,
            )
            .unwrap();
        let www: Name = "www.example.org.".parse().unwrap();
        builder
            .record(
                Section::Answer,
                NameRef::parse(www.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
                60,
                &[192, 0, 2, 1],
            )
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::SOA,
                Class::IN,
                60,
                &soa,
            )
            .unwrap();
        let _ = builder.finish();
        socket.write_u16(response.len() as u16).await.unwrap();
        socket.write_all(&response).await.unwrap();
    });
    let corefile = format!("example.org:53 {{\n secondary {{\n transfer from {address}\n }}\n}}");
    let blocks = parse("Corefile", &corefile).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let chain = &configured[0].config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    primary.await.unwrap();
    let apex: Name = "example.org.".parse().unwrap();
    let www: Name = "www.example.org.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(www.as_wire(), 0).unwrap(),
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
        domain: &apex,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while chain.serve(&mut cx).await != Outcome::Response {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let before = INSTRUMENTED_SYSTEM.stats();
    for _ in 0..100 {
        assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    }
    let after = INSTRUMENTED_SYSTEM.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

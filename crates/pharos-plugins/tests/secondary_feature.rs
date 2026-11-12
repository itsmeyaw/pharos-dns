#![cfg(feature = "plugin-secondary")]
#![recursion_limit = "512"]

#[test]
fn secondary_feature_exposes_shared_zone() {
    let _: Option<pharos_plugins::zone::ZoneHolder> = None;
}

#[test]
fn coredns_secondary_setup_cases() {
    for (directive, valid) in [
        ("secondary {\n transfer from 127.0.0.1\n}", true),
        (
            "secondary example.org {\n transfer from 127.0.0.1\n fallthrough example.org\n}",
            true,
        ),
        (
            "secondary catalog.example {\n transfer from 127.0.0.1\n catalog example.org internal.example\n}",
            true,
        ),
        (
            "secondary catalog.example {\n transfer from 127.0.0.1\n catalog :\n}",
            false,
        ),
        ("secondary", false),
        (
            "secondary example.org {\n transferr from 127.0.0.1\n}",
            false,
        ),
        ("secondary {\n transfer from *\n}", false),
        ("secondary {\n transfer from fe80::1%en0\n}", true),
        (
            "secondary {\n transfer from 127.0.0.1\n fallthrough\n}",
            true,
        ),
        (
            "secondary catalog.example {\n transfer from 127.0.0.1\n catalog EXAMPLE.ORG example.org\n catalog internal.example\n}",
            true,
        ),
        (
            "secondary catalog.example {\n transfer from 127.0.0.1\n catalog example.org\n catalog\n}",
            true,
        ),
    ] {
        let corefile = format!("example.org:53 {{\n {directive}\n}}");
        let parsed = pharos_corefile::parse("Corefile", &corefile).unwrap();
        assert_eq!(
            pharos_corefile::configure::<pharos_plugins::Chain>(
                &parsed,
                pharos_plugins::directives()
            )
            .is_ok(),
            valid,
            "{directive}"
        );
    }
}

#[tokio::test]
async fn transfers_zone_in_background_and_serves_it() {
    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
    use pharos_server::{Context, Metadata, Outcome, Phase, Protocol, Transport};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let primary = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let length = socket.read_u16().await.unwrap();
        let mut query = vec![0; usize::from(length)];
        socket.read_exact(&mut query).await.unwrap();
        let query = Message::parse(&query).unwrap();
        let q = query.questions().next().unwrap();
        assert_eq!(q.qtype, Type::AXFR);
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, query.id(), 0x8400).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        let mut soa = vec![0, 0];
        for value in [1u32, 3600, 600, 86400, 60] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        builder
            .record(Section::Answer, q.name, Type::SOA, Class::IN, 60, &soa)
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
            .record(Section::Answer, q.name, Type::SOA, Class::IN, 60, &soa)
            .unwrap();
        let _ = builder.finish();
        socket.write_u16(wire.len() as u16).await.unwrap();
        socket.write_all(&wire).await.unwrap();
    });
    let corefile = format!("example.org:53 {{\n secondary {{\n transfer from {address}\n }}\n}}");
    let parsed = pharos_corefile::parse("Corefile", &corefile).unwrap();
    let configured =
        pharos_corefile::configure::<pharos_plugins::Chain>(&parsed, pharos_plugins::directives())
            .unwrap();
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
        loop {
            if chain.serve(&mut cx).await == Outcome::Response {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 1]
    );
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn notify_checks_primary_and_transfers_new_serial() {
    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
    use pharos_server::{Context, Metadata, Outcome, Phase, Protocol, Transport};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let primary = tokio::spawn(async move {
        let mut serial = 1u32;
        for _ in 0..3 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let len = socket.read_u16().await.unwrap();
            let mut input = vec![0; usize::from(len)];
            socket.read_exact(&mut input).await.unwrap();
            let query = Message::parse(&input).unwrap();
            let question = query.questions().next().unwrap();
            if question.qtype == Type::SOA {
                serial = 2;
            }
            let mut output = Vec::with_capacity(512);
            let mut builder = MessageBuilder::new(&mut output, 512, query.id(), 0x8400).unwrap();
            builder
                .question(question.name, question.qtype, question.qclass)
                .unwrap();
            let mut soa = vec![0, 0];
            for value in [serial, 3600, 600, 86400, 60] {
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
            if question.qtype == Type::AXFR {
                let www: Name = "www.example.org.".parse().unwrap();
                builder
                    .record(
                        Section::Answer,
                        NameRef::parse(www.as_wire(), 0).unwrap(),
                        Type::A,
                        Class::IN,
                        60,
                        &[192, 0, 2, serial as u8],
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
            }
            let _ = builder.finish();
            socket.write_u16(output.len() as u16).await.unwrap();
            socket.write_all(&output).await.unwrap();
        }
    });
    let corefile = format!("example.org:53 {{\n secondary {{\n transfer from {address}\n }}\n}}");
    let parsed = pharos_corefile::parse("Corefile", &corefile).unwrap();
    let configured =
        pharos_corefile::configure::<pharos_plugins::Chain>(&parsed, pharos_plugins::directives())
            .unwrap();
    let chain = &configured[0].config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    let apex: Name = "example.org.".parse().unwrap();
    let www: Name = "www.example.org.".parse().unwrap();
    let make_query = |name: &Name, kind: Type, flags| {
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, flags).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        let _ = builder.finish();
        wire
    };
    let query = make_query(&www, Type::A, 0);
    let notify = make_query(&apex, Type::SOA, 0x2400);
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
    cx.query = Message::parse(&notify).unwrap();
    assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    cx.query = Message::parse(&query).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if chain.serve(&mut cx).await == Outcome::Response
                && Message::parse(cx.response)
                    .unwrap()
                    .answers()
                    .next()
                    .is_some_and(|rr| rr.rdata == [192, 0, 2, 2])
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    primary.await.unwrap();
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

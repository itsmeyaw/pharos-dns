#![forbid(unsafe_code)]
#![cfg(feature = "plugin-k8s-external")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers_with_registry};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Type};
use pharos_server::{Action, Handler, Phase, Protocol, metrics::Registry};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn routed_k8s_external_queries_do_not_allocate() {
    if crate::run_isolated(
        "k8s_external::k8s_external_allocations::routed_k8s_external_queries_do_not_allocate",
    ) {
        return;
    }

    // Plugin Chain futures exceed the default debug test-thread stack; see #90.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(scenario())
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn scenario() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0; 4096];
                let n = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                let (kind, items) = if request.contains("/api/v1/services") {
                    (
                        "ServiceList",
                        r#"[{"metadata":{"name":"web","namespace":"prod"},"spec":{"clusterIP":"10.0.0.1","externalIPs":["192.0.2.1","2001:db8::1"],"ports":[{"name":"http","protocol":"TCP","port":80}]}}]"#,
                    )
                } else if request.contains("/endpointslices") {
                    ("EndpointSliceList", "[]")
                } else if request.contains("/api/v1/pods") {
                    ("PodList", "[]")
                } else {
                    ("NamespaceList", r#"[{"metadata":{"name":"prod"}}]"#)
                };
                let body = if request.contains("watch=true") {
                    String::new()
                } else {
                    format!(
                        r#"{{"apiVersion":"v1","kind":"{kind}","metadata":{{"resourceVersion":"1"}},"items":{items}}}"#
                    )
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });

    let text = format!(
        ".:0 {{\n {}\n kubernetes cluster.local {{\n  endpoint http://{address}\n  startup_timeout 3s\n }}\n k8s_external example.org in-addr.arpa\n}}",
        if cfg!(feature = "plugin-metadata") {
            "metadata"
        } else {
            ""
        }
    );
    let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let (mut servers, lifecycle) =
        servers_with_registry(blocks, Registry::new("test", "test", "rust")).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();

    // RFC 1035 §3.4.1, RFC 3596 §2.2, and RFC 2782 §3: query both address families and SRV.
    // RFC 1035 §3.3.12–13: query the reverse PTR and zone apex SOA.
    let mut queries = Vec::new();
    for (name, kind) in [
        ("web.prod.example.org.", Type::A),
        ("web.prod.example.org.", Type::AAAA),
        ("_http._tcp.web.prod.example.org.", Type::SRV),
        ("1.2.0.192.in-addr.arpa.", Type::PTR),
        ("example.org.", Type::SOA),
    ] {
        let name: Name = name.parse().unwrap();
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x0100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        let _ = builder.finish();
        queries.push(query);
    }
    let client = "127.0.0.1:1001".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    for (index, query) in queries.iter().enumerate() {
        let before = GLOBAL.stats();
        let action = server
            .handle(query, client, Protocol::Udp, &mut response)
            .await;
        let after = GLOBAL.stats();
        assert_eq!(action, Action::Respond);
        assert_eq!(
            after.allocations - before.allocations,
            0,
            "first query {index}"
        );
        assert_eq!(
            after.reallocations - before.reallocations,
            0,
            "first query {index}"
        );

        let message = Message::parse(&response).unwrap();
        assert_eq!(message.rcode(), Rcode::NOERROR);
        assert_eq!(message.answer_count(), 1);
        let answer = message.answers().next().unwrap();
        let query_message = Message::parse(query).unwrap();
        let question = query_message.questions().next().unwrap();
        assert_eq!(answer.name, question.name);
        match index {
            0 => assert_eq!(
                answer.data().unwrap(),
                Rdata::A("192.0.2.1".parse().unwrap())
            ),
            1 => assert_eq!(
                answer.data().unwrap(),
                Rdata::Aaaa("2001:db8::1".parse().unwrap())
            ),
            2 => {
                let Rdata::Srv {
                    priority,
                    weight,
                    port,
                    target,
                } = answer.data().unwrap()
                else {
                    panic!("expected SRV");
                };
                assert_eq!((priority, weight, port), (0, 50, 80));
                assert_eq!(target.to_string(), "web.prod.example.org.");
                assert_eq!(message.additional_count(), 2);
                let mut additional = message.additionals();
                assert_eq!(
                    additional.next().unwrap().data().unwrap(),
                    Rdata::A("192.0.2.1".parse().unwrap())
                );
                assert_eq!(
                    additional.next().unwrap().data().unwrap(),
                    Rdata::Aaaa("2001:db8::1".parse().unwrap())
                );
            }
            3 => {
                let Rdata::Ptr(target) = answer.data().unwrap() else {
                    panic!("expected PTR");
                };
                assert_eq!(target.to_string(), "web.prod.example.org.");
            }
            4 => {
                let Rdata::Soa {
                    mname,
                    rname,
                    refresh,
                    retry,
                    expire,
                    minimum,
                    ..
                } = answer.data().unwrap()
                else {
                    panic!("expected SOA");
                };
                assert_eq!(mname.to_string(), "ns1.dns.example.org.");
                assert_eq!(rname.to_string(), "hostmaster.dns.example.org.");
                assert_eq!((refresh, retry, expire, minimum), (7200, 1800, 86400, 5));
            }
            _ => unreachable!(),
        }
    }

    let before = GLOBAL.stats();
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
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);

    lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

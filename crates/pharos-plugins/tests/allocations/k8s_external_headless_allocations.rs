#![forbid(unsafe_code)]
#![cfg(feature = "plugin-k8s-external")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Type};
use pharos_server::{Action, Handler, Phase, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::{alloc::System, collections::HashSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[tokio::test]
async fn many_headless_endpoints_and_ports_are_deduplicated_without_warm_allocations() {
    if crate::run_isolated(
        "k8s_external::headless::many_headless_endpoints_and_ports_are_deduplicated_without_warm_allocations",
    ) {
        return;
    }
    scenario().await;
}

async fn scenario() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let ports = (0..4)
        .map(|i| format!(r#"{{"name":"p{i}","protocol":"TCP","port":{}}}"#, 8000 + i))
        .collect::<Vec<_>>()
        .join(",");
    let endpoints = (1..=64)
        .map(|i| format!(r#"{{"addresses":["192.0.2.{i}"],"hostname":"pod-{i}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let slices = ["one", "two"].iter().map(|name| format!(r#"{{"metadata":{{"name":"{name}","namespace":"prod","labels":{{"kubernetes.io/service-name":"head"}}}},"addressType":"IPv4","ports":[{ports}],"endpoints":[{endpoints}]}}"#)).collect::<Vec<_>>().join(",");
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let slices = slices.clone();
            tokio::spawn(async move {
                let mut request = [0; 4096];
                let n = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                if request.contains("watch=true") {
                    if socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").await.is_ok() {
                        let _ = socket.read(&mut [0; 1]).await;
                    }
                    return;
                }
                let (kind, items) = if request.contains("/api/v1/services") {
                    ("ServiceList", r#"[{"metadata":{"name":"head","namespace":"prod"},"spec":{"clusterIP":"None"}}]"#.to_owned())
                } else if request.contains("/endpointslices") {
                    ("EndpointSliceList", format!("[{slices}]"))
                } else {
                    (
                        "NamespaceList",
                        r#"[{"metadata":{"name":"prod"}}]"#.to_owned(),
                    )
                };
                let body = format!(
                    r#"{{"apiVersion":"v1","kind":"{kind}","metadata":{{"resourceVersion":"1"}},"items":{items}}}"#
                );
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
            });
        }
    });
    let text = format!(
        ".:0 {{\n kubernetes cluster.local {{\n  endpoint http://{address}\n  startup_timeout 3s\n }}\n k8s_external example.org {{\n  headless\n }}\n}}"
    );
    let (mut servers, lifecycle) =
        servers(configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap())
            .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let name: Name = "head.prod.example.org.".parse().unwrap();
    let mut queries = Vec::new();
    for kind in [Type::A, Type::SRV] {
        let mut request = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut request, 512, 1, 0x100).unwrap();
        b.question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        let _ = b.finish();
        queries.push(request);
    }
    let mut response = Vec::with_capacity(65535);
    for query in &queries {
        assert_eq!(
            server
                .handle(
                    query,
                    "127.0.0.1:1234".parse().unwrap(),
                    Protocol::Tcp,
                    &mut response
                )
                .await,
            Action::Respond
        );
        let msg = Message::parse(&response).unwrap();
        assert_eq!(msg.rcode(), Rcode::NOERROR);
        assert!(!msg.tc());
        if msg.questions().next().unwrap().qtype == Type::A {
            let addresses: HashSet<_> = msg
                .answers()
                .map(|r| match r.data().unwrap() {
                    Rdata::A(ip) => ip,
                    _ => panic!("expected A"),
                })
                .collect();
            assert_eq!(msg.answer_count(), 64);
            assert_eq!(
                addresses,
                (1..=64)
                    .map(|i| format!("192.0.2.{i}").parse().unwrap())
                    .collect()
            );
        } else {
            let mut records = HashSet::new();
            for rr in msg.answers() {
                let Rdata::Srv {
                    priority,
                    weight,
                    port,
                    target,
                } = rr.data().unwrap()
                else {
                    panic!("expected SRV")
                };
                assert_eq!((priority, weight), (0, 1));
                records.insert((target.to_string(), port));
            }
            assert_eq!(msg.answer_count(), 256);
            let expected: HashSet<_> = (1..=64)
                .flat_map(|i| {
                    (8000..8004).map(move |port| (format!("pod-{i}.head.prod.example.org."), port))
                })
                .collect();
            assert_eq!(records, expected);
            assert_eq!(msg.additional_count(), 64);
        }
    }
    let before = GLOBAL.stats();
    for _ in 0..10 {
        for query in &queries {
            assert_eq!(
                server
                    .handle(
                        query,
                        "127.0.0.1:1234".parse().unwrap(),
                        Protocol::Tcp,
                        &mut response
                    )
                    .await,
                Action::Respond
            );
        }
    }
    let after = GLOBAL.stats();
    assert_eq!(
        (
            after.allocations - before.allocations,
            after.reallocations - before.reallocations
        ),
        (0, 0)
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

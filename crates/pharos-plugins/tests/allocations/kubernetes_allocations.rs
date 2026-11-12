#![forbid(unsafe_code)]
#![cfg(feature = "plugin-kubernetes")]

use crate::support;

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers_with_registry};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Type};
use pharos_server::{Action, Handler, Phase, Protocol, metrics::Registry};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[tokio::test(flavor = "current_thread")]
async fn routed_kubernetes_cluster_ip_queries_do_not_allocate() {
    if crate::run_isolated(
        "kubernetes::kubernetes_allocations::routed_kubernetes_cluster_ip_queries_do_not_allocate",
    ) {
        return;
    }
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", support::free_port()))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0; 4096];
                let n = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                let (kind, items) = if request.contains("/serviceimports") {
                    (
                        "ServiceImportList",
                        r#"[{"apiVersion":"multicluster.x-k8s.io/v1alpha1","kind":"ServiceImport","metadata":{"name":"web","namespace":"prod"},"spec":{"type":"ClusterSetIP","ips":["10.0.0.2"],"ports":[{"name":"http","protocol":"TCP","port":80}]}}]"#,
                    )
                } else if request.contains("/api/v1/services") {
                    (
                        "ServiceList",
                        r#"[{"metadata":{"name":"web","namespace":"prod"},"spec":{"clusterIPs":["10.0.0.1","2001:db8::1"],"ports":[{"name":"http","protocol":"TCP","port":80}]}}]"#,
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
        ".:0 {{\n {}\n kubernetes cluster.local clusterset.local {{\n  endpoint http://{address}\n  multicluster clusterset.local\n  startup_timeout 3s\n }}\n}}",
        if cfg!(feature = "plugin-metadata") {
            "metadata"
        } else {
            ""
        }
    );
    let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    #[cfg(feature = "plugin-transfer")]
    let transferer = blocks[0].config.kubernetes.as_ref().unwrap().clone();
    let (mut servers, lifecycle) =
        servers_with_registry(blocks, Registry::new("test", "test", "rust")).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();

    let mut queries = Vec::new();
    for (name, kind) in [
        ("web.prod.svc.cluster.local.", Type::A),
        ("web.prod.svc.cluster.local.", Type::AAAA),
        ("_http._tcp.web.prod.svc.cluster.local.", Type::SRV),
        ("web.prod.svc.clusterset.local.", Type::A),
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
        assert_eq!(
            server
                .handle(query, client, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
        let message = Message::parse(&response).unwrap();
        assert_eq!(message.rcode(), Rcode::NOERROR);
        assert_eq!(message.answer_count(), 1);
        let answer = message.answers().next().unwrap();
        let expected_name = match index {
            2 => "_http._tcp.web.prod.svc.cluster.local.",
            3 => "web.prod.svc.clusterset.local.",
            _ => "web.prod.svc.cluster.local.",
        };
        assert_eq!(answer.name.to_string(), expected_name);
        match index {
            0 => assert_eq!(
                answer.data().unwrap(),
                Rdata::A("10.0.0.1".parse().unwrap())
            ),
            1 => assert_eq!(
                answer.data().unwrap(),
                Rdata::Aaaa("2001:db8::1".parse().unwrap())
            ),
            3 => assert_eq!(
                answer.data().unwrap(),
                Rdata::A("10.0.0.2".parse().unwrap())
            ),
            _ => {
                let Rdata::Srv {
                    priority,
                    weight,
                    port,
                    target,
                } = answer.data().unwrap()
                else {
                    panic!("not SRV");
                };
                assert_eq!((priority, weight, port), (0, 50, 80));
                assert_eq!(target.to_string(), "web.prod.svc.cluster.local.");
                assert_eq!(message.additional_count(), 2);
                let mut additional = message.additionals();
                let v4 = additional.next().unwrap();
                let v6 = additional.next().unwrap();
                assert_eq!(v4.name.to_string(), "web.prod.svc.cluster.local.");
                assert_eq!(v6.name.to_string(), "web.prod.svc.cluster.local.");
                assert_eq!(v4.data().unwrap(), Rdata::A("10.0.0.1".parse().unwrap()));
                assert_eq!(
                    v6.data().unwrap(),
                    Rdata::Aaaa("2001:db8::1".parse().unwrap())
                );
            }
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

    #[cfg(feature = "plugin-transfer")]
    {
        use pharos_plugins::transfer::{TransferRequest, Transferer};
        let zone: Name = "cluster.local.".parse().unwrap();
        let before = GLOBAL.stats();
        let mut stream = transferer
            .transfer(TransferRequest {
                zone: NameRef::parse(zone.as_wire(), 0).unwrap(),
                serial: 0,
                id: 1,
                flags: 0,
                protocol: Protocol::Tcp,
                qtype: Type::AXFR,
                qclass: Class::IN,
            })
            .unwrap()
            .unwrap();
        let after = GLOBAL.stats();
        // One snapshot, one sorted Service list per encoding pass, and one shared Stream
        // handle, independent of record count.
        assert_eq!(after.allocations - before.allocations, 4);
        assert_eq!(after.reallocations - before.reallocations, 0);
        let mut wire = Vec::with_capacity(65535);
        let before = GLOBAL.stats();
        assert!(stream.next(&mut wire).unwrap());
        let first = GLOBAL.stats();
        assert!(!stream.next(&mut wire).unwrap());
        let after = GLOBAL.stats();
        // macOS lazily allocates the Stream's pthread mutex on its first lock.
        assert!(first.allocations - before.allocations <= 1);
        assert_eq!(after.allocations - first.allocations, 0);
        assert_eq!(after.reallocations - before.reallocations, 0);
        assert!(Message::parse(&wire).unwrap().answer_count() >= 5);
    }
    lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

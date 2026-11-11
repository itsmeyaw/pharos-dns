#![forbid(unsafe_code)]
#![cfg(feature = "plugin-kubernetes")]

#[path = "../../../pharos/tests/support/mod.rs"]
mod support;

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Type};
use pharos_server::{Context, Metadata, Outcome, Phase, Plugin, Protocol, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::{alloc::System, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[tokio::test(flavor = "current_thread")]
async fn large_endpoints_preserve_records_and_do_not_allocate_after_warmup() {
    let _serial = crate::serial();
    let local_ip = nix::ifaddrs::getifaddrs()
        .unwrap()
        .filter_map(|entry| entry.address?.as_sockaddr_in().map(|ip| ip.ip()))
        .find(|ip| !ip.is_loopback());
    let endpoints = (0..5000)
        .map(|i| {
            format!(
                r#"{{"addresses":["10.0.1.{}"],"hostname":"node{}"}}"#,
                i % 100,
                i % 100
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let many = (0..5000)
        .map(|i| {
            format!(
                r#"{{"addresses":["10.2.{}.{}"],"hostname":"node{i}"}}"#,
                i / 256,
                i % 256
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let reverse = (0..5000)
        .map(|i| {
            format!(
                r#"{{"addresses":["10.9.0.1"],"hostname":"node{}"}}"#,
                i % 1000
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let dns = local_ip.map_or_else(String::new, |ip| {
        let endpoints = (0..5000)
            .map(|i| format!(r#"{{"addresses":["{ip}"],"hostname":"node{}"}}"#, i % 100))
            .collect::<Vec<_>>()
            .join(",");
        format!(r#",{{"metadata":{{"name":"dns","namespace":"prod","labels":{{"kubernetes.io/service-name":"dns"}}}},"addressType":"IPv4","endpoints":[{endpoints}]}}"#)
    });
    let slices = format!(
        r#"[{{"metadata":{{"name":"large","namespace":"prod","labels":{{"kubernetes.io/service-name":"large"}}}},"addressType":"IPv4","ports":[{{"name":"http","protocol":"TCP","port":80}}],"endpoints":[{endpoints}]}},{{"metadata":{{"name":"many","namespace":"prod","labels":{{"kubernetes.io/service-name":"many"}}}},"addressType":"IPv4","ports":[{{"name":"http","protocol":"TCP","port":80}}],"endpoints":[{many}]}},{{"metadata":{{"name":"reverse","namespace":"prod","labels":{{"kubernetes.io/service-name":"reverse"}}}},"addressType":"IPv4","endpoints":[{reverse}]}},{{"metadata":{{"name":"v6","namespace":"prod","labels":{{"kubernetes.io/service-name":"v6"}}}},"addressType":"IPv6","ports":[{{"name":"http","protocol":"TCP","port":80}}],"endpoints":[{{"addresses":["2001:db8::1"],"hostname":"same"}},{{"addresses":["2001:0db8::1"],"hostname":"same"}}]}},{{"metadata":{{"name":"weight-ports","namespace":"prod","labels":{{"kubernetes.io/service-name":"weight"}}}},"addressType":"IPv4","ports":[{{"name":"http","protocol":"TCP","port":80}}],"endpoints":[{{"addresses":["10.3.0.1"],"hostname":"same"}},{{"addresses":["10.3.0.2"],"hostname":"same"}}]}},{{"metadata":{{"name":"weight-sentinel","namespace":"prod","labels":{{"kubernetes.io/service-name":"weight"}}}},"addressType":"IPv4","endpoints":[{{"addresses":["10.3.0.3"],"hostname":"same"}}]}}{dns}]"#
    );
    let slices = Arc::new(slices);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", support::free_port()))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
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
                    (
                        "ServiceList",
                        r#"[{"metadata":{"name":"large","namespace":"prod"},"spec":{"clusterIP":"None"}},{"metadata":{"name":"many","namespace":"prod"},"spec":{"clusterIP":"None"}},{"metadata":{"name":"dns","namespace":"prod"},"spec":{"clusterIP":"None"}},{"metadata":{"name":"v6","namespace":"prod"},"spec":{"clusterIP":"None"}},{"metadata":{"name":"weight","namespace":"prod"},"spec":{"clusterIP":"None"}}]"#,
                    )
                } else if request.contains("/endpointslices") {
                    ("EndpointSliceList", slices.as_str())
                } else if request.contains("/api/v1/pods") {
                    ("PodList", "[]")
                } else {
                    ("NamespaceList", r#"[{"metadata":{"name":"prod"}}]"#)
                };
                let body = format!(
                    r#"{{"apiVersion":"v1","kind":"{kind}","metadata":{{"resourceVersion":"1"}},"items":{items}}}"#
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    let text = format!(
        ".:53 {{\n kubernetes cluster.local in-addr.arpa ip6.arpa {{\n  endpoint http://{address}\n  startup_timeout 3s\n }}\n}}"
    );
    let mut blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let chain = blocks.remove(0).config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    assert!(
        chain
            .kubernetes
            .as_ref()
            .unwrap()
            .readiness()
            .unwrap()
            .ready()
    );

    let mut queries = Vec::new();
    for (name, kind) in [
        ("large.prod.svc.cluster.local.", Type::A),
        ("v6.prod.svc.cluster.local.", Type::AAAA),
        ("_http._tcp.large.prod.svc.cluster.local.", Type::SRV),
        ("_http._tcp.v6.prod.svc.cluster.local.", Type::SRV),
        ("0.1.0.10.in-addr.arpa.", Type::PTR),
        ("cluster.local.", Type::NS),
        ("many.prod.svc.cluster.local.", Type::A),
        ("_http._tcp.many.prod.svc.cluster.local.", Type::SRV),
        ("weight.prod.svc.cluster.local.", Type::SRV),
        ("1.0.9.10.in-addr.arpa.", Type::PTR),
        (
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            Type::PTR,
        ),
    ] {
        let name: Name = name.parse().unwrap();
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        let _ = builder.finish();
        queries.push(query);
    }
    let root: Name = ".".parse().unwrap();
    let client = "127.0.0.1:1234".parse().unwrap();
    let local = "127.0.0.1:53".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    for (index, query) in queries.iter().enumerate() {
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(query).unwrap(),
            client,
            local,
            transport: Transport::Dns,
            protocol: Protocol::Tcp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 65535,
        };
        assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
        let message = Message::parse(&response).unwrap();
        assert_eq!(message.rcode(), Rcode::NOERROR);
        match index {
            0 => {
                assert_eq!(message.answer_count(), 100);
                for (i, rr) in message.answers().enumerate() {
                    assert_eq!(
                        rr.data().unwrap(),
                        Rdata::A(std::net::Ipv4Addr::new(10, 0, 1, i as u8))
                    );
                }
            }
            1 => {
                assert_eq!(message.answer_count(), 2);
                for rr in message.answers() {
                    assert_eq!(
                        rr.data().unwrap(),
                        Rdata::Aaaa("2001:db8::1".parse().unwrap())
                    );
                }
            }
            2 => {
                assert_eq!(message.answer_count(), 100);
                assert_eq!(message.additional_count(), 100);
                for (i, rr) in message.answers().enumerate() {
                    let Rdata::Srv {
                        weight,
                        port,
                        target,
                        ..
                    } = rr.data().unwrap()
                    else {
                        panic!("expected SRV")
                    };
                    assert_eq!((weight, port), (1, 80));
                    assert_eq!(
                        target.to_string(),
                        format!("node{i}.large.prod.svc.cluster.local.")
                    );
                }
            }
            3 => {
                assert_eq!(message.answer_count(), 1);
                assert_eq!(message.additional_count(), 2);
                for rr in message.additionals() {
                    assert_eq!(
                        rr.data().unwrap(),
                        Rdata::Aaaa("2001:db8::1".parse().unwrap())
                    );
                }
            }
            4 => {
                assert_eq!(message.answer_count(), 1);
                assert!(matches!(
                    message.answers().next().unwrap().data().unwrap(),
                    Rdata::Ptr(_)
                ));
            }
            5 if local_ip.is_some() => {
                assert_eq!(message.answer_count(), 100);
                // RFC 2181 §5: one glue record per (name, address), so it all fits.
                assert!(!message.tc());
                assert_eq!(message.additional_count(), 100);
                for (i, rr) in message.answers().enumerate() {
                    let Rdata::Ns(target) = rr.data().unwrap() else {
                        panic!("expected NS")
                    };
                    assert_eq!(
                        target.to_string(),
                        format!("node{i}.dns.prod.svc.cluster.local.")
                    );
                }
                for rr in message.additionals() {
                    assert_eq!(rr.data().unwrap(), Rdata::A(local_ip.unwrap()));
                }
            }
            6 | 7 => {
                assert!(message.tc());
                assert!(message.answer_count() > 0);
            }
            8 => {
                assert_eq!(message.answer_count(), 1);
                assert_eq!(message.additional_count(), 2);
                assert!(matches!(
                    message.answers().next().unwrap().data().unwrap(),
                    Rdata::Srv {
                        weight: 33,
                        port: 80,
                        ..
                    }
                ));
            }
            9 => {
                assert_eq!(message.answer_count(), 1000);
                for (i, rr) in message.answers().enumerate() {
                    let Rdata::Ptr(target) = rr.data().unwrap() else {
                        panic!("expected PTR")
                    };
                    assert_eq!(
                        target.to_string(),
                        format!("node{i}.reverse.prod.svc.cluster.local.")
                    );
                }
            }
            10 => assert_eq!(message.answer_count(), 1),
            _ => {}
        }
    }
    let before = GLOBAL.stats();
    for query in &queries {
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(query).unwrap(),
            client,
            local,
            transport: Transport::Dns,
            protocol: Protocol::Tcp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 65535,
        };
        assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

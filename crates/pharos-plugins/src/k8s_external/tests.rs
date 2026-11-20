use super::*;
use pharos_corefile::{Cursor, parse};
use pharos_proto::{Class, Message, MessageBuilder, NameRef, Rcode, Rdata, Type};
use pharos_server::{Metadata, Protocol, Transport};

struct Sentinel;
impl Next for Sentinel {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(Rcode::REFUSED)
    }
}

async fn assert_reverse_snapshot(
    kubernetes: &crate::kubernetes::Kubernetes,
    store: &pharos_kubernetes::store::Store,
) {
    store.with_read(|index| {
        assert_eq!(
            index
                .services_by_external_ip_unfiltered("192.0.2.1")
                .count(),
            2
        );
        assert_eq!(
            index
                .services_by_external_ip_unfiltered("192.0.2.3")
                .count(),
            1
        );
        assert!(!index.namespace_exposed("secret"));
    });
    let blocks = parse(
        "Corefile",
        ".:53 {\n k8s_external example.com in-addr.arpa\n}",
    )
    .unwrap();
    let config = setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
        &["."],
    )
    .unwrap();
    let mut external = External::new(config).unwrap();
    external.bind_kubernetes(kubernetes);
    let zone: Name = "in-addr.arpa.".parse().unwrap();
    let name: Name = "1.2.0.192.in-addr.arpa.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::PTR,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let empty = pharos_kubernetes::store::Store::default();
    for (index_store, fallthrough, expected) in [
        (store, false, Some(Rcode::NOERROR)),
        (&empty, false, Some(Rcode::NXDOMAIN)),
        (&empty, true, None),
        (store, true, Some(Rcode::NOERROR)),
    ] {
        external.fallthrough = if fallthrough {
            vec![zone.clone()]
        } else {
            vec![]
        };
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &zone,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let outcome = index_store.with_read(|index| {
            external.reverse_response(index, &mut cx, &external.zones[1], "192.0.2.1")
        });
        if let Some(code) = expected {
            assert!(matches!(outcome, Some(Outcome::Response)));
            let message = Message::parse(&response).unwrap();
            assert_eq!(message.rcode(), code);
            if code == Rcode::NOERROR {
                assert_eq!(message.answer_count(), 1);
                let Rdata::Ptr(target) = message.answers().next().unwrap().data().unwrap() else {
                    panic!("expected PTR")
                };
                assert_eq!(target.to_string(), "web.prod.example.com.");
            } else {
                assert_eq!(message.answer_count(), 0);
                let Rdata::Soa { serial, .. } =
                    message.authorities().next().unwrap().data().unwrap()
                else {
                    panic!("expected SOA")
                };
                assert_eq!(
                    serial,
                    index_store.with_read(|index| index.external_serial())
                );
            }
        } else {
            assert!(outcome.is_none());
            assert!(response.is_empty());
        }
    }
    for (name, fallthrough, expected) in [
        ("1.2.0.192.in-addr.arpa.", false, Some(Rcode::NOERROR)),
        ("3.2.0.192.in-addr.arpa.", false, Some(Rcode::NXDOMAIN)),
        ("3.2.0.192.in-addr.arpa.", true, None),
    ] {
        external.fallthrough = if fallthrough {
            vec![zone.clone()]
        } else {
            vec![]
        };
        let name: Name = name.parse().unwrap();
        query.clear();
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::PTR,
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
            domain: &zone,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let outcome = external.answer(&mut cx).await;
        if let Some(code) = expected {
            assert!(matches!(outcome, Some(Outcome::Response)));
            let message = Message::parse(&response).unwrap();
            assert_eq!(message.rcode(), code);
            assert_eq!(message.answer_count(), u16::from(code == Rcode::NOERROR));
        } else {
            assert!(outcome.is_none());
        }
    }
}

#[tokio::test]
async fn reverse_follows_namespace_labels_filter() {
    use pharos_corefile::configure;
    use pharos_server::Phase;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0; 4096];
                let n = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                let (kind, items) = if request.contains("/services") {
                    (
                        "ServiceList",
                        r#"[{"metadata":{"name":"web","namespace":"prod"},"spec":{"externalIPs":["192.0.2.1"]}},{"metadata":{"name":"hidden","namespace":"dev"},"spec":{"externalIPs":["192.0.2.1","192.0.2.3"]}}]"#,
                    )
                } else if request.contains("/endpointslices") {
                    ("EndpointSliceList", "[]")
                } else if request.contains("labelSelector=") {
                    (
                        "NamespaceList",
                        r#"[{"metadata":{"name":"prod","labels":{"team":"a"}}}]"#,
                    )
                } else {
                    (
                        "NamespaceList",
                        r#"[{"metadata":{"name":"prod","labels":{"team":"a"}}},{"metadata":{"name":"dev"}}]"#,
                    )
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
        ".:53 {{\n kubernetes cluster.local {{\n  endpoint http://{server}\n  namespace_labels team=a\n  startup_timeout 3s\n }}\n}} "
    );
    let chain = configure::<crate::Chain>(&parse("Corefile", &text).unwrap(), crate::directives())
        .unwrap()
        .remove(0)
        .config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    let kubernetes = chain.kubernetes.as_ref().unwrap();
    let store = kubernetes.store().unwrap();
    let blocks = parse(
        "Corefile",
        ".:53 {\n k8s_external example.com in-addr.arpa\n}",
    )
    .unwrap();
    let config = setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
        &["."],
    )
    .unwrap();
    let mut external = External::new(config).unwrap();
    external.bind_kubernetes(kubernetes);
    let zone: Name = "in-addr.arpa.".parse().unwrap();
    for (qname, ip, rcode, targets) in [
        (
            "1.2.0.192.in-addr.arpa.",
            "192.0.2.1",
            Rcode::NOERROR,
            &["web.prod.example.com."][..],
        ),
        (
            "3.2.0.192.in-addr.arpa.",
            "192.0.2.3",
            Rcode::NXDOMAIN,
            &[][..],
        ),
    ] {
        let name: Name = qname.parse().unwrap();
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::PTR,
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
            domain: &zone,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let outcome = store
            .with_read(|index| external.reverse_response(index, &mut cx, &external.zones[1], ip));
        assert!(matches!(outcome, Some(Outcome::Response)), "{qname}");
        let message = Message::parse(&response).unwrap();
        assert_eq!(message.rcode(), rcode, "{qname}");
        let answers: Vec<_> = message
            .answers()
            .map(|record| match record.data().unwrap() {
                Rdata::Ptr(target) => target.to_string(),
                _ => panic!("expected PTR"),
            })
            .collect();
        assert_eq!(answers, targets, "{qname}");
    }
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

#[test]
fn hostname_fqdn_handles_escaped_final_dot() {
    let mut wire = [0; 255];
    assert_eq!(
        hostname(r"example\.", &mut wire).unwrap().to_string(),
        r"example\.."
    );
    assert_eq!(
        hostname(r"example\\.", &mut wire).unwrap().to_string(),
        r"example\\."
    );
}

#[test]
fn cname_target_rcode_replaces_initial_rcode() {
    let target: Name = "missing.example.net.".parse().unwrap();
    let mut wire = Vec::with_capacity(128);
    let mut builder = MessageBuilder::new(&mut wire, 128, 1, 0x8000 | Rcode::NXDOMAIN.0).unwrap();
    builder
        .question(
            NameRef::parse(target.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let chased = [Chased {
        ordinal: 0,
        name: target,
        answers: [Some(wire), None],
    }];
    assert_eq!(final_rcode(Rcode::NOERROR, &chased), Rcode::NXDOMAIN);
    let positive_name: Name = "found.example.net.".parse().unwrap();
    let positive_ref = NameRef::parse(positive_name.as_wire(), 0).unwrap();
    let mut positive_wire = Vec::with_capacity(128);
    let mut builder = MessageBuilder::new(&mut positive_wire, 128, 1, 0x8000).unwrap();
    builder.question(positive_ref, Type::A, Class::IN).unwrap();
    builder
        .record(
            Section::Answer,
            positive_ref,
            Type::A,
            Class::IN,
            30,
            &[192, 0, 2, 1],
        )
        .unwrap();
    let _ = builder.finish();
    let mixed = [
        Chased {
            ordinal: 0,
            name: positive_name,
            answers: [Some(positive_wire), None],
        },
        Chased {
            ordinal: 1,
            name: "missing.example.net.".parse().unwrap(),
            answers: [Some(chased[0].answers[0].clone().unwrap()), None],
        },
    ];
    assert_eq!(final_rcode(Rcode::NXDOMAIN, &mixed), Rcode::NOERROR);
    assert!(final_response(Rcode::NXDOMAIN, &mixed).1.is_none());
    assert_eq!(
        final_rcode(
            Rcode::NOERROR,
            &[Chased {
                ordinal: 0,
                name: "failed.example.net.".parse().unwrap(),
                answers: [None, None],
            }]
        ),
        Rcode::SERVFAIL
    );
    assert_eq!(final_rcode(Rcode::SERVFAIL, &[]), Rcode::SERVFAIL);
}

#[test]
fn captured_target_matches_ascii_case_insensitively() {
    let chased = [Chased {
        ordinal: 0,
        name: "MiXeD.example.net.".parse().unwrap(),
        answers: [None, None],
    }];
    assert!(chased_at(&chased, 0, "mixed.example.net").is_some());
}

#[test]
fn srv_target_must_resolve_to_address_without_cname() {
    let target: Name = "target.example.net.".parse().unwrap();
    let target_ref = NameRef::parse(target.as_wire(), 0).unwrap();
    let make_response = |alias: bool| {
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x8000).unwrap();
        builder.question(target_ref, Type::A, Class::IN).unwrap();
        if alias {
            builder
                .record_with(
                    Section::Answer,
                    target_ref,
                    Type::CNAME,
                    Class::IN,
                    30,
                    |w| w.write_name(target_ref),
                )
                .unwrap();
        } else {
            builder
                .record(
                    Section::Answer,
                    target_ref,
                    Type::A,
                    Class::IN,
                    30,
                    &[192, 0, 2, 1],
                )
                .unwrap();
        }
        let _ = builder.finish();
        wire
    };
    let address = Chased {
        ordinal: 0,
        name: target.clone(),
        answers: [Some(make_response(false)), None],
    };
    let alias = Chased {
        ordinal: 0,
        name: target.clone(),
        answers: [Some(make_response(true)), None],
    };
    assert!(has_address_target("target.example.net", Some(&address)));
    assert!(!has_address_target("target.example.net", Some(&alias)));
    assert!(!has_address_target("target.example.net", None));
}

#[tokio::test]
async fn headless_query_retains_service_and_slices_during_hostname_chase() {
    use pharos_corefile::configure;
    use pharos_server::{
        Action, Chain as ServerChain, Handler, ListenerKey, Phase, Router, Server,
    };
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{Notify, Semaphore, broadcast};

    enum TestChain {
        External(Box<External>),
        Target {
            started: Arc<Notify>,
            resume: Arc<Semaphore>,
        },
    }
    impl ServerChain for TestChain {
        async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
            match self {
                Self::External(external) => external.serve(cx, Sentinel).await,
                Self::Target { started, resume } => {
                    started.notify_one();
                    resume.acquire().await.unwrap().forget();
                    let q = cx.query.questions().next().unwrap();
                    let mut b =
                        MessageBuilder::new(cx.response, 65535, cx.query.id(), 0x8000).unwrap();
                    b.question(q.name, q.qtype, q.qclass).unwrap();
                    b.record(
                        Section::Answer,
                        q.name,
                        Type::A,
                        Class::IN,
                        30,
                        &[203, 0, 113, 1],
                    )
                    .unwrap();
                    let _ = b.finish();
                    Outcome::Response
                }
            }
        }
        fn is_empty(&self) -> bool {
            false
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (services, _) = broadcast::channel::<&'static str>(4);
    let (slices, _) = broadcast::channel::<&'static str>(4);
    let service_ready = Arc::new(Notify::new());
    let slice_ready = Arc::new(Notify::new());
    let api = tokio::spawn({
        let services = services.clone();
        let slices = slices.clone();
        let service_ready = service_ready.clone();
        let slice_ready = slice_ready.clone();
        async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let services = services.clone();
                let slices = slices.clone();
                let service_ready = service_ready.clone();
                let slice_ready = slice_ready.clone();
                tokio::spawn(async move {
                    let mut request = [0; 4096];
                    let n = socket.read(&mut request).await.unwrap();
                    let request = String::from_utf8_lossy(&request[..n]);
                    let is_service = request.contains("/services");
                    let is_slice = request.contains("/endpointslices");
                    if request.contains("watch=true") {
                        if !is_service && !is_slice {
                            let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").await;
                            let _ = socket.read(&mut [0; 1]).await;
                            return;
                        }
                        let mut rx = if is_service {
                            services.subscribe()
                        } else {
                            slices.subscribe()
                        };
                        if socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").await.is_err() { return; }
                        if is_service {
                            service_ready.notify_one();
                        } else if is_slice {
                            slice_ready.notify_one();
                        }
                        while let Ok(event) = rx.recv().await {
                            let chunk = format!("{:x}\r\n{}\r\n", event.len(), event);
                            if socket.write_all(chunk.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                        return;
                    }
                    let (kind, items) = if is_service {
                        (
                            "ServiceList",
                            r#"[{"metadata":{"name":"head","namespace":"prod","resourceVersion":"1"},"spec":{"clusterIP":"None"}}]"#,
                        )
                    } else if is_slice {
                        (
                            "EndpointSliceList",
                            r#"[{"metadata":{"name":"head-1","namespace":"prod","resourceVersion":"1","labels":{"kubernetes.io/service-name":"head"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.1"],"hostname":"pod1"},{"addresses":["lb.target.test"],"hostname":"pod2"},{"addresses":["192.0.2.2"],"hostname":"pod3"}],"ports":[{"name":"http","protocol":"TCP","port":80},{"name":"https","protocol":"TCP","port":443}]}]"#,
                        )
                    } else {
                        (
                            "NamespaceList",
                            r#"[{"metadata":{"name":"prod","resourceVersion":"1"}}]"#,
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
        }
    });
    let text = format!(
        ".:53 {{\n kubernetes cluster.local {{\n  endpoint http://{address}\n  startup_timeout 3s\n }}\n}}"
    );
    let chain = configure::<crate::Chain>(&parse("Corefile", &text).unwrap(), crate::directives())
        .unwrap()
        .remove(0)
        .config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    let kubernetes = chain.kubernetes.as_ref().unwrap();
    let store = kubernetes.store().unwrap();
    let later_request = lookup::parse(&[b"later", b"prod"]).unwrap();
    let absent = store.with_read(|index| lookup::capture(index, &later_request, true));
    assert!(matches!(absent, lookup::Snapshot::MissingService));
    let blocks = parse(
        "Corefile",
        ".:53 {\n k8s_external example.org {\n  headless\n }\n}",
    )
    .unwrap();
    let config = setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
        &["."],
    )
    .unwrap();
    let mut external = External::new(config).unwrap();
    external.bind_kubernetes(kubernetes);
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let started = Arc::new(Notify::new());
    let resume = Arc::new(Semaphore::new(0));
    let mut router = Router::default();
    router.add(
        key,
        "example.org.".parse().unwrap(),
        Some(TestChain::External(Box::new(external))),
        vec![],
    );
    router.add(
        key,
        "target.test.".parse().unwrap(),
        Some(TestChain::Target {
            started: started.clone(),
            resume: resume.clone(),
        }),
        vec![],
    );
    let server = Arc::new(Server::new(router, key));
    let name: Name = "head.prod.example.org.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(65535);
    {
        let future = Handler::handle_shared(
            &server,
            &query,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Tcp,
            &mut response,
        );
        tokio::pin!(future);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::select! { _ = started.notified() => {}, _ = &mut future => panic!("chase completed before mutation") }
        }).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            service_ready.notified().await;
            slice_ready.notified().await;
        })
        .await
        .unwrap();
        services.send("{\"type\":\"MODIFIED\",\"object\":{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"head\",\"namespace\":\"prod\",\"resourceVersion\":\"2\"},\"spec\":{\"clusterIP\":\"10.0.0.1\",\"externalIPs\":[\"198.51.100.1\"]}}}\n").unwrap();
        services.send("{\"type\":\"ADDED\",\"object\":{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"later\",\"namespace\":\"prod\",\"resourceVersion\":\"3\"},\"spec\":{\"clusterIP\":\"10.0.0.2\",\"externalIPs\":[\"198.51.100.3\"],\"ports\":[{\"name\":\"http\",\"protocol\":\"TCP\",\"port\":80}]}}}\n").unwrap();
        slices.send("{\"type\":\"MODIFIED\",\"object\":{\"apiVersion\":\"discovery.k8s.io/v1\",\"kind\":\"EndpointSlice\",\"metadata\":{\"name\":\"head-1\",\"namespace\":\"prod\",\"resourceVersion\":\"2\",\"labels\":{\"kubernetes.io/service-name\":\"head\"}},\"addressType\":\"IPv4\",\"endpoints\":[{\"addresses\":[\"198.51.100.2\"]}],\"ports\":[{\"name\":\"http\",\"protocol\":\"TCP\",\"port\":80}]}}\n").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if store.with_read(|index| {
                    index
                        .service("prod", "head")
                        .is_some_and(|s| s.external_ips == ["198.51.100.1"])
                        && index.service("prod", "later").is_some()
                        && index
                            .endpoints("prod", "head")
                            .next()
                            .is_some_and(|ep| ep.addresses[0].ip == "198.51.100.2")
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        store.with_read(|index| {
            assert_eq!(
                lookup::lookup(index, &later_request, true, false, |_, _, _| {}),
                Rcode::NOERROR
            );
            assert_eq!(
                lookup::snapshot_or_lookup(
                    index,
                    &later_request,
                    true,
                    false,
                    Some(&absent),
                    |_, _, _| panic!("absent snapshot read added Service")
                ),
                Rcode::NXDOMAIN
            );
        });
        resume.add_permits(2);
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(3), &mut future)
                .await
                .unwrap(),
            Action::Respond
        );
    }
    let msg = Message::parse(&response).unwrap();
    let records: Vec<_> = msg
        .answers()
        .map(|rr| match rr.data().unwrap() {
            Rdata::A(ip) => format!("A {ip}"),
            Rdata::Cname(name) => format!("CNAME {name}"),
            other => panic!("unexpected record: {other:?}"),
        })
        .collect();
    assert_eq!(
        records,
        [
            "A 192.0.2.1",
            "CNAME lb.target.test.",
            "A 203.0.113.1",
            "CNAME lb.target.test.",
            "A 203.0.113.1",
            "A 192.0.2.2"
        ]
    );
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    api.abort();
}

#[tokio::test]
async fn mixed_addresses_and_chased_answers_follow_service_order() {
    use pharos_corefile::configure;
    use pharos_server::Phase;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0; 4096];
                let n = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                let (kind, items) = if request.contains("/services") {
                    (
                        "ServiceList",
                        r#"[{"metadata":{"name":"web","namespace":"prod"},"spec":{"externalIPs":["192.0.2.1","lb.example.net","192.0.2.1","192.0.2.2"],"ports":[{"name":"http","protocol":"TCP","port":80},{"name":"https","protocol":"TCP","port":443}]}},{"metadata":{"name":"hidden","namespace":"secret"},"spec":{"externalIPs":["192.0.2.1","192.0.2.3"]}}]"#,
                    )
                } else if request.contains("/endpointslices") {
                    ("EndpointSliceList", "[]")
                } else {
                    (
                        "NamespaceList",
                        r#"[{"metadata":{"name":"prod"}},{"metadata":{"name":"secret"}}]"#,
                    )
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
        ".:53 {{\n kubernetes cluster.local {{\n  endpoint http://{server}\n  namespaces prod\n  startup_timeout 3s\n }}\n}} "
    );
    let chain = configure::<crate::Chain>(&parse("Corefile", &text).unwrap(), crate::directives())
        .unwrap()
        .remove(0)
        .config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    let kubernetes = chain.kubernetes.as_ref().unwrap();
    let store = kubernetes.store().unwrap();
    assert_reverse_snapshot(kubernetes, &store).await;
    let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
    let config = setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
        &["."],
    )
    .unwrap();
    let external = External::new(config).unwrap();
    let zone: Name = "example.com.".parse().unwrap();
    let owner: Name = "web.prod.example.com.".parse().unwrap();
    let target: Name = "lb.example.net.".parse().unwrap();
    let request = lookup::parse(&[b"web", b"prod"]).unwrap();
    let mut chased_wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut chased_wire, 512, 1, 0x8000).unwrap();
    let target_ref = NameRef::parse(target.as_wire(), 0).unwrap();
    b.question(target_ref, Type::A, Class::IN).unwrap();
    b.record(
        Section::Answer,
        target_ref,
        Type::A,
        Class::IN,
        30,
        &[203, 0, 113, 1],
    )
    .unwrap();
    let _ = b.finish();
    let chased = [
        Chased {
            ordinal: 2,
            name: target.clone(),
            answers: [Some(chased_wire.clone()), None],
        },
        Chased {
            ordinal: 3,
            name: target,
            answers: [Some(chased_wire), None],
        },
    ];
    let mut query = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
    b.question(
        NameRef::parse(owner.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(4096);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &zone,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 4096,
    };
    assert!(matches!(
        external.service_response(
            &mut cx,
            &external.zones[0],
            kubernetes,
            &store,
            None,
            Some(&request),
            Rcode::NOERROR,
            &chased
        ),
        Outcome::Response
    ));
    let message = Message::parse(&response).unwrap();
    let records: Vec<_> = message
        .answers()
        .map(|rr| (rr.rtype, rr.name.to_string()))
        .collect();
    assert_eq!(
        records,
        [
            (Type::A, "web.prod.example.com.".into()),
            (Type::CNAME, "web.prod.example.com.".into()),
            (Type::A, "lb.example.net.".into()),
            (Type::CNAME, "web.prod.example.com.".into()),
            (Type::A, "lb.example.net.".into()),
            (Type::A, "web.prod.example.com.".into())
        ]
    );
    let addresses: Vec<_> = message
        .answers()
        .filter_map(|rr| match rr.data().unwrap() {
            Rdata::A(ip) => Some(ip),
            _ => None,
        })
        .collect();
    assert_eq!(
        addresses,
        [
            "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap(),
            "203.0.113.1".parse().unwrap(),
            "203.0.113.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap()
        ]
    );

    for (empty, code) in [
        (lookup::Snapshot::NamespaceOnly, Rcode::NOERROR),
        (lookup::Snapshot::MissingService, Rcode::NXDOMAIN),
        (lookup::Snapshot::MissingNamespace, Rcode::NXDOMAIN),
    ] {
        response.clear();
        let mut empty_slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &zone,
            metadata: Metadata::new(&mut empty_slots),
            response: &mut response,
            max_response_size: 4096,
        };
        assert!(matches!(
            external.service_response(
                &mut cx,
                &external.zones[0],
                kubernetes,
                &store,
                Some(&empty),
                Some(&request),
                code,
                &[]
            ),
            Outcome::Response
        ));
        let message = Message::parse(&response).unwrap();
        assert_eq!(message.rcode(), code);
        assert_eq!(message.answer_count(), 0);
    }

    let mut stale_wire = chased[0].answers[0].clone().unwrap();
    stale_wire[2] |= 0x02;
    let mut stale = [
        Chased {
            ordinal: 2,
            name: "old.example.net.".parse().unwrap(),
            answers: [Some(stale_wire), None],
        },
        Chased {
            ordinal: 3,
            name: chased[1].name.clone(),
            answers: chased[1].answers.clone(),
        },
    ];
    response.clear();
    let mut stale_slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &zone,
        metadata: Metadata::new(&mut stale_slots),
        response: &mut response,
        max_response_size: 4096,
    };
    assert!(matches!(
        external.service_response(
            &mut cx,
            &external.zones[0],
            kubernetes,
            &store,
            None,
            Some(&request),
            Rcode::NOERROR,
            &stale,
        ),
        Outcome::Response
    ));
    let message = Message::parse(&response).unwrap();
    assert!(!message.tc(), "discarded stale lookup must not set TC");
    assert_eq!(
        message
            .answers()
            .filter(|rr| rr.rtype == Type::CNAME)
            .count(),
        1
    );
    assert!(message.answers().all(|rr| match rr.data().unwrap() {
        Rdata::Cname(target) => target.to_string() == "lb.example.net.",
        _ => true,
    }));

    stale[0].name = "lb.example.net.".parse().unwrap();
    response.clear();
    let mut valid_slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &zone,
        metadata: Metadata::new(&mut valid_slots),
        response: &mut response,
        max_response_size: 4096,
    };
    assert!(matches!(
        external.service_response(
            &mut cx,
            &external.zones[0],
            kubernetes,
            &store,
            None,
            Some(&request),
            Rcode::NOERROR,
            &stale
        ),
        Outcome::Response
    ));
    assert!(
        Message::parse(&response).unwrap().tc(),
        "followed lookup must preserve TC"
    );

    let srv_chased = [Chased {
        ordinal: 2,
        name: chased[0].name.clone(),
        answers: chased[0].answers.clone(),
    }];
    query.clear();
    let mut b = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
    b.question(
        NameRef::parse(owner.as_wire(), 0).unwrap(),
        Type::SRV,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    response.clear();
    let mut srv_slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &zone,
        metadata: Metadata::new(&mut srv_slots),
        response: &mut response,
        max_response_size: 4096,
    };
    assert!(matches!(
        external.service_response(
            &mut cx,
            &external.zones[0],
            kubernetes,
            &store,
            None,
            Some(&request),
            Rcode::NOERROR,
            &srv_chased
        ),
        Outcome::Response
    ));
    let message = Message::parse(&response).unwrap();
    let srv: Vec<_> = message
        .answers()
        .map(|rr| match rr.data().unwrap() {
            Rdata::Srv { target, port, .. } => (target.to_string(), port),
            _ => panic!("expected SRV"),
        })
        .collect();
    assert_eq!(
        srv,
        [
            ("web.prod.example.com.".into(), 80),
            ("web.prod.example.com.".into(), 443),
            ("lb.example.net.".into(), 80),
            ("lb.example.net.".into(), 443),
        ]
    );
    let extra: Vec<_> = message
        .additionals()
        .map(|rr| (rr.name.to_string(), rr.data().unwrap()))
        .collect();
    assert_eq!(
        extra,
        [
            (
                "web.prod.example.com.".into(),
                Rdata::A("192.0.2.1".parse().unwrap())
            ),
            (
                "lb.example.net.".into(),
                Rdata::A("203.0.113.1".parse().unwrap())
            ),
            (
                "web.prod.example.com.".into(),
                Rdata::A("192.0.2.2".parse().unwrap())
            )
        ]
    );

    let mut snapshot = store.with_read(|index| index.service_snapshot("prod", "web").unwrap());
    std::sync::Arc::make_mut(&mut snapshot).external_ips = vec![
        "198.51.100.1".into(),
        "lb.example.net".into(),
        "198.51.100.2".into(),
    ];
    query.clear();
    let mut b = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
    b.question(
        NameRef::parse(owner.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    response.clear();
    let mut snapshot_slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &zone,
        metadata: Metadata::new(&mut snapshot_slots),
        response: &mut response,
        max_response_size: 4096,
    };
    assert!(matches!(
        external.service_response(
            &mut cx,
            &external.zones[0],
            kubernetes,
            &store,
            Some(&lookup::Snapshot::Service(snapshot)),
            Some(&request),
            Rcode::NOERROR,
            &chased
        ),
        Outcome::Response
    ));
    let message = Message::parse(&response).unwrap();
    let addresses: Vec<_> = message
        .answers()
        .filter_map(|rr| match rr.data().unwrap() {
            Rdata::A(ip) => Some(ip),
            _ => None,
        })
        .collect();
    assert_eq!(
        addresses,
        [
            "198.51.100.1".parse::<std::net::Ipv4Addr>().unwrap(),
            "203.0.113.1".parse().unwrap(),
            "203.0.113.1".parse().unwrap(),
            "198.51.100.2".parse().unwrap()
        ]
    );
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

#[test]
fn chased_at_uses_callback_ordinal_and_hostname() {
    let chased = [
        Chased {
            ordinal: 1,
            name: "old.example.".parse().unwrap(),
            answers: [None, None],
        },
        Chased {
            ordinal: 3,
            name: "same.example.".parse().unwrap(),
            answers: [None, None],
        },
        Chased {
            ordinal: 5,
            name: "later.example.".parse().unwrap(),
            answers: [None, None],
        },
    ];
    assert_eq!(chased_at(&chased, 1, "old.example").unwrap().ordinal, 1);
    assert!(chased_at(&chased, 1, "same.example").is_none());
    assert!(chased_at(&chased, 4, "other.example").is_none());
    assert_eq!(
        chased_at(&chased, 5, "later.example")
            .unwrap()
            .name
            .to_string(),
        "later.example."
    );
    assert!(chased_at(&chased, 20, "same.example").is_none());
}

#[test]
fn one_hostname_chase_serves_each_service_port() {
    let chased = [Chased {
        ordinal: 2,
        name: "lb.example.net.".parse().unwrap(),
        answers: [None, None],
    }];
    let mut targets = scratch::Targets::default();
    let name = NameRef::parse(chased[0].name.as_wire(), 0).unwrap();
    let mut wire = [0; 255];
    let key = canonical_wire(name, &mut wire).unwrap();
    assert!(targets.insert(key, 0, true));
    assert!(chased_for_target(&targets, &chased, name).is_some());
    assert!(chased_for_target(&targets, &chased, name).is_some());
}

#[test]
fn hostname_chase_survives_interleaved_target_callbacks() {
    let chased = [
        Chased {
            ordinal: 0,
            name: "lb-a.example.net.".parse().unwrap(),
            answers: [None, None],
        },
        Chased {
            ordinal: 1,
            name: "lb-b.example.net.".parse().unwrap(),
            answers: [None, None],
        },
    ];
    let mut targets = scratch::Targets::default();
    for (index, entry) in chased.iter().enumerate() {
        let name = NameRef::parse(entry.name.as_wire(), 0).unwrap();
        let mut wire = [0; 255];
        let key = canonical_wire(name, &mut wire).unwrap();
        assert!(targets.insert(key, index, true));
    }
    for host in ["lb-a.example.net", "lb-b.example.net", "lb-a.example.net"] {
        let mut wire = [0; 255];
        let name = hostname(host, &mut wire).unwrap();
        assert!(chased_for_target(&targets, &chased, name).is_some());
    }
}

#[test]
fn chased_hosts_match_dns_labels_without_copying_presentation() {
    let chased = [Chased {
        ordinal: 0,
        name: r"a\.b.Example.".parse().unwrap(),
        answers: [None, None],
    }];
    let matches = |address| chased_at(&chased, 0, address).is_some();
    assert!(matches(r"a\.b.Example"));
    assert!(matches(r"a\046b.Example."));
    assert!(!matches(r"a.b.Example"));
    assert!(matches(r"a\.b.example"));
    assert!(!matches(r"a\.c.Example"));
    assert!(!matches(r"a\.b.Example.."));
}

#[test]
fn chased_hosts_handle_long_escapes_and_duplicate_ports() {
    let label = "a".repeat(63);
    let host = format!("{label}.Example");
    let escaped = format!("{}.Example.", r"\097".repeat(63));
    let name: Name = format!("{host}.").parse().unwrap();
    let chased = [
        Chased {
            ordinal: 0,
            name: name.clone(),
            answers: [None, None],
        },
        Chased {
            ordinal: 1,
            name,
            answers: [None, None],
        },
    ];
    assert!(chased_at(&chased, 0, &escaped).is_some());
    assert!(chased_at(&chased, 1, &host).is_some());
    assert!(chased_at(&chased, 0, &"x".repeat(8192)).is_none());
}

#[test]
fn endpoint_target_interprets_dots_as_name_separators() {
    let request = lookup::parse(&[b"web", b"prod"]).unwrap();
    let zone: Name = "example.org.".parse().unwrap();
    let mut wire = [0; 255];
    let target = service_target(
        &request,
        Some(b"pod.name"),
        "192.0.2.1",
        NameRef::parse(zone.as_wire(), 0).unwrap(),
        &mut wire,
    )
    .unwrap();
    assert_eq!(target.to_string(), "pod.name.web.prod.example.org.");
}

// CoreDNS v1.15.0 plugin/k8s_external/apex_test.go, TestApex.
#[tokio::test]
async fn apex_soa_uses_external_zone_and_serial() {
    let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
    let config = setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
        &["."],
    )
    .unwrap();
    let mut external = External::new(config).unwrap();
    let blocks = parse("Corefile", ".:53 {\n kubernetes cluster.local\n}").unwrap();
    let config = crate::kubernetes::setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
        &["."],
    )
    .unwrap();
    external.bind_kubernetes(&crate::kubernetes::Kubernetes::new(config).unwrap());
    let zone: Name = "example.com.".parse().unwrap();
    let zone_ref = NameRef::parse(zone.as_wire(), 0).unwrap();
    let mut request = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut request, 512, 1, 0).unwrap();
    b.question(zone_ref, Type::SOA, Class::IN).unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&request).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &zone,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert!(matches!(
        external.serve(&mut cx, Sentinel).await,
        Outcome::Response
    ));
    let message = Message::parse(&response).unwrap();
    let record = message.answers().next().unwrap();
    assert_eq!(record.ttl, 5);
    let Rdata::Soa {
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    } = record.data().unwrap()
    else {
        panic!("expected SOA")
    };
    assert_eq!(mname.to_string(), "ns1.dns.example.com.");
    assert_eq!(rname.to_string(), "hostmaster.dns.example.com.");
    assert_eq!(
        (serial, refresh, retry, expire, minimum),
        (0, 7200, 1800, 86400, 5)
    );
}

#[tokio::test]
async fn apex_without_matching_type_returns_nodata_with_soa() {
    let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
    let config = setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
        &["."],
    )
    .unwrap();
    let mut external = External::new(config).unwrap();
    let blocks = parse("Corefile", ".:53 {\n kubernetes cluster.local\n}").unwrap();
    let config = crate::kubernetes::setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
        &["."],
    )
    .unwrap();
    external.bind_kubernetes(&crate::kubernetes::Kubernetes::new(config).unwrap());
    let zone: Name = "example.com.".parse().unwrap();
    let zone_ref = NameRef::parse(zone.as_wire(), 0).unwrap();
    let mut request = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut request, 512, 1, 0).unwrap();
    b.question(zone_ref, Type::A, Class::IN).unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&request).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &zone,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert!(matches!(
        external.serve(&mut cx, Sentinel).await,
        Outcome::Response
    ));
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(message.answer_count(), 0);
    assert_eq!(message.authorities().next().unwrap().rtype, Type::SOA);
}

#[tokio::test]
async fn apex_ns_has_external_nameserver_target() {
    let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
    let config = setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
        &["."],
    )
    .unwrap();
    let mut external = External::new(config).unwrap();
    let blocks = parse("Corefile", ".:53 {\n kubernetes cluster.local\n}").unwrap();
    let config = crate::kubernetes::setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
        &["."],
    )
    .unwrap();
    external.bind_kubernetes(&crate::kubernetes::Kubernetes::new(config).unwrap());
    let zone: Name = "example.com.".parse().unwrap();
    let zone_ref = NameRef::parse(zone.as_wire(), 0).unwrap();
    let mut request = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut request, 512, 1, 0).unwrap();
    b.question(zone_ref, Type::NS, Class::IN).unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&request).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &zone,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert!(matches!(
        external.serve(&mut cx, Sentinel).await,
        Outcome::Response
    ));
    let message = Message::parse(&response).unwrap();
    let record = message.answers().next().unwrap();
    let Rdata::Ns(target) = record.data().unwrap() else {
        panic!("expected NS")
    };
    assert_eq!(target.to_string(), "ns1.dns.example.com.");
    assert_eq!(message.authorities().count(), 0);
}

#[tokio::test]
async fn apex_subdomain_rejects_other_names() {
    let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
    let config = setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
        &["."],
    )
    .unwrap();
    let mut external = External::new(config).unwrap();
    let blocks = parse("Corefile", ".:53 {\n kubernetes cluster.local\n}").unwrap();
    let config = crate::kubernetes::setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
        &["."],
    )
    .unwrap();
    external.bind_kubernetes(&crate::kubernetes::Kubernetes::new(config).unwrap());
    let zone: Name = "example.com.".parse().unwrap();
    let name: Name = "other.dns.example.com.".parse().unwrap();
    let mut request = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut request, 512, 1, 0).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&request).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &zone,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert!(matches!(
        external.serve(&mut cx, Sentinel).await,
        Outcome::Response
    ));
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(message.authorities().next().unwrap().rtype, Type::SOA);
}

#[tokio::test]
async fn unknown_namespace_is_nxdomain_not_fallthrough() {
    let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
    let config = setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
        &["."],
    )
    .unwrap();
    let mut external = External::new(config).unwrap();
    let blocks = parse("Corefile", ".:53 {\n kubernetes cluster.local\n}").unwrap();
    let config = crate::kubernetes::setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
        &["."],
    )
    .unwrap();
    external.bind_kubernetes(&crate::kubernetes::Kubernetes::new(config).unwrap());
    let zone: Name = "example.com.".parse().unwrap();
    let name: Name = "web.unknown.example.com.".parse().unwrap();
    let mut request = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut request, 512, 1, 0).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&request).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &zone,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert!(matches!(
        external.serve(&mut cx, Sentinel).await,
        Outcome::Response
    ));
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(message.authorities().next().unwrap().rtype, Type::SOA);
}

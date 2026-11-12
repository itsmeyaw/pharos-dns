#![forbid(unsafe_code)]
#![cfg(feature = "plugin-kubernetes")]

use crate::support;

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Context, Metadata, Outcome, Phase, Plugin, Protocol, Transport};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
};

async fn api() -> (
    String,
    watch::Sender<bool>,
    watch::Sender<bool>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", support::free_port()))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (gate, _) = watch::channel(false);
    let rx = gate.subscribe();
    let (lists, _) = watch::channel(true);
    let lists_rx = lists.subscribe();
    let requests = Arc::new(AtomicUsize::new(0));
    let watches = Arc::new(AtomicUsize::new(0));
    let observed_requests = requests.clone();
    let active_watches = watches.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut rx = rx.clone();
            let mut lists_rx = lists_rx.clone();
            let requests = observed_requests.clone();
            let watches = active_watches.clone();
            tokio::spawn(async move {
                let mut buf = [0; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                let request = String::from_utf8_lossy(&buf[..n]);
                if request.contains("watch=true") {
                    let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
                    if socket.write_all(response.as_bytes()).await.is_ok() {
                        requests.fetch_add(1, Ordering::SeqCst);
                        watches.fetch_add(1, Ordering::SeqCst);
                        let _ = socket.read(&mut buf).await;
                        watches.fetch_sub(1, Ordering::SeqCst);
                    }
                    return;
                }
                while !*lists_rx.borrow_and_update() {
                    if lists_rx.changed().await.is_err() {
                        return;
                    }
                }
                let (kind, items) = if request.contains("/api/v1/services") {
                    let ips = (1..=40)
                        .map(|n| format!("\"10.1.0.{n}\""))
                        .collect::<Vec<_>>()
                        .join(",");
                    let ports = (1..=40)
                        .map(|n| format!(r#"{{"name":"p{n}","protocol":"TCP","port":{n}}}"#))
                        .collect::<Vec<_>>()
                        .join(",");
                    (
                        "ServiceList",
                        format!(
                            r#"[{{"metadata":{{"name":"web","namespace":"prod"}},"spec":{{"clusterIP":"10.0.0.1","ports":[{{"name":"http","protocol":"TCP","port":80}}]}}}},{{"metadata":{{"name":"bulk","namespace":"prod"}},"spec":{{"clusterIPs":[{ips}],"ports":[{ports}]}}}}]"#
                        ),
                    )
                } else if request.contains("/endpointslices") {
                    while !*rx.borrow_and_update() {
                        if rx.changed().await.is_err() {
                            return;
                        }
                    }
                    ("EndpointSliceList", r#"[{"metadata":{"name":"web-1","namespace":"prod","labels":{"kubernetes.io/service-name":"web"},"annotations":{"endpoints.kubernetes.io/last-change-trigger-time":"2024-01-01T00:00:00Z"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.0.2"]}]}]"#.to_owned())
                } else {
                    (
                        "NamespaceList",
                        r#"[{"metadata":{"name":"prod"}}]"#.to_owned(),
                    )
                };
                let body = format!(
                    r#"{{"apiVersion":"v1","kind":"{kind}","metadata":{{"resourceVersion":"1"}},"items":{items}}}"#
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                if socket.write_all(response.as_bytes()).await.is_ok() {
                    requests.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    (
        format!("http://{address}"),
        gate,
        lists,
        requests,
        watches,
        task,
    )
}

fn chain(endpoint: &str, timeout: &str) -> Arc<Chain> {
    let text = format!(
        ".:53 {{\n kubernetes cluster.local {{\n  endpoint {endpoint}\n  startup_timeout {timeout}\n }}\n}}"
    );
    let mut blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    Arc::new(blocks.remove(0).config)
}

async fn query(chain: &Chain, name: &str, kind: Type) -> (Rcode, u16) {
    let (code, answers, _, _) = query_details(chain, name, kind).await;
    (code, answers)
}

async fn query_details(chain: &Chain, name: &str, kind: Type) -> (Rcode, u16, u16, bool) {
    let name: Name = name.parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
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
    assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    let message = Message::parse(&response).unwrap();
    (
        message.rcode(),
        message.answer_count(),
        message.additional_count(),
        message.tc(),
    )
}

#[tokio::test]
async fn partial_cache_is_visible_while_startup_waits() {
    let (endpoint, gate, _, _, _, server) = api().await;
    let chain = chain(&endpoint, "5s");
    let readiness = chain.kubernetes.as_ref().unwrap().readiness().unwrap();
    assert!(!readiness.ready());
    let lifecycle = chain.lifecycle.clone();
    let startup = tokio::spawn(async move { lifecycle.run(Phase::Startup).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if query(&chain, "web.prod.svc.cluster.local.", Type::A).await == (Rcode::NOERROR, 1) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cached service was unavailable during startup");
    assert!(!startup.is_finished());
    assert!(!readiness.ready());
    assert_eq!(
        query(&chain, "_http._tcp.web.prod.svc.cluster.local.", Type::SRV).await,
        (Rcode::NOERROR, 1)
    );
    assert_eq!(
        query(&chain, "missing.prod.svc.cluster.local.", Type::A).await,
        (Rcode::SERVFAIL, 0)
    );
    gate.send(true).unwrap();
    startup.await.unwrap();
    assert!(readiness.ready());
    assert_eq!(
        query(&chain, "missing.prod.svc.cluster.local.", Type::A).await,
        (Rcode::NXDOMAIN, 0)
    );
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    assert!(!readiness.ready());
    server.abort();
}

#[tokio::test]
async fn failed_restart_keeps_cached_answers_until_new_lists_complete() {
    let (endpoint, gate, lists, _, watches, server) = api().await;
    gate.send(true).unwrap();
    let chain = chain(&endpoint, "2s");
    let readiness = chain.kubernetes.as_ref().unwrap().readiness().unwrap();
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    assert!(readiness.ready());
    until(|| watches.load(Ordering::SeqCst) == 3).await;
    assert_eq!(
        query(&chain, "web.prod.svc.cluster.local.", Type::A).await,
        (Rcode::NOERROR, 1)
    );
    lists.send(false).unwrap();
    chain.lifecycle.run(Phase::Restart).await.unwrap();
    until(|| watches.load(Ordering::SeqCst) == 0).await;
    assert!(!readiness.ready());
    assert_eq!(
        query(&chain, "web.prod.svc.cluster.local.", Type::A).await,
        (Rcode::NOERROR, 1)
    );
    assert_eq!(
        query(&chain, "missing.prod.svc.cluster.local.", Type::A).await,
        (Rcode::SERVFAIL, 0)
    );
    let lifecycle = chain.lifecycle.clone();
    let restart = tokio::spawn(async move { lifecycle.run(Phase::RestartFailed).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!restart.is_finished());
    assert!(!readiness.ready());
    assert_eq!(
        query(&chain, "web.prod.svc.cluster.local.", Type::A).await,
        (Rcode::NOERROR, 1)
    );
    assert_eq!(
        query(&chain, "missing.prod.svc.cluster.local.", Type::A).await,
        (Rcode::SERVFAIL, 0)
    );
    lists.send(true).unwrap();
    restart.await.unwrap();
    assert!(readiness.ready());
    until(|| watches.load(Ordering::SeqCst) == 3).await;
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    until(|| watches.load(Ordering::SeqCst) == 0).await;
    server.abort();
}

async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("condition did not become true");
}

#[tokio::test]
async fn startup_timeout_returns_before_sync_and_readiness_recovers() {
    let (endpoint, gate, _, _, _, server) = api().await;
    let chain = chain(&endpoint, "200ms");
    let readiness = chain.kubernetes.as_ref().unwrap().readiness().unwrap();
    tokio::time::timeout(Duration::from_secs(1), chain.lifecycle.run(Phase::Startup))
        .await
        .unwrap()
        .unwrap();
    assert!(!readiness.ready());
    tokio::time::timeout(Duration::from_secs(2), async {
        while query(&chain, "web.prod.svc.cluster.local.", Type::A).await != (Rcode::NOERROR, 1) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        query(&chain, "missing.prod.svc.cluster.local.", Type::A).await,
        (Rcode::SERVFAIL, 0)
    );
    gate.send(true).unwrap();
    until(|| readiness.ready()).await;
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readiness_stays_true_during_queries() {
    let (endpoint, gate, _, _, _, server) = api().await;
    gate.send(true).unwrap();
    let chain = chain(&endpoint, "2s");
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let chain = chain.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..1000 {
                assert_eq!(
                    query(&chain, "web.prod.svc.cluster.local.", Type::A).await,
                    (Rcode::NOERROR, 1)
                );
                tokio::task::yield_now().await;
            }
        }));
    }
    for _ in 0..5000 {
        assert!(
            chain
                .kubernetes
                .as_ref()
                .unwrap()
                .readiness()
                .unwrap()
                .ready()
        );
        tokio::task::yield_now().await;
    }
    for task in tasks {
        task.await.unwrap();
    }
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn successful_reload_retires_only_old_watchers() {
    let (endpoint, gate, _, _, watches, server) = api().await;
    gate.send(true).unwrap();
    let old = chain(&endpoint, "2s");
    old.lifecycle.run(Phase::Startup).await.unwrap();
    until(|| watches.load(Ordering::SeqCst) == 3).await;
    old.lifecycle.run(Phase::Restart).await.unwrap();
    until(|| watches.load(Ordering::SeqCst) == 0).await;
    let new = chain(&endpoint, "2s");
    new.lifecycle.run(Phase::Startup).await.unwrap();
    until(|| watches.load(Ordering::SeqCst) == 3).await;
    old.lifecycle.run(Phase::Shutdown).await.unwrap();
    assert!(
        new.kubernetes
            .as_ref()
            .unwrap()
            .readiness()
            .unwrap()
            .ready()
    );
    assert_eq!(
        query(&new, "web.prod.svc.cluster.local.", Type::A).await,
        (Rcode::NOERROR, 1)
    );
    assert_eq!(watches.load(Ordering::SeqCst), 3);
    new.lifecycle.run(Phase::Shutdown).await.unwrap();
    until(|| watches.load(Ordering::SeqCst) == 0).await;
    server.abort();
}

#[tokio::test]
async fn large_answers_stop_with_truncation_and_no_srv_glue() {
    let (endpoint, gate, _, _, _, server) = api().await;
    gate.send(true).unwrap();
    let chain = chain(&endpoint, "2s");
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    for kind in [Type::A, Type::SRV] {
        let (code, answers, additional, truncated) =
            query_details(&chain, "bulk.prod.svc.cluster.local.", kind).await;
        assert_eq!(code, Rcode::NOERROR);
        assert!(answers > 0);
        assert!(truncated);
        assert_eq!(additional, 0);
    }
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn registry_counts_each_api_request_once_across_restart() {
    let (endpoint, gate, _, requests, watches, server) = api().await;
    gate.send(true).unwrap();
    let text = format!(
        ".:53 {{\n kubernetes cluster.local {{\n  endpoint {endpoint}\n  startup_timeout 2s\n }}\n}}"
    );
    let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let registry = pharos_server::metrics::Registry::new("test", "test", "test");
    let (_servers, lifecycle) =
        pharos_plugins::servers_with_registry(blocks, registry.clone()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    until(|| watches.load(Ordering::SeqCst) == 3).await;
    until(|| metric_requests(&registry) == requests.load(Ordering::SeqCst)).await;
    assert_eq!(metric_requests(&registry), 6);
    lifecycle.run(Phase::Restart).await.unwrap();
    until(|| watches.load(Ordering::SeqCst) == 0).await;
    lifecycle.run(Phase::RestartFailed).await.unwrap();
    until(|| watches.load(Ordering::SeqCst) == 3).await;
    until(|| metric_requests(&registry) == requests.load(Ordering::SeqCst)).await;
    assert_eq!(metric_requests(&registry), 12);
    lifecycle.run(Phase::Shutdown).await.unwrap();
    until(|| watches.load(Ordering::SeqCst) == 0).await;
    server.abort();
}

#[tokio::test]
async fn registry_records_endpoint_programming_once_per_list() {
    registry_records_endpoint_programming().await;
}

async fn registry_records_endpoint_programming() {
    let (endpoint, gate, _, _, _, server) = api().await;
    let text = format!(
        ".:53 {{\n kubernetes cluster.local {{\n  endpoint {endpoint}\n  startup_timeout 2s\n }}\n}}"
    );
    let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let registry = pharos_server::metrics::Registry::new("test", "test", "test");
    let (mut servers, lifecycle) =
        pharos_plugins::servers_with_registry(blocks, registry.clone()).unwrap();
    let (_, dns) = servers.drain().next().unwrap();
    let startup_lifecycle = lifecycle.clone();
    let startup = tokio::spawn(async move { startup_lifecycle.run(Phase::Startup).await.unwrap() });
    let name: Name = "web.prod.svc.cluster.local.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            pharos_server::Handler::handle(
                &dns,
                &wire,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await;
            if Message::parse(&response).is_ok_and(|message| message.answer_count() == 1) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    gate.send(true).unwrap();
    startup.await.unwrap();
    let mut encoded = String::new();
    registry.encode(&mut encoded);
    assert_eq!(
        encoded
            .lines()
            .filter(|line| line
                .starts_with("pharos_kubernetes_dns_programming_duration_seconds_count{")
                && line.ends_with(" 1"))
            .count(),
        1
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
    server.abort();
}

fn metric_requests(registry: &pharos_server::metrics::Registry) -> usize {
    let mut text = String::new();
    registry.encode(&mut text);
    text.lines()
        .filter(|line| line.starts_with("pharos_kubernetes_rest_client_requests_total{"))
        .map(|line| line.rsplit_once(' ').unwrap().1.parse::<usize>().unwrap())
        .sum()
}

#![forbid(unsafe_code)]
#![cfg(feature = "plugin-kubernetes")]

use crate::support;

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Type};
use pharos_server::{Context, Metadata, Outcome, Phase, Plugin, Protocol, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Fixtures match the object-level cases in CoreDNS v1.15.0 kubernetes_test.go.
async fn api() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", support::free_port()))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0; 8192];
                let n = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                let (kind, items) = if request.contains("/api/v1/services") {
                    let mut items = vec![
                        r#"{"metadata":{"name":"svc1","namespace":"testns"},"spec":{"clusterIP":"10.0.0.1","ports":[{"name":"http","protocol":"TCP","port":80}]}}"#.to_string(),
                        r#"{"metadata":{"name":"svc-dual-stack","namespace":"testns"},"spec":{"clusterIPs":["10.0.0.2","10::2"],"ports":[{"name":"http","protocol":"TCP","port":80}]}}"#.to_string(),
                        r#"{"metadata":{"name":"hdls1","namespace":"testns"},"spec":{"clusterIP":"None"}}"#.to_string(),
                        r#"{"metadata":{"name":"external","namespace":"testns"},"spec":{"type":"ExternalName","externalName":"coredns.io","ports":[{"name":"http","protocol":"TCP","port":80}]}}"#.to_string(),
                        r#"{"metadata":{"name":"webs","namespace":"mynamespace"},"spec":{"clusterIP":"None"}}"#.to_string(),
                    ];
                    for i in 0..8 {
                        items.push(format!(r#"{{"metadata":{{"name":"ep{i}","namespace":"testns"}},"spec":{{"clusterIP":"None"}}}}"#));
                    }
                    ("ServiceList", items.join(","))
                } else if request.contains("/endpointslices") {
                    // The synthetic "zone" protocol makes parse row 10 observable through DNS.
                    let mut items = vec![
                        r#"{"metadata":{"name":"svc1-slice1","namespace":"testns","labels":{"kubernetes.io/service-name":"svc1"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":80}],"endpoints":[{"addresses":["172.0.0.1"],"hostname":"ep1a"}]}"#.to_string(),
                        r#"{"metadata":{"name":"hdls1-slice1","namespace":"testns","labels":{"kubernetes.io/service-name":"hdls1"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":80}],"endpoints":[{"addresses":["172.0.0.2"]}]}"#.to_string(),
                        r#"{"metadata":{"name":"webs-slice","namespace":"mynamespace","labels":{"kubernetes.io/service-name":"webs"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":80},{"name":"us-west-2a","protocol":"zone","port":81}],"endpoints":[{"addresses":["1.2.3.4"],"zone":"us-west-2a"},{"addresses":["1.2.3.5"],"zone":"corp.example.com"}]}"#.to_string(),
                    ];
                    for (i, (ip, hostname, pod)) in [
                        ("10.11.12.13", "", ""),
                        ("10.11.12.13", "epname", ""),
                        ("10.11.12.13", "", "hello-abcde"),
                        ("10.11.12.13", "epname", "hello-abcde"),
                        ("10.11.12.13", "epname", "hello-abcde"),
                        ("10.11.12.13", "", "hello-abcde"),
                        ("2001:db8:3333:4444:5555:6666:7777:8888", "", ""),
                        ("2001:db8:3333:4444:5555:6666::", "", ""),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        let family = if ip.contains(':') { "IPv6" } else { "IPv4" };
                        items.push(format!(r#"{{"metadata":{{"name":"ep{i}-slice","namespace":"testns","labels":{{"kubernetes.io/service-name":"ep{i}"}}}},"addressType":"{family}","ports":[{{"name":"http","protocol":"TCP","port":80}}],"endpoints":[{{"addresses":["{ip}"],"hostname":"{hostname}","targetRef":{{"name":"{pod}"}}}}]}}"#));
                    }
                    ("EndpointSliceList", items.join(","))
                } else if request.contains("/api/v1/pods") {
                    ("PodList", String::new())
                } else {
                    (
                        "NamespaceList",
                        r#"{"metadata":{"name":"testns"}},{"metadata":{"name":"mynamespace"}}"#
                            .to_string(),
                    )
                };
                if request.contains("watch=true") {
                    if socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").await.is_ok() {
                        let _ = socket.read(&mut [0; 1]).await;
                    }
                    return;
                }
                let body = format!(
                    r#"{{"apiVersion":"v1","kind":"{kind}","metadata":{{"resourceVersion":"1"}},"items":[{items}]}}"#
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (format!("http://{address}"), task)
}

async fn chain(endpoint: &str, options: &str) -> Chain {
    let text = format!(
        ".:53 {{\n kubernetes interwebs.test inter.webs.tests inter.webs.test {{\n  endpoint {endpoint}\n  startup_timeout 3s\n  {options}\n }}\n}}"
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
    chain
}

async fn query(chain: &Chain, name: &str, kind: Type, local: &str) -> Vec<u8> {
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
        local: local.parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(chain.serve(&mut cx).await, Outcome::Response, "{name}");
    response
}

#[tokio::test]
async fn coredns_endpoint_hostname_rows() {
    let (endpoint, server) = api().await;
    let standard = chain(&endpoint, "").await;
    let pod_names = chain(&endpoint, "endpoint_pod_names").await;
    let mut failures = Vec::new();
    for (i, expected) in [
        "10-11-12-13",
        "epname",
        "10-11-12-13",
        "epname",
        "epname",
        "hello-abcde",
        "2001-db8-3333-4444-5555-6666-7777-8888",
        "2001-db8-3333-4444-5555-6666--0",
    ]
    .into_iter()
    .enumerate()
    {
        let chain = if i == 4 || i == 5 {
            &pod_names
        } else {
            &standard
        };
        let name = format!("_http._tcp.ep{i}.testns.svc.interwebs.test.");
        let wire = query(chain, &name, Type::SRV, "192.0.2.1:53").await;
        let message = Message::parse(&wire).unwrap();
        let actual = message
            .answers()
            .next()
            .and_then(|rr| match rr.data().ok()? {
                Rdata::Srv {
                    target, port: 80, ..
                } => Some(target.to_string()),
                _ => None,
            });
        let expected = format!("{expected}.ep{i}.testns.svc.interwebs.test.");
        if message.rcode() != Rcode::NOERROR
            || actual.as_deref() != Some(&expected)
            || message.answer_count() != 1
        {
            failures.push(format!(
                "TestEndpointHostname[{i}] expected {expected}, got {:?} {actual:?}",
                message.rcode()
            ));
        }
    }
    standard.lifecycle.run(Phase::Shutdown).await.unwrap();
    pod_names.lifecycle.run(Phase::Shutdown).await.unwrap();
    server.abort();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn coredns_services_rows() {
    let (endpoint, server) = api().await;
    let chain = chain(&endpoint, "").await;
    let mut failures = Vec::new();
    for (i, name, kind, expected) in [
        (0, "svc1.testns.svc.interwebs.test.", Type::A, "10.0.0.1"),
        (
            1,
            "_http._tcp.svc1.testns.svc.interwebs.test.",
            Type::SRV,
            "svc1.testns.svc.interwebs.test.",
        ),
        (
            2,
            "ep1a.svc1.testns.svc.interwebs.test.",
            Type::A,
            "172.0.0.1",
        ),
        (
            3,
            "_http._tcp.svc-dual-stack.testns.svc.interwebs.test.",
            Type::SRV,
            "svc-dual-stack.testns.svc.interwebs.test.",
        ),
        (
            4,
            "external.testns.svc.interwebs.test.",
            Type::CNAME,
            "coredns.io.",
        ),
        (5, "hdls1.testns.svc.interwebs.test.", Type::A, "172.0.0.2"),
    ] {
        let wire = query(&chain, name, kind, "192.0.2.1:53").await;
        let message = Message::parse(&wire).unwrap();
        let actual = message
            .answers()
            .next()
            .and_then(|rr| match rr.data().ok()? {
                Rdata::A(ip) => Some(ip.to_string()),
                Rdata::Srv {
                    target, port: 80, ..
                } => Some(target.to_string()),
                Rdata::Cname(target) => Some(target.to_string()),
                _ => None,
            });
        let mut glue: Vec<_> = message
            .additionals()
            .filter_map(|rr| match rr.data().ok()? {
                Rdata::A(ip) => Some(ip.to_string()),
                Rdata::Aaaa(ip) => Some(ip.to_string()),
                _ => None,
            })
            .collect();
        glue.sort();
        let expected_glue = match i {
            1 => vec!["10.0.0.1"],
            3 => vec!["10.0.0.2", "10::2"],
            _ => vec![],
        };
        if message.rcode() != Rcode::NOERROR
            || message.answer_count() != 1
            || actual.as_deref() != Some(expected)
            || glue != expected_glue
        {
            failures.push(format!("TestServices[{i}] expected {expected} glue {expected_glue:?}, got {:?} {actual:?} glue {glue:?}", message.rcode()));
        }
    }
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    server.abort();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn coredns_parse_request_dns_visible_rows() {
    let (endpoint, server) = api().await;
    let zonal = chain(&endpoint, "zonal").await;
    let ordinary = chain(&endpoint, "").await;
    let mut failures = Vec::new();
    for (id, chain, name, kind, expected_code, expected_ips) in [
        (
            "TestParseRequest[0]",
            &ordinary,
            "_http._tcp.webs.mynamespace.svc.inter.webs.tests.",
            Type::A,
            Rcode::NOERROR,
            vec!["1.2.3.4", "1.2.3.5"],
        ),
        (
            "TestParseRequest[1]",
            &ordinary,
            "1-2-3-4.webs.mynamespace.svc.inter.webs.tests.",
            Type::A,
            Rcode::NOERROR,
            vec!["1.2.3.4"],
        ),
        (
            "TestParseRequest[2]",
            &ordinary,
            "inter.webs.tests.",
            Type::A,
            Rcode::NOERROR,
            vec![],
        ),
        (
            "TestParseRequest[3]",
            &ordinary,
            "svc.inter.webs.tests.",
            Type::A,
            Rcode::NOERROR,
            vec![],
        ),
        (
            "TestParseRequest[4]",
            &ordinary,
            "pod.inter.webs.tests.",
            Type::A,
            Rcode::NOERROR,
            vec![],
        ),
        (
            "TestParseRequest[7]",
            &zonal,
            "us-west-2a.pin._zone.webs.mynamespace.svc.inter.webs.tests.",
            Type::A,
            Rcode::NOERROR,
            vec!["1.2.3.4"],
        ),
        (
            "TestParseRequest[8]",
            &zonal,
            "us-west-2a.prefer._zone.webs.mynamespace.svc.inter.webs.tests.",
            Type::A,
            Rcode::NOERROR,
            vec!["1.2.3.4"],
        ),
        (
            "TestParseRequest[9]",
            &zonal,
            "corp.example.com.pin._zone.webs.mynamespace.svc.inter.webs.tests.",
            Type::A,
            Rcode::NOERROR,
            vec!["1.2.3.5"],
        ),
        (
            "TestParseRequest[10]",
            &zonal,
            "us-west-2a._zone.webs.mynamespace.svc.inter.webs.tests.",
            Type::A,
            Rcode::NOERROR,
            vec!["1.2.3.4", "1.2.3.5"],
        ),
        (
            "TestParseInvalidRequest[0]",
            &ordinary,
            "webs.mynamespace.pood.inter.webs.test.",
            Type::A,
            Rcode::NXDOMAIN,
            vec![],
        ),
        (
            "TestParseInvalidRequest[1]",
            &ordinary,
            "too.long.for.what.I.am.trying.to.pod.inter.webs.tests.",
            Type::A,
            Rcode::NXDOMAIN,
            vec![],
        ),
        (
            "TestParseInvalidRequest[2]",
            &ordinary,
            "us-west-2a.pin._zone.webs.mynamespace.svc.inter.webs.tests.",
            Type::A,
            Rcode::NXDOMAIN,
            vec![],
        ),
        (
            "TestParseInvalidRequest.zonalInvalid[0]",
            &zonal,
            "us-west-2a.pin._zone.webs.mynamespace.pod.inter.webs.tests.",
            Type::A,
            Rcode::NXDOMAIN,
            vec![],
        ),
        (
            "TestParseInvalidRequest.zonalInvalid[1]",
            &zonal,
            "us-west-2a.florp._zone.webs.mynamespace.svc.inter.webs.tests.",
            Type::A,
            Rcode::NXDOMAIN,
            vec![],
        ),
    ] {
        let wire = query(chain, name, kind, "192.0.2.1:53").await;
        let message = Message::parse(&wire).unwrap();
        let mut ips: Vec<_> = message
            .answers()
            .filter_map(|rr| match rr.data().ok()? {
                Rdata::A(ip) => Some(ip.to_string()),
                _ => None,
            })
            .collect();
        ips.sort();
        if message.rcode() != expected_code
            || ips != expected_ips
            || usize::from(message.answer_count()) != expected_ips.len()
        {
            failures.push(format!(
                "{id} expected {expected_code:?} {expected_ips:?}, got {:?} {ips:?}",
                message.rcode()
            ));
        }
    }
    zonal.lifecycle.run(Phase::Shutdown).await.unwrap();
    ordinary.lifecycle.run(Phase::Shutdown).await.unwrap();
    server.abort();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

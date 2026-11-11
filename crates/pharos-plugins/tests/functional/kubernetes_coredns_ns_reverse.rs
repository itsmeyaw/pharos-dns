#![forbid(unsafe_code)]
#![cfg(feature = "plugin-kubernetes")]

use crate::support;

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Record, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Phase, Plugin, Protocol, Transport};
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SERVICES: &str = r#"[
 {"metadata":{"name":"dns-service","namespace":"kube-system"},"spec":{"clusterIP":"10.0.0.111"}},
 {"metadata":{"name":"hdls-dns-service","namespace":"kube-system"},"spec":{"clusterIP":"None"}},
 {"metadata":{"name":"dns6-service","namespace":"kube-system"},"spec":{"clusterIP":"10::111"}},
 {"metadata":{"name":"svc1","namespace":"testns"},"spec":{"clusterIP":"192.168.1.100","ports":[{"name":"http","protocol":"TCP","port":80}]}}
]"#;

// The ns_test.go endpoint's synthetic local IP is replaced with a real interface.
async fn api(local: IpAddr) -> (String, tokio::task::JoinHandle<()>) {
    api_with(local, &["slice1"]).await
}

async fn api_with(local: IpAddr, dns_slices: &[&str]) -> (String, tokio::task::JoinHandle<()>) {
    let family = if local.is_ipv4() { "IPv4" } else { "IPv6" };
    let mut slices = Vec::new();
    for service in ["dns-service", "hdls-dns-service", "dns6-service"] {
        for slice in dns_slices {
            slices.push(format!(r#"{{"metadata":{{"name":"{service}-{slice}","namespace":"kube-system","labels":{{"kubernetes.io/service-name":"{service}"}}}},"addressType":"{family}","endpoints":[{{"addresses":["{local}"]}}]}}"#));
        }
    }
    slices.extend([
        r#"{"metadata":{"name":"svc1-slice1","namespace":"testns","labels":{"kubernetes.io/service-name":"svc1"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":80}],"endpoints":[{"addresses":["10.0.0.100"],"hostname":"ep1a"},{"addresses":["10.0.0.99"],"hostname":"double-ep"},{"addresses":["192.168.1.100"],"hostname":"shadowed"}]}"#.to_string(),
        r#"{"metadata":{"name":"svc1-slice2","namespace":"testns","labels":{"kubernetes.io/service-name":"svc1"}},"addressType":"IPv6","ports":[{"name":"http","protocol":"TCP","port":80}],"endpoints":[{"addresses":["1234:abcd::1"],"hostname":"ep1b"},{"addresses":["fd00:77:30::a"],"hostname":"ip6svc1ex"},{"addresses":["fd00:77:30::2:9ba6"],"hostname":"ip6svc1in"}]}"#.to_string(),
        r#"{"metadata":{"name":"svc1-ccccc","namespace":"testns","labels":{"kubernetes.io/service-name":"svc1"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":80}],"endpoints":[{"addresses":["10.0.0.100"],"hostname":"ep1a"}]}"#.to_string(),
        r#"{"metadata":{"name":"svc2-slice1","namespace":"testns","labels":{"kubernetes.io/service-name":"svc2"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":80}],"endpoints":[{"addresses":["10.0.0.99"],"hostname":"double-ep"}]}"#.to_string(),
    ]);
    let endpoints = format!("[{}]", slices.join(","));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", support::free_port()))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let endpoints = endpoints.clone();
            tokio::spawn(async move {
                let mut request = [0; 8192];
                let n = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                if request.contains("watch=true") {
                    if socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").await.is_ok() {
                        let _ = socket.read(&mut [0; 1]).await;
                    }
                    return;
                }
                let (kind, items) = if request.contains("/api/v1/services") {
                    ("ServiceList", SERVICES)
                } else if request.contains("/endpointslices") {
                    ("EndpointSliceList", endpoints.as_str())
                } else if request.contains("/api/v1/pods") {
                    ("PodList", "[]")
                } else if request.contains("labelSelector=") {
                    (
                        "NamespaceList",
                        r#"[{"metadata":{"name":"other","labels":{"dns":"yes"}}}]"#,
                    )
                } else {
                    (
                        "NamespaceList",
                        r#"[{"metadata":{"name":"kube-system","labels":{"dns":"no"}}},{"metadata":{"name":"testns","labels":{"dns":"no"}}},{"metadata":{"name":"other","labels":{"dns":"yes"}}}]"#,
                    )
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
    (format!("http://{address}"), task)
}

fn local_ip() -> IpAddr {
    let addresses: Vec<_> = nix::ifaddrs::getifaddrs()
        .unwrap()
        .filter_map(|item| {
            let address = item.address?;
            address
                .as_sockaddr_in()
                .map(|a| IpAddr::V4(a.ip()))
                .or_else(|| address.as_sockaddr_in6().map(|a| IpAddr::V6(a.ip())))
        })
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .collect();
    let ip = addresses
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| addresses.first())
        .copied()
        .expect("NS test requires a non-loopback interface address");
    if ip.is_ipv6() {
        eprintln!("NS upstream IPv4 substitution unavailable; using local IPv6 {ip}");
    }
    ip
}

async fn chain(endpoint: &str, zones: &str, options: &str) -> Chain {
    let text = format!(
        ".:53 {{\n kubernetes {zones} {{\n  endpoint {endpoint}\n  startup_timeout 3s\n  {options}\n }}\n}}"
    );
    let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    chain
}

struct Sentinel;
impl Next for Sentinel {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(Rcode::REFUSED)
    }
}

async fn query(chain: &Chain, name: &str, kind: Type) -> (Outcome, Vec<u8>) {
    let name: Name = name.parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut request = Vec::with_capacity(4096);
    let mut builder = MessageBuilder::new(&mut request, 4096, 1, 0x100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(4096);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&request).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "192.0.2.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 4096,
    };
    let outcome = chain
        .kubernetes
        .as_ref()
        .unwrap()
        .serve(&mut cx, Sentinel)
        .await;
    (outcome, response)
}

fn record(rr: Record<'_>) -> String {
    assert_eq!(rr.class, Class::IN);
    assert_eq!(rr.ttl, 5);
    let data = match rr.data().unwrap() {
        Rdata::A(ip) => format!("A {ip}"),
        Rdata::Aaaa(ip) => format!("AAAA {ip}"),
        Rdata::Ns(name) => format!("NS {name}"),
        Rdata::Ptr(name) => format!("PTR {name}"),
        Rdata::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            assert!(serial == 0 || serial > 1_000_000_000);
            format!("SOA {mname} {rname} {refresh} {retry} {expire} {minimum}")
        }
        data => panic!("unexpected RR: {data:?}"),
    };
    format!("{} {data}", rr.name)
}

fn check(
    wire: &[u8],
    code: Rcode,
    answers: &[String],
    authority: &[String],
    additional: &[String],
    id: &str,
) {
    let msg = Message::parse(wire).unwrap();
    assert!(!msg.tc(), "{id}");
    let mut actual = [
        msg.answers().map(record).collect::<Vec<_>>(),
        msg.authorities().map(record).collect(),
        msg.additionals().map(record).collect(),
    ];
    let mut expected = [answers.to_vec(), authority.to_vec(), additional.to_vec()];
    for list in &mut actual {
        list.sort();
    }
    for list in &mut expected {
        list.sort();
    }
    assert_eq!(msg.rcode(), code, "{id}: sections {actual:?}");
    assert_eq!(actual, expected, "{id}");
}

fn soa(zone: &str) -> String {
    format!("{zone} SOA ns.dns.{zone} hostmaster.{zone} 7200 1800 86400 5")
}

// CoreDNS ns_test.go: TestNsAddrs.
// Skipped: TestNsAddrsExternalHeadless, TestNsAddrsExternal, and
// TestNsAddrsExternalWithPreexistingExternalIP exercise k8s_external, not kubernetes.
#[tokio::test]
async fn coredns_ns_addrs_and_namespace_filters() {
    let local = local_ip();
    let (endpoint, task) = api(local).await;
    let mut label = local.to_string().replace(['.', ':'], "-");
    if label.ends_with('-') {
        label.push('0');
    }
    let zone = "inter.webs.test.";
    let head = format!("{label}.hdls-dns-service.kube-system.svc.{zone}");
    let dns = format!("dns-service.kube-system.svc.{zone}");
    let dns6 = format!("dns6-service.kube-system.svc.{zone}");
    for options in ["", "namespaces other", "namespace_labels dns=yes"] {
        let chain = chain(&endpoint, zone, options).await;
        let (outcome, wire) = query(&chain, zone, Type::NS).await;
        assert_eq!(outcome, Outcome::Response);
        let ordered: Vec<_> = Message::parse(&wire)
            .unwrap()
            .answers()
            .map(|record| match record.data().unwrap() {
                Rdata::Ns(name) => name.to_string(),
                _ => panic!("expected NS"),
            })
            .collect();
        assert_eq!(
            ordered,
            [dns.as_str(), head.as_str(), dns6.as_str()],
            "first-seen NS order: {options}"
        );
        check(
            &wire,
            Rcode::NOERROR,
            &[
                format!("{zone} NS {dns}"),
                format!("{zone} NS {head}"),
                format!("{zone} NS {dns6}"),
            ],
            &[],
            &[
                format!("{dns} A 10.0.0.111"),
                format!(
                    "{head} {} {local}",
                    if local.is_ipv4() { "A" } else { "AAAA" }
                ),
                format!("{dns6} AAAA 10::111"),
            ],
            &format!("TestNsAddrs {options}"),
        );
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    }
    task.abort();
}

// A local address in two slices of one Service (dual-stack, or a mirrored
// slice) must not duplicate glue; CoreDNS's plugin.NS appends it per slice.
#[tokio::test]
async fn apex_ns_glue_is_not_duplicated() {
    let local = local_ip();
    let (endpoint, task) = api_with(local, &["slice1", "slice2"]).await;
    let zone = "inter.webs.test.";
    let chain = chain(&endpoint, zone, "").await;
    let (outcome, wire) = query(&chain, zone, Type::NS).await;
    assert_eq!(outcome, Outcome::Response);
    let mut additional: Vec<_> = Message::parse(&wire)
        .unwrap()
        .additionals()
        .map(record)
        .collect();
    let total = additional.len();
    additional.sort();
    additional.dedup();
    assert_eq!(additional.len(), total, "{additional:?}");
    assert_eq!(total, 3);
    let (_, wire) = query(&chain, &format!("ns.dns.{zone}"), Type::A).await;
    assert_eq!(
        Message::parse(&wire).unwrap().answer_count(),
        1 + u16::from(local.is_ipv4())
    );
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

const ZONES: &str = "cluster.local 0.10.in-addr.arpa 168.192.in-addr.arpa 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.c.b.a.4.3.2.1.ip6.arpa 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.0.0.7.7.0.0.0.0.d.f.ip6.arpa";

// One-based row numbers are the TestReverse table in CoreDNS v1.15.0.
#[tokio::test]
async fn coredns_reverse_rows() {
    type ReverseCase<'a> = (&'a str, Type, Rcode, &'a [&'a str], Option<&'a str>);
    let (endpoint, task) = api("192.0.2.200".parse().unwrap()).await;
    let chain = chain(&endpoint, ZONES, "").await;
    let cases: &[ReverseCase<'_>] = &[
        (
            "100.0.0.10.in-addr.arpa.",
            Type::PTR,
            Rcode::NOERROR,
            &["ep1a.svc1.testns.svc.cluster.local."],
            None,
        ),
        (
            "100.1.168.192.in-addr.arpa.",
            Type::PTR,
            Rcode::NOERROR,
            &["svc1.testns.svc.cluster.local."],
            None,
        ),
        (
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.c.b.a.4.3.2.1.ip6.arpa.",
            Type::PTR,
            Rcode::NOERROR,
            &["ep1b.svc1.testns.svc.cluster.local."],
            None,
        ),
        (
            "a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.0.0.7.7.0.0.0.0.d.f.ip6.arpa.",
            Type::PTR,
            Rcode::NOERROR,
            &["ip6svc1ex.svc1.testns.svc.cluster.local."],
            None,
        ),
        (
            "6.a.b.9.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.0.0.7.7.0.0.0.0.d.f.ip6.arpa.",
            Type::PTR,
            Rcode::NOERROR,
            &["ip6svc1in.svc1.testns.svc.cluster.local."],
            None,
        ),
        (
            "101.0.0.10.in-addr.arpa.",
            Type::PTR,
            Rcode::NXDOMAIN,
            &[],
            Some("0.10.in-addr.arpa."),
        ),
        (
            "example.org.cluster.local.",
            Type::PTR,
            Rcode::NXDOMAIN,
            &[],
            Some("cluster.local."),
        ),
        (
            "svc1.testns.svc.cluster.local.",
            Type::PTR,
            Rcode::NOERROR,
            &[],
            Some("cluster.local."),
        ),
        (
            "svc1.testns.svc.0.10.in-addr.arpa.",
            Type::A,
            Rcode::NXDOMAIN,
            &[],
            Some("0.10.in-addr.arpa."),
        ),
        (
            "100.0.0.10.cluster.local.",
            Type::PTR,
            Rcode::NXDOMAIN,
            &[],
            Some("cluster.local."),
        ),
        (
            "99.0.0.10.in-addr.arpa.",
            Type::PTR,
            Rcode::NOERROR,
            &[
                "double-ep.svc1.testns.svc.cluster.local.",
                "double-ep.svc2.testns.svc.cluster.local.",
            ],
            None,
        ),
    ];
    for (index, (name, kind, code, targets, zone)) in cases.iter().enumerate() {
        if index == 8 {
            continue; // Row 9 is isolated so a regression cannot hide later rows.
        }
        let (outcome, wire) = query(&chain, name, *kind).await;
        assert_eq!(outcome, Outcome::Response, "TestReverse row {}", index + 1);
        check(
            &wire,
            *code,
            &targets
                .iter()
                .map(|target| format!("{name} PTR {target}"))
                .collect::<Vec<_>>(),
            &zone.iter().map(|z| soa(z)).collect::<Vec<_>>(),
            &[],
            &format!("TestReverse row {}", index + 1),
        );
    }
    let (outcome, wire) = query(&chain, "100.0.0.10.other.example.", Type::PTR).await;
    assert_eq!(outcome, Outcome::Unanswered(Rcode::REFUSED));
    assert!(wire.is_empty());
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

#[tokio::test]
async fn coredns_reverse_wrong_zone_row_9() {
    let (endpoint, task) = api("192.0.2.200".parse().unwrap()).await;
    let chain = chain(&endpoint, ZONES, "").await;
    let name = "svc1.testns.svc.0.10.in-addr.arpa.";
    for kind in [Type::A, Type::AAAA, Type::SRV, Type::CNAME, Type::TXT] {
        let (outcome, wire) = query(&chain, name, kind).await;
        assert_eq!(outcome, Outcome::Response);
        check(
            &wire,
            Rcode::NXDOMAIN,
            &[],
            &[soa("0.10.in-addr.arpa.")],
            &[],
            "TestReverse row 9",
        );
    }
    // SOA is special-cased by the handler even for nonexistent names.
    let (outcome, wire) = query(&chain, name, Type::SOA).await;
    assert_eq!(outcome, Outcome::Response);
    check(
        &wire,
        Rcode::NOERROR,
        &[],
        &[soa("0.10.in-addr.arpa.")],
        &[],
        "SOA in reverse Domain",
    );
    let (outcome, wire) = query(&chain, "dns-version.0.10.in-addr.arpa.", Type::TXT).await;
    assert_eq!(outcome, Outcome::Response);
    let message = Message::parse(&wire).unwrap();
    assert_eq!(
        (message.rcode(), message.answer_count()),
        (Rcode::NOERROR, 1)
    );
    let record = message.answers().next().unwrap();
    assert_eq!(record.ttl, 28800);
    assert!(matches!(record.data().unwrap(), Rdata::Txt(data) if data == b"\x051.1.0"));
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

#[tokio::test]
async fn reverse_filtering_and_explicit_fallthrough() {
    let (endpoint, task) = api("192.0.2.200".parse().unwrap()).await;
    for (option, code, targets) in [
        ("namespaces other", Rcode::NXDOMAIN, vec![]),
        (
            "namespaces testns",
            Rcode::NOERROR,
            vec!["ep1a.svc1.testns.svc.cluster.local."],
        ),
        (
            "namespace_labels dns=yes",
            Rcode::NOERROR,
            vec!["ep1a.svc1.testns.svc.cluster.local."],
        ),
    ] {
        let chain = chain(&endpoint, ZONES, option).await;
        let name = "100.0.0.10.in-addr.arpa.";
        let (outcome, wire) = query(&chain, name, Type::PTR).await;
        assert_eq!(outcome, Outcome::Response);
        let answers: Vec<_> = targets
            .iter()
            .map(|target| format!("{name} PTR {target}"))
            .collect();
        let authority = if targets.is_empty() {
            vec![soa("0.10.in-addr.arpa.")]
        } else {
            vec![]
        };
        check(&wire, code, &answers, &authority, &[], option);
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    }
    let chain = chain(&endpoint, ZONES, "fallthrough 0.10.in-addr.arpa").await;
    for (name, kind, fallthrough) in [
        ("101.0.0.10.in-addr.arpa.", Type::PTR, true),
        ("100.0.0.10.in-addr.arpa.", Type::PTR, false),
        ("example.org.cluster.local.", Type::PTR, false),
        ("101.0.0.10.in-addr.arpa.", Type::A, true),
    ] {
        let (outcome, wire) = query(&chain, name, kind).await;
        if fallthrough {
            assert_eq!(outcome, Outcome::Unanswered(Rcode::REFUSED), "{name}");
            assert!(wire.is_empty());
        } else if name.starts_with("100.") {
            assert_eq!(outcome, Outcome::Response);
            check(
                &wire,
                Rcode::NOERROR,
                &[format!("{name} PTR ep1a.svc1.testns.svc.cluster.local.")],
                &[],
                &[],
                name,
            );
        } else {
            assert_eq!(outcome, Outcome::Response);
            check(
                &wire,
                Rcode::NXDOMAIN,
                &[],
                &[soa("cluster.local.")],
                &[],
                name,
            );
        }
    }
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

#![forbid(unsafe_code)]
#![cfg(feature = "plugin-k8s-external")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Record, Type};
use pharos_server::{Action, Handler, Phase, Protocol};
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// CoreDNS v1.15.0 plugin/k8s_external/external_test.go fixtures.
const SERVICES: &str = r#"[
 {"metadata":{"name":"svc1","namespace":"testns"},"spec":{"type":"ClusterIP","clusterIP":"10.0.0.1","externalIPs":["1.2.3.4"],"ports":[{"name":"http","protocol":"TCP","port":80}]}},
 {"metadata":{"name":"svc6","namespace":"testns"},"spec":{"type":"ClusterIP","clusterIP":"10.0.0.3","externalIPs":["1:2::5"],"ports":[{"name":"http","protocol":"TCP","port":80}]}},
 {"metadata":{"name":"svc11","namespace":"testns"},"spec":{"type":"LoadBalancer","clusterIP":"10.0.0.3","externalIPs":["2.3.4.5"],"ports":[{"name":"http","protocol":"TCP","port":80}]}},
 {"metadata":{"name":"svc12","namespace":"testns"},"spec":{"type":"LoadBalancer","clusterIP":"10.0.0.3","externalIPs":["dummy.hostname"],"ports":[{"name":"http","protocol":"TCP","port":80}]}},
 {"metadata":{"name":"mixed","namespace":"testns"},"spec":{"type":"LoadBalancer","clusterIP":"10.0.0.4","externalIPs":["192.0.2.1"],"ports":[{"name":"http","protocol":"TCP","port":80},{"name":"https","protocol":"TCP","port":443}]},"status":{"loadBalancer":{"ingress":[{"hostname":"one.target.test"},{"ip":"2001:db8::1"},{"ip":"192.0.2.2"},{"ip":"2001:0db8:0:0:0:0:0:1"},{"hostname":"two.target.test"},{"ip":"2001:db8::2"},{"ip":"192.0.2.1"}]}}},
 {"metadata":{"name":"svc-headless","namespace":"testns"},"spec":{"type":"ClusterIP","clusterIP":"None","ports":[{"name":"http","protocol":"TCP","port":80}]}},
 {"metadata":{"name":"dns-service","namespace":"kube-system"},"spec":{"clusterIP":"10.0.0.111","externalIPs":["127.0.0.1"]}}
]"#;

async fn api(local: IpAddr) -> (String, tokio::task::JoinHandle<()>) {
    let family = if local.is_ipv4() { "IPv4" } else { "IPv6" };
    let endpoints = format!(
        r#"[
     {{"metadata":{{"name":"svc-headless-slice","namespace":"testns","labels":{{"kubernetes.io/service-name":"svc-headless"}}}},"addressType":"IPv4","ports":[{{"name":"http","protocol":"TCP","port":80}}],"endpoints":[{{"addresses":["1.2.3.4"],"hostname":"endpoint-svc-0","nodeName":"test-node","targetRef":{{"name":"endpoint-svc-0"}}}},{{"addresses":["1.2.3.5"],"hostname":"endpoint-svc-1","nodeName":"test-node","targetRef":{{"name":"endpoint-svc-1"}}}}]}},
     {{"metadata":{{"name":"dns-service-slice","namespace":"kube-system","labels":{{"kubernetes.io/service-name":"dns-service"}}}},"addressType":"{family}","endpoints":[{{"addresses":["{local}"]}}]}}
    ]"#
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                } else {
                    (
                        "NamespaceList",
                        r#"[{"metadata":{"name":"testns"}},{"metadata":{"name":"kube-system"}}]"#,
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
    nix::ifaddrs::getifaddrs()
        .unwrap()
        .filter_map(|item| {
            item.netmask?;
            let address = item.address?;
            address
                .as_sockaddr_in()
                .map(|a| IpAddr::V4(a.ip()))
                .or_else(|| address.as_sockaddr_in6().map(|a| IpAddr::V6(a.ip())))
        })
        .find(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .expect("nameserver fixture requires a non-loopback interface")
}

fn record(rr: Record<'_>) -> String {
    // RFC 1035 §3.2.1 and RFC 2782 §3: check RR class, TTL, and SRV fields.
    assert_eq!(rr.class, Class::IN);
    assert_eq!(rr.ttl, 5);
    let data = match rr.data().unwrap() {
        Rdata::A(ip) => format!("A {ip}"),
        Rdata::Aaaa(ip) => format!("AAAA {ip}"),
        Rdata::Ns(name) => format!("NS {name}"),
        Rdata::Cname(name) => format!("CNAME {name}"),
        Rdata::Ptr(name) => format!("PTR {name}"),
        Rdata::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("SRV {priority} {weight} {port} {target}"),
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

struct Case {
    name: &'static str,
    kind: Type,
    code: Rcode,
    answer: &'static [&'static str],
    authority: &'static [&'static str],
    additional: &'static [&'static str],
}

const SOA: &str =
    "example.com. SOA ns1.dns.example.com. hostmaster.dns.example.com. 7200 1800 86400 5";

async fn check(server: &pharos_server::Server<std::sync::Arc<Chain>>, case: &Case) -> Option<u32> {
    let name: Name = case.name.parse().unwrap();
    let mut request = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut request, 512, 123, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            case.kind,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(
                &request,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
        Action::Respond,
        "{} {:?}",
        case.name,
        case.kind
    );
    let msg = Message::parse(&response).unwrap();
    assert_eq!(msg.rcode(), case.code, "{} {:?}", case.name, case.kind);
    // RFC 1035 §4.1.1: an authoritative response sets AA.
    assert!(msg.aa(), "{} {:?}", case.name, case.kind);
    assert!(!msg.tc(), "{} {:?}", case.name, case.kind);
    let mut actual = [
        msg.answers().map(record).collect::<Vec<_>>(),
        msg.authorities().map(record).collect(),
        msg.additionals().map(record).collect(),
    ];
    let mut expected = [
        case.answer.to_vec(),
        case.authority.to_vec(),
        case.additional.to_vec(),
    ];
    for section in &mut actual {
        section.sort();
    }
    for section in &mut expected {
        section.sort();
    }
    assert_eq!(actual, expected, "{} {:?}", case.name, case.kind);
    msg.answers().chain(msg.authorities()).find_map(|rr| {
        if let Rdata::Soa { serial, .. } = rr.data().unwrap() {
            Some(serial)
        } else {
            None
        }
    })
}

macro_rules! case {
    ($name:literal, $kind:ident, $code:ident, [$($answer:expr),* $(,)?], [$($authority:expr),* $(,)?], [$($additional:expr),* $(,)?]) => {
        Case { name: $name, kind: Type::$kind, code: Rcode::$code, answer: &[$($answer),*], authority: &[$($authority),*], additional: &[$($additional),*] }
    };
}

// CoreDNS v1.15.0 external_test.go TestExternal and apex_test.go TestApex.
#[tokio::test]
async fn coredns_external_and_apex_responses() {
    coredns_scenario().await;
}

async fn coredns_scenario() {
    let (endpoint, task) = api(local_ip()).await;
    let config = format!(
        ".:53 {{\n k8s_external example.com in-addr.arpa {{\n  headless\n }}\n kubernetes cluster.local {{\n  endpoint {endpoint}\n  namespaces testns\n  startup_timeout 3s\n }}\n}}"
    );
    let (mut configured, lifecycle) =
        servers(configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap())
            .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = configured.drain().next().unwrap();
    let cases = [
        case!(
            "4.3.2.1.in-addr.arpa.",
            PTR,
            NOERROR,
            ["4.3.2.1.in-addr.arpa. PTR svc1.testns.example.com."],
            [],
            []
        ),
        case!("svc1.testns.example.com.", PTR, NOERROR, [], [SOA], []),
        case!(
            "not-existing.testns.example.com.",
            PTR,
            NXDOMAIN,
            [],
            [SOA],
            []
        ),
        case!(
            "svc1.testns.example.com.",
            A,
            NOERROR,
            ["svc1.testns.example.com. A 1.2.3.4"],
            [],
            []
        ),
        case!(
            "svc1.testns.example.com.",
            SRV,
            NOERROR,
            ["svc1.testns.example.com. SRV 0 100 80 svc1.testns.example.com."],
            [],
            ["svc1.testns.example.com. A 1.2.3.4"]
        ),
        case!(
            "*._not-udp-or-tcp.svc1.testns.example.com.",
            SRV,
            NXDOMAIN,
            [],
            [SOA],
            []
        ),
        case!(
            "_http._tcp.svc1.testns.example.com.",
            SRV,
            NOERROR,
            ["_http._tcp.svc1.testns.example.com. SRV 0 100 80 svc1.testns.example.com."],
            [],
            ["svc1.testns.example.com. A 1.2.3.4"]
        ),
        case!("svc1.testns.example.com.", AAAA, NOERROR, [], [SOA], []),
        case!("svc0.testns.example.com.", AAAA, NXDOMAIN, [], [SOA], []),
        case!("svc0.testns.example.com.", A, NXDOMAIN, [], [SOA], []),
        case!("svc0.svc-nons.example.com.", A, NXDOMAIN, [], [SOA], []),
        case!(
            "svc6.testns.example.com.",
            AAAA,
            NOERROR,
            ["svc6.testns.example.com. AAAA 1:2::5"],
            [],
            []
        ),
        case!(
            "_http._tcp.svc6.testns.example.com.",
            SRV,
            NOERROR,
            ["_http._tcp.svc6.testns.example.com. SRV 0 100 80 svc6.testns.example.com."],
            [],
            ["svc6.testns.example.com. AAAA 1:2::5"]
        ),
        case!(
            "svc6.testns.example.com.",
            SRV,
            NOERROR,
            ["svc6.testns.example.com. SRV 0 100 80 svc6.testns.example.com."],
            [],
            ["svc6.testns.example.com. AAAA 1:2::5"]
        ),
        case!("testns.example.com.", A, NOERROR, [], [SOA], []),
        case!("testns.example.com.", SOA, NOERROR, [], [SOA], []),
        case!(
            "svc11.testns.example.com.",
            A,
            NOERROR,
            ["svc11.testns.example.com. A 2.3.4.5"],
            [],
            []
        ),
        case!(
            "_http._tcp.svc11.testns.example.com.",
            SRV,
            NOERROR,
            ["_http._tcp.svc11.testns.example.com. SRV 0 100 80 svc11.testns.example.com."],
            [],
            ["svc11.testns.example.com. A 2.3.4.5"]
        ),
        case!(
            "svc11.testns.example.com.",
            SRV,
            NOERROR,
            ["svc11.testns.example.com. SRV 0 100 80 svc11.testns.example.com."],
            [],
            ["svc11.testns.example.com. A 2.3.4.5"]
        ),
        case!(
            "svc12.testns.example.com.",
            A,
            NOERROR,
            ["svc12.testns.example.com. CNAME dummy.hostname."],
            [],
            []
        ),
        case!(
            "_http._tcp.svc12.testns.example.com.",
            SRV,
            NOERROR,
            ["_http._tcp.svc12.testns.example.com. SRV 0 100 80 dummy.hostname."],
            [],
            []
        ),
        case!(
            "svc12.testns.example.com.",
            SRV,
            NOERROR,
            ["svc12.testns.example.com. SRV 0 100 80 dummy.hostname."],
            [],
            []
        ),
        case!(
            "svc-headless.testns.example.com.",
            A,
            NOERROR,
            [
                "svc-headless.testns.example.com. A 1.2.3.4",
                "svc-headless.testns.example.com. A 1.2.3.5"
            ],
            [],
            []
        ),
        case!(
            "svc-headless.testns.example.com.",
            SRV,
            NOERROR,
            [
                "svc-headless.testns.example.com. SRV 0 50 80 endpoint-svc-0.svc-headless.testns.example.com.",
                "svc-headless.testns.example.com. SRV 0 50 80 endpoint-svc-1.svc-headless.testns.example.com."
            ],
            [],
            [
                "endpoint-svc-0.svc-headless.testns.example.com. A 1.2.3.4",
                "endpoint-svc-1.svc-headless.testns.example.com. A 1.2.3.5"
            ]
        ),
        case!(
            "_http._tcp.svc-headless.testns.example.com.",
            SRV,
            NOERROR,
            [
                "_http._tcp.svc-headless.testns.example.com. SRV 0 50 80 endpoint-svc-0.svc-headless.testns.example.com.",
                "_http._tcp.svc-headless.testns.example.com. SRV 0 50 80 endpoint-svc-1.svc-headless.testns.example.com."
            ],
            [],
            [
                "endpoint-svc-0.svc-headless.testns.example.com. A 1.2.3.4",
                "endpoint-svc-1.svc-headless.testns.example.com. A 1.2.3.5"
            ]
        ),
        case!(
            "endpoint-svc-0.svc-headless.testns.example.com.",
            SRV,
            NOERROR,
            [
                "endpoint-svc-0.svc-headless.testns.example.com. SRV 0 100 80 endpoint-svc-0.svc-headless.testns.example.com."
            ],
            [],
            ["endpoint-svc-0.svc-headless.testns.example.com. A 1.2.3.4"]
        ),
        case!(
            "endpoint-svc-1.svc-headless.testns.example.com.",
            SRV,
            NOERROR,
            [
                "endpoint-svc-1.svc-headless.testns.example.com. SRV 0 100 80 endpoint-svc-1.svc-headless.testns.example.com."
            ],
            [],
            ["endpoint-svc-1.svc-headless.testns.example.com. A 1.2.3.5"]
        ),
        case!(
            "endpoint-svc-0.svc-headless.testns.example.com.",
            A,
            NOERROR,
            ["endpoint-svc-0.svc-headless.testns.example.com. A 1.2.3.4"],
            [],
            []
        ),
        case!(
            "endpoint-svc-1.svc-headless.testns.example.com.",
            A,
            NOERROR,
            ["endpoint-svc-1.svc-headless.testns.example.com. A 1.2.3.5"],
            [],
            []
        ),
        case!("example.com.", SOA, NOERROR, [SOA], [], []),
        case!(
            "example.com.",
            NS,
            NOERROR,
            ["example.com. NS ns1.dns.example.com."],
            [],
            ["ns1.dns.example.com. A 127.0.0.1"]
        ),
        case!("example.com.", SRV, NOERROR, [], [SOA], []),
        case!("dns.example.com.", SRV, NOERROR, [], [SOA], []),
        case!("dns.example.com.", NS, NOERROR, [], [SOA], []),
        case!("ns1.dns.example.com.", SRV, NOERROR, [], [SOA], []),
        case!("ns1.dns.example.com.", NS, NOERROR, [], [SOA], []),
        case!("ns1.dns.example.com.", AAAA, NOERROR, [], [SOA], []),
        case!(
            "ns1.dns.example.com.",
            A,
            NOERROR,
            ["ns1.dns.example.com. A 127.0.0.1"],
            [],
            []
        ),
    ];
    let mut serial = None;
    for case in &cases {
        if let Some(actual) = check(&server, case).await {
            assert_eq!(*serial.get_or_insert(actual), actual, "SOA serial changed");
        }
    }
    lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

#[tokio::test]
#[cfg(feature = "plugin-hosts")]
async fn mixed_external_addresses_preserve_coredns_answer_order() {
    mixed_order_scenario().await;
}

#[cfg(feature = "plugin-hosts")]
async fn mixed_order_scenario() {
    let (endpoint, task) = api(local_ip()).await;
    let text = format!(
        ".:0 {{\n k8s_external example.com\n kubernetes cluster.local {{\n  endpoint {endpoint}\n  startup_timeout 3s\n }}\n hosts /nonexistent target.test {{\n  203.0.113.1 one.target.test\n  203.0.113.2 two.target.test\n  2001:db8::11 one.target.test\n  2001:db8::22 two.target.test\n }}\n}}"
    );
    let (mut configured, lifecycle) =
        servers(configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap())
            .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = configured.drain().next().unwrap();
    let name: Name = "mixed.testns.example.com.".parse().unwrap();
    for (kind, expected) in [
        (
            Type::A,
            vec![
                "A 192.0.2.1",
                "CNAME one.target.test.",
                "A 203.0.113.1",
                "CNAME one.target.test.",
                "A 203.0.113.1",
                "A 192.0.2.2",
                "CNAME two.target.test.",
                "A 203.0.113.2",
                "CNAME two.target.test.",
                "A 203.0.113.2",
            ],
        ),
        (
            Type::AAAA,
            vec![
                "CNAME one.target.test.",
                "AAAA 2001:db8::11",
                "CNAME one.target.test.",
                "AAAA 2001:db8::11",
                "AAAA 2001:db8::1",
                "AAAA 2001:db8::1",
                "CNAME two.target.test.",
                "AAAA 2001:db8::22",
                "CNAME two.target.test.",
                "AAAA 2001:db8::22",
                "AAAA 2001:db8::2",
            ],
        ),
    ] {
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    &query,
                    "127.0.0.1:1234".parse().unwrap(),
                    Protocol::Udp,
                    &mut response
                )
                .await,
            Action::Respond
        );
        let message = Message::parse(&response).unwrap();
        assert_eq!(message.rcode(), Rcode::NOERROR, "{kind:?}: {message:?}");
        let actual: Vec<_> = message
            .answers()
            .map(|rr| match rr.data().unwrap() {
                Rdata::A(ip) => format!("A {ip}"),
                Rdata::Aaaa(ip) => format!("AAAA {ip}"),
                Rdata::Cname(name) => format!("CNAME {name}"),
                other => panic!("unexpected answer: {other:?}"),
            })
            .collect();
        assert_eq!(actual, expected, "{kind:?}");
    }
    lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

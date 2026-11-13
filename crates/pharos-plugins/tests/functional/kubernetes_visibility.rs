#![forbid(unsafe_code)]
#![cfg(feature = "plugin-kubernetes")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Type};
use pharos_server::{Context, Metadata, Outcome, Phase, Protocol, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::support;

const WILDCARD: &str = "0.0.0.0:53";

async fn fake_api(
    replacements: &[(&str, String)],
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let replacements = replacements
        .iter()
        .map(|(from, to)| ((*from).to_owned(), to.clone()))
        .collect::<Vec<_>>();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", support::free_port()))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let replacements = replacements.clone();
            tokio::spawn(async move {
                let mut request = [0; 4096];
                let n = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                let (kind, items) = if request.contains("/api/v1/services") {
                    (
                        "ServiceList",
                        r#"[{"metadata":{"name":"dns","namespace":"hidden"},"spec":{"clusterIPs":["10.0.0.111","2001:db8::111"]}},{"metadata":{"name":"head","namespace":"hidden"},"spec":{"clusterIP":"None"}},{"metadata":{"name":"dns6","namespace":"hidden"},"spec":{"clusterIP":"10.0.0.112"}},{"metadata":{"name":"missing","namespace":"absent"},"spec":{"clusterIP":"10.0.0.113"}},{"metadata":{"name":"visible","namespace":"visible"},"spec":{"clusterIP":"10.0.0.114"}}]"#,
                    )
                } else if request.contains("/endpointslices") {
                    (
                        "EndpointSliceList",
                        r#"[{"metadata":{"name":"dns","namespace":"hidden","labels":{"kubernetes.io/service-name":"dns"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.30"],"hostname":"dns-pod"}]},{"metadata":{"name":"head","namespace":"hidden","labels":{"kubernetes.io/service-name":"head"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.30"],"hostname":"head-pod"},{"addresses":["10.0.0.99"],"hostname":"double"},{"addresses":["10.0.0.111"],"hostname":"shadowed"}]},{"metadata":{"name":"head-duplicate","namespace":"hidden","labels":{"kubernetes.io/service-name":"head"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.0.99"],"hostname":"double"}]},{"metadata":{"name":"dns6","namespace":"hidden","labels":{"kubernetes.io/service-name":"dns6"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.30"],"hostname":"dns6-pod"},{"addresses":["10.0.0.99"],"hostname":"double"}]},{"metadata":{"name":"v6","namespace":"hidden","labels":{"kubernetes.io/service-name":"head"}},"addressType":"IPv6","endpoints":[{"addresses":["2001:db8::2"],"hostname":"v6"},{"addresses":["2001:db8::30"],"hostname":"local6"}]},{"metadata":{"name":"orphan","namespace":"hidden","labels":{"kubernetes.io/service-name":"orphan"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.31"],"hostname":"orphan"}]},{"metadata":{"name":"missing","namespace":"absent","labels":{"kubernetes.io/service-name":"missing"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.0.115"],"hostname":"missing"},{"addresses":["192.0.2.30"],"hostname":"missing-local"}]}]"#,
                    )
                } else {
                    let namespaces = if request.contains("labelSelector=") {
                        r#"[{"metadata":{"name":"visible","labels":{"dns":"yes"}}}]"#
                    } else {
                        r#"[{"metadata":{"name":"visible","labels":{"dns":"yes"}}},{"metadata":{"name":"hidden","labels":{"dns":"no"}}}]"#
                    };
                    ("NamespaceList", namespaces)
                };
                let body = if request.contains("watch=true") {
                    String::new()
                } else {
                    let mut body = format!(
                        r#"{{"apiVersion":"v1","kind":"{kind}","metadata":{{"resourceVersion":"1"}},"items":{items}}}"#
                    );
                    for (from, to) in replacements {
                        body = body.replace(&from, &to);
                    }
                    body
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (address, task)
}

fn chain(address: std::net::SocketAddr, option: &str) -> Chain {
    let text = format!(
        ".:53 {{\n kubernetes cluster.local in-addr.arpa ip6.arpa {{\n  endpoint http://{address}\n  startup_timeout 3s\n  {option}\n }}\n}}"
    );
    configure::<Chain>(&parse("Corefile", &text).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config
}

async fn query(chain: &Chain, name: &str, kind: Type, local: &str) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(4096);
    let mut builder = MessageBuilder::new(&mut wire, 4096, 1, 0x100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(4096);
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
        max_response_size: 4096,
    };
    // Keep the unmeasured Chain future out of the visibility fixture's stack.
    assert_eq!(Box::pin(chain.serve(&mut cx)).await, Outcome::Response);
    response
}

#[tokio::test]
async fn ns_discovery_ignores_namespace_restrictions() {
    let interfaces: Vec<_> = nix::ifaddrs::getifaddrs()
        .unwrap()
        .filter_map(|item| {
            let address = item.address?;
            address
                .as_sockaddr_in()
                .map(|a| std::net::IpAddr::V4(a.ip()))
                .or_else(|| {
                    address
                        .as_sockaddr_in6()
                        .map(|a| std::net::IpAddr::V6(a.ip()))
                })
        })
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .collect();
    let local_v4 = interfaces
        .iter()
        .find(|ip| ip.is_ipv4())
        .expect("a non-loopback IPv4 interface is required")
        .to_string();
    let local_v6 = interfaces
        .iter()
        .find(|ip| ip.is_ipv6())
        .map(ToString::to_string);
    let (address, task) = fake_api(&[("192.0.2.30", local_v4.clone())]).await;
    for option in ["namespace_labels dns=yes", "namespaces visible"] {
        let chain = chain(address, option);
        chain.lifecycle.run(Phase::Startup).await.unwrap();
        let wire = query(&chain, "cluster.local.", Type::NS, WILDCARD).await;
        let msg = Message::parse(&wire).unwrap();
        assert_eq!(msg.rcode(), Rcode::NOERROR, "{option}");
        let mut targets: Vec<_> = msg
            .answers()
            .map(|rr| {
                assert_eq!(rr.name.to_string(), "cluster.local.");
                match rr.data().unwrap() {
                    Rdata::Ns(name) => name.to_string(),
                    _ => panic!("not NS"),
                }
            })
            .collect();
        targets.sort();
        assert_eq!(
            targets,
            [
                "dns.hidden.svc.cluster.local.",
                "dns6.hidden.svc.cluster.local.",
                "double.head.hidden.svc.cluster.local.",
                "head-pod.head.hidden.svc.cluster.local.",
                "missing.absent.svc.cluster.local.",
                "shadowed.head.hidden.svc.cluster.local."
            ],
            "{option}"
        );
        let mut glue: Vec<_> = msg
            .additionals()
            .map(|rr| {
                let ip = match rr.data().unwrap() {
                    Rdata::A(ip) => ip.to_string(),
                    Rdata::Aaaa(ip) => ip.to_string(),
                    _ => panic!("not address"),
                };
                (rr.name.to_string(), ip)
            })
            .collect();
        glue.sort();
        assert_eq!(
            glue,
            [
                ("dns.hidden.svc.cluster.local.", "10.0.0.111"),
                ("dns.hidden.svc.cluster.local.", "2001:db8::111"),
                ("dns6.hidden.svc.cluster.local.", "10.0.0.112"),
                ("double.head.hidden.svc.cluster.local.", "10.0.0.99"),
                ("head-pod.head.hidden.svc.cluster.local.", local_v4.as_str()),
                ("missing.absent.svc.cluster.local.", "10.0.0.113"),
                ("shadowed.head.hidden.svc.cluster.local.", "10.0.0.111")
            ]
            .map(|(n, ip)| (n.to_owned(), ip.to_owned()))
        );
        let wire = query(&chain, "dns.hidden.svc.cluster.local.", Type::A, WILDCARD).await;
        assert_eq!(
            Message::parse(&wire).unwrap().rcode(),
            Rcode::NXDOMAIN,
            "forward lookup remains filtered: {option}"
        );
        let wire = query(&chain, "ns.dns.cluster.local.", Type::AAAA, WILDCARD).await;
        let msg = Message::parse(&wire).unwrap();
        assert_eq!(msg.answer_count(), 1);
        let rr = msg.answers().next().unwrap();
        assert_eq!(rr.name.to_string(), "ns.dns.cluster.local.");
        assert!(matches!(rr.data().unwrap(), Rdata::Aaaa(ip) if ip.to_string() == "2001:db8::111"));
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    }
    task.abort();
    for (replacement, expect_orphan) in [
        (Some(("192.0.2.31", local_v4.clone())), true),
        (None, false),
    ] {
        let replacements: Vec<_> = replacement.into_iter().collect();
        let (address, task) = fake_api(&replacements).await;
        let chain = chain(address, "namespace_labels dns=yes");
        chain.lifecycle.run(Phase::Startup).await.unwrap();
        let wire = query(&chain, "cluster.local.", Type::NS, WILDCARD).await;
        let msg = Message::parse(&wire).unwrap();
        if expect_orphan {
            assert_eq!(
                (msg.answer_count(), msg.additional_count()),
                (0, 0),
                "orphan suppresses fallback"
            );
        } else {
            assert!(
                matches!(msg.answers().next().unwrap().data().unwrap(), Rdata::Ns(name) if name.to_string() == "ns.dns.cluster.local.")
            );
            assert!(msg.additionals().any(|rr| rr.name.to_string() == "ns.dns.cluster.local." && matches!(rr.data().unwrap(), Rdata::A(ip) if ip.to_string() == local_v4)));
        }
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
        task.abort();
    }
    if let Some(local_v6) = local_v6 {
        let (address, task) = fake_api(&[("2001:db8::30", local_v6.clone())]).await;
        let chain = chain(address, "namespace_labels dns=yes");
        chain.lifecycle.run(Phase::Startup).await.unwrap();
        let wire = query(&chain, "cluster.local.", Type::NS, WILDCARD).await;
        let msg = Message::parse(&wire).unwrap();
        let mut targets: Vec<_> = msg
            .answers()
            .map(|rr| match rr.data().unwrap() {
                Rdata::Ns(name) => name.to_string(),
                _ => panic!("not NS"),
            })
            .collect();
        targets.sort();
        assert_eq!(
            targets,
            [
                "local6.head.hidden.svc.cluster.local.",
                "v6.head.hidden.svc.cluster.local."
            ]
        );
        let mut glue: Vec<_> = msg
            .additionals()
            .map(|rr| match rr.data().unwrap() {
                Rdata::Aaaa(ip) => (rr.name.to_string(), ip.to_string()),
                _ => panic!("not AAAA"),
            })
            .collect();
        glue.sort();
        assert_eq!(
            glue,
            [
                ("local6.head.hidden.svc.cluster.local.".to_owned(), local_v6),
                (
                    "v6.head.hidden.svc.cluster.local.".to_owned(),
                    "2001:db8::2".to_owned()
                )
            ]
        );
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
        task.abort();
    }
}

#[tokio::test]
async fn reverse_namespace_visibility_matches_coredns() {
    let (address, task) = fake_api(&[]).await;
    for (option, qname, expected) in [
        (
            "namespace_labels dns=yes",
            "111.0.0.10.in-addr.arpa.",
            vec!["dns.hidden.svc.cluster.local."],
        ),
        (
            "namespace_labels dns=yes",
            "1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            vec!["dns.hidden.svc.cluster.local."],
        ),
        (
            "namespace_labels dns=yes",
            "113.0.0.10.in-addr.arpa.",
            vec!["missing.absent.svc.cluster.local."],
        ),
        (
            "namespace_labels dns=yes",
            "99.0.0.10.in-addr.arpa.",
            vec![
                "double.dns6.hidden.svc.cluster.local.",
                "double.head.hidden.svc.cluster.local.",
            ],
        ),
        (
            "namespace_labels dns=yes",
            "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            vec!["v6.head.hidden.svc.cluster.local."],
        ),
        (
            "namespaces hidden absent",
            "111.0.0.10.in-addr.arpa.",
            vec!["dns.hidden.svc.cluster.local."],
        ),
        (
            "namespaces hidden absent",
            "99.0.0.10.in-addr.arpa.",
            vec![
                "double.dns6.hidden.svc.cluster.local.",
                "double.head.hidden.svc.cluster.local.",
            ],
        ),
        (
            "namespaces hidden absent",
            "113.0.0.10.in-addr.arpa.",
            vec![],
        ),
        (
            "namespaces hidden absent",
            "115.0.0.10.in-addr.arpa.",
            vec![],
        ),
        ("namespaces visible", "111.0.0.10.in-addr.arpa.", vec![]),
        (
            "namespaces visible",
            "114.0.0.10.in-addr.arpa.",
            vec!["visible.visible.svc.cluster.local."],
        ),
    ] {
        let chain = chain(address, option);
        chain.lifecycle.run(Phase::Startup).await.unwrap();
        let wire = query(&chain, qname, Type::PTR, WILDCARD).await;
        let msg = Message::parse(&wire).unwrap();
        assert_eq!(
            msg.rcode(),
            if expected.is_empty() {
                Rcode::NXDOMAIN
            } else {
                Rcode::NOERROR
            },
            "{option} {qname}"
        );
        let mut targets: Vec<_> = msg
            .answers()
            .map(|rr| {
                assert_eq!(rr.name.to_string(), qname);
                match rr.data().unwrap() {
                    Rdata::Ptr(name) => name.to_string(),
                    _ => panic!("not PTR"),
                }
            })
            .collect();
        targets.sort();
        assert_eq!(targets, expected, "{option} {qname}");
        assert_eq!(msg.additional_count(), 0);
        if expected.is_empty() {
            let authority = msg.authorities().next().unwrap();
            assert_eq!(authority.rtype, Type::SOA);
            assert_eq!(authority.name.to_string(), "in-addr.arpa.");
        } else {
            assert_eq!(msg.authority_count(), 0);
        }
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    }
    task.abort();
}

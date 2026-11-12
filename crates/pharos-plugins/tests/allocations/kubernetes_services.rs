#![forbid(unsafe_code)]
#![cfg(feature = "plugin-kubernetes")]

use crate::support;

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Type};
use pharos_server::{Context, Metadata, Outcome, Phase, Plugin, Protocol, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

enum TruncatedRoute {
    Kubernetes(Box<Chain>),
    Target,
}

impl pharos_server::Chain for TruncatedRoute {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        match self {
            Self::Kubernetes(chain) => chain.serve(cx).await,
            Self::Target => {
                let question = cx.query.questions().next().unwrap();
                let mut builder =
                    MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8200).unwrap();
                builder
                    .question(question.name, question.qtype, question.qclass)
                    .unwrap();
                let _ = builder.finish();
                Outcome::Response
            }
        }
    }

    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn services_are_answered_from_watched_kubernetes_objects() {
    if crate::run_isolated(
        "kubernetes::kubernetes_services::services_are_answered_from_watched_kubernetes_objects",
    ) {
        return;
    }
    // Spawn the whole multi-Query fixture once, before measuring allocations.
    tokio::spawn(services_scenario()).await.unwrap();
}

async fn services_scenario() {
    let mut local_ips: Vec<std::net::IpAddr> = nix::ifaddrs::getifaddrs()
        .unwrap()
        .filter_map(|entry| {
            let address = entry.address?;
            address
                .as_sockaddr_in()
                .map(|ip| std::net::IpAddr::V4(ip.ip()))
                .or_else(|| {
                    address
                        .as_sockaddr_in6()
                        .map(|ip| std::net::IpAddr::V6(ip.ip()))
                })
        })
        .filter(|ip| !ip.is_loopback())
        .collect();
    // RFC 2181 §5: an address on several interfaces yields one glue record.
    let mut seen = std::collections::HashSet::new();
    local_ips.retain(|ip| seen.insert(*ip));
    let v4_count = local_ips
        .iter()
        .filter(|ip| ip.is_ipv4())
        .collect::<std::collections::HashSet<_>>()
        .len();
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
                let (kind, items) = if request.contains("/api/v1/services") {
                    (
                        "ServiceList",
                        r#"[{"metadata":{"name":"web","namespace":"prod"},"spec":{"clusterIPs":["10.0.0.1","2001:db8::1"],"ports":[{"name":"http","protocol":"TCP","port":80},{"name":"https","protocol":"TCP","port":443}]}},{"metadata":{"name":"head","namespace":"prod"},"spec":{"clusterIP":"None"}},{"metadata":{"name":"pool","namespace":"prod"},"spec":{"clusterIP":"None"}},{"metadata":{"name":"dead","namespace":"prod"},"spec":{"clusterIP":"10.0.0.8"}},{"metadata":{"name":"v6head","namespace":"prod"},"spec":{"clusterIP":"None"}},{"metadata":{"name":"alias","namespace":"prod"},"spec":{"type":"ExternalName","externalName":"example.org"}},{"metadata":{"name":"internal","namespace":"prod"},"spec":{"type":"ExternalName","externalName":"web.prod.svc.cluster.local"}}]"#,
                    )
                } else if request.contains("/endpointslices") {
                    (
                        "EndpointSliceList",
                        r#"[{"metadata":{"name":"one","namespace":"prod","labels":{"kubernetes.io/service-name":"head"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":8080}],"endpoints":[{"addresses":["10.0.1.2"],"hostname":"one","targetRef":{"name":"ignored"},"zone":"us.a"}]},{"metadata":{"name":"two","namespace":"prod","labels":{"kubernetes.io/service-name":"head"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.1.3"],"targetRef":{"name":"pod-two"},"zone":"us.b"}]},{"metadata":{"name":"pool","namespace":"prod","labels":{"kubernetes.io/service-name":"pool"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":8080}],"endpoints":[{"addresses":["10.0.5.1"],"hostname":"a","zone":"us.a"},{"addresses":["10.0.5.2"],"hostname":"b","zone":"us.a"},{"addresses":["10.0.5.3"],"hostname":"c","zone":"us.b"}]},{"metadata":{"name":"v6","namespace":"prod","labels":{"kubernetes.io/service-name":"v6head"}},"addressType":"IPv6","ports":[{"name":"http","protocol":"TCP","port":8080}],"endpoints":[{"addresses":["2001:db8::2"],"zone":"us.a"}]},{"metadata":{"name":"dns","namespace":"prod","labels":{"kubernetes.io/service-name":"web"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.30"]}]},{"metadata":{"name":"duplicate-one","namespace":"prod","labels":{"kubernetes.io/service-name":"dupa"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.1.4"],"hostname":"same"}]},{"metadata":{"name":"duplicate-two","namespace":"prod","labels":{"kubernetes.io/service-name":"dupa"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.1.4"],"hostname":"same"}]},{"metadata":{"name":"other","namespace":"prod","labels":{"kubernetes.io/service-name":"dupb"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.1.4"],"hostname":"other"}]}]"#,
                    )
                } else if request.contains("/api/v1/pods") {
                    (
                        "PodList",
                        r#"[{"metadata":{"name":"pod-one","namespace":"prod"},"status":{"podIPs":[{"ip":"10.0.1.2"}]}}]"#,
                    )
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
    let hosts = if cfg!(feature = "plugin-hosts") {
        " hosts /nonexistent example.org {\n  192.0.2.42 example.org\n }\n"
    } else {
        ""
    };
    let ready_address = if cfg!(feature = "plugin-ready") {
        Some(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            support::free_port(),
        )))
    } else {
        None
    };
    let ready = ready_address.map_or_else(String::new, |address| format!(" ready {address}\n"));
    let text = format!(
        ".:53 {{\n{hosts}{ready} kubernetes cluster.local in-addr.arpa ip6.arpa {{\n  endpoint http://{address}\n  startup_timeout 3s\n  ignore empty_service\n  zonal\n  pods insecure\n  endpoint_pod_names\n }}\n}}"
    );
    let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let chain = &blocks[0].config;
    let prestart_name: Name = "missing.prod.svc.cluster.local.".parse().unwrap();
    let prestart_root: Name = ".".parse().unwrap();
    let mut prestart_query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut prestart_query, 512, 1, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(prestart_name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut prestart_response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&prestart_query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &prestart_root,
        metadata: Metadata::new(&mut slots),
        response: &mut prestart_response,
        max_response_size: 512,
    };
    assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    let before = GLOBAL.stats();
    for _ in 0..50 {
        assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    assert_eq!(
        Message::parse(cx.response).unwrap().rcode(),
        Rcode::SERVFAIL
    );
    let readiness = chain.kubernetes.as_ref().unwrap().readiness().unwrap();
    assert!(!readiness.ready());
    let lifecycle = &chain.lifecycle;
    lifecycle.run(Phase::Startup).await.unwrap();
    assert!(readiness.ready());
    let root: Name = ".".parse().unwrap();
    for (name, kind, code, answers, extra) in [
        ("web.prod.svc.cluster.local.", Type::A, Rcode::NOERROR, 1, 0),
        ("1.0.0.10.in-addr.arpa.", Type::PTR, Rcode::NOERROR, 1, 0),
        ("1.0.0.10.in-addr.arpa.", Type::A, Rcode::NXDOMAIN, 0, 0),
        ("9.0.0.10.in-addr.arpa.", Type::SOA, Rcode::NOERROR, 0, 0),
        ("2.1.0.10.in-addr.arpa.", Type::PTR, Rcode::NOERROR, 1, 0),
        ("3.1.0.10.in-addr.arpa.", Type::PTR, Rcode::NOERROR, 1, 0),
        ("4.1.0.10.in-addr.arpa.", Type::PTR, Rcode::NOERROR, 2, 0),
        ("8.0.0.10.in-addr.arpa.", Type::PTR, Rcode::NOERROR, 1, 0),
        ("9.0.0.10.in-addr.arpa.", Type::PTR, Rcode::NXDOMAIN, 0, 0),
        (
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            Type::PTR,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            Type::PTR,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            Type::PTR,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        (
            "web.prod.svc.cluster.local.",
            Type::ANY,
            Rcode::NOERROR,
            0,
            0,
        ),
        (
            "missing.prod.svc.cluster.local.",
            Type::ANY,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        (
            "10-0-1-2.prod.pod.cluster.local.",
            Type::A,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "10-0-1-2.prod.pod.cluster.local.",
            Type::AAAA,
            Rcode::NOERROR,
            0,
            0,
        ),
        (
            "10-0-1-2.prod.pod.cluster.local.",
            Type::SRV,
            Rcode::NOERROR,
            1,
            1,
        ),
        (
            "2001-db8--1.prod.pod.cluster.local.",
            Type::AAAA,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "bad.prod.pod.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        (
            "10-0-1-2.missing.pod.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        ("prod.pod.cluster.local.", Type::A, Rcode::NOERROR, 0, 0),
        (
            "pod-two.head.prod.svc.cluster.local.",
            Type::A,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "ignored.head.prod.svc.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        (
            "*.head.prod.svc.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        ("*.prod.svc.cluster.local.", Type::A, Rcode::NXDOMAIN, 0, 0),
        (
            "us.a.pin._zone.head.prod.svc.cluster.local.",
            Type::A,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "us.c.pin._zone.head.prod.svc.cluster.local.",
            Type::A,
            Rcode::NOERROR,
            0,
            0,
        ),
        (
            "us.c.pin._zone.head.prod.svc.cluster.local.",
            Type::TXT,
            Rcode::NOERROR,
            0,
            0,
        ),
        (
            "us.c.prefer._zone.head.prod.svc.cluster.local.",
            Type::A,
            Rcode::NOERROR,
            2,
            0,
        ),
        (
            "us.a.pin._zone.head.prod.svc.cluster.local.",
            Type::AAAA,
            Rcode::NOERROR,
            0,
            0,
        ),
        (
            "us.a.pin._zone.v6head.prod.svc.cluster.local.",
            Type::AAAA,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "us.a.pin._zone.v6head.prod.svc.cluster.local.",
            Type::A,
            Rcode::NOERROR,
            0,
            0,
        ),
        (
            "us.a.pin._zone.v6head.prod.svc.cluster.local.",
            Type::SRV,
            Rcode::NOERROR,
            1,
            1,
        ),
        (
            "us.a.pin._zone.head.prod.svc.cluster.local.",
            Type::SRV,
            Rcode::NOERROR,
            1,
            1,
        ),
        (
            "us.a.prefer._zone.pool.prod.svc.cluster.local.",
            Type::SRV,
            Rcode::NOERROR,
            2,
            2,
        ),
        (
            "us.c.prefer._zone.pool.prod.svc.cluster.local.",
            Type::SRV,
            Rcode::NOERROR,
            3,
            3,
        ),
        (
            "us.c.prefer._zone.head.prod.svc.cluster.local.",
            Type::SRV,
            Rcode::NOERROR,
            1,
            1,
        ),
        (
            "us.a.pin._zone.web.prod.svc.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        (
            "us.a.pin._zone.missing.prod.svc.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        (
            "WEB.prod.svc.cluster.local.",
            Type::AAAA,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "_http._tcp.web.prod.svc.cluster.local.",
            Type::SRV,
            Rcode::NOERROR,
            1,
            2,
        ),
        (
            "_http._tcp.WEB.prod.SVC.Cluster.Local.",
            Type::SRV,
            Rcode::NOERROR,
            1,
            2,
        ),
        (
            "web.prod.svc.cluster.local.",
            Type::SRV,
            Rcode::NOERROR,
            2,
            2,
        ),
        (
            "_missing._tcp.web.prod.svc.cluster.local.",
            Type::SRV,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        (
            "head.prod.svc.cluster.local.",
            Type::A,
            Rcode::NOERROR,
            2,
            0,
        ),
        (
            "head.prod.svc.cluster.local.",
            Type::AAAA,
            Rcode::NOERROR,
            0,
            0,
        ),
        (
            "dead.prod.svc.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        (
            "head.prod.svc.cluster.local.",
            Type::SRV,
            Rcode::NOERROR,
            1,
            1,
        ),
        (
            "_http._tcp.head.prod.svc.cluster.local.",
            Type::SRV,
            Rcode::NOERROR,
            1,
            1,
        ),
        (
            "one.head.prod.svc.cluster.local.",
            Type::A,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "alias.prod.svc.cluster.local.",
            Type::CNAME,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "alias.prod.svc.cluster.local.",
            Type::TXT,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "alias.prod.svc.cluster.local.",
            Type::SRV,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "alias.prod.svc.cluster.local.",
            Type::HTTPS,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "alias.prod.svc.cluster.local.",
            Type::MX,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "alias.prod.svc.cluster.local.",
            Type::SOA,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "alias.prod.svc.cluster.local.",
            Type::NS,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "internal.prod.svc.cluster.local.",
            Type::TXT,
            Rcode::NOERROR,
            1,
            0,
        ),
        (
            "sub.alias.prod.svc.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        (
            "_http._tcp.alias.prod.svc.cluster.local.",
            Type::SRV,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        (
            "dns-version.cluster.local.",
            Type::TXT,
            Rcode::NOERROR,
            1,
            0,
        ),
        ("cluster.local.", Type::SOA, Rcode::NOERROR, 1, 0),
        ("cluster.local.", Type::A, Rcode::NOERROR, 0, 0),
        ("cluster.local.", Type::AAAA, Rcode::NOERROR, 0, 0),
        ("cluster.local.", Type::HINFO, Rcode::NOERROR, 0, 0),
        ("cluster.local.", Type::SRV, Rcode::NOERROR, 0, 0),
        ("cluster.local.", Type::TXT, Rcode::NXDOMAIN, 0, 0),
        ("svc.cluster.local.", Type::TXT, Rcode::NXDOMAIN, 0, 0),
        ("prod.svc.cluster.local.", Type::TXT, Rcode::NXDOMAIN, 0, 0),
        ("ns.dns.cluster.local.", Type::TXT, Rcode::NXDOMAIN, 0, 0),
        (
            "missing.prod.svc.cluster.local.",
            Type::SOA,
            Rcode::NOERROR,
            0,
            0,
        ),
        (
            "cluster.local.",
            Type::NS,
            Rcode::NOERROR,
            u16::from(!local_ips.is_empty()),
            local_ips.len() as u16,
        ),
        (
            "Cluster.Local.",
            Type::NS,
            Rcode::NOERROR,
            u16::from(!local_ips.is_empty()),
            local_ips.len() as u16,
        ),
        ("Cluster.Local.", Type::SOA, Rcode::NOERROR, 1, 0),
        (
            "missing.prod.svc.Cluster.Local.",
            Type::A,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        (
            "ns.dns.cluster.local.",
            Type::A,
            Rcode::NOERROR,
            v4_count as u16,
            0,
        ),
        (
            "missing.prod.svc.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            0,
            0,
        ),
        (
            "web.prod.svc.cluster.local.",
            Type::TXT,
            Rcode::NOERROR,
            0,
            0,
        ),
    ] {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(4096);
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "192.0.2.30:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 4096,
        };
        assert_eq!(chain.serve(&mut cx).await, Outcome::Response, "{name}");
        let message = Message::parse(&response).unwrap();
        assert_eq!(
            (
                message.rcode(),
                message.answer_count(),
                message.additional_count()
            ),
            (code, answers, extra),
            "{name} {kind:?}"
        );
        assert!(message.aa());
        let qname = name.to_string();
        // ExternalName rows: only the CNAME is checked.
        if (qname.starts_with("alias.") || qname.starts_with("internal."))
            && !matches!(kind, Type::A | Type::AAAA)
            && answers == 1
        {
            let rr = message.answers().next().unwrap();
            assert!(
                matches!(rr.data().unwrap(), Rdata::Cname(_)),
                "{qname} {kind:?}"
            );
            continue;
        }
        if kind == Type::PTR && answers == 1 {
            let Rdata::Ptr(target) = message.answers().next().unwrap().data().unwrap() else {
                panic!("not PTR")
            };
            let expected = match qname.as_str() {
                "1.0.0.10.in-addr.arpa." => "web.prod.svc.cluster.local.",
                "2.1.0.10.in-addr.arpa." => "one.head.prod.svc.cluster.local.",
                "3.1.0.10.in-addr.arpa." => "pod-two.head.prod.svc.cluster.local.",
                "8.0.0.10.in-addr.arpa." => "dead.prod.svc.cluster.local.",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa." => {
                    "web.prod.svc.cluster.local."
                }
                "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa." => {
                    "2001-db8--2.v6head.prod.svc.cluster.local."
                }
                _ => panic!("unexpected PTR query"),
            };
            assert_eq!(target.to_string(), expected);
        }
        if qname == "4.1.0.10.in-addr.arpa." {
            let mut targets: Vec<_> = message
                .answers()
                .map(|rr| match rr.data().unwrap() {
                    Rdata::Ptr(target) => target.to_string(),
                    _ => panic!("not PTR"),
                })
                .collect();
            targets.sort();
            assert_eq!(
                targets,
                [
                    "other.dupb.prod.svc.cluster.local.",
                    "same.dupa.prod.svc.cluster.local."
                ]
            );
        }
        if qname == "us.a.pin._zone.head.prod.svc.cluster.local." && kind == Type::A {
            assert_eq!(message.answers().next().unwrap().rdata, [10, 0, 1, 2]);
        }
        if qname == "us.a.pin._zone.v6head.prod.svc.cluster.local." && kind == Type::AAAA {
            assert_eq!(
                message.answers().next().unwrap().rdata,
                "2001:db8::2"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
            );
        }
        if qname == "us.a.pin._zone.v6head.prod.svc.cluster.local." && kind == Type::SRV {
            let Rdata::Srv {
                weight,
                port,
                target,
                ..
            } = message.answers().next().unwrap().data().unwrap()
            else {
                panic!("not SRV")
            };
            assert_eq!((weight, port), (100, 8080));
            assert_eq!(
                target.to_string(),
                "2001-db8--2.v6head.prod.svc.cluster.local."
            );
            assert_eq!(message.additionals().next().unwrap().rtype, Type::AAAA);
        }
        if qname.contains(".pool.") && kind == Type::SRV {
            let weight = if qname.starts_with("us.a.") { 50 } else { 33 };
            for record in message.answers() {
                assert!(
                    matches!(record.data(), Ok(Rdata::Srv { weight: actual, port: 8080, .. }) if actual == weight)
                );
            }
            assert!(message.additionals().all(|record| record.rtype == Type::A));
        }
        if qname == "us.c.prefer._zone.head.prod.svc.cluster.local." && kind == Type::A {
            let ips: Vec<_> = message.answers().map(|rr| rr.rdata.to_vec()).collect();
            assert!(ips.contains(&vec![10, 0, 1, 2]));
            assert!(ips.contains(&vec![10, 0, 1, 3]));
        }
        if answers > 0 {
            assert_eq!(
                message.answers().next().unwrap().name.to_string(),
                name.to_string()
            );
        }
        if kind == Type::NS && answers > 0 {
            let Rdata::Ns(ns) = message.answers().next().unwrap().data().unwrap() else {
                panic!("not NS")
            };
            assert_eq!(
                ns.to_string(),
                if name.to_string().contains("Cluster.Local.") {
                    "ns.dns.Cluster.Local."
                } else {
                    "ns.dns.cluster.local."
                }
            );
        }
        if kind == Type::SRV
            && answers > 0
            && !name.to_string().contains(".pod.")
            && !name.to_string().contains(".v6head.")
            && !name.to_string().contains(".pool.")
        {
            let record = message.answers().next().unwrap();
            assert_eq!(
                record.rdata[6] & 0xc0,
                0,
                "SRV target must not be compressed"
            );
            let Rdata::Srv {
                priority,
                weight,
                port,
                target,
            } = record.data().unwrap()
            else {
                panic!("not SRV")
            };
            assert_eq!(priority, 0);
            let lower = name.to_string().to_ascii_lowercase();
            assert_eq!(
                weight,
                if lower.starts_with("us.c.prefer.") {
                    50
                } else if lower.starts_with("web.") {
                    25
                } else if lower.contains("web.") || lower.starts_with("head.") {
                    50
                } else {
                    100
                }
            );
            assert_eq!(port, if lower.contains("web.") { 80 } else { 8080 });
            let zone = if name.to_string().contains("Cluster.Local.") {
                "Cluster.Local."
            } else {
                "cluster.local."
            };
            let service = if lower.contains("web.") {
                "web.prod.svc"
            } else {
                "one.head.prod.svc"
            };
            assert_eq!(target.to_string(), format!("{service}.{zone}"));
        }
        if kind == Type::SOA || message.answer_count() == 0 {
            let record = if kind == Type::SOA && message.answer_count() > 0 {
                message.answers().next().unwrap()
            } else {
                message.authorities().next().unwrap()
            };
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
                panic!("not SOA")
            };
            let zone = if name.to_string().ends_with(".in-addr.arpa.") {
                "in-addr.arpa."
            } else if name.to_string().ends_with(".ip6.arpa.") {
                "ip6.arpa."
            } else if name.to_string().contains("Cluster.Local.") {
                "Cluster.Local."
            } else {
                "cluster.local."
            };
            assert_eq!(record.name.to_string(), zone);
            assert_eq!(mname.to_string(), format!("ns.dns.{zone}"));
            assert_eq!(rname.to_string(), format!("hostmaster.{zone}"));
            assert_eq!((refresh, retry, expire, minimum), (7200, 1800, 86400, 5));
            assert!(serial > 1_000_000_000);
        }
        if name.to_string() == "dns-version.cluster.local." {
            assert_eq!(message.answers().next().unwrap().ttl, 28800);
        }
    }

    let name: Name = "cluster.local.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::NS,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "0.0.0.0:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    let wildcard = Message::parse(&response).unwrap();
    for record in wildcard.additionals() {
        match record.data().unwrap() {
            Rdata::A(ip) => assert!(!ip.is_loopback()),
            Rdata::Aaaa(ip) => assert!(!ip.is_loopback()),
            _ => panic!("unexpected NS additional"),
        }
    }
    if !local_ips.contains(&"192.0.2.30".parse().unwrap()) {
        assert_eq!(wildcard.answer_count(), u16::from(!local_ips.is_empty()));
        assert_eq!(
            wildcard.tc(),
            usize::from(wildcard.additional_count()) < local_ips.len()
        );
        for (rr, expected) in wildcard.additionals().zip(&local_ips) {
            let actual = match rr.data().unwrap() {
                Rdata::A(ip) => std::net::IpAddr::V4(ip),
                Rdata::Aaaa(ip) => std::net::IpAddr::V6(ip),
                _ => unreachable!(),
            };
            assert_eq!(&actual, expected);
        }
    }
    let wildcard_response = response.clone();
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
    assert_eq!(
        response, wildcard_response,
        "NS addresses must not depend on the Query's Listener address"
    );

    let mut queries = Vec::new();
    for (name, kind) in [
        ("web.prod.svc.cluster.local.", Type::A),
        ("web.prod.svc.cluster.local.", Type::AAAA),
        ("_http._tcp.web.prod.svc.cluster.local.", Type::SRV),
        ("alias.prod.svc.cluster.local.", Type::CNAME),
        ("internal.prod.svc.cluster.local.", Type::CNAME),
    ] {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
            .unwrap();
        let _ = builder.finish();
        queries.push(wire);
    }
    let mut response = Vec::with_capacity(512);
    let before = GLOBAL.stats();
    for _ in 0..50 {
        for wire in &queries {
            let mut slots = [None; 8];
            let mut cx = Context {
                query: Message::parse(wire).unwrap(),
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
        }
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert!(!readiness.ready());
    let (mut routed, lifecycle) = pharos_plugins::servers(blocks).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    if let Some(address) = ready_address {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }
    let (_, server) = routed.drain().next().unwrap();
    let mut targets = vec![("internal.prod.svc.cluster.local.", [10, 0, 0, 1])];
    if cfg!(feature = "plugin-hosts") {
        targets.push(("alias.prod.svc.cluster.local.", [192, 0, 2, 42]));
    }
    for (name, expected) in targets {
        let name: Name = name.parse().unwrap();
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        assert_eq!(
            pharos_server::Handler::handle(
                &server,
                &query,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
            pharos_server::Action::Respond
        );
        let message = Message::parse(&response).unwrap();
        assert_eq!(message.answer_count(), 2);
        assert_eq!(message.answers().next().unwrap().rtype, Type::CNAME);
        assert_eq!(message.answers().last().unwrap().rdata, expected);
    }
    lifecycle.run(Phase::Shutdown).await.unwrap();
    let text =
        format!(".:53 {{\n kubernetes cluster.local {{\n  endpoint http://{address}\n }}\n}}");
    let mut blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let chain = blocks.remove(0).config;
    let lifecycle = chain.lifecycle.clone();
    lifecycle.run(Phase::Startup).await.unwrap();
    let key = pharos_server::ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = pharos_server::Router::default();
    router.add(
        key,
        ".".parse().unwrap(),
        Some(TruncatedRoute::Kubernetes(Box::new(chain))),
        vec![],
    );
    router.add(
        key,
        "example.org.".parse().unwrap(),
        Some(TruncatedRoute::Target),
        vec![],
    );
    let server = pharos_server::Server::new(router, key);
    let name: Name = "alias.prod.svc.cluster.local.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        pharos_server::Handler::handle(
            &server,
            &query,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response
        )
        .await,
        pharos_server::Action::Respond
    );
    let response = Message::parse(&response).unwrap();
    assert!(response.tc());
    assert_eq!(response.answers().next().unwrap().rtype, Type::CNAME);
    lifecycle.run(Phase::Shutdown).await.unwrap();
    for (options, qname, expected) in [
        (
            "pods verified",
            "10-0-1-2.prod.pod.cluster.local.",
            Rcode::NOERROR,
        ),
        (
            "pods verified",
            "10-0-1-3.prod.pod.cluster.local.",
            Rcode::NXDOMAIN,
        ),
        (
            "pods disabled",
            "10-0-1-2.prod.pod.cluster.local.",
            Rcode::NXDOMAIN,
        ),
        (
            "noendpoints",
            "head.prod.svc.cluster.local.",
            Rcode::NXDOMAIN,
        ),
        ("noendpoints", "web.prod.svc.cluster.local.", Rcode::NOERROR),
        ("noendpoints", "1.0.0.10.in-addr.arpa.", Rcode::NOERROR),
        ("noendpoints", "2.1.0.10.in-addr.arpa.", Rcode::NXDOMAIN),
        (
            "noendpoints",
            "us.a.pin._zone.head.prod.svc.cluster.local.",
            Rcode::NXDOMAIN,
        ),
        (
            "namespaces other",
            "web.prod.svc.cluster.local.",
            Rcode::NXDOMAIN,
        ),
    ] {
        let text = format!(
            ".:53 {{\n kubernetes cluster.local in-addr.arpa {{\n endpoint http://{address}\n {options}\n }}\n}}"
        );
        let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
        let chain = &blocks[0].config;
        chain.lifecycle.run(Phase::Startup).await.unwrap();
        let name: Name = qname.parse().unwrap();
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                if qname.ends_with(".in-addr.arpa.") {
                    Type::PTR
                } else {
                    Type::A
                },
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
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
        assert_eq!(
            Message::parse(&response).unwrap().rcode(),
            expected,
            "{options} {qname}"
        );
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    }
    #[cfg(feature = "plugin-whoami")]
    {
        let text = format!(
            ".:53 {{\n kubernetes cluster.local in-addr.arpa {{\n endpoint http://{address}\n fallthrough in-addr.arpa\n }}\n whoami\n}}"
        );
        let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
        let chain = &blocks[0].config;
        chain.lifecycle.run(Phase::Startup).await.unwrap();
        for (name, kind, code, additional) in [
            ("9.0.0.10.in-addr.arpa.", Type::PTR, Rcode::NOERROR, 2),
            (
                "missing.prod.svc.cluster.local.",
                Type::A,
                Rcode::NXDOMAIN,
                0,
            ),
        ] {
            let name: Name = name.parse().unwrap();
            let mut query = Vec::with_capacity(512);
            let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
            builder
                .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
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
                domain: &root,
                metadata: Metadata::new(&mut slots),
                response: &mut response,
                max_response_size: 512,
            };
            assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
            let message = Message::parse(&response).unwrap();
            assert_eq!(
                (message.rcode(), message.additional_count()),
                (code, additional)
            );
        }
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    }
    task.abort();
    missing_name_is_servfail_before_cache_sync().await;
}

async fn missing_name_is_servfail_before_cache_sync() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", support::free_port()))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let text = format!(
        ".:53 {{\n kubernetes cluster.local {{\n  endpoint http://{address}\n  startup_timeout 0s\n }}\n}}"
    );
    let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let chain = &blocks[0].config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    assert!(
        !chain
            .kubernetes
            .as_ref()
            .unwrap()
            .readiness()
            .unwrap()
            .ready()
    );
    let name: Name = "missing.prod.svc.cluster.local.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
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
    assert_eq!(message.rcode(), Rcode::SERVFAIL);
    assert_eq!(message.authority_count(), 1);
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

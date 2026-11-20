use super::*;

#[test]
fn retained_endpoint_group_preserves_order_and_filters() {
    use pharos_kubernetes::object::{EndpointAddress, Endpoints, Port};
    use std::sync::Arc;
    let slice = |name: &str, address: &str, hostname: &str| {
        Arc::new(Endpoints {
            version: "1".into(),
            name: name.into(),
            namespace: "prod".into(),
            service_name: "head".into(),
            addresses: vec![EndpointAddress {
                ip: address.into(),
                hostname: hostname.into(),
                target_ref_name: String::new().into(),
                ready: true,
            }],
            ports: vec![
                Port {
                    name: "http".into(),
                    protocol: "TCP".into(),
                    port: 80,
                },
                Port {
                    name: "https".into(),
                    protocol: "TCP".into(),
                    port: 443,
                },
            ],
            zones: None,
        })
    };
    let mut current = Arc::new(vec![
        slice("one", "lb.target.test", "pod1"),
        slice("two", "192.0.2.2", "pod2"),
    ]);
    let snapshot = Snapshot::Headless {
        service: Arc::new(Service {
            version: "1".into(),
            name: "head".into(),
            namespace: "prod".into(),
            cluster_ips: vec!["None".into()],
            service_type: String::new().into(),
            external_name: String::new(),
            ports: vec![],
            external_ips: vec![],
            tolerate_unready_endpoints: false,
        }),
        endpoints: Some(Arc::clone(&current)),
    };
    Arc::make_mut(&mut current).reverse();
    let index = Index::default();
    let request = parse(&[b"_HTTP", b"_tcp", b"head", b"prod"]).unwrap();
    let mut rows = Vec::new();
    let code = snapshot_or_lookup(
        &index,
        &request,
        true,
        false,
        Some(&snapshot),
        |host, port, endpoint| {
            rows.push((
                host.to_owned(),
                port.port,
                String::from_utf8(endpoint.unwrap().to_vec()).unwrap(),
            ));
        },
    );
    assert_eq!(code, Rcode::NOERROR);
    assert_eq!(
        rows,
        [
            ("lb.target.test".into(), 80, "pod1".into()),
            ("192.0.2.2".into(), 80, "pod2".into())
        ]
    );
    let request = parse(&[b"pod2", b"head", b"prod"]).unwrap();
    rows.clear();
    snapshot_or_lookup(
        &index,
        &request,
        true,
        false,
        Some(&snapshot),
        |host, port, endpoint| {
            rows.push((
                host.to_owned(),
                port.port,
                String::from_utf8(endpoint.unwrap().to_vec()).unwrap(),
            ));
        },
    );
    assert_eq!(
        rows,
        [
            ("192.0.2.2".into(), 80, "pod2".into()),
            ("192.0.2.2".into(), 443, "pod2".into())
        ]
    );
}

#[test]
fn service_policy_controls_unready_endpoint_lookup() {
    use pharos_kubernetes::object::{EndpointAddress, Endpoints, Port};
    let slice = Endpoints {
        version: "1".into(),
        name: "one".into(),
        namespace: "prod".into(),
        service_name: "head".into(),
        addresses: vec![EndpointAddress {
            ip: "192.0.2.1".into(),
            hostname: "node".into(),
            target_ref_name: String::new().into(),
            ready: false,
        }],
        ports: vec![Port {
            name: "http".into(),
            protocol: "TCP".into(),
            port: 80,
        }],
        zones: None,
    };
    let request = parse(&[b"_http", b"_tcp", b"head", b"prod"]).unwrap();
    let mut returned = false;
    assert_eq!(
        endpoints([&slice], &request, false, false, |_, _, _| returned = true),
        Rcode::NXDOMAIN
    );
    assert!(!returned);
    // Kubernetes DNS spec 1.1.0 §2.1: the annotation opts into unready endpoint data.
    assert_eq!(
        endpoints([&slice], &request, false, true, |_, _, _| returned = true),
        Rcode::NOERROR
    );
    assert!(returned);
}

#[test]
fn retained_external_service_keeps_order_and_port_filter_after_update() {
    use pharos_kubernetes::object::{Port, Service};
    use std::sync::Arc;
    let mut current = Arc::new(Service {
        version: "1".into(),
        name: "web".into(),
        namespace: "prod".into(),
        cluster_ips: vec![],
        service_type: "LoadBalancer".into(),
        external_name: String::new(),
        external_ips: vec!["192.0.2.1".into(), "old.example".into(), "192.0.2.2".into()],
        tolerate_unready_endpoints: false,
        ports: vec![
            Port {
                name: "http".into(),
                protocol: "TCP".into(),
                port: 80,
            },
            Port {
                name: "https".into(),
                protocol: "TCP".into(),
                port: 443,
            },
        ],
    });
    let snapshot = Arc::clone(&current);
    Arc::make_mut(&mut current).external_ips = vec!["new.example".into()];
    let request = parse(&[b"web", b"prod"]).unwrap();
    let mut rows = Vec::new();
    assert_eq!(
        external(&snapshot, &request, |host, port, _| rows
            .push((host.to_owned(), port.port))),
        Rcode::NOERROR
    );
    assert_eq!(
        rows,
        [
            ("192.0.2.1".into(), 80),
            ("192.0.2.1".into(), 443),
            ("old.example".into(), 80),
            ("old.example".into(), 443),
            ("192.0.2.2".into(), 80),
            ("192.0.2.2".into(), 443)
        ]
    );
    let request = parse(&[b"_HTTP", b"_tcp", b"web", b"prod"]).unwrap();
    rows.clear();
    assert_eq!(
        external(&snapshot, &request, |host, port, _| rows
            .push((host.to_owned(), port.port))),
        Rcode::NOERROR
    );
    assert_eq!(
        rows,
        [
            ("192.0.2.1".into(), 80),
            ("old.example".into(), 80),
            ("192.0.2.2".into(), 80)
        ]
    );
}

#[test]
fn parses_namespace_service_endpoint_and_port_names() {
    let req = parse(&[b"prod"]).unwrap();
    assert_eq!(req.namespace, b"prod");
    assert!(req.service.is_empty());
    let req = parse(&[b"web", b"prod"]).unwrap();
    assert_eq!(req.service, b"web");
    let req = parse(&[b"_pod-1", b"web", b"prod"]).unwrap();
    assert_eq!(req.endpoint, b"pod-1");
    let req = parse(&[b"_http", b"_tcp", b"web", b"prod"]).unwrap();
    assert_eq!((req.port, req.protocol), (&b"http"[..], &b"tcp"[..]));
    let req = parse(&[b"__http", b"tcp", b"web", b"prod"]).unwrap();
    assert_eq!((req.port, req.protocol), (&b"_http"[..], &b"tcp"[..]));
}

#[test]
fn rejects_empty_or_too_long_relative_names() {
    assert_eq!(parse(&[]), Err(Rcode::SERVFAIL));
    assert_eq!(
        parse(&[b"a", b"b", b"c", b"web", b"prod"]),
        Err(Rcode::NXDOMAIN)
    );
}

#[test]
fn missing_namespace_is_nxdomain() {
    let index = Index::default();
    let req = parse(&[b"missing"]).unwrap();
    assert_eq!(
        lookup(&index, &req, true, false, |_, _, _| panic!(
            "unexpected result"
        )),
        Rcode::NXDOMAIN
    );
}

#[test]
fn endpoint_labels_follow_hostname_pod_and_ip_precedence() {
    let mut addr = EndpointAddress {
        ip: "2001:db8::".into(),
        hostname: "explicit".into(),
        target_ref_name: "pod".into(),
        ready: true,
    };
    let mut buf = [0; 64];
    assert_eq!(endpoint_label(&addr, true, &mut buf), b"explicit");
    addr.hostname.clear();
    assert_eq!(endpoint_label(&addr, true, &mut buf), b"pod");
    assert_eq!(endpoint_label(&addr, false, &mut buf), b"2001-db8--0");
    addr.ip = "192.0.2.1".into();
    assert_eq!(endpoint_label(&addr, false, &mut buf), b"192-0-2-1");
    addr.ip = "::ffff:192.0.2.1".into();
    assert_eq!(endpoint_label(&addr, false, &mut buf), b"::ffff:192-0-2-1");
    addr.ip = "not-an-ip".into();
    assert_eq!(endpoint_label(&addr, false, &mut buf), b"");
}

#[tokio::test]
async fn lookup_matches_external_ips_headless_endpoints_and_visibility() {
    use pharos_corefile::{configure, parse as parse_corefile};
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
                        r#"[{"metadata":{"name":"web","namespace":"prod"},"spec":{"clusterIP":"None","externalIPs":["192.0.2.1"],"ports":[{"name":"http","protocol":"TCP","port":80}]}},{"metadata":{"name":"head","namespace":"prod"},"spec":{"clusterIP":"None"}},{"metadata":{"name":"head-empty","namespace":"prod"},"spec":{"clusterIP":"None"}},{"metadata":{"name":"noport","namespace":"prod"},"spec":{"clusterIP":"10.0.0.1","externalIPs":["192.0.2.2"]}},{"metadata":{"name":"ordinary","namespace":"prod"},"spec":{"clusterIP":"10.0.0.1"}},{"metadata":{"name":"hidden","namespace":"secret"},"spec":{"externalIPs":["192.0.2.3"]}}]"#,
                    )
                } else if request.contains("/endpointslices") {
                    (
                        "EndpointSliceList",
                        r#"[{"metadata":{"name":"web-1","namespace":"prod","labels":{"kubernetes.io/service-name":"web"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.0.1"],"hostname":"pod-1"}],"ports":[{"name":"http","protocol":"TCP","port":8080}]},{"metadata":{"name":"head-1","namespace":"prod","labels":{"kubernetes.io/service-name":"head"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.0.2"],"hostname":"pod-2"}]},{"metadata":{"name":"ordinary-1","namespace":"prod","labels":{"kubernetes.io/service-name":"ordinary"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.0.3"],"hostname":"pod-3"}]}]"#,
                    )
                } else {
                    (
                        "NamespaceList",
                        r#"[{"metadata":{"name":"prod"}},{"metadata":{"name":"empty"}},{"metadata":{"name":"secret"}}]"#,
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
        ".:53 {{\n kubernetes cluster.local {{\n  endpoint http://{server}\n  namespaces prod empty\n  startup_timeout 3s\n }}\n}}"
    );
    let chain = configure::<crate::Chain>(
        &parse_corefile("Corefile", &text).unwrap(),
        crate::directives(),
    )
    .unwrap()
    .remove(0)
    .config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    let store = chain.kubernetes.as_ref().unwrap().store().unwrap();
    store.with_read(|index| {
        let empty_request = parse(&[b"head-empty", b"prod"]).unwrap();
        let captured = capture(index, &empty_request, true);
        assert!(matches!(
            captured,
            Snapshot::Headless {
                endpoints: None,
                ..
            }
        ));
        assert_eq!(
            snapshot_or_lookup(
                index,
                &empty_request,
                true,
                false,
                Some(&captured),
                |_, _, _| panic!("empty group returned data")
            ),
            Rcode::NXDOMAIN
        );
        assert!(matches!(
            capture(index, &parse(&[b"missing", b"prod"]).unwrap(), true),
            Snapshot::MissingService
        ));
        assert!(matches!(
            capture(index, &parse(&[b"web", b"missing"]).unwrap(), true),
            Snapshot::MissingNamespace
        ));
        assert!(matches!(
            capture(index, &parse(&[b"prod"]).unwrap(), true),
            Snapshot::NamespaceOnly
        ));
        let req = parse(&[b"web", b"prod"]).unwrap();
        let empty = Snapshot::Headless {
            service: index.service_snapshot("prod", "web").unwrap(),
            endpoints: None,
        };
        assert_eq!(
            snapshot_or_lookup(index, &req, true, false, Some(&empty), |_, _, _| panic!(
                "empty snapshot read live data"
            )),
            Rcode::NXDOMAIN
        );
        for (empty, expected) in [
            (Snapshot::NamespaceOnly, Rcode::NOERROR),
            (Snapshot::MissingService, Rcode::NXDOMAIN),
            (Snapshot::MissingNamespace, Rcode::NXDOMAIN),
        ] {
            assert_eq!(
                snapshot_or_lookup(index, &req, true, false, Some(&empty), |_, _, _| panic!(
                    "missing snapshot read live data"
                )),
                expected
            );
        }
        let mut answers = Vec::new();
        let mut check =
            |labels: &[&[u8]], headless, expected, rows: &[(&str, i32, Option<&str>)]| {
                answers.clear();
                let req = parse(labels).unwrap();
                let rcode = lookup(index, &req, headless, false, |host, port, label| {
                    answers.push((
                        host.to_owned(),
                        port.port,
                        label.map(|label| String::from_utf8(label.to_vec()).unwrap()),
                    ));
                });
                assert_eq!(rcode, expected);
                let expected: Vec<_> = rows
                    .iter()
                    .map(|(host, port, label)| (host.to_string(), *port, label.map(str::to_owned)))
                    .collect();
                assert_eq!(answers, expected);
            };
        check(&[b"prod"], true, Rcode::NOERROR, &[]);
        check(&[b"empty"], true, Rcode::NOERROR, &[]);
        check(&[b"secret"], true, Rcode::NXDOMAIN, &[]);
        check(&[b"hidden", b"secret"], true, Rcode::NXDOMAIN, &[]);
        check(&[b"absent"], true, Rcode::NXDOMAIN, &[]);
        check(&[b"missing", b"prod"], true, Rcode::NXDOMAIN, &[]);
        check(
            &[b"_http", b"_tcp", b"web", b"prod"],
            true,
            Rcode::NOERROR,
            &[("192.0.2.1", 80, None)],
        );
        check(
            &[b"pod-1", b"web", b"prod"],
            true,
            Rcode::NOERROR,
            &[("192.0.2.1", 80, None)],
        );
        check(
            &[b"pod-2", b"head", b"prod"],
            true,
            Rcode::NOERROR,
            &[("10.0.0.2", -1, Some("pod-2"))],
        );
        check(&[b"wrong", b"head", b"prod"], true, Rcode::NXDOMAIN, &[]);
        check(&[b"head", b"prod"], false, Rcode::NXDOMAIN, &[]);
        check(&[b"ordinary", b"prod"], true, Rcode::NXDOMAIN, &[]);
        check(
            &[b"pod-3", b"ordinary", b"prod"],
            true,
            Rcode::NOERROR,
            &[("10.0.0.3", -1, Some("pod-3"))],
        );
        check(
            &[b"noport", b"prod"],
            false,
            Rcode::NOERROR,
            &[("192.0.2.2", -1, None)],
        );
        check(
            &[b"_http", b"_tcp", b"noport", b"prod"],
            false,
            Rcode::NXDOMAIN,
            &[],
        );
    });
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

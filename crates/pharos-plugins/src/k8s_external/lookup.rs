use pharos_kubernetes::{
    object::{EndpointAddress, Port},
    store::Index,
};
use pharos_proto::Rcode;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Request<'a> {
    pub(super) namespace: &'a [u8],
    pub(super) service: &'a [u8],
    pub(super) endpoint: &'a [u8],
    pub(super) port: &'a [u8],
    pub(super) protocol: &'a [u8],
}

pub(super) fn parse<'a>(labels: &'a [&'a [u8]]) -> Result<Request<'a>, Rcode> {
    let Some((&namespace, remaining)) = labels.split_last() else {
        return Err(Rcode::SERVFAIL);
    };
    let mut req = Request {
        namespace,
        ..Request::default()
    };
    let Some((&service, remaining)) = remaining.split_last() else {
        return Ok(req);
    };
    req.service = service;
    match remaining {
        [] => {}
        [endpoint] => req.endpoint = endpoint.strip_prefix(b"_").unwrap_or(endpoint),
        [port, protocol] => {
            // Kubernetes DNS spec 1.1.0 §2.3.2: SRV names contain port and protocol labels.
            req.port = port.strip_prefix(b"_").unwrap_or(port);
            req.protocol = protocol.strip_prefix(b"_").unwrap_or(protocol);
        }
        _ => return Err(Rcode::NXDOMAIN),
    }
    Ok(req)
}

pub(super) fn lookup(
    index: &Index,
    req: &Request<'_>,
    headless: bool,
    endpoint_pod_names: bool,
    mut callback: impl FnMut(&str, &Port, Option<&[u8]>),
) -> Rcode {
    let Ok(namespace) = std::str::from_utf8(req.namespace) else {
        return Rcode::NXDOMAIN;
    };
    if !index.namespace_exposed(namespace) {
        return Rcode::NXDOMAIN;
    }
    if req.service.is_empty() {
        return Rcode::NOERROR;
    }
    let Ok(service) = std::str::from_utf8(req.service) else {
        return Rcode::NXDOMAIN;
    };
    let Some(svc) = index.service(namespace, service) else {
        return Rcode::NXDOMAIN;
    };
    let matches = |port: &Port| {
        (req.port.is_empty() || req.port.eq_ignore_ascii_case(port.name.as_bytes()))
            && (req.protocol.is_empty()
                || req.protocol.eq_ignore_ascii_case(port.protocol.as_bytes()))
    };
    let mut code = Rcode::NXDOMAIN;
    if headless && svc.external_ips.is_empty() && (svc.headless() || !req.endpoint.is_empty()) {
        // Kubernetes DNS spec 1.1.0 §2.4.1: headless records use ready endpoint addresses.
        for ep in index.endpoints(namespace, service) {
            for addr in &ep.addresses {
                let mut buf = [0; 64];
                let label = endpoint_label(addr, endpoint_pod_names, &mut buf);
                if !req.endpoint.is_empty() && !req.endpoint.eq_ignore_ascii_case(label) {
                    continue;
                }
                for port in &ep.ports {
                    if matches(port) {
                        code = Rcode::NOERROR;
                        callback(&addr.ip, port, Some(label));
                    }
                }
            }
        }
    } else {
        for ip in &svc.external_ips {
            for port in &svc.ports {
                if matches(port) {
                    code = Rcode::NOERROR;
                    callback(ip, port, None);
                }
            }
        }
    }
    code
}

pub(super) fn endpoint_label<'a>(
    addr: &'a EndpointAddress,
    pod_names: bool,
    buf: &'a mut [u8; 64],
) -> &'a [u8] {
    // Kubernetes DNS spec 1.1.0 §2.1: an explicit endpoint hostname takes precedence.
    if !addr.hostname.is_empty() {
        return addr.hostname.as_bytes();
    }
    if pod_names && !addr.target_ref_name.is_empty() {
        return addr.target_ref_name.as_bytes();
    }
    let ip = addr.ip.as_bytes();
    let separator = if ip.contains(&b'.') {
        b'.'
    } else if ip.contains(&b':') {
        b':'
    } else {
        return b"";
    };
    let suffix = separator == b':' && ip.last() == Some(&b':');
    if ip.len() + usize::from(suffix) > buf.len() {
        return b"";
    }
    for (slot, byte) in buf.iter_mut().zip(ip) {
        *slot = if *byte == separator { b'-' } else { *byte };
    }
    if suffix {
        buf[ip.len()] = b'0';
    }
    &buf[..ip.len() + usize::from(suffix)]
}

#[cfg(test)]
mod tests {
    use super::*;

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
            node_name: String::new(),
            target_ref_name: "pod".into(),
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
                            r#"[{"metadata":{"name":"web","namespace":"prod"},"spec":{"clusterIP":"None","externalIPs":["192.0.2.1"],"ports":[{"name":"http","protocol":"TCP","port":80}]}},{"metadata":{"name":"head","namespace":"prod"},"spec":{"clusterIP":"None"}},{"metadata":{"name":"noport","namespace":"prod"},"spec":{"clusterIP":"10.0.0.1","externalIPs":["192.0.2.2"]}},{"metadata":{"name":"ordinary","namespace":"prod"},"spec":{"clusterIP":"10.0.0.1"}},{"metadata":{"name":"hidden","namespace":"secret"},"spec":{"externalIPs":["192.0.2.3"]}}]"#,
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
            let mut answers = Vec::new();
            let mut check = |labels: &[&[u8]],
                             headless,
                             expected,
                             rows: &[(&str, i32, Option<&str>)]| {
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
}

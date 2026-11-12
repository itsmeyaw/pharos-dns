use std::net::IpAddr;

use pharos_kubernetes::{
    object::{Endpoints, Service},
    store::{Index, Store},
};

use super::{Kubernetes, scratch};

impl Kubernetes {
    pub(crate) fn store(&self) -> Option<Store> {
        self.state.cache.read().unwrap().store.clone()
    }

    pub(crate) fn endpoint_pod_names(&self) -> bool {
        self.config.endpoint_pod_names
    }

    pub(crate) fn ttl(&self) -> u32 {
        self.config.ttl
    }

    pub(crate) fn has_namespace_filter(&self) -> bool {
        !self.config.namespaces.is_empty()
    }

    /// Visit addresses while the caller holds the store's read lock.
    /// An invalid CoreDNS IP is represented by `None` (its nil AAAA address).
    pub(crate) fn visit_external_ns(
        &self,
        index: &Index,
        headless: bool,
        visit: impl FnMut(Option<IpAddr>),
    ) {
        visit_external_ns(index, &self.local_ips, headless, visit);
    }
}

fn parse_ip(text: &str) -> Option<IpAddr> {
    Some(normalize_ip(text.parse().ok()?))
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    // RFC 4291 §2.5.5.2: IPv4-mapped addresses contain an IPv4 address in their low 32 bits.
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}

fn visit_service(
    service: &Service,
    endpoints: &Endpoints,
    headless: bool,
    visit: &mut impl FnMut(Option<IpAddr>),
) {
    // CoreDNS kubernetes/ns.go nsAddrs: headless mode selects endpoints before external IPs.
    if headless && service.headless() {
        for address in &endpoints.addresses {
            visit(parse_ip(&address.ip));
        }
    } else {
        for ip in &service.external_ips {
            visit(parse_ip(ip));
        }
    }
}

fn visit_external_ns(
    index: &Index,
    locals: &[IpAddr],
    headless: bool,
    mut visit: impl FnMut(Option<IpAddr>),
) {
    let mut found = false;
    // CoreDNS kubernetes/ns.go nsAddrs: any matching endpoint prevents local fallback.
    for local in locals {
        let text = scratch::IpText::new(normalize_ip(*local));
        for endpoints in index.endpoints_by_ip_unfiltered(text.as_str()) {
            found = true;
            if let Some(service) =
                index.service_unfiltered(&endpoints.namespace, &endpoints.service_name)
            {
                visit_service(service, endpoints, headless, &mut visit);
            }
        }
    }
    if !found {
        for local in locals {
            visit(Some(normalize_ip(*local)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_kubernetes::object::{EndpointAddress, Endpoints, Service};

    fn service(headless: bool, external_ips: &[&str]) -> Service {
        Service {
            version: String::new(),
            name: "dns".into(),
            namespace: "system".into(),
            cluster_ips: vec![if headless { "None" } else { "10.0.0.10" }.into()],
            service_type: String::new(),
            external_name: String::new(),
            ports: vec![],
            external_ips: external_ips.iter().map(|ip| (*ip).into()).collect(),
        }
    }

    fn endpoints() -> Endpoints {
        Endpoints {
            version: String::new(),
            name: "dns-1".into(),
            namespace: "system".into(),
            service_name: "dns".into(),
            addresses: ["10.0.0.1", "2001:db8::1"]
                .into_iter()
                .map(|ip| EndpointAddress {
                    ip: ip.into(),
                    hostname: String::new(),
                    node_name: String::new(),
                    target_ref_name: String::new(),
                })
                .collect(),
            ports: vec![],
            zones: None,
        }
    }

    #[test]
    fn headless_service_uses_endpoint_addresses_even_with_external_ips() {
        let svc = service(true, &["192.0.2.1"]);
        let ep = endpoints();
        let mut results = Vec::new();
        visit_service(&svc, &ep, true, &mut |ip| {
            results.push(ip);
        });
        assert_eq!(
            results,
            [
                Some("10.0.0.1".parse().unwrap()),
                Some("2001:db8::1".parse().unwrap())
            ]
        );
    }

    #[test]
    fn non_headless_mode_uses_external_ips_and_retains_invalid_addresses() {
        let svc = service(true, &["192.0.2.1", "dns.example", "::ffff:192.0.2.2"]);
        let mut results = Vec::new();
        visit_service(&svc, &endpoints(), false, &mut |ip| {
            results.push(ip);
        });
        assert_eq!(
            results,
            [
                Some("192.0.2.1".parse().unwrap()),
                None,
                Some("192.0.2.2".parse().unwrap())
            ]
        );
    }

    #[test]
    fn external_ns_falls_back_to_all_local_addresses_without_endpoints() {
        let index = pharos_kubernetes::store::Index::default();
        let locals = [
            "192.0.2.1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            "::ffff:192.0.2.2".parse().unwrap(),
        ];
        let mut results = Vec::new();
        visit_external_ns(&index, &locals, true, |ip| {
            results.push(ip);
        });
        assert_eq!(
            results,
            [
                Some("192.0.2.1".parse().unwrap()),
                Some("2001:db8::1".parse().unwrap()),
                Some("192.0.2.2".parse().unwrap()),
            ]
        );
    }

    #[tokio::test]
    async fn external_ns_visits_unfiltered_store_and_suppresses_orphan_fallback() {
        use pharos_corefile::{configure, parse};
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
                            r#"[{"metadata":{"name":"dns","namespace":"hidden"},"spec":{"clusterIP":"10.0.0.10","externalIPs":["198.51.100.1"]}},{"metadata":{"name":"head","namespace":"hidden"},"spec":{"clusterIP":"None","externalIPs":["198.51.100.2"]}},{"metadata":{"name":"empty","namespace":"hidden"},"spec":{"clusterIP":"10.0.0.11"}}]"#,
                        )
                    } else if request.contains("/endpointslices") {
                        (
                            "EndpointSliceList",
                            r#"[{"metadata":{"name":"dns","namespace":"hidden","labels":{"kubernetes.io/service-name":"dns"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.1"]}]},{"metadata":{"name":"head","namespace":"hidden","labels":{"kubernetes.io/service-name":"head"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.1"],"hostname":"first"},{"addresses":["192.0.2.2"],"hostname":"second"}]},{"metadata":{"name":"empty","namespace":"hidden","labels":{"kubernetes.io/service-name":"empty"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.3"]}]},{"metadata":{"name":"orphan","namespace":"hidden","labels":{"kubernetes.io/service-name":"orphan"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.4"]}]}]"#,
                        )
                    } else {
                        ("NamespaceList", r#"[{"metadata":{"name":"visible"}}]"#)
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
            ".:53 {{\n kubernetes cluster.local {{\n  endpoint http://{server}\n  namespaces visible\n  endpoint_pod_names\n  startup_timeout 3s\n }}\n}}"
        );
        let mut chain =
            configure::<crate::Chain>(&parse("Corefile", &text).unwrap(), crate::directives())
                .unwrap()
                .remove(0)
                .config;
        let plugin = chain.kubernetes.as_mut().unwrap();
        plugin.local_ips = vec!["192.0.2.1".parse().unwrap()];
        assert!(plugin.store().is_none());
        assert!(plugin.endpoint_pod_names());
        chain.lifecycle.run(Phase::Startup).await.unwrap();
        let plugin = chain.kubernetes.as_mut().unwrap();
        let store = plugin.store().unwrap();
        let mut results = Vec::new();
        store.with_read(|index| plugin.visit_external_ns(index, true, |ip| results.push(ip)));
        results.sort();
        assert_eq!(
            results,
            [
                Some("192.0.2.1".parse().unwrap()),
                Some("192.0.2.2".parse().unwrap()),
                Some("198.51.100.1".parse().unwrap()),
            ]
        );
        for local in ["192.0.2.3", "192.0.2.4"] {
            plugin.local_ips = vec![local.parse().unwrap()];
            store.with_read(|index| {
                plugin.visit_external_ns(index, true, |_| panic!("unexpected fallback for {local}"))
            });
        }
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
        task.abort();
    }
}

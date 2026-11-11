//! Compact Kubernetes objects retained by the DNS store.

use std::sync::Arc;

use k8s_openapi::api::{core::v1, discovery::v1::EndpointSlice};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Port {
    pub name: String,
    pub protocol: String,
    pub port: i32,
}

impl Port {
    fn sentinel() -> Self {
        Self {
            name: String::new(),
            protocol: String::new(),
            port: -1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    pub version: String,
    pub name: Arc<str>,
    pub namespace: Arc<str>,
    pub cluster_ips: Vec<String>,
    pub service_type: String,
    pub external_name: String,
    pub ports: Vec<Port>,
    pub external_ips: Vec<String>,
}

impl Service {
    pub fn headless(&self) -> bool {
        self.cluster_ips.first().is_some_and(|ip| ip == "None")
    }
}

impl From<v1::Service> for Service {
    fn from(input: v1::Service) -> Self {
        let spec = input.spec.unwrap_or_default();
        let mut external_ips = spec.external_ips.unwrap_or_default();
        if let Some(ingress) = input
            .status
            .and_then(|s| s.load_balancer)
            .and_then(|lb| lb.ingress)
        {
            external_ips.extend(ingress.into_iter().map(|entry| {
                entry
                    .ip
                    .filter(|ip| !ip.is_empty())
                    .or(entry.hostname)
                    .unwrap_or_default()
            }));
        }
        let cluster_ips = spec
            .cluster_ips
            .filter(|ips| !ips.is_empty())
            .unwrap_or_else(|| vec![spec.cluster_ip.unwrap_or_default()]);
        let mut ports: Vec<_> = spec
            .ports
            .unwrap_or_default()
            .into_iter()
            .map(|port| Port {
                name: port.name.unwrap_or_default(),
                protocol: port.protocol.unwrap_or_default(),
                port: port.port,
            })
            .collect();
        if ports.is_empty() {
            ports.push(Port::sentinel());
        }
        Self {
            version: input.metadata.resource_version.unwrap_or_default(),
            name: input.metadata.name.unwrap_or_default().into(),
            namespace: input.metadata.namespace.unwrap_or_default().into(),
            cluster_ips,
            service_type: spec.type_.unwrap_or_default(),
            external_name: spec.external_name.unwrap_or_default(),
            ports,
            external_ips,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointAddress {
    pub ip: String,
    pub hostname: String,
    pub node_name: String,
    pub target_ref_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoints {
    pub version: String,
    pub name: Arc<str>,
    pub namespace: Arc<str>,
    pub service_name: Arc<str>,
    pub addresses: Vec<EndpointAddress>,
    pub ports: Vec<Port>,
}

impl From<EndpointSlice> for Endpoints {
    fn from(input: EndpointSlice) -> Self {
        let service_name = input
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get("kubernetes.io/service-name"))
            .map_or("", String::as_str)
            .into();
        let mut ports: Vec<_> = input
            .ports
            .unwrap_or_default()
            .into_iter()
            .map(|port| Port {
                name: port.name.unwrap_or_default(),
                protocol: port.protocol.unwrap_or_default(),
                port: port.port.unwrap_or(-1),
            })
            .collect();
        if ports.is_empty() {
            ports.push(Port::sentinel());
        }
        let mut addresses = Vec::new();
        for endpoint in input.endpoints.unwrap_or_default() {
            if input.address_type != "IPv4" && input.address_type != "IPv6" {
                continue;
            }
            if endpoint.conditions.and_then(|condition| condition.ready) == Some(false) {
                continue;
            }
            let hostname = endpoint.hostname.unwrap_or_default();
            let node_name = endpoint.node_name.unwrap_or_default();
            let target_ref_name = endpoint
                .target_ref
                .and_then(|target| target.name)
                .filter(|name| name.len() < 64)
                .unwrap_or_default();
            for ip in endpoint.addresses {
                addresses.push(EndpointAddress {
                    ip,
                    hostname: hostname.clone(),
                    node_name: node_name.clone(),
                    target_ref_name: target_ref_name.clone(),
                });
            }
        }
        Self {
            version: input.metadata.resource_version.unwrap_or_default(),
            name: input.metadata.name.unwrap_or_default().into(),
            namespace: input.metadata.namespace.unwrap_or_default().into(),
            service_name,
            addresses,
            ports,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pod {
    pub version: String,
    pub name: Arc<str>,
    pub namespace: Arc<str>,
    pub ips: Vec<String>,
    pub deleting: bool,
}

impl From<v1::Pod> for Pod {
    fn from(input: v1::Pod) -> Self {
        Self {
            version: input.metadata.resource_version.unwrap_or_default(),
            name: input.metadata.name.unwrap_or_default().into(),
            namespace: input.metadata.namespace.unwrap_or_default().into(),
            ips: input
                .status
                .and_then(|status| status.pod_ips)
                .unwrap_or_default()
                .into_iter()
                .map(|ip| ip.ip)
                .collect(),
            deleting: input.metadata.deletion_timestamp.is_some(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Namespace {
    pub version: String,
    pub name: Arc<str>,
}

impl From<v1::Namespace> for Namespace {
    fn from(input: v1::Namespace) -> Self {
        Self {
            version: input.metadata.resource_version.unwrap_or_default(),
            name: input.metadata.name.unwrap_or_default().into(),
        }
    }
}

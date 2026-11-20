use pharos_kubernetes::{
    object::{EndpointAddress, Endpoints, Port, Service},
    store::Index,
};
use pharos_proto::Rcode;
use std::sync::Arc;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Request<'a> {
    pub(super) namespace: &'a [u8],
    pub(super) service: &'a [u8],
    pub(super) endpoint: &'a [u8],
    pub(super) port: &'a [u8],
    pub(super) protocol: &'a [u8],
}

pub(super) enum Snapshot {
    Service(Arc<Service>),
    Headless {
        service: Arc<Service>,
        endpoints: Option<Arc<Vec<Arc<Endpoints>>>>,
    },
    MissingNamespace,
    MissingService,
    NamespaceOnly,
}

// CoreDNS retains lookup results across Self Lookups, even if the Kubernetes data changes.
pub(super) fn capture(index: &Index, req: &Request<'_>, headless: bool) -> Snapshot {
    let Ok(namespace) = std::str::from_utf8(req.namespace) else {
        return Snapshot::MissingNamespace;
    };
    if !index.namespace_exposed(namespace) {
        return Snapshot::MissingNamespace;
    }
    if req.service.is_empty() {
        return Snapshot::NamespaceOnly;
    }
    let Ok(name) = std::str::from_utf8(req.service) else {
        return Snapshot::MissingService;
    };
    let Some(service) = index.service_snapshot(namespace, name) else {
        return Snapshot::MissingService;
    };
    if uses_endpoints(&service, req, headless) {
        Snapshot::Headless {
            service,
            endpoints: index.endpoints_snapshot(namespace, name),
        }
    } else {
        Snapshot::Service(service)
    }
}

fn uses_endpoints(svc: &Service, req: &Request<'_>, headless: bool) -> bool {
    headless && svc.external_ips.is_empty() && (svc.headless() || !req.endpoint.is_empty())
}

pub(super) fn parse<'a>(labels: &'a [&'a [u8]]) -> Result<Request<'a>, Rcode> {
    let Some((&namespace, remaining)) = labels.split_last() else {
        // RFC 1035 §3.1: The empty relative-label slice is not the encoded root name.
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
            // RFC 2782 §The format of the SRV RR: Service and Proto use underscore prefixes.
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
    callback: impl FnMut(&str, &Port, Option<&[u8]>),
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
    if uses_endpoints(svc, req, headless) {
        // Kubernetes DNS spec 1.1.0 §2.4.1: headless records use ready endpoint addresses.
        endpoints(
            index.endpoints(namespace, service),
            req,
            endpoint_pod_names,
            svc.tolerate_unready_endpoints,
            callback,
        )
    } else {
        external(svc, req, callback)
    }
}

fn endpoints<'a>(
    slices: impl IntoIterator<Item = &'a Endpoints>,
    req: &Request<'_>,
    endpoint_pod_names: bool,
    tolerate_unready: bool,
    mut callback: impl FnMut(&str, &Port, Option<&[u8]>),
) -> Rcode {
    let mut code = Rcode::NXDOMAIN;
    for ep in slices {
        for addr in &ep.addresses {
            if !addr.dns_eligible(tolerate_unready) {
                continue;
            }
            let mut buf = [0; 64];
            let label = endpoint_label(addr, endpoint_pod_names, &mut buf);
            if !req.endpoint.is_empty() && !req.endpoint.eq_ignore_ascii_case(label) {
                continue;
            }
            // Kubernetes DNS spec 1.1.0 §2.4.2: Headless SRV maps ready endpoints and ports.
            for port in &ep.ports {
                if matches(req, port) {
                    code = Rcode::NOERROR;
                    callback(&addr.ip, port, Some(label));
                }
            }
        }
    }
    code
}

// RFC 1035 §2.3.3: DNS character-string comparisons are case-insensitive.
fn matches(req: &Request<'_>, port: &Port) -> bool {
    (req.port.is_empty() || req.port.eq_ignore_ascii_case(port.name.as_bytes()))
        && (req.protocol.is_empty() || req.protocol.eq_ignore_ascii_case(port.protocol.as_bytes()))
}

pub(super) fn external(
    svc: &Service,
    req: &Request<'_>,
    mut callback: impl FnMut(&str, &Port, Option<&[u8]>),
) -> Rcode {
    let mut code = Rcode::NXDOMAIN;
    for ip in &svc.external_ips {
        for port in &svc.ports {
            if matches(req, port) {
                code = Rcode::NOERROR;
                callback(ip, port, None);
            }
        }
    }
    code
}

pub(super) fn snapshot_or_lookup(
    index: &Index,
    req: &Request<'_>,
    headless: bool,
    endpoint_pod_names: bool,
    snapshot: Option<&Snapshot>,
    callback: impl FnMut(&str, &Port, Option<&[u8]>),
) -> Rcode {
    match snapshot {
        Some(Snapshot::Headless {
            service,
            endpoints: slices,
            ..
        }) => endpoints(
            slices
                .iter()
                .flat_map(|slices| slices.iter())
                .map(Arc::as_ref),
            req,
            endpoint_pod_names,
            service.tolerate_unready_endpoints,
            callback,
        ),
        Some(Snapshot::Service(service)) => external(service, req, callback),
        Some(Snapshot::MissingNamespace | Snapshot::MissingService) => Rcode::NXDOMAIN,
        Some(Snapshot::NamespaceOnly) => Rcode::NOERROR,
        None => lookup(index, req, headless, endpoint_pod_names, callback),
    }
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
    // Kubernetes DNS spec 1.1.0 §2.1: Use a unique identifier when hostname is absent.
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
mod tests;

//! Kubernetes authoritative DNS backend.

#[cfg(test)]
#[allow(unused_attributes)]
mod authority_test;
#[cfg(feature = "plugin-k8s-external")]
pub(crate) mod external;
mod local;
mod name;
pub(crate) mod reverse;
pub(crate) mod scratch;
pub mod setup;
#[cfg(feature = "plugin-transfer")]
mod transfer;

use pharos_kubernetes::{
    Controller,
    object::{EndpointAddress, Port},
    store::{Index, Store},
};
use pharos_proto::{
    BuildError, Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type,
};
use pharos_server::{Context, Next, Outcome, Phase, Protocol};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex, RwLock},
};

#[derive(Default)]
struct State {
    controller: Mutex<Option<Controller>>,
    cache: RwLock<Cache>,
    metrics: Mutex<pharos_server::metrics::Registry>,
    scratch: scratch::Pool,
    empty_store: Store,
    #[cfg(feature = "plugin-transfer")]
    notifier: Mutex<transfer::Notifier>,
}

#[derive(Default)]
struct Cache {
    store: Option<Store>,
    sync: Option<Arc<dyn pharos_server::Readiness>>,
}

#[derive(Clone)]
pub struct Kubernetes {
    config: Arc<setup::Config>,
    zones: Vec<Name>,
    multicluster_zones: Vec<Name>,
    fallthrough: Vec<Name>,
    local_ips: Vec<IpAddr>,
    state: Arc<State>,
}

/// Invalid Kubernetes Plugin configuration.
#[derive(Debug)]
pub enum KubernetesError {
    InvalidName(pharos_proto::NameError),
}

impl std::fmt::Display for KubernetesError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for KubernetesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidName(error) => Some(error),
        }
    }
}

impl std::fmt::Debug for Kubernetes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kubernetes")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Kubernetes {
    #[cfg(feature = "plugin-autopath")]
    pub(crate) fn autopath_client(
        &self,
        cx: &Context<'_, '_>,
    ) -> Option<(Arc<pharos_kubernetes::object::Pod>, &Name)> {
        if self.config.pod_mode != "verified" {
            return None;
        }
        let q = cx.query.questions().next()?;
        let zone = self
            .zones
            .iter()
            .filter(|zone| contains(q.name, zone))
            .max_by_key(|zone| zone.label_count())?;
        let ip = scratch::IpText::new(cx.client.ip());
        let store = self.state.cache.read().unwrap().store.clone()?;
        let pod = store.with_read(|index| index.pod_snapshot_by_ip(ip.as_str()))?;
        Some((pod, zone))
    }
    #[cfg(feature = "plugin-metadata")]
    pub(crate) fn collect_metadata(&self, cx: &mut Context<'_, '_>) {
        if self.config.pod_mode == "verified" {
            let ip = scratch::IpText::new(cx.client.ip());
            let store = self.state.cache.read().unwrap().store.clone();
            if let Some(pod) = store
                .and_then(|store| store.with_read(|index| index.pod_snapshot_by_ip(ip.as_str())))
            {
                cx.metadata.set_source(pod);
            }
        }
        let Some(question) = cx.query.questions().next() else {
            return;
        };
        let Some(zone) = self
            .zones
            .iter()
            .filter(|zone| contains(question.name, zone))
            .max_by_key(|zone| zone.label_count())
        else {
            return;
        };
        let mut lower = [0u8; 255];
        let mut len = 0;
        for label in question.name.labels() {
            lower[len] = label.len() as u8;
            len += 1;
            for byte in label {
                lower[len] = byte.to_ascii_lowercase();
                len += 1;
            }
        }
        let name = NameRef::parse(&lower[..=len], 0).unwrap();
        let mut labels = [&[][..]; 127];
        let count = name.labels().count() - zone.label_count();
        for (slot, label) in labels.iter_mut().zip(name.labels().take(count)) {
            *slot = label;
        }
        let multicluster = self.multicluster_zones.contains(zone);
        let Some(request) =
            name::parse_multicluster(&labels[..count], self.config.zonal, multicluster)
        else {
            cx.metadata
                .insert("kubernetes/parse-error", "invalid query name");
            return;
        };
        for (key, value) in [
            ("kubernetes/port-name", request.port),
            ("kubernetes/protocol", request.protocol),
            ("kubernetes/endpoint", request.endpoint),
            ("kubernetes/service", request.service),
            ("kubernetes/namespace", request.namespace),
            ("kubernetes/kind", request.kind),
        ] {
            if let Ok(value) = std::str::from_utf8(value) {
                cx.metadata.insert_copied(key, value);
            }
        }
        if multicluster && let Ok(cluster) = std::str::from_utf8(request.cluster) {
            cx.metadata.insert_copied("kubernetes/cluster", cluster);
        }
        if self.config.zonal {
            let mut zone = [0u8; 255];
            let mut used = 0;
            for label in request.zone {
                if used > 0 {
                    zone[used] = b'.';
                    used += 1;
                }
                zone[used..used + label.len()].copy_from_slice(label);
                used += label.len();
            }
            if let Ok(value) = std::str::from_utf8(&zone[..used]) {
                cx.metadata.insert_copied("kubernetes/zone", value);
            }
        }
    }

    pub fn new(config: setup::Config) -> Result<Self, KubernetesError> {
        Self::with_listen_addresses(config, &[])
    }

    pub(crate) fn with_listen_addresses(
        config: setup::Config,
        listen_addresses: &[String],
    ) -> Result<Self, KubernetesError> {
        let zones = config
            .zones
            .iter()
            .map(|z| z.parse::<Name>().map_err(KubernetesError::InvalidName))
            .collect::<Result<_, _>>()?;
        let fallthrough = config
            .fallthrough
            .domains
            .iter()
            .map(|z| z.parse::<Name>().map_err(KubernetesError::InvalidName))
            .collect::<Result<_, _>>()?;
        let multicluster_zones = config
            .multicluster_zones
            .iter()
            .map(|z| z.parse::<Name>().map_err(KubernetesError::InvalidName))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            config: Arc::new(config),
            zones,
            multicluster_zones,
            fallthrough,
            local_ips: local::snapshot(listen_addresses),
            state: Arc::default(),
        })
    }

    pub(crate) fn set_metrics(&self, registry: &pharos_server::metrics::Registry) {
        *self.state.metrics.lock().unwrap() = registry.clone();
    }

    pub(crate) fn register_hooks(&self, lifecycle: &mut pharos_server::Lifecycle) {
        let state = self.state.clone();
        let config = self.config.clone();
        #[cfg(feature = "plugin-transfer")]
        let zones = self.zones.clone();
        #[cfg(feature = "plugin-transfer")]
        let multicluster_zones = self.multicluster_zones.clone();
        let start = move || {
            let state = state.clone();
            let config = config.clone();
            #[cfg(feature = "plugin-transfer")]
            let zones = zones.clone();
            #[cfg(feature = "plugin-transfer")]
            let multicluster_zones = multicluster_zones.clone();
            async move {
                let previous = state.controller.lock().unwrap().take();
                let controller = if let Some(controller) = previous {
                    controller.restart().await
                } else {
                    let registry = state.metrics.lock().unwrap().clone();
                    let client = config
                        .client_config()
                        .client(&registry)
                        .await
                        .map_err(std::io::Error::other)?;
                    Controller::start_with_metrics(
                        client,
                        config.watch_config(),
                        registry.kubernetes(),
                    )
                };
                let sync = controller.sync_status();
                let store = controller.store();
                *state.controller.lock().unwrap() = Some(controller);
                *state.cache.write().unwrap() = Cache {
                    store: Some(store),
                    sync: Some(sync.clone()),
                };
                #[cfg(feature = "plugin-transfer")]
                transfer::start(&state, &zones, &multicluster_zones);
                Controller::wait_for_sync_status(sync.as_ref(), config.startup_timeout).await;
                Ok(())
            }
        };
        lifecycle.register(Phase::Startup, start.clone());
        lifecycle.register(Phase::RestartFailed, start);
        let state = self.state.clone();
        let stop = move || {
            #[cfg(feature = "plugin-transfer")]
            transfer::stop(&state);
            state.cache.write().unwrap().sync = None;
            let controller = state.controller.lock().unwrap().take();
            let state = state.clone();
            async move {
                if let Some(mut controller) = controller {
                    controller.stop().await;
                    *state.controller.lock().unwrap() = Some(controller);
                }
                Ok(())
            }
        };
        lifecycle.register(Phase::Restart, stop.clone());
        lifecycle.register(Phase::Shutdown, stop);
    }
}

fn contains(name: NameRef<'_>, zone: &Name) -> bool {
    let z = NameRef::parse(zone.as_wire(), 0).unwrap();
    let n = name.labels().count();
    let count = z.labels().count();
    n >= count
        && name
            .labels()
            .skip(n - count)
            .zip(z.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn child<'a>(prefix: &[&[u8]], zone: NameRef<'_>, wire: &'a mut [u8; 255]) -> Option<NameRef<'a>> {
    let mut n = 0;
    // RFC 1035 §3.1: labels are at most 63 octets and wire names at most 255 octets.
    for label in prefix.iter().copied().chain(zone.labels()) {
        if label.is_empty() || label.len() > 63 || n + label.len() + 2 > 255 {
            return None;
        }
        wire[n] = label.len() as u8;
        n += 1;
        wire[n..n + label.len()].copy_from_slice(label);
        n += label.len();
    }
    wire[n] = 0;
    NameRef::parse(&wire[..n + 1], 0).ok()
}

// RFC 1035 §3.3.13 and RFC 2308 §5: SOA RDATA order and negative-cache TTL.
fn soa(
    builder: &mut MessageBuilder<'_>,
    section: Section,
    zone: NameRef<'_>,
    ttl: u32,
    serial: u32,
) -> Result<(), BuildError> {
    let mut ns_wire = [0; 255];
    let mut host_wire = [0; 255];
    let ns = child(&[b"ns", b"dns"], zone, &mut ns_wire).ok_or(BuildError::InvalidRdata)?;
    let host = child(&[b"hostmaster"], zone, &mut host_wire).ok_or(BuildError::InvalidRdata)?;
    builder.record_with(section, zone, Type::SOA, Class::IN, ttl.min(300), |w| {
        w.write_name(ns)?;
        w.write_name(host)?;
        for number in [serial, 7200, 1800, 86400, ttl] {
            w.write_bytes(&number.to_be_bytes())?;
        }
        Ok(())
    })?;
    Ok(())
}

fn matching(request: &name::Request<'_>, port: &Port) -> bool {
    (request.port.is_empty() || request.port.eq_ignore_ascii_case(port.name.as_bytes()))
        && (request.protocol.is_empty()
            || request
                .protocol
                .eq_ignore_ascii_case(port.protocol.as_bytes()))
}

fn pod_ip(index: &Index, req: &name::Request<'_>, config: &setup::Config) -> Option<IpAddr> {
    if config.pod_mode == "disabled" {
        return None;
    }
    let namespace = std::str::from_utf8(req.namespace).ok()?;
    if index.namespace(namespace).is_none() || req.service.len() > 63 {
        return None;
    }
    let ipv4 = req.service.iter().filter(|&&b| b == b'-').count() == 3
        && !req.service.windows(2).any(|w| w == b"--");
    let mut buf = [0; 63];
    for (i, &byte) in req.service.iter().enumerate() {
        buf[i] = if byte == b'-' {
            if ipv4 { b'.' } else { b':' }
        } else {
            byte
        };
    }
    let text = std::str::from_utf8(&buf[..req.service.len()]).ok()?;
    let ip = text.parse().ok()?;
    if config.pod_mode == "verified"
        && !index
            .pods_by_ip(text)
            .any(|pod| pod.namespace.as_ref().eq_ignore_ascii_case(namespace))
    {
        return None;
    }
    Some(ip)
}

fn endpoint_label<'a>(
    address: &'a EndpointAddress,
    pod_names: bool,
    buf: &'a mut [u8; 64],
) -> &'a [u8] {
    // Kubernetes DNS spec 1.1.0 §2.1: an explicit endpoint hostname takes precedence.
    if !address.hostname.is_empty() {
        return address.hostname.as_bytes();
    }
    if pod_names && !address.target_ref_name.is_empty() {
        return address.target_ref_name.as_bytes();
    }
    let bytes = address.ip.as_bytes();
    if bytes.len() + 1 > buf.len() {
        return b"";
    }
    for (i, byte) in bytes.iter().enumerate() {
        buf[i] = if *byte == b'.' || *byte == b':' {
            b'-'
        } else {
            *byte
        };
    }
    let mut n = bytes.len();
    if bytes.last() == Some(&b':') {
        buf[n] = b'0';
        n += 1;
    }
    &buf[..n]
}

fn visit_reverse(
    index: &Index,
    ip: &str,
    zone: NameRef<'_>,
    config: &setup::Config,
    mut visit: impl FnMut(NameRef<'_>),
) -> bool {
    let exposed =
        |namespace: &str| config.namespaces.is_empty() || index.namespace(namespace).is_some();
    // Kubernetes DNS spec 1.1.0 §2.3.3: a ClusterIP PTR points to its service name.
    if let Some(service) = index
        .services_by_ip_unfiltered(ip)
        .find(|service| exposed(&service.namespace))
    {
        let mut wire = [0; 255];
        if let Some(target) = child(
            &[
                service.name.as_bytes(),
                service.namespace.as_bytes(),
                b"svc",
            ],
            zone,
            &mut wire,
        ) {
            visit(target);
            return true;
        }
        return false;
    }
    let mut found = false;
    // Kubernetes DNS spec 1.1.0 §2.4.3: endpoint PTRs point to hostname.service names.
    for endpoints in index.endpoints_by_ip_unfiltered(ip) {
        if !exposed(&endpoints.namespace) {
            continue;
        }
        for address in &endpoints.addresses {
            if address.ip != ip {
                continue;
            }
            let mut label = [0; 64];
            let hostname = endpoint_label(address, config.endpoint_pod_names, &mut label);
            let mut wire = [0; 255];
            if let Some(target) = child(
                &[
                    hostname,
                    endpoints.service_name.as_bytes(),
                    endpoints.namespace.as_bytes(),
                    b"svc",
                ],
                zone,
                &mut wire,
            ) {
                visit(target);
                found = true;
            }
        }
    }
    found
}

fn external_name(index: &Index, req: &name::Request<'_>) -> Option<Option<Arc<Name>>> {
    let namespace = std::str::from_utf8(req.namespace).ok()?;
    let name = std::str::from_utf8(req.service).ok()?;
    let service = index.service(namespace, name)?;
    (service.service_type == "ExternalName").then(|| index.external_name(namespace, name))
}

fn visit(
    index: &Index,
    req: &name::Request<'_>,
    config: &setup::Config,
    mut f: impl FnMut(&str, &Port, Option<(&[u8], Option<&[u8]>)>),
) -> bool {
    let Ok(namespace) = std::str::from_utf8(req.namespace) else {
        return false;
    };
    let Ok(service) = std::str::from_utf8(req.service) else {
        return false;
    };
    if index.namespace(namespace).is_none() {
        return false;
    }
    if req.multicluster {
        let Some(svc) = index.service_import(namespace, service) else {
            return false;
        };
        if config.ignore_empty_service
            && !svc.headless()
            && !index
                .multicluster_endpoints(namespace, service)
                .any(|ep| !ep.endpoints.addresses.is_empty())
        {
            return false;
        }
        // KEP-1645 MCS DNS spec §2.4.1: headless records use ready endpoint addresses.
        if svc.headless() || !req.endpoint.is_empty() {
            let mut found = false;
            for ep in index.multicluster_endpoints(namespace, service) {
                if !req.endpoint.is_empty()
                    && !req.cluster.eq_ignore_ascii_case(ep.cluster_id.as_bytes())
                {
                    continue;
                }
                for addr in &ep.endpoints.addresses {
                    let mut buf = [0; 64];
                    let label = endpoint_label(addr, config.endpoint_pod_names, &mut buf);
                    if !req.endpoint.is_empty() && !req.endpoint.eq_ignore_ascii_case(label) {
                        continue;
                    }
                    for port in &ep.endpoints.ports {
                        if matching(req, port) {
                            found = true;
                            f(
                                &addr.ip,
                                port,
                                Some((label, Some(ep.cluster_id.as_bytes()))),
                            );
                        }
                    }
                }
            }
            return found;
        }
        let mut found = false;
        // KEP-1645 MCS DNS spec §2.3.1: ClusterSetIP records use the service IPs.
        for port in &svc.ports {
            if matching(req, port) {
                found = true;
                for ip in &svc.cluster_ips {
                    f(ip, port, None);
                }
            }
        }
        return found;
    }
    let Some(svc) = index.service(namespace, service) else {
        return false;
    };
    if config.ignore_empty_service
        && !svc.headless()
        && svc.service_type != "ExternalName"
        && !index
            .endpoints(namespace, service)
            .any(|e| !e.addresses.is_empty())
    {
        return false;
    }
    if !req.zone.is_empty() && !svc.headless() {
        return false;
    }
    if svc.service_type == "ExternalName" {
        return req.endpoint.is_empty()
            && req.port.is_empty()
            && req.protocol.is_empty()
            && !svc.external_name.is_empty()
            && svc.external_name.parse::<IpAddr>().is_err();
    }
    let mut found = !req.zone.is_empty();
    // Kubernetes DNS spec 1.1.0 §2.4.1: headless records use ready endpoint addresses.
    if svc.headless() || !req.endpoint.is_empty() {
        let zone_matches = |ep: &pharos_kubernetes::object::Endpoints, addr: &EndpointAddress| {
            ep.zones
                .as_ref()
                .and_then(|zones| zones.get(&addr.ip))
                .is_some_and(|zone| {
                    zone.as_bytes()
                        .split(|b| *b == b'.')
                        .eq(req.zone.iter().copied())
                })
        };
        let filter_zone = !req.zone.is_empty()
            && (!req.prefer
                || index.endpoints(namespace, service).any(|ep| {
                    ep.addresses.iter().any(|addr| {
                        zone_matches(ep, addr) && ep.ports.iter().any(|port| matching(req, port))
                    })
                }));
        for ep in index.endpoints(namespace, service) {
            for addr in &ep.addresses {
                if filter_zone && !zone_matches(ep, addr) {
                    continue;
                }
                let mut buf = [0; 64];
                let label = endpoint_label(addr, config.endpoint_pod_names, &mut buf);
                if !req.endpoint.is_empty() && !req.endpoint.eq_ignore_ascii_case(label) {
                    continue;
                }
                for port in &ep.ports {
                    if matching(req, port) {
                        found = true;
                        f(&addr.ip, port, Some((label, None)));
                    }
                }
            }
        }
    } else {
        // Kubernetes DNS spec 1.1.0 §2.3.1: ClusterIP records use the service IPs.
        for port in &svc.ports {
            if matching(req, port) {
                found = true;
                for ip in &svc.cluster_ips {
                    f(ip, port, None);
                }
            }
        }
    }
    found
}

fn visit_ns(
    index: &Index,
    locals: &[IpAddr],
    zone: NameRef<'_>,
    config: &setup::Config,
    mut f: impl FnMut(NameRef<'_>, IpAddr),
) {
    let mut found = false;
    for local in locals {
        let local_text = scratch::IpText::new(*local);
        for ep in index.endpoints_by_ip_unfiltered(local_text.as_str()) {
            found = true;
            let Some(svc) = index.service_unfiltered(&ep.namespace, &ep.service_name) else {
                continue;
            };
            if svc.headless() {
                for addr in &ep.addresses {
                    let Ok(ip) = addr.ip.parse() else { continue };
                    let mut label = [0; 64];
                    let hostname = endpoint_label(addr, config.endpoint_pod_names, &mut label);
                    let mut wire = [0; 255];
                    if let Some(target) = child(
                        &[
                            hostname,
                            svc.name.as_bytes(),
                            svc.namespace.as_bytes(),
                            b"svc",
                        ],
                        zone,
                        &mut wire,
                    ) {
                        f(target, ip);
                    }
                }
            } else {
                for addr in &svc.cluster_ips {
                    let Ok(ip) = addr.parse() else { continue };
                    let mut wire = [0; 255];
                    if let Some(target) = child(
                        &[svc.name.as_bytes(), svc.namespace.as_bytes(), b"svc"],
                        zone,
                        &mut wire,
                    ) {
                        f(target, ip);
                    }
                }
            }
        }
    }
    if !found {
        let mut wire = [0; 255];
        if let Some(target) = child(&[b"ns", b"dns"], zone, &mut wire) {
            for local in locals {
                f(target, *local);
            }
        }
    }
}

impl pharos_server::Plugin for Kubernetes {
    fn readiness(&self) -> Option<&dyn pharos_server::Readiness> {
        Some(self)
    }

    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let Some(q) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        let Some(zone) = self
            .zones
            .iter()
            .filter(|z| contains(q.name, z))
            .max_by_key(|z| z.label_count())
        else {
            return next.run(cx).await;
        };
        if q.qtype == Type::AXFR || q.qtype == Type::IXFR {
            return Outcome::Unanswered(Rcode::REFUSED);
        }
        let mut lower = [0u8; 255];
        let mut n = 0;
        for label in q.name.labels() {
            lower[n] = label.len() as u8;
            n += 1;
            for b in label {
                lower[n] = b.to_ascii_lowercase();
                n += 1;
            }
        }
        n += 1;
        let lower_name = NameRef::parse(&lower[..n], 0).unwrap();
        let mut labels = [&[][..]; 127];
        let mut count = 0;
        for label in lower_name.labels() {
            labels[count] = label;
            count += 1;
        }
        let reverse_name = reverse::is_reverse(&labels[..count]);
        let reverse_ip = (q.qtype == Type::PTR)
            .then(|| reverse::address(&labels[..count]))
            .flatten()
            .map(scratch::IpText::new);
        let count = count - zone.label_count();
        let mut zone_wire = [0u8; 255];
        let mut zone_len = 0;
        for label in q.name.labels().skip(count) {
            zone_wire[zone_len] = label.len() as u8;
            zone_len += 1;
            zone_wire[zone_len..zone_len + label.len()].copy_from_slice(label);
            zone_len += label.len();
        }
        let zone_ref = NameRef::parse(&zone_wire[..zone_len + 1], 0).unwrap();
        let multicluster = self.multicluster_zones.contains(zone);
        let req = name::parse_multicluster(&labels[..count], self.config.zonal, multicluster);
        let (store, synced) = {
            let guard = self.state.cache.read().unwrap();
            (
                guard.store.clone(),
                guard.sync.as_ref().is_some_and(|sync| sync.ready()),
            )
        };
        let store = store.unwrap_or_else(|| self.state.empty_store.clone());
        let mut external = None;
        let mut pod = None;
        let primary =
            NameRef::parse(self.zones[self.config.primary_zone_index].as_wire(), 0).unwrap();
        let exists = if let Some(ip) = &reverse_ip {
            store
                .with_read(|index| visit_reverse(index, ip.as_str(), primary, &self.config, |_| {}))
        } else if q.qtype == Type::SOA
            || count == 1 && labels[0] == b"dns-version" && q.qtype == Type::TXT
            || q.qtype != Type::TXT
                && (count == 0
                    || count == 1 && (labels[0] == b"svc" || labels[0] == b"pod")
                    || count == 2 && labels[0] == b"ns" && labels[1] == b"dns")
        {
            if q.qtype == Type::SOA
                && !multicluster
                && !reverse_name
                && let Some(req) = &req
                && req.kind == b"svc"
                && !req.service.is_empty()
            {
                external = store.with_read(|i| {
                    visit(i, req, &self.config, |_, _, _| {})
                        .then(|| external_name(i, req))
                        .flatten()
                });
            }
            true
        } else if let Some(req) = &req {
            if reverse_name && !req.kind.is_empty() {
                false
            } else if req.kind == b"svc" && req.service.is_empty() {
                q.qtype != Type::TXT
                    && std::str::from_utf8(req.namespace)
                        .ok()
                        .is_some_and(|ns| store.with_read(|i| i.namespace(ns).is_some()))
            } else if req.kind == b"svc" {
                store.with_read(|i| {
                    let ok = visit(i, req, &self.config, |_, _, _| {});
                    if ok && !multicluster {
                        external = external_name(i, req);
                    }
                    ok
                })
            } else if req.kind == b"pod" {
                if req.service.is_empty() {
                    q.qtype != Type::TXT
                        && self.config.pod_mode != "disabled"
                        && std::str::from_utf8(req.namespace)
                            .ok()
                            .is_some_and(|ns| store.with_read(|i| i.namespace(ns).is_some()))
                } else {
                    pod = store.with_read(|i| pod_ip(i, req, &self.config));
                    pod.is_some()
                }
            } else {
                false
            }
        } else {
            false
        };
        if !exists && self.fallthrough.iter().any(|z| contains(q.name, z)) {
            return next.run(cx).await;
        }
        let code = if exists {
            Rcode::NOERROR
        } else if synced {
            Rcode::NXDOMAIN
        } else {
            Rcode::SERVFAIL
        };
        let target = external.as_ref().and_then(Option::as_ref);
        let mut truncated = false;
        let chased = if matches!(q.qtype, Type::A | Type::AAAA)
            && target.is_some_and(|t| {
                NameRef::parse(t.as_wire(), 0).is_ok_and(|name| name != lower_name)
            }) {
            if let Some(target) = target {
                // shortcut: Self Lookup allocates per Query until #86 pools its buffers and futures.
                let result = cx.self_lookup(target, q.qtype).await.ok();
                truncated = result
                    .as_deref()
                    .and_then(|wire| Message::parse(wire).ok())
                    .is_some_and(|message| message.tc());
                if NameRef::parse(target.as_wire(), 0).is_ok_and(|name| contains(name, zone)) {
                    result.filter(|wire| {
                        Message::parse(wire).is_ok_and(|msg| {
                            msg.rcode() == Rcode::NOERROR && msg.answer_count() > 0
                        })
                    })
                } else {
                    result
                }
            } else {
                None
            }
        } else {
            None
        };
        let ns_ips = &self.local_ips;
        let max = cx.max_response_size.max(512);
        if cx.response.capacity() < max {
            if cx.protocol == Protocol::Tcp {
                cx.response.reserve(max - cx.response.len());
            } else {
                return Outcome::Error(pharos_server::Error::ResponseBufferTooSmall);
            }
        }
        let mut scratch = self.state.scratch.lease();
        let result = (|| -> Result<(), BuildError> {
            // RFC 1035 §4.1.1: set Response and authoritative flags while retaining Query flags.
            let mut b = MessageBuilder::new(
                cx.response,
                max,
                cx.query.id(),
                0x8400
                    | (cx.query.flags() & 0x7910)
                    | code.0
                    | if truncated && chased.is_some() {
                        0x0200
                    } else {
                        0
                    },
            )?;
            b.question(q.name, q.qtype, q.qclass)?;
            let mut answers = 0usize;
            if exists && let Some(ip) = &reverse_ip {
                let mut error = None;
                store.with_read(|index| {
                    visit_reverse(index, ip.as_str(), primary, &self.config, |target| {
                        if error.is_none() && scratch.names.insert(scratch::Name::new(target)) {
                            match b.record_with(
                                Section::Answer,
                                q.name,
                                Type::PTR,
                                Class::IN,
                                self.config.ttl,
                                |writer| writer.write_name(target),
                            ) {
                                Ok(true) => answers += 1,
                                Ok(false) => {}
                                Err(err) => error = Some(err),
                            }
                        }
                    });
                });
                if let Some(err) = error {
                    return Err(err);
                }
            }
            if count == 0 && q.qtype == Type::SOA {
                soa(
                    &mut b,
                    Section::Answer,
                    zone_ref,
                    self.config.ttl,
                    store.with_read(|i| {
                        if multicluster {
                            i.multicluster_serial()
                        } else {
                            i.serial()
                        }
                    }),
                )?;
                answers += 1;
            }
            if count == 0 && q.qtype == Type::NS {
                let mut err = None;
                store.with_read(|i| {
                    visit_ns(i, ns_ips, zone_ref, &self.config, |ns, _| {
                        if err.is_none() && scratch.names.insert(scratch::Name::new(ns)) {
                            match b.record_with(
                                Section::Answer,
                                q.name,
                                Type::NS,
                                Class::IN,
                                self.config.ttl,
                                |w| w.write_name(ns),
                            ) {
                                Ok(true) => answers += 1,
                                Ok(false) => {}
                                Err(e) => err = Some(e),
                            }
                        }
                    })
                });
                if let Some(e) = err {
                    return Err(e);
                }
                store.with_read(|i| {
                    visit_ns(i, ns_ips, zone_ref, &self.config, |ns, ip| {
                        // RFC 2181 §5: duplicate RRs in an RRset are suppressed.
                        if err.is_some()
                            || !scratch.extra.insert((
                                scratch::Name::new(ns),
                                scratch::Address::new(scratch::IpText::new(ip).as_str()),
                            ))
                        {
                            return;
                        }
                        let result = match ip {
                            IpAddr::V4(ip) => b.record(
                                Section::Additional,
                                ns,
                                Type::A,
                                Class::IN,
                                self.config.ttl,
                                &ip.octets(),
                            ),
                            IpAddr::V6(ip) => b.record(
                                Section::Additional,
                                ns,
                                Type::AAAA,
                                Class::IN,
                                self.config.ttl,
                                &ip.octets(),
                            ),
                        };
                        if let Err(e) = result {
                            err = Some(e);
                        }
                    })
                });
                if let Some(e) = err {
                    return Err(e);
                }
            }
            if count == 2 && labels[0] == b"ns" && labels[1] == b"dns" {
                let mut err = None;
                store.with_read(|i| {
                    visit_ns(i, ns_ips, zone_ref, &self.config, |_, ip| {
                        // RFC 2181 §5: duplicate RRs in an RRset are suppressed.
                        if !scratch
                            .addresses
                            .insert(scratch::Address::new(scratch::IpText::new(ip).as_str()))
                        {
                            return;
                        }
                        let result = match ip {
                            IpAddr::V4(ip) if q.qtype == Type::A => b.record(
                                Section::Answer,
                                q.name,
                                Type::A,
                                Class::IN,
                                self.config.ttl,
                                &ip.octets(),
                            ),
                            IpAddr::V6(ip) if q.qtype == Type::AAAA => b.record(
                                Section::Answer,
                                q.name,
                                Type::AAAA,
                                Class::IN,
                                self.config.ttl,
                                &ip.octets(),
                            ),
                            _ => return,
                        };
                        match result {
                            Ok(true) => answers += 1,
                            Ok(false) => {}
                            Err(e) => err = Some(e),
                        }
                    })
                });
                if let Some(e) = err {
                    return Err(e);
                }
            }
            // Kubernetes DNS spec 1.1.0 §2.2: dns-version carries the schema version in TXT.
            if count == 1 && labels[0] == b"dns-version" && q.qtype == Type::TXT {
                b.record(
                    Section::Answer,
                    q.name,
                    Type::TXT,
                    Class::IN,
                    28800,
                    b"\x051.1.0",
                )?;
                answers += 1;
            }
            if let Some(ip) = pod {
                if q.qtype == Type::SRV
                    && let Some(req) = &req
                {
                    let mut wire = [0; 255];
                    if let Some(target) =
                        child(&[req.service, req.namespace, b"pod"], zone_ref, &mut wire)
                        && b.record_with(
                            Section::Answer,
                            q.name,
                            Type::SRV,
                            Class::IN,
                            self.config.ttl,
                            |w| {
                                w.write_bytes(&[0, 0, 0, 100, 0, 0])?;
                                w.write_uncompressed_name(target)
                            },
                        )?
                    {
                        answers += 1;
                        match ip {
                            IpAddr::V4(ip) => b.record(
                                Section::Additional,
                                target,
                                Type::A,
                                Class::IN,
                                self.config.ttl,
                                &ip.octets(),
                            )?,
                            IpAddr::V6(ip) => b.record(
                                Section::Additional,
                                target,
                                Type::AAAA,
                                Class::IN,
                                self.config.ttl,
                                &ip.octets(),
                            )?,
                        };
                    }
                }
                let result = match ip {
                    IpAddr::V4(ip) if q.qtype == Type::A => b.record(
                        Section::Answer,
                        q.name,
                        Type::A,
                        Class::IN,
                        self.config.ttl,
                        &ip.octets(),
                    )?,
                    IpAddr::V6(ip) if q.qtype == Type::AAAA => b.record(
                        Section::Answer,
                        q.name,
                        Type::AAAA,
                        Class::IN,
                        self.config.ttl,
                        &ip.octets(),
                    )?,
                    _ => false,
                };
                if result {
                    answers += 1;
                }
            }
            // Kubernetes DNS spec 1.1.0 §2.5: ExternalName services have a CNAME to the target.
            // RFC 1034 §4.3.2 step 3a: the CNAME is returned whatever the QTYPE.
            if let Some(target) = target
                && (!matches!(q.qtype, Type::A | Type::AAAA) || chased.is_some())
            {
                let target_ref = NameRef::parse(target.as_wire(), 0).unwrap();
                b.record_with(
                    Section::Answer,
                    q.name,
                    Type::CNAME,
                    Class::IN,
                    self.config.ttl,
                    |w| w.write_name(target_ref),
                )?;
                answers += 1;
                if let Some(wire) = &chased
                    && let Ok(message) = Message::parse(wire)
                {
                    // RFC 1034 §4.3.2: include records found while following a CNAME.
                    for rr in message.answers() {
                        if let Ok(data) = rr.data() {
                            b.record_with(
                                Section::Answer,
                                rr.name,
                                rr.rtype,
                                rr.class,
                                rr.ttl,
                                |w| data.write(w),
                            )?;
                            answers += 1;
                        }
                    }
                }
            }
            if exists
                && external.is_none()
                && let Some(req) = &req
                && req.kind == b"svc"
                && !req.service.is_empty()
            {
                store.with_read(|i| -> Result<(), BuildError> {
                    let mut total = 0usize;
                    visit(i, req, &self.config, |_, _, _| total += 1);
                    let mut write_error = None;
                    let mut stopped = false;
                    visit(i, req, &self.config, |ip, port, endpoint| {
                        if stopped || write_error.is_some() {
                            return;
                        }
                        let ip_text = ip;
                        let Ok(ip) = ip_text.parse::<IpAddr>() else {
                            return;
                        };
                        let result = if q.qtype == Type::A || q.qtype == Type::AAAA {
                            if !scratch.addresses.insert(scratch::Address::new(ip_text)) {
                                return;
                            }
                            match ip {
                                IpAddr::V4(ip) if q.qtype == Type::A => b.record(
                                    Section::Answer,
                                    q.name,
                                    Type::A,
                                    Class::IN,
                                    self.config.ttl,
                                    &ip.octets(),
                                ),
                                IpAddr::V6(ip) if q.qtype == Type::AAAA => b.record(
                                    Section::Answer,
                                    q.name,
                                    Type::AAAA,
                                    Class::IN,
                                    self.config.ttl,
                                    &ip.octets(),
                                ),
                                _ => return,
                            }
                        } else if q.qtype == Type::SRV && port.port >= 0 {
                            // Kubernetes DNS spec 1.1.0 §2.3.2: ClusterIP SRV targets name services.
                            // Kubernetes DNS spec 1.1.0 §2.4.2: headless SRV targets name endpoints.
                            // KEP-1645 MCS DNS spec §2.4.2: headless SRV targets include cluster IDs.
                            let mut wire = [0; 255];
                            let mut parts = [&[][..]; 5];
                            let start = if let Some((endpoint, cluster)) = endpoint {
                                parts[0] = endpoint;
                                if let Some(cluster) = cluster {
                                    parts[1] = cluster;
                                    0
                                } else {
                                    parts[1] = endpoint;
                                    1
                                }
                            } else {
                                2
                            };
                            parts[2] = req.service;
                            parts[3] = req.namespace;
                            parts[4] = b"svc";
                            let Some(target) = child(&parts[start..], zone_ref, &mut wire) else {
                                return;
                            };
                            if !scratch
                                .srv
                                .insert((scratch::Name::new(target), port.port as u16))
                            {
                                return;
                            }
                            // RFC 2782 §3: SRV RDATA contains priority, weight, port and target.
                            let weight = (100 / total.max(1)).max(1) as u16;
                            b.record_with(
                                Section::Answer,
                                q.name,
                                Type::SRV,
                                Class::IN,
                                self.config.ttl,
                                |w| {
                                    w.write_bytes(&0u16.to_be_bytes())?;
                                    w.write_bytes(&weight.to_be_bytes())?;
                                    w.write_bytes(&(port.port as u16).to_be_bytes())?;
                                    w.write_uncompressed_name(target)
                                },
                            )
                        } else {
                            return;
                        };
                        match result {
                            Ok(true) => answers += 1,
                            Ok(false) => stopped = true,
                            Err(e) => write_error = Some(e),
                        }
                    });
                    if let Some(err) = write_error {
                        return Err(err);
                    }
                    // Kubernetes DNS spec 1.1.0 §2.4.2: SRV answers may include target addresses.
                    if !stopped && q.qtype == Type::SRV && answers > 0 {
                        let mut error = None;
                        visit(i, req, &self.config, |ip, port, endpoint| {
                            if stopped || error.is_some() || port.port < 0 {
                                return;
                            }
                            let ip_text = ip;
                            let Ok(ip) = ip_text.parse::<IpAddr>() else {
                                return;
                            };
                            let mut wire = [0; 255];
                            let mut parts = [&[][..]; 5];
                            let start = if let Some((endpoint, cluster)) = endpoint {
                                parts[0] = endpoint;
                                if let Some(cluster) = cluster {
                                    parts[1] = cluster;
                                    0
                                } else {
                                    parts[1] = endpoint;
                                    1
                                }
                            } else {
                                2
                            };
                            parts[2] = req.service;
                            parts[3] = req.namespace;
                            parts[4] = b"svc";
                            let Some(target) = child(&parts[start..], zone_ref, &mut wire) else {
                                return;
                            };
                            if !scratch.extra.insert((
                                scratch::Name::new(target),
                                scratch::Address::new(ip_text),
                            )) {
                                return;
                            }
                            let result = match ip {
                                IpAddr::V4(ip) => b.record(
                                    Section::Additional,
                                    target,
                                    Type::A,
                                    Class::IN,
                                    self.config.ttl,
                                    &ip.octets(),
                                ),
                                IpAddr::V6(ip) => b.record(
                                    Section::Additional,
                                    target,
                                    Type::AAAA,
                                    Class::IN,
                                    self.config.ttl,
                                    &ip.octets(),
                                ),
                            };
                            match result {
                                Ok(true) => {}
                                Ok(false) => stopped = true,
                                Err(e) => error = Some(e),
                            }
                        });
                        if let Some(err) = error {
                            return Err(err);
                        }
                    }
                    Ok(())
                })?;
            }
            // RFC 2308 §3: authoritative NXDOMAIN and NODATA responses include the zone SOA.
            if answers == 0 {
                soa(
                    &mut b,
                    Section::Authority,
                    zone_ref,
                    self.config.ttl,
                    store.with_read(|i| {
                        if multicluster {
                            i.multicluster_serial()
                        } else {
                            i.serial()
                        }
                    }),
                )?;
            }
            let _ = b.finish();
            Ok(())
        })();
        result.map_or_else(
            |e| Outcome::Error(pharos_server::Error::Build(e)),
            |()| Outcome::Response,
        )
    }
}

impl pharos_server::Readiness for Kubernetes {
    fn ready(&self) -> bool {
        self.state
            .cache
            .read()
            .unwrap()
            .sync
            .as_ref()
            .is_some_and(|sync| sync.ready())
    }
}

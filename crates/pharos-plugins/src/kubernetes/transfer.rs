use super::*;
use crate::{serial::serial_at_least, transfer::TransferRequest};
use pharos_kubernetes::object::{Endpoints, Port};
use pharos_proto::{FixedBuffer, Rdata};
use pharos_server::{Error, Stream};

#[derive(Default)]
pub(super) struct Notifier {
    transfer: Option<crate::transfer::Transfer>,
    active: bool,
    task: Option<tokio::task::JoinHandle<()>>,
    runtime: Option<tokio::runtime::Handle>,
}

impl Kubernetes {
    /// Bind the transfer Plugin before Startup, or replace it while running.
    pub fn bind_transfer(&self, transfer: Option<&crate::transfer::Transfer>) {
        let cache = self.state.cache.read().unwrap();
        let store = cache.store.clone();
        let sync = cache.sync.clone();
        drop(cache);
        let mut notifier = self.state.notifier.lock().unwrap();
        notifier.transfer = transfer.cloned();
        if let Some(task) = notifier.task.take() {
            task.abort();
        }
        if notifier.active {
            spawn_watcher(
                &mut notifier,
                store.as_ref(),
                sync.as_ref(),
                &self.zones,
                &self.multicluster_zones,
            );
        }
    }
}

fn spawn_watcher(
    notifier: &mut Notifier,
    store: Option<&Store>,
    sync: Option<&Arc<dyn pharos_server::Readiness>>,
    zones: &[Name],
    multi: &[Name],
) {
    let (Some(transfer), Some(store), Some(sync), Some(runtime)) =
        (&notifier.transfer, store, sync, &notifier.runtime)
    else {
        return;
    };
    let receiver = store.subscribe_changes();
    notifier.task = Some(runtime.spawn(watch_changes(
        receiver,
        transfer.clone(),
        zones.to_vec(),
        multi.to_vec(),
        sync.clone(),
    )));
}

pub(super) fn start(state: &State, zones: &[Name], multi: &[Name]) {
    let cache = state.cache.read().unwrap();
    let store = cache.store.clone();
    let sync = cache.sync.clone();
    drop(cache);
    let mut notifier = state.notifier.lock().unwrap();
    if let Some(task) = notifier.task.take() {
        task.abort();
    }
    notifier.active = true;
    notifier.runtime = Some(tokio::runtime::Handle::current());
    spawn_watcher(&mut notifier, store.as_ref(), sync.as_ref(), zones, multi);
}

pub(super) fn stop(state: &State) {
    let mut notifier = state.notifier.lock().unwrap();
    notifier.active = false;
    if let Some(task) = notifier.task.take() {
        task.abort();
    }
    notifier.runtime = None;
}

async fn watch_changes(
    mut changes: tokio::sync::watch::Receiver<pharos_kubernetes::store::Changes>,
    transfer: crate::transfer::Transfer,
    zones: Vec<Name>,
    multi: Vec<Name>,
    sync: Arc<dyn pharos_server::Readiness>,
) {
    while !sync.ready() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let mut previous = *changes.borrow_and_update();
    // RFC 1996 §4.1: send an initial SOA NOTIFY after startup.
    for zone in &zones {
        notify(&transfer, zone).await;
    }
    loop {
        if changes.changed().await.is_err() {
            break;
        }
        let current = *changes.borrow_and_update();
        let internal_changed = current.internal != previous.internal;
        let multi_changed = current.multicluster != previous.multicluster;
        previous = current;
        for zone in &zones {
            let Ok(zone_ref) = NameRef::parse(zone.as_wire(), 0) else {
                continue;
            };
            if internal_changed
                || multi_changed && multi.iter().any(|parent| contains(zone_ref, parent))
            {
                // RFC 1996 §3.1: notify Secondary Servers when authoritative Zone data changes.
                notify(&transfer, zone).await;
            }
        }
    }
}

async fn notify(transfer: &crate::transfer::Transfer, zone: &Name) {
    if let Err(error) = transfer.notify(zone).await {
        pharos_server::logging::log("ERROR", "kubernetes", &format!("NOTIFY {zone}: {error}"));
    }
}

// Each snapshot is encoded twice under the same read lock: first to size one
// allocation, then to fill it. Individual records never allocate.
struct Snapshot<'a> {
    zone: NameRef<'a>,
    id: u16,
    flags: u16,
    protocol: Protocol,
    authoritative: bool,
    qtype: Type,
    qclass: Class,
    ttl: u32,
    pod_names: bool,
    bytes: Option<Vec<u8>>,
    size: usize,
}

impl Snapshot<'_> {
    fn record(
        &mut self,
        owner: NameRef<'_>,
        kind: Type,
        ttl: u32,
        write: impl FnOnce(
            &mut pharos_proto::RdataWriter<'_, '_, FixedBuffer<'_>>,
        ) -> Result<(), BuildError>,
    ) -> Result<(), Error> {
        let mut scratch = [0; 1024];
        let mut wire = FixedBuffer::new(&mut scratch);
        // RFC 5936 §2.2: AXFR Messages are authoritative and echo the Question.
        // RFC 5936 §2: Normal AXFR Messages leave TC clear.
        let mut builder = MessageBuilder::new(
            &mut wire,
            1024,
            self.id,
            // RFC 5936 §2.2.1: response CD is always zero.
            0x8000 | if self.authoritative { 0x0400 } else { 0 } | (self.flags & 0x0100),
        )
        .map_err(Error::Build)?;
        if !builder
            .question(self.zone, self.qtype, self.qclass)
            .map_err(Error::Build)?
            || !builder
                .record_with(Section::Answer, owner, kind, Class::IN, ttl, write)
                .map_err(Error::Build)?
        {
            return Err(Error::ResponseBufferTooSmall);
        }
        let wire = builder.finish();
        self.size = self
            .size
            .checked_add(wire.len() + 2)
            .ok_or(Error::ResponseBufferTooSmall)?;
        if let Some(bytes) = &mut self.bytes {
            bytes.extend_from_slice(&(wire.len() as u16).to_be_bytes());
            bytes.extend_from_slice(wire);
        }
        Ok(())
    }

    fn soa(&mut self, serial: u32) -> Result<(), Error> {
        let mut ns_wire = [0; 255];
        let mut host_wire = [0; 255];
        let ns = child(&[b"ns", b"dns"], self.zone, &mut ns_wire)
            .ok_or(Error::Build(BuildError::InvalidRdata))?;
        let host = child(&[b"hostmaster"], self.zone, &mut host_wire)
            .ok_or(Error::Build(BuildError::InvalidRdata))?;
        let ttl = self.ttl;
        // RFC 1035 §3.3.13: SOA fields match the Kubernetes authority Response.
        self.record(self.zone, Type::SOA, ttl.min(300), |w| {
            w.write_name(ns)?;
            w.write_name(host)?;
            for number in [serial, 7200, 1800, 86400, ttl] {
                w.write_bytes(&number.to_be_bytes())?;
            }
            Ok(())
        })
    }

    fn address(&mut self, owner: NameRef<'_>, ip: &str) -> Result<bool, Error> {
        self.address_with_ttl(owner, ip, self.ttl)
    }

    // KEP-563 §CoreDNS Operation: Encode service and endpoint addresses by IP family.
    fn address_with_ttl(&mut self, owner: NameRef<'_>, ip: &str, ttl: u32) -> Result<bool, Error> {
        let Ok(ip) = ip.parse::<IpAddr>() else {
            return Ok(false);
        };
        let ip = match ip {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
            ip => ip,
        };
        // RFC 1035 §3.4.1 and RFC 3596 §2.2: address RDATA is in network byte order.
        match ip {
            IpAddr::V4(ip) => self.record(owner, Type::A, ttl, |w| w.write_bytes(&ip.octets()))?,
            IpAddr::V6(ip) => {
                self.record(owner, Type::AAAA, ttl, |w| w.write_bytes(&ip.octets()))?
            }
        }
        Ok(true)
    }

    fn srv(
        &mut self,
        owner: NameRef<'_>,
        target: NameRef<'_>,
        port: i32,
        weight: u16,
    ) -> Result<(), Error> {
        // RFC 2782 §The format of the SRV RR: SRV RDATA has priority, weight, port, and target.
        self.record(owner, Type::SRV, self.ttl, |w| {
            w.write_bytes(&0u16.to_be_bytes())?;
            w.write_bytes(&weight.to_be_bytes())?;
            w.write_bytes(&(port as u16).to_be_bytes())?;
            w.write_uncompressed_name(target)
        })
    }

    // Kubernetes DNS spec 1.1.0 §2.4.2: Headless SRV records use named endpoint ports.
    fn ports(
        &mut self,
        base: NameRef<'_>,
        target: NameRef<'_>,
        ports: &[Port],
        weight: u16,
        base_srv: bool,
    ) -> Result<(), Error> {
        for port in ports {
            // Kubernetes DNS spec 1.1.0 §2.3.2 and KEP-752: unnamed and nil ports have no SRV.
            if !port.has_srv() {
                continue;
            }
            if base_srv {
                self.srv(base, target, port.port, weight)?;
            }
            let mut name = [0; 64];
            let mut protocol = [0; 64];
            if port.name.len() >= 63 || port.protocol.len() >= 63 {
                continue;
            }
            // RFC 2782 §The format of the SRV RR: Service and Proto labels use lowercase and _.
            name[0] = b'_';
            protocol[0] = b'_';
            for (out, b) in name[1..].iter_mut().zip(port.name.bytes()) {
                *out = b.to_ascii_lowercase();
            }
            for (out, b) in protocol[1..].iter_mut().zip(port.protocol.bytes()) {
                *out = b.to_ascii_lowercase();
            }
            let mut wire = [0; 255];
            if let Some(owner) = child(
                &[
                    &name[..port.name.len() + 1],
                    &protocol[..port.protocol.len() + 1],
                ],
                base,
                &mut wire,
            ) {
                self.srv(owner, target, port.port, weight)?;
            }
        }
        Ok(())
    }

    // KEP-752 §Proposal > EndpointSlice API: SRV ports come from EndpointSlice ports.
    fn endpoints(
        &mut self,
        base: NameRef<'_>,
        endpoints: &Endpoints,
        pod_names: bool,
        tolerate_unready: bool,
        cluster_id: Option<&str>,
    ) -> Result<(), Error> {
        // Kubernetes DNS spec 1.1.0 §2.1: only DNS-eligible endpoints contribute to transfer data.
        let weight = (100
            / endpoints
                .addresses
                .iter()
                .filter(|address| address.dns_eligible(tolerate_unready))
                .count()
                .max(1))
        .max(1) as u16;
        for addr in &endpoints.addresses {
            if !addr.dns_eligible(tolerate_unready) {
                continue;
            }
            self.address(base, &addr.ip)?;
            let mut label_buf = [0; 64];
            let label = endpoint_label(addr, pod_names, &mut label_buf);
            let mut wire = [0; 255];
            if let Some(target) = endpoint_name(label, cluster_id, base, &mut wire) {
                let valid = self.address(target, &addr.ip)?;
                let root = NameRef::parse(&[0], 0).map_err(|_| Error::InvalidQuery)?;
                self.ports(
                    base,
                    if valid { target } else { root },
                    &endpoints.ports,
                    weight,
                    false,
                )?;
            }
        }
        Ok(())
    }

    // Kubernetes DNS spec 1.1.0 §2.3.1: ClusterIP transfers include service addresses.
    fn service(
        &mut self,
        index: &Index,
        namespace: &str,
        name: &str,
        ips: &[String],
        ports: &[Port],
        multi: bool,
    ) -> Result<(), Error> {
        let mut wire = [0; 255];
        let Some(base) = child(
            &[name.as_bytes(), namespace.as_bytes(), b"svc"],
            self.zone,
            &mut wire,
        ) else {
            return Ok(());
        };
        if ips.first().is_some_and(|ip| ip.parse::<IpAddr>().is_ok()) {
            let mut valid = false;
            for ip in ips {
                valid = self.address(base, ip)?;
            }
            let root = NameRef::parse(&[0], 0).map_err(|_| Error::InvalidQuery)?;
            self.ports(base, if valid { base } else { root }, ports, 100, true)?;
        } else if multi {
            for ep in index.multicluster_endpoints(namespace, name) {
                self.endpoints(
                    base,
                    &ep.endpoints,
                    self.pod_names,
                    false,
                    Some(&ep.cluster_id),
                )?;
            }
        } else {
            let tolerate_unready = index
                .service(namespace, name)
                .is_some_and(|service| service.tolerate_unready_endpoints);
            for ep in index.endpoints(namespace, name) {
                self.endpoints(base, ep, self.pod_names, tolerate_unready, None)?;
            }
        }
        Ok(())
    }
}

fn endpoint_name<'a>(
    label: &[u8],
    cluster_id: Option<&str>,
    base: NameRef<'_>,
    wire: &'a mut [u8; 255],
) -> Option<NameRef<'a>> {
    if let Some(cluster_id) = cluster_id {
        // KEP-1645 §2.4.1: encode each source-cluster ID label as a separate DNS label.
        let (first, second) = super::cluster_id_parts(cluster_id.as_bytes())?;
        if let Some(second) = second {
            child(&[label, first, second], base, wire)
        } else {
            child(&[label, first], base, wire)
        }
    } else {
        child(&[label], base, wire)
    }
}

fn generate(
    snapshot: &mut Snapshot<'_>,
    index: &Index,
    plugin: &Kubernetes,
    serial: u32,
    current: u32,
    multi: bool,
) -> Result<(), Error> {
    // RFC 5936 §2.2 and RFC 1995 §2: AXFR is SOA-bracketed; equal or newer IXFR returns one SOA.
    let soa_only = snapshot.qtype == Type::IXFR
        && (snapshot.protocol == Protocol::Udp || serial_at_least(serial, current));
    if soa_only && snapshot.protocol == Protocol::Tcp {
        snapshot.authoritative = false;
    }
    snapshot.soa(current)?;
    // RFC 1995 §2: UDP IXFR returns the current SOA to trigger TCP fallback.
    if soa_only {
        return Ok(());
    }

    let mut n = 0usize;
    let mut err = None;
    visit_ns(
        index,
        &plugin.local_ips,
        snapshot.zone,
        &plugin.config,
        |name, _| {
            let mut previous = 0usize;
            let mut seen = false;
            visit_ns(
                index,
                &plugin.local_ips,
                snapshot.zone,
                &plugin.config,
                |other, _| {
                    if previous < n && other == name {
                        seen = true;
                    }
                    previous += 1;
                },
            );
            n += 1;
            if !seen && err.is_none() {
                err = snapshot
                    .record(snapshot.zone, Type::NS, snapshot.ttl, |w| {
                        w.write_name(name)
                    })
                    .err();
            }
        },
    );
    if let Some(err) = err {
        return Err(err);
    }
    let mut err = None;
    visit_ns(
        index,
        &plugin.local_ips,
        snapshot.zone,
        &plugin.config,
        |name, ip| {
            if err.is_none() {
                err = snapshot
                    .address_with_ttl(name, scratch::IpText::new(ip).as_str(), 0)
                    .err();
            }
        },
    );
    if let Some(err) = err {
        return Err(err);
    }

    // RFC 1035 §3.5 and RFC 3596 §2.5: reverse zones end in in-addr.arpa or ip6.arpa.
    let label_count = snapshot.zone.labels().count();
    let mut suffix = snapshot.zone.labels().skip(label_count.saturating_sub(2));
    let is_reverse_zone = suffix.next().is_some_and(|label| {
        label.eq_ignore_ascii_case(b"in-addr") || label.eq_ignore_ascii_case(b"ip6")
    }) && suffix
        .next()
        .is_some_and(|label| label.eq_ignore_ascii_case(b"arpa"));
    if !is_reverse_zone {
        // Kubernetes DNS spec 1.1.0 §2.2: forward transfers include dns-version TXT.
        let mut version_wire = [0; 255];
        if let Some(owner) = child(&[b"dns-version"], snapshot.zone, &mut version_wire) {
            snapshot.record(owner, Type::TXT, 28800, |w| w.write_bytes(b"\x051.1.0"))?;
        }
    }

    if multi {
        for service in index.service_imports() {
            if index.namespace(&service.namespace).is_some() {
                snapshot.service(
                    index,
                    &service.namespace,
                    &service.name,
                    &service.cluster_ips,
                    &service.ports,
                    true,
                )?;
            }
        }
    } else {
        for service in index.services() {
            if index.namespace(&service.namespace).is_none() {
                continue;
            }
            if service.service_type.as_ref() == "ExternalName" {
                if service.external_name.parse::<IpAddr>().is_ok() {
                    continue;
                }
                let Some(target) = index.external_name(&service.namespace, &service.name) else {
                    continue;
                };
                let target =
                    NameRef::parse(target.as_wire(), 0).map_err(|_| Error::InvalidQuery)?;
                let mut wire = [0; 255];
                if let Some(base) = child(
                    &[
                        service.name.as_bytes(),
                        service.namespace.as_bytes(),
                        b"svc",
                    ],
                    snapshot.zone,
                    &mut wire,
                ) {
                    // RFC 1034 §3.6.2: ExternalName is represented by a CNAME.
                    // Kubernetes DNS spec 1.1.0 §2.5: ExternalName transfers use CNAME records.
                    snapshot.record(base, Type::CNAME, snapshot.ttl, |w| w.write_name(target))?;
                }
            } else if matches!(
                service.service_type.as_ref(),
                "ClusterIP" | "NodePort" | "LoadBalancer"
            ) {
                snapshot.service(
                    index,
                    &service.namespace,
                    &service.name,
                    &service.cluster_ips,
                    &service.ports,
                    false,
                )?;
            }
        }
    }
    snapshot.soa(current)
}

impl crate::transfer::Transferer for Kubernetes {
    fn bind_transfer(&self, transfer: Option<&crate::transfer::Transfer>) {
        Kubernetes::bind_transfer(self, transfer);
    }

    fn transfer(&self, request: TransferRequest<'_>) -> Result<Option<Stream>, Error> {
        let TransferRequest {
            zone,
            serial,
            id,
            flags,
            protocol,
            qtype,
            qclass,
        } = request;
        // RFC 1035 §3.7.1: this transfer contains only Internet-class records.
        if qclass != Class::IN {
            return Ok(None);
        }
        let zone_ref = zone;
        if !self.zones.iter().any(|z| contains(zone_ref, z)) {
            return Ok(None);
        }
        let multi = self
            .multicluster_zones
            .iter()
            .any(|z| contains(zone_ref, z));
        let store = self
            .state
            .cache
            .read()
            .unwrap()
            .store
            .clone()
            .unwrap_or_else(|| self.state.empty_store.clone());
        // RFC 5936 §3: Encode records from one immutable Store snapshot.
        let bytes = store.with_read(|index| {
            // CoreDNS xfr.go calls SOA with an empty request, selecting the internal serial.
            let current = index.serial();
            let mut snapshot = Snapshot {
                zone: zone_ref,
                id,
                flags,
                protocol,
                authoritative: true,
                qtype,
                qclass,
                ttl: self.config.ttl,
                pod_names: self.config.endpoint_pod_names,
                bytes: None,
                size: 0,
            };
            generate(&mut snapshot, index, self, serial, current, multi)?;
            // shortcut: snapshot the whole Zone synchronously; stream incrementally when the store retains immutable snapshots.
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(snapshot.size)
                .map_err(|_| Error::ResponseBufferTooSmall)?;
            snapshot.bytes = Some(bytes);
            snapshot.size = 0;
            generate(&mut snapshot, index, self, serial, current, multi)?;
            snapshot.bytes.ok_or(Error::InvalidQuery)
        })?;
        Ok(Some(stream_snapshot(bytes)))
    }
}

fn stream_snapshot(bytes: Vec<u8>) -> Stream {
    let mut offset = 0;
    Stream::new(move |response| {
        if offset == bytes.len() {
            return Ok(false);
        }
        if offset == 0 && response.capacity() < 65535 {
            // RFC 8945 §5.3: leave room for Listener-applied TSIG.
            response.reserve(65535 - response.len());
        }
        let len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        let first = Message::parse(&bytes[offset + 2..offset + 2 + len])
            .map_err(|_| Error::InvalidQuery)?;
        let question = first.questions().next().ok_or(Error::InvalidQuery)?;
        let mut builder = MessageBuilder::new(response, 64500, first.id(), first.flags())
            .map_err(Error::Build)?;
        if !builder
            .question(question.name, question.qtype, question.qclass)
            .map_err(Error::Build)?
        {
            return Err(Error::ResponseBufferTooSmall);
        }
        let mut batch_size = 0;
        while offset < bytes.len() {
            let len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            let message = Message::parse(&bytes[offset + 2..offset + 2 + len])
                .map_err(|_| Error::InvalidQuery)?;
            let record = message.answers().next().ok_or(Error::InvalidQuery)?;
            let data = record.data().map_err(|_| Error::InvalidQuery)?;
            let size = transfer_record_len(record.name, &data)?;
            if batch_size > 0 && batch_size + size > 63000 {
                break;
            }
            if !builder
                .record_with(
                    Section::Answer,
                    record.name,
                    record.rtype,
                    record.class,
                    record.ttl,
                    |writer| data.write(writer),
                )
                .map_err(Error::Build)?
            {
                return Err(Error::ResponseBufferTooSmall);
            }
            batch_size += size;
            offset += len + 2;
        }
        let _ = builder.finish();
        Ok(true)
    })
}

fn transfer_record_len(owner: NameRef<'_>, data: &Rdata<'_>) -> Result<usize, Error> {
    let name_len =
        |name: NameRef<'_>| 1 + name.labels().map(|label| label.len() + 1).sum::<usize>();
    let data_len = match data {
        Rdata::A(_) => 4,
        Rdata::Aaaa(_) => 16,
        // RFC 1035 §3.3.14: TXT RDATA is a sequence of wire character-strings.
        Rdata::Txt(bytes) => bytes.len(),
        Rdata::Ns(name) | Rdata::Cname(name) => name_len(*name),
        Rdata::Soa { mname, rname, .. } => name_len(*mname) + name_len(*rname) + 20,
        Rdata::Srv { target, .. } => 6 + name_len(*target),
        _ => return Err(Error::InvalidQuery),
    };
    Ok(name_len(owner) + 10 + data_len)
}

#[cfg(test)]
mod tests;

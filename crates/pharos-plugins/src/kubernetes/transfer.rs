use super::*;
use crate::transfer::TransferRequest;
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
        let mut builder = MessageBuilder::new(
            &mut wire,
            1024,
            self.id,
            0x8000 | if self.authoritative { 0x0400 } else { 0 } | (self.flags & 0x0110),
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
        // RFC 2782 §3: SRV RDATA is priority, weight, port, and uncompressed target.
        self.record(owner, Type::SRV, self.ttl, |w| {
            w.write_bytes(&0u16.to_be_bytes())?;
            w.write_bytes(&weight.to_be_bytes())?;
            w.write_bytes(&(port as u16).to_be_bytes())?;
            w.write_uncompressed_name(target)
        })
    }

    fn ports(
        &mut self,
        base: NameRef<'_>,
        target: NameRef<'_>,
        ports: &[Port],
        weight: u16,
        base_srv: bool,
    ) -> Result<(), Error> {
        for port in ports {
            if base_srv {
                self.srv(base, target, port.port, weight)?;
            }
            if port.name.is_empty() {
                continue;
            }
            let mut name = [0; 64];
            let mut protocol = [0; 64];
            if port.name.len() >= 63 || port.protocol.len() >= 63 {
                continue;
            }
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

    fn endpoints(
        &mut self,
        base: NameRef<'_>,
        endpoints: &Endpoints,
        pod_names: bool,
    ) -> Result<(), Error> {
        let weight = (100 / endpoints.addresses.len().max(1)).max(1) as u16;
        for addr in &endpoints.addresses {
            self.address(base, &addr.ip)?;
            let mut label_buf = [0; 64];
            let label = endpoint_label(addr, pod_names, &mut label_buf);
            let mut wire = [0; 255];
            if let Some(target) = child(&[label], base, &mut wire) {
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
                self.endpoints(base, &ep.endpoints, self.pod_names)?;
            }
        } else {
            for ep in index.endpoints(namespace, name) {
                self.endpoints(base, ep, self.pod_names)?;
            }
        }
        Ok(())
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
    // RFC 5936 §2.2 and RFC 1995 §2: an AXFR is bracketed by SOA; a current IXFR has one SOA.
    if serial != 0 && serial == current && snapshot.protocol == Protocol::Tcp {
        snapshot.authoritative = false;
    }
    snapshot.soa(current)?;
    // RFC 1995 §2: UDP IXFR returns the current SOA to trigger TCP fallback.
    if serial != 0 && serial == current
        || snapshot.qtype == Type::IXFR && snapshot.protocol == Protocol::Udp
    {
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
            if service.service_type == "ExternalName" {
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
                    snapshot.record(base, Type::CNAME, snapshot.ttl, |w| w.write_name(target))?;
                }
            } else if matches!(
                service.service_type.as_str(),
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
        Rdata::Ns(name) | Rdata::Cname(name) => name_len(*name),
        Rdata::Soa { mname, rname, .. } => name_len(*mname) + name_len(*rname) + 20,
        Rdata::Srv { target, .. } => 6 + name_len(*target),
        _ => return Err(Error::InvalidQuery),
    };
    Ok(name_len(owner) + 10 + data_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::Transferer;
    use pharos_kubernetes::object::{EndpointAddress, Endpoints, Port};
    use pharos_proto::Rdata;

    struct Ready;
    impl pharos_server::Readiness for Ready {
        fn ready(&self) -> bool {
            true
        }
    }

    fn plugin() -> Kubernetes {
        let blocks =
            pharos_corefile::parse("Corefile", ".:53 {\n kubernetes cluster.local\n}").unwrap();
        let config = setup::parse(
            &mut pharos_corefile::Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
            &["."],
        )
        .unwrap();
        let mut plugin = Kubernetes::new(config).unwrap();
        plugin.local_ips = vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        plugin
    }

    fn answers(mut stream: pharos_server::Stream) -> Vec<(String, Type)> {
        let mut wire = Vec::new();
        let mut records = Vec::new();
        while stream.next(&mut wire).unwrap() {
            let msg = Message::parse(&wire).unwrap();
            assert_eq!(msg.id(), 42);
            records.extend(msg.answers().map(|rr| (rr.name.to_string(), rr.rtype)));
        }
        records
    }

    fn request(zone: &Name, flags: u16) -> TransferRequest<'_> {
        TransferRequest {
            zone: NameRef::parse(zone.as_wire(), 0).unwrap(),
            serial: 0,
            id: 42,
            flags,
            protocol: Protocol::Tcp,
            qtype: Type::AXFR,
            qclass: Class::IN,
        }
    }

    #[test]
    fn axfr_frames_zone_with_soa_and_source_ns() {
        let plugin = plugin();
        let zone: Name = "cluster.local.".parse().unwrap();
        let stream = plugin.transfer(request(&zone, 0)).unwrap().unwrap();
        assert_eq!(
            answers(stream),
            [
                ("cluster.local.".into(), Type::SOA),
                ("cluster.local.".into(), Type::NS),
                ("ns.dns.cluster.local.".into(), Type::A),
                ("ns.dns.cluster.local.".into(), Type::AAAA),
                ("cluster.local.".into(), Type::SOA),
            ]
        );
    }

    #[test]
    fn small_zone_is_batched_into_one_message() {
        let plugin = plugin();
        let zone: Name = "cluster.local.".parse().unwrap();
        let mut stream = plugin.transfer(request(&zone, 0x0100)).unwrap().unwrap();
        let mut wire = Vec::new();
        assert!(stream.next(&mut wire).unwrap());
        assert_eq!(Message::parse(&wire).unwrap().answer_count(), 5);
        assert_eq!(Message::parse(&wire).unwrap().flags(), 0x8500);
        assert!(!stream.next(&mut wire).unwrap());
    }

    #[test]
    fn large_zone_spans_bounded_messages_without_losing_records() {
        let zone: Name = "cluster.local.".parse().unwrap();
        let mut snapshot = snapshot(&zone);
        snapshot.soa(1).unwrap();
        for _ in 0..4000 {
            snapshot
                .address(NameRef::parse(zone.as_wire(), 0).unwrap(), "192.0.2.1")
                .unwrap();
        }
        snapshot.soa(1).unwrap();
        let mut stream = stream_snapshot(snapshot.bytes.unwrap());
        let mut wire = Vec::new();
        let mut count = 0;
        let mut messages = 0;
        while stream.next(&mut wire).unwrap() {
            assert!(wire.len() <= 64500);
            count += Message::parse(&wire).unwrap().answer_count() as usize;
            messages += 1;
        }
        assert_eq!(count, 4002);
        assert!(messages > 1);
    }

    #[test]
    fn source_ns_addresses_have_coredns_zero_ttl() {
        let plugin = plugin();
        let zone: Name = "cluster.local.".parse().unwrap();
        let mut stream = plugin.transfer(request(&zone, 0)).unwrap().unwrap();
        let mut wire = Vec::new();
        while stream.next(&mut wire).unwrap() {
            let message = Message::parse(&wire).unwrap();
            for rr in message.answers() {
                if matches!(rr.rtype, Type::A | Type::AAAA) {
                    assert_eq!(rr.ttl, 0);
                }
            }
        }
    }

    #[test]
    fn transfer_outside_zone_returns_none() {
        let zone: Name = "elsewhere.".parse().unwrap();
        assert!(plugin().transfer(request(&zone, 0)).unwrap().is_none());
    }

    fn snapshot(zone: &Name) -> Snapshot<'_> {
        Snapshot {
            zone: NameRef::parse(zone.as_wire(), 0).unwrap(),
            id: 42,
            flags: 0,
            protocol: Protocol::Tcp,
            authoritative: true,
            qtype: Type::AXFR,
            qclass: Class::IN,
            ttl: 5,
            pod_names: false,
            bytes: Some(Vec::new()),
            size: 0,
        }
    }

    fn messages(bytes: &[u8]) -> Vec<&[u8]> {
        let mut messages = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            messages.push(&rest[2..2 + len]);
            rest = &rest[2 + len..];
        }
        messages
    }

    #[test]
    fn cluster_service_transfers_addresses_and_named_and_unnamed_srv() {
        let zone: Name = "cluster.local.".parse().unwrap();
        let mut snapshot = snapshot(&zone);
        let ports = [
            Port {
                name: "HTTP".into(),
                protocol: "TCP".into(),
                port: 8080,
            },
            Port {
                name: "".into(),
                protocol: "TCP".into(),
                port: 53,
            },
        ];
        snapshot
            .service(
                &Index::default(),
                "prod",
                "web",
                &["10.0.0.1".into(), "2001:db8::1".into()],
                &ports,
                false,
            )
            .unwrap();
        let bytes = snapshot.bytes.unwrap();
        let messages = messages(&bytes);
        let records: Vec<_> = messages
            .iter()
            .map(|wire| Message::parse(wire).unwrap().answers().next().unwrap())
            .collect();
        assert_eq!(
            records.iter().map(|rr| rr.rtype).collect::<Vec<_>>(),
            [Type::A, Type::AAAA, Type::SRV, Type::SRV, Type::SRV]
        );
        assert_eq!(
            records[3].name.to_string(),
            "_http._tcp.web.prod.svc.cluster.local."
        );
        assert!(
            matches!(records[3].data().unwrap(), Rdata::Srv { weight: 100, port: 8080, target, .. } if target.to_string() == "web.prod.svc.cluster.local.")
        );
        assert!(matches!(
            records[4].data().unwrap(),
            Rdata::Srv {
                weight: 100,
                port: 53,
                ..
            }
        ));
    }

    // CoreDNS's Kubernetes controller represents a Service with no ports by port -1.
    #[test]
    fn service_without_ports_transfers_coredns_sentinel_srv() {
        let zone: Name = "cluster.local.".parse().unwrap();
        let mut snapshot = snapshot(&zone);
        snapshot
            .service(
                &Index::default(),
                "prod",
                "web",
                &["10.0.0.1".into()],
                &[Port {
                    name: String::new(),
                    protocol: String::new(),
                    port: -1,
                }],
                false,
            )
            .unwrap();
        let bytes = snapshot.bytes.unwrap();
        let messages = messages(&bytes);
        assert_eq!(messages.len(), 2);
        assert_eq!(
            Message::parse(messages[0])
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rtype,
            Type::A
        );
        assert!(matches!(
            Message::parse(messages[1])
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .data()
                .unwrap(),
            Rdata::Srv { port: 65535, .. }
        ));
    }

    #[test]
    fn headless_endpoints_transfer_hostnames_and_weighted_srv() {
        let zone: Name = "cluster.local.".parse().unwrap();
        let base_name: Name = "web.prod.svc.cluster.local.".parse().unwrap();
        let base = NameRef::parse(base_name.as_wire(), 0).unwrap();
        let mut snapshot = snapshot(&zone);
        let endpoints = Endpoints {
            version: "1".into(),
            name: "slice".into(),
            namespace: "prod".into(),
            service_name: "web".into(),
            addresses: ["10.0.0.1", "10.0.0.2"]
                .into_iter()
                .enumerate()
                .map(|(i, ip)| EndpointAddress {
                    ip: ip.into(),
                    hostname: format!("node{i}"),
                    node_name: String::new(),
                    target_ref_name: String::new(),
                })
                .collect(),
            ports: vec![Port {
                name: "http".into(),
                protocol: "TCP".into(),
                port: 80,
            }],
            zones: None,
        };
        snapshot.endpoints(base, &endpoints, false).unwrap();
        let bytes = snapshot.bytes.unwrap();
        let messages = messages(&bytes);
        let records: Vec<_> = messages
            .iter()
            .map(|wire| Message::parse(wire).unwrap().answers().next().unwrap())
            .collect();
        assert_eq!(records.len(), 6);
        assert_eq!(
            records[1].name.to_string(),
            "node0.web.prod.svc.cluster.local."
        );
        assert_eq!(
            records[2].name.to_string(),
            "_http._tcp.web.prod.svc.cluster.local."
        );
        assert!(
            matches!(records[2].data().unwrap(), Rdata::Srv { weight: 50, port: 80, target, .. } if target.to_string() == "node0.web.prod.svc.cluster.local.")
        );
    }

    #[test]
    fn current_ixfr_has_one_soa_with_unchanged_fields() {
        let zone: Name = "cluster.local.".parse().unwrap();
        let mut snapshot = snapshot(&zone);
        snapshot.qtype = Type::IXFR;
        generate(&mut snapshot, &Index::default(), &plugin(), 123, 123, false).unwrap();
        let bytes = snapshot.bytes.unwrap();
        let messages = messages(&bytes);
        assert_eq!(messages.len(), 1);
        let message = Message::parse(messages[0]).unwrap();
        assert_eq!(message.flags() & 0x0400, 0);
        let rr = message.answers().next().unwrap();
        assert_eq!(rr.ttl, 5);
        assert!(matches!(
            rr.data().unwrap(),
            Rdata::Soa {
                serial: 123,
                refresh: 7200,
                retry: 1800,
                expire: 86400,
                minimum: 5,
                ..
            }
        ));
    }

    #[test]
    fn current_udp_ixfr_keeps_authoritative_flag() {
        let zone: Name = "cluster.local.".parse().unwrap();
        let mut snapshot = snapshot(&zone);
        snapshot.qtype = Type::IXFR;
        snapshot.protocol = Protocol::Udp;
        generate(&mut snapshot, &Index::default(), &plugin(), 123, 123, false).unwrap();
        let bytes = snapshot.bytes.unwrap();
        let messages = messages(&bytes);
        assert_ne!(Message::parse(messages[0]).unwrap().flags() & 0x0400, 0);
    }

    #[test]
    fn outdated_udp_ixfr_snapshots_only_current_soa() {
        let zone: Name = "cluster.local.".parse().unwrap();
        let mut snapshot = snapshot(&zone);
        snapshot.qtype = Type::IXFR;
        snapshot.protocol = Protocol::Udp;
        generate(&mut snapshot, &Index::default(), &plugin(), 1, 123, false).unwrap();
        let bytes = snapshot.bytes.unwrap();
        let messages = messages(&bytes);
        assert_eq!(messages.len(), 1);
        assert_eq!(
            Message::parse(messages[0])
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rtype,
            Type::SOA
        );
    }

    #[tokio::test]
    async fn initial_notify_waits_for_first_sync_even_for_empty_zone() {
        use crate::transfer::{Destination, Transfer, TransferZone};
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Sync(AtomicBool);
        impl pharos_server::Readiness for Sync {
            fn ready(&self) -> bool {
                self.0.load(Ordering::Acquire)
            }
        }
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transfer = Transfer {
            zones: vec![TransferZone {
                domains: vec![".".parse().unwrap()],
                destinations: vec![Destination::Address {
                    host: "127.0.0.1".into(),
                    port: socket.local_addr().unwrap().port().to_string(),
                }],
                source: None,
            }],
        };
        let sync = Arc::new(Sync(AtomicBool::new(false)));
        let (send, receive) =
            tokio::sync::watch::channel(pharos_kubernetes::store::Changes::default());
        let task = tokio::spawn(watch_changes(
            receive,
            transfer,
            vec!["cluster.local.".parse().unwrap()],
            vec![],
            sync.clone(),
        ));
        send.send_modify(|value| value.internal += 1);
        let mut wire = [0; 512];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(80),
                socket.recv_from(&mut wire)
            )
            .await
            .is_err()
        );
        sync.0.store(true, Ordering::Release);
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut wire),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            Message::parse(&wire[..len])
                .unwrap()
                .questions()
                .next()
                .unwrap()
                .name
                .to_string(),
            "cluster.local."
        );
        wire[2] |= 0x80;
        socket.send_to(&wire[..len], from).await.unwrap();
        drop(send);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn change_watcher_notifies_affected_zones_and_stops() {
        use crate::transfer::{Destination, Transfer, TransferZone};
        use pharos_kubernetes::store::Changes;
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transfer = Transfer {
            zones: vec![TransferZone {
                domains: vec![".".parse().unwrap()],
                destinations: vec![Destination::Address {
                    host: "127.0.0.1".into(),
                    port: socket.local_addr().unwrap().port().to_string(),
                }],
                source: None,
            }],
        };
        let zones: Vec<Name> = ["cluster.local.", "clusterset.local."]
            .map(|z| z.parse().unwrap())
            .into();
        let multi = vec![zones[1].clone()];
        let (send, receive) = tokio::sync::watch::channel(Changes::default());
        let task = tokio::spawn(watch_changes(
            receive,
            transfer,
            zones,
            multi,
            Arc::new(Ready),
        ));
        let mut wire = [0; 512];
        for expected in ["cluster.local.", "clusterset.local."] {
            let (len, from) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                socket.recv_from(&mut wire),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                Message::parse(&wire[..len])
                    .unwrap()
                    .questions()
                    .next()
                    .unwrap()
                    .name
                    .to_string(),
                expected
            );
            wire[2] |= 0x80;
            socket.send_to(&wire[..len], from).await.unwrap();
        }
        send.send_modify(|v| v.multicluster += 1);
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut wire),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            Message::parse(&wire[..len])
                .unwrap()
                .questions()
                .next()
                .unwrap()
                .name
                .to_string(),
            "clusterset.local."
        );
        wire[2] |= 0x80;
        socket.send_to(&wire[..len], from).await.unwrap();
        send.send_modify(|v| v.internal += 1);
        for expected in ["cluster.local.", "clusterset.local."] {
            let (len, from) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                socket.recv_from(&mut wire),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                Message::parse(&wire[..len])
                    .unwrap()
                    .questions()
                    .next()
                    .unwrap()
                    .name
                    .to_string(),
                expected
            );
            wire[2] |= 0x80;
            socket.send_to(&wire[..len], from).await.unwrap();
        }
        task.abort();
        let _ = task.await;
        send.send_modify(|v| v.internal += 1);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                socket.recv_from(&mut wire)
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn notifier_lifecycle_rebinds_and_stops_watcher() {
        let plugin = plugin();
        let transfer = crate::transfer::Transfer { zones: Vec::new() };
        Transferer::bind_transfer(&plugin, Some(&transfer));
        {
            let mut cache = plugin.state.cache.write().unwrap();
            cache.store = Some(Store::default());
            cache.sync = Some(Arc::new(Ready));
        }
        start(&plugin.state, &plugin.zones, &plugin.multicluster_zones);
        assert!(plugin.state.notifier.lock().unwrap().task.is_some());
        Transferer::bind_transfer(&plugin, None);
        assert!(plugin.state.notifier.lock().unwrap().task.is_none());
        Transferer::bind_transfer(&plugin, Some(&transfer));
        assert!(plugin.state.notifier.lock().unwrap().task.is_some());
        stop(&plugin.state);
        let notifier = plugin.state.notifier.lock().unwrap();
        assert!(!notifier.active);
        assert!(notifier.task.is_none());
    }
}

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    net::IpAddr,
};

use super::{External, Zone};
use crate::kubernetes::Kubernetes;
use crate::transfer::{TransferRequest, Transferer};
use pharos_kubernetes::{
    object::{EndpointAddress, Service},
    store::Index,
};
use pharos_proto::{
    BuildError, Class, FixedBuffer, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type,
};
use pharos_server::{Error, Protocol, Stream};

// CoreDNS v1.15.0 plugin/k8s_external/transfer.go and plugin/kubernetes/external.go.
// RFC 1035 §3.1: each label and the whole wire name have fixed maximum lengths.
fn child<'a>(labels: &[&[u8]], base: NameRef<'_>, wire: &'a mut [u8; 255]) -> Option<NameRef<'a>> {
    let mut n = 0;
    for label in labels.iter().copied().chain(base.labels()) {
        if label.is_empty() || label.len() > 63 || n + label.len() + 2 > wire.len() {
            return None;
        }
        wire[n] = label.len() as u8;
        n += 1;
        wire[n..n + label.len()].copy_from_slice(label);
        n += label.len();
    }
    wire[n] = 0;
    NameRef::parse(&wire[..=n], 0).ok()
}

fn hostname<'a>(text: &str, strip: usize, wire: &'a mut [u8; 255]) -> Result<NameRef<'a>, Error> {
    let mut presentation = [0u8; 1024];
    let bytes = text.as_bytes();
    if bytes.len() + 1 > presentation.len() {
        return Err(Error::Build(BuildError::InvalidRdata));
    }
    presentation[..bytes.len()].copy_from_slice(bytes);
    let len = if bytes.last() == Some(&b'.') {
        bytes.len()
    } else {
        presentation[bytes.len()] = b'.';
        bytes.len() + 1
    };
    let text = std::str::from_utf8(&presentation[..len]).map_err(|_| Error::InvalidQuery)?;
    let parsed = Name::parse_absolute_into(text, wire)
        .map_err(|_| Error::Build(BuildError::InvalidRdata))?;
    let name = NameRef::parse(parsed, 0).map_err(|_| Error::InvalidQuery)?;
    let count = name.labels().count();
    if strip == 0 || count <= strip {
        return Ok(name);
    }
    let offset = name.labels().take(strip).map(|label| label.len() + 1).sum();
    NameRef::parse(parsed, offset).map_err(|_| Error::InvalidQuery)
}

use super::lookup::endpoint_label;

fn endpoint_owner<'a>(
    label: &[u8],
    base: NameRef<'_>,
    wire: &'a mut [u8; 255],
) -> Option<NameRef<'a>> {
    if label.is_empty() {
        return child(&[], base, wire);
    }
    let mut prefix_wire = [0; 255];
    let prefix = hostname(std::str::from_utf8(label).ok()?, 0, &mut prefix_wire).ok()?;
    let mut n = 0;
    // RFC 1035 §3.1: concatenate the parsed endpoint labels with the Service name.
    for part in prefix.labels().chain(base.labels()) {
        if n + part.len() + 2 > wire.len() {
            return None;
        }
        wire[n] = part.len() as u8;
        n += 1;
        wire[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    wire[n] = 0;
    NameRef::parse(&wire[..=n], 0).ok()
}

fn normalized_ip(text: &str) -> Option<IpAddr> {
    // RFC 4291 §2.5.5.2: IPv4-mapped addresses contain an IPv4 address in their low 32 bits.
    match text.parse().ok()? {
        IpAddr::V6(ip) => Some(ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4)),
        ip => Some(ip),
    }
}

struct Snapshot<'a> {
    request: TransferRequest<'a>,
    ns: NameRef<'a>,
    host: NameRef<'a>,
    ttl: u32,
    service_ttl: u32,
    authoritative: bool,
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
        let mut b = MessageBuilder::new(
            &mut wire,
            1024,
            self.request.id,
            0x8000 | if self.authoritative { 0x0400 } else { 0 } | (self.request.flags & 0x0110),
        )
        .map_err(Error::Build)?;
        if !b
            .question(self.request.zone, self.request.qtype, self.request.qclass)
            .map_err(Error::Build)?
            || !b
                .record_with(Section::Answer, owner, kind, Class::IN, ttl, write)
                .map_err(Error::Build)?
        {
            return Err(Error::ResponseBufferTooSmall);
        }
        let wire = b.finish();
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
        let (ns, host, ttl) = (self.ns, self.host, self.ttl);
        // RFC 1035 §3.3.13: SOA RDATA contains the primary, mailbox, and timers.
        self.record(self.request.zone, Type::SOA, ttl, |w| {
            w.write_name(ns)?;
            w.write_name(host)?;
            for value in [serial, 7200, 1800, 86400, ttl] {
                w.write_bytes(&value.to_be_bytes())?;
            }
            Ok(())
        })
    }

    fn ip(&mut self, owner: NameRef<'_>, ip: Option<IpAddr>, ttl: u32) -> Result<(), Error> {
        // RFC 1035 §3.4.1 and RFC 3596 §2.2: IP addresses use network byte order.
        match ip {
            Some(IpAddr::V4(ip)) => {
                self.record(owner, Type::A, ttl, |w| w.write_bytes(&ip.octets()))
            }
            Some(IpAddr::V6(ip)) => {
                self.record(owner, Type::AAAA, ttl, |w| w.write_bytes(&ip.octets()))
            }
            None => self.record(owner, Type::AAAA, ttl, |_| Ok(())),
        }
    }

    fn address(&mut self, owner: NameRef<'_>, text: &str) -> Result<(), Error> {
        if let Some(ip) = normalized_ip(text) {
            return self.ip(owner, Some(ip), self.ttl);
        }
        let mut wire = [0; 255];
        let target = hostname(text, 0, &mut wire)?;
        // CoreDNS uses context.Background(), so upstream lookup fails during transfers.
        // RFC 1035 §3.3.1: CNAME RDATA names the canonical target.
        for _ in 0..2 {
            self.record(owner, Type::CNAME, self.service_ttl, |w| {
                w.write_name(target)
            })?;
        }
        Ok(())
    }

    fn srv(
        &mut self,
        owner: NameRef<'_>,
        target: NameRef<'_>,
        port: i32,
        weight: u16,
    ) -> Result<(), Error> {
        // RFC 2782 §3: SRV contains priority, weight, port, and an uncompressed target.
        self.record(owner, Type::SRV, self.service_ttl, |w| {
            w.write_bytes(&0u16.to_be_bytes())?;
            w.write_bytes(&weight.to_be_bytes())?;
            w.write_bytes(&(port as u16).to_be_bytes())?;
            w.write_uncompressed_name(target)
        })
    }
}

fn named_owner<'a>(
    port: &str,
    protocol: &str,
    base: NameRef<'_>,
    wire: &'a mut [u8; 255],
) -> Option<NameRef<'a>> {
    if port.len() >= 63 || protocol.len() >= 63 {
        return None;
    }
    let mut p = [0; 64];
    let mut proto = [0; 64];
    p[0] = b'_';
    proto[0] = b'_';
    for (dst, src) in p[1..].iter_mut().zip(port.bytes()) {
        *dst = src.to_ascii_lowercase();
    }
    for (dst, src) in proto[1..].iter_mut().zip(protocol.bytes()) {
        *dst = src.to_ascii_lowercase();
    }
    child(
        &[&p[..port.len() + 1], &proto[..protocol.len() + 1]],
        base,
        wire,
    )
}

fn weight(count: usize) -> u16 {
    (100 / count.max(1)).max(1) as u16
}

fn non_headless<'a>(
    snapshot: &mut Snapshot<'_>,
    service: &'a Service,
    base: NameRef<'_>,
    seen: &mut HashMap<Seen<'a>, usize>,
) -> Result<(), Error> {
    seen.clear();
    let mut bare_seen = false;
    for ip in &service.external_ips {
        for port in &service.ports {
            snapshot.address(base, ip)?;
            if port.port == -1 {
                continue;
            }
            if !bare_seen {
                let mut target_wire = [0; 255];
                let target = if normalized_ip(ip).is_some() {
                    base
                } else {
                    hostname(ip, 0, &mut target_wire)?
                };
                snapshot.srv(base, target, port.port, 100)?;
                bare_seen = true;
            }
            if seen
                .insert(
                    Seen::Count(CaseInsensitive(&port.name), CaseInsensitive(&port.protocol)),
                    0,
                )
                .is_some()
            {
                continue;
            }
            let mut owner_wire = [0; 255];
            if let Some(owner) = named_owner(&port.name, &port.protocol, base, &mut owner_wire) {
                let mut target_wire = [0; 255];
                let target = if normalized_ip(ip).is_some() {
                    base
                } else {
                    hostname(ip, 2, &mut target_wire)?
                };
                snapshot.srv(owner, target, port.port, 100)?;
            }
        }
    }
    Ok(())
}

fn entries<'a>(
    index: &'a Index,
    service: &'a Service,
) -> impl Iterator<Item = (&'a EndpointAddress, &'a pharos_kubernetes::object::Port)> {
    index
        .endpoints_unfiltered(&service.namespace, &service.name)
        .flat_map(|ep| {
            ep.addresses
                .iter()
                .flat_map(|address| ep.ports.iter().map(move |port| (address, port)))
        })
}

#[derive(Clone, Copy)]
struct CaseInsensitive<'a>(&'a str);

impl PartialEq for CaseInsensitive<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl Eq for CaseInsensitive<'_> {}

impl Hash for CaseInsensitive<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.len().hash(state);
        for byte in self.0.bytes() {
            byte.to_ascii_lowercase().hash(state);
        }
    }
}

#[derive(Clone, Copy)]
struct Label<'a>(&'a EndpointAddress, bool);

impl PartialEq for Label<'_> {
    fn eq(&self, other: &Self) -> bool {
        let mut left = [0; 64];
        let mut right = [0; 64];
        endpoint_label(self.0, self.1, &mut left) == endpoint_label(other.0, other.1, &mut right)
    }
}

impl Eq for Label<'_> {}

impl Hash for Label<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut buffer = [0; 64];
        endpoint_label(self.0, self.1, &mut buffer).hash(state);
    }
}

#[derive(Hash, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "transfer keys must not allocate per record"
)]
enum Seen<'a> {
    Address(&'a str),
    Bare([u8; 255], i32),
    Named(CaseInsensitive<'a>, CaseInsensitive<'a>, i32, Label<'a>),
    Count(CaseInsensitive<'a>, CaseInsensitive<'a>),
}

fn target_key(target: NameRef<'_>) -> [u8; 255] {
    let mut wire = [0; 255];
    let mut offset = 0;
    for label in target.labels() {
        wire[offset] = label.len() as u8;
        offset += 1;
        wire[offset..offset + label.len()].copy_from_slice(label);
        offset += label.len();
    }
    wire
}

fn headless<'a, I>(
    snapshot: &mut Snapshot<'_>,
    entries: impl Fn() -> I,
    base: NameRef<'_>,
    pod_names: bool,
    seen: &mut HashMap<Seen<'a>, usize>,
) -> Result<(), Error>
where
    I: Iterator<Item = (&'a EndpointAddress, &'a pharos_kubernetes::object::Port)>,
{
    seen.clear();
    let mut total = 0;
    for (_, port) in entries() {
        total += 1;
        *seen
            .entry(Seen::Count(
                CaseInsensitive(&port.name),
                CaseInsensitive(&port.protocol),
            ))
            .or_default() += 1;
    }
    for (address, port) in entries() {
        let mut label_buf = [0; 64];
        let label = endpoint_label(address, pod_names, &mut label_buf);
        let mut target_wire = [0; 255];
        let endpoint = endpoint_owner(label, base, &mut target_wire);
        let ip = normalized_ip(&address.ip);
        let previous_ip = seen.insert(Seen::Address(&address.ip), 0).is_some();
        if ip.is_none() || !previous_ip {
            snapshot.address(base, &address.ip)?;
        }
        let Some(endpoint) = endpoint else {
            continue;
        };
        let mut host_wire = [0; 255];
        let target = if ip.is_some() {
            Some(endpoint)
        } else {
            hostname(&address.ip, 0, &mut host_wire).ok()
        };
        let duplicate_bare = target.is_some_and(|target| {
            seen.insert(Seen::Bare(target_key(target), port.port), 0)
                .is_some()
        });
        let duplicate_named = seen
            .insert(
                Seen::Named(
                    CaseInsensitive(&port.name),
                    CaseInsensitive(&port.protocol),
                    port.port,
                    Label(address, pod_names),
                ),
                0,
            )
            .is_some();
        if port.port != -1 {
            let mut host_wire = [0; 255];
            let target = if ip.is_some() {
                endpoint
            } else {
                hostname(&address.ip, 0, &mut host_wire)?
            };
            if !duplicate_bare {
                for _ in 0..2 {
                    snapshot.srv(base, target, port.port, weight(total))?;
                }
            }
        }
        snapshot.address(endpoint, &address.ip)?;
        if port.port != -1 {
            let mut host_wire = [0; 255];
            let target = if ip.is_some() {
                endpoint
            } else {
                hostname(&address.ip, 0, &mut host_wire)?
            };
            for _ in 0..2 {
                snapshot.srv(endpoint, target, port.port, 100)?;
            }
        }
        if port.name.is_empty() || port.port == -1 {
            continue;
        }
        if !duplicate_named {
            let count =
                seen[&Seen::Count(CaseInsensitive(&port.name), CaseInsensitive(&port.protocol))];
            let mut owner_wire = [0; 255];
            if let Some(owner) = named_owner(&port.name, &port.protocol, base, &mut owner_wire) {
                snapshot.srv(owner, endpoint, port.port, weight(count))?;
            }
        }
    }
    Ok(())
}

fn generate<'a>(
    snapshot: &mut Snapshot<'_>,
    plugin: &External,
    kubernetes: &Kubernetes,
    index: &'a Index,
    seen: &mut HashMap<Seen<'a>, usize>,
) -> Result<(), Error> {
    let current = index.external_serial();
    // RFC 1995 §2: a current IXFR is a single SOA; UDP IXFR returns the current SOA.
    if snapshot.request.serial != 0
        && snapshot.request.serial >= current
        && snapshot.request.protocol == Protocol::Tcp
    {
        snapshot.authoritative = false;
    }
    snapshot.soa(current)?;
    if snapshot.request.serial != 0 && snapshot.request.serial >= current
        || snapshot.request.qtype == Type::IXFR && snapshot.request.protocol == Protocol::Udp
    {
        return Ok(());
    }
    let ns = snapshot.ns;
    snapshot.record(snapshot.request.zone, Type::NS, snapshot.ttl, |w| {
        w.write_name(ns)
    })?;
    let mut error = None;
    kubernetes.visit_external_ns(index, plugin.config.headless, |ip| {
        if error.is_none() {
            error = snapshot.ip(ns, ip, snapshot.ttl).err();
        }
    });
    if let Some(error) = error {
        return Err(error);
    }
    for headless_group in [false, true] {
        for service in index.services_unfiltered() {
            let is_headless =
                plugin.config.headless && service.external_ips.is_empty() && service.headless();
            if is_headless != headless_group {
                continue;
            }
            let mut wire = [0; 255];
            let Some(base) = child(
                &[service.name.as_bytes(), service.namespace.as_bytes()],
                snapshot.request.zone,
                &mut wire,
            ) else {
                continue;
            };
            if is_headless {
                headless(
                    snapshot,
                    || entries(index, service),
                    base,
                    kubernetes.endpoint_pod_names(),
                    seen,
                )?;
            } else {
                non_headless(snapshot, service, base, seen)?;
            }
        }
    }
    snapshot.soa(current)
}

fn encode(
    plugin: &External,
    kubernetes: &Kubernetes,
    zone: &Zone,
    index: &Index,
    request: TransferRequest<'_>,
) -> Result<Vec<u8>, Error> {
    let ns = zone
        .ns
        .as_ref()
        .ok_or(Error::Build(BuildError::InvalidRdata))?;
    let host = zone
        .host
        .as_ref()
        .ok_or(Error::Build(BuildError::InvalidRdata))?;
    let mut snapshot = Snapshot {
        request,
        ns: NameRef::parse(ns.as_wire(), 0).map_err(|_| Error::InvalidQuery)?,
        host: NameRef::parse(host.as_wire(), 0).map_err(|_| Error::InvalidQuery)?,
        ttl: plugin.config.ttl,
        service_ttl: kubernetes.ttl(),
        authoritative: true,
        bytes: None,
        size: 0,
    };
    let mut capacity = 0;
    for service in index.services_unfiltered() {
        let needed =
            if plugin.config.headless && service.external_ips.is_empty() && service.headless() {
                entries(index, service)
                    .count()
                    .checked_mul(4)
                    .ok_or(Error::ResponseBufferTooSmall)?
            } else if !service.external_ips.is_empty() {
                service.ports.len()
            } else {
                0
            };
        capacity = capacity.max(needed);
    }
    // shortcut: allocate transfer scratch once; reuse immutable snapshots for incremental streaming.
    let mut seen = HashMap::new();
    seen.try_reserve(capacity)
        .map_err(|_| Error::ResponseBufferTooSmall)?;
    generate(&mut snapshot, plugin, kubernetes, index, &mut seen)?;
    // shortcut: the snapshot and Stream each allocate once; use immutable snapshots for incremental streaming.
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(snapshot.size)
        .map_err(|_| Error::ResponseBufferTooSmall)?;
    snapshot.bytes = Some(bytes);
    snapshot.size = 0;
    generate(&mut snapshot, plugin, kubernetes, index, &mut seen)?;
    snapshot.bytes.ok_or(Error::InvalidQuery)
}

impl Transferer for External {
    fn transfer(&self, request: TransferRequest<'_>) -> Result<Option<Stream>, Error> {
        let Some(zone) = self.zones.iter().find(|zone| {
            NameRef::parse(zone.name.as_wire(), 0).is_ok_and(|name| name == request.zone)
        }) else {
            return Ok(None);
        };
        let kubernetes = self.kubernetes.as_ref().ok_or(Error::InvalidQuery)?;
        let store = kubernetes
            .store()
            .unwrap_or_else(|| self.empty_store.clone());
        let bytes = store.with_read(|index| encode(self, kubernetes, zone, index, request))?;
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
            let data = record.data().ok();
            if data.is_none() && !(record.rtype == Type::AAAA && record.rdata.is_empty()) {
                return Err(Error::InvalidQuery);
            }
            let size = transfer_record_len(record.name, data.as_ref())?;
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
                    |writer| match &data {
                        Some(data) => data.write(writer),
                        None => writer.write_bytes(record.rdata),
                    },
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

fn transfer_record_len(owner: NameRef<'_>, data: Option<&Rdata<'_>>) -> Result<usize, Error> {
    let name_len =
        |name: NameRef<'_>| 1 + name.labels().map(|label| label.len() + 1).sum::<usize>();
    let data_len = match data {
        None => 0,
        Some(Rdata::A(_)) => 4,
        Some(Rdata::Aaaa(_)) => 16,
        Some(Rdata::Ns(name) | Rdata::Cname(name)) => name_len(*name),
        Some(Rdata::Soa { mname, rname, .. }) => name_len(*mname) + name_len(*rname) + 20,
        Some(Rdata::Srv { target, .. }) => 6 + name_len(*target),
        _ => return Err(Error::InvalidQuery),
    };
    Ok(name_len(owner) + 10 + data_len)
}

#[cfg(test)]
mod tests {
    use super::super::External;
    use super::*;
    use crate::transfer::{TransferRequest, Transferer};
    use pharos_corefile::{Cursor, parse};
    use pharos_proto::{Class, Message, Name, NameRef, Rdata, Type};
    use pharos_server::Protocol;

    fn plugin() -> External {
        let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
        let config = super::super::setup::parse(
            &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
            &["."],
        )
        .unwrap();
        let mut external = External::new(config).unwrap();
        let blocks = parse("Corefile", ".:53 {\n kubernetes cluster.local\n}").unwrap();
        let config = crate::kubernetes::setup::parse(
            &mut Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
            &["."],
        )
        .unwrap();
        external.bind_kubernetes(&crate::kubernetes::Kubernetes::new(config).unwrap());
        external
    }

    fn request(zone: &Name, qtype: Type, serial: u32, protocol: Protocol) -> TransferRequest<'_> {
        TransferRequest {
            zone: NameRef::parse(zone.as_wire(), 0).unwrap(),
            serial,
            id: 42,
            flags: 0x0100,
            protocol,
            qtype,
            qclass: Class::IN,
        }
    }

    #[test]
    fn transfer_requires_an_exact_configured_zone() {
        let plugin = plugin();
        for name in ["child.example.com.", "elsewhere."] {
            let zone: Name = name.parse().unwrap();
            assert!(
                plugin
                    .transfer(request(&zone, Type::AXFR, 0, Protocol::Tcp))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn axfr_has_matching_soa_boundaries_and_apex_nameserver() {
        let zone: Name = "example.com.".parse().unwrap();
        let mut stream = plugin()
            .transfer(request(&zone, Type::AXFR, 0, Protocol::Tcp))
            .unwrap()
            .unwrap();
        let mut wire = Vec::new();
        let mut records = Vec::new();
        while stream.next(&mut wire).unwrap() {
            let message = Message::parse(&wire).unwrap();
            assert_eq!(message.id(), 42);
            for record in message.answers() {
                match record.data().unwrap() {
                    Rdata::Soa {
                        mname,
                        rname,
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum,
                    } => {
                        assert_eq!(record.ttl, 5);
                        assert_eq!(mname.to_string(), "ns1.dns.example.com.");
                        assert_eq!(rname.to_string(), "hostmaster.dns.example.com.");
                        assert_eq!(
                            (serial, refresh, retry, expire, minimum),
                            (0, 7200, 1800, 86400, 5)
                        );
                    }
                    Rdata::Ns(target) => assert_eq!(target.to_string(), "ns1.dns.example.com."),
                    _ => {}
                }
                records.push(record.rtype);
            }
        }
        assert_eq!(records.first(), Some(&Type::SOA));
        assert_eq!(records.last(), Some(&Type::SOA));
        assert_eq!(records.iter().filter(|&&kind| kind == Type::SOA).count(), 2);
        assert_eq!(records.iter().filter(|&&kind| kind == Type::NS).count(), 1);
    }

    #[test]
    fn ixfr_with_newer_serial_returns_only_current_soa() {
        let zone: Name = "example.com.".parse().unwrap();
        let mut stream = plugin()
            .transfer(request(&zone, Type::IXFR, 1, Protocol::Tcp))
            .unwrap()
            .unwrap();
        let mut wire = Vec::new();
        assert!(stream.next(&mut wire).unwrap());
        let message = Message::parse(&wire).unwrap();
        assert_eq!(message.answer_count(), 1);
        assert_eq!(message.answers().next().unwrap().rtype, Type::SOA);
        assert!(!stream.next(&mut wire).unwrap());
    }

    #[test]
    fn udp_ixfr_returns_only_current_soa() {
        let zone: Name = "example.com.".parse().unwrap();
        let mut stream = plugin()
            .transfer(request(&zone, Type::IXFR, 0, Protocol::Udp))
            .unwrap()
            .unwrap();
        let mut wire = Vec::new();
        assert!(stream.next(&mut wire).unwrap());
        let message = Message::parse(&wire).unwrap();
        assert_eq!(message.answer_count(), 1);
        assert_eq!(message.answers().next().unwrap().rtype, Type::SOA);
        assert!(!stream.next(&mut wire).unwrap());
    }

    fn fixture_service() -> pharos_kubernetes::object::Service {
        use pharos_kubernetes::object::{Port, Service};
        Service {
            version: "1".into(),
            name: "web".into(),
            namespace: "hidden".into(),
            cluster_ips: vec!["10.0.0.1".into()],
            service_type: "LoadBalancer".into(),
            external_name: String::new(),
            external_ips: vec!["192.0.2.1".into(), "lb.example.net".into()],
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
        }
    }

    fn fixture_snapshot<'a>(plugin: &'a External, zone: &'a Name) -> Snapshot<'a> {
        Snapshot {
            request: request(zone, Type::AXFR, 0, Protocol::Tcp),
            ns: NameRef::parse(plugin.zones[0].ns.as_ref().unwrap().as_wire(), 0).unwrap(),
            host: NameRef::parse(plugin.zones[0].host.as_ref().unwrap().as_wire(), 0).unwrap(),
            ttl: plugin.config.ttl,
            service_ttl: plugin.kubernetes.as_ref().unwrap().ttl(),
            authoritative: true,
            bytes: Some(Vec::new()),
            size: 0,
        }
    }

    #[test]
    fn external_service_preserves_coredns_ttls_and_duplicates() {
        let mut plugin = plugin();
        let blocks = parse(
            "Corefile",
            ".:53 {\n kubernetes cluster.local {\n ttl 37\n }\n}",
        )
        .unwrap();
        let config = crate::kubernetes::setup::parse(
            &mut Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
            &["."],
        )
        .unwrap();
        plugin.bind_kubernetes(&crate::kubernetes::Kubernetes::new(config).unwrap());
        let zone: Name = "example.com.".parse().unwrap();
        let base: Name = "web.hidden.example.com.".parse().unwrap();
        let mut snapshot = fixture_snapshot(&plugin, &zone);
        non_headless(
            &mut snapshot,
            &fixture_service(),
            NameRef::parse(base.as_wire(), 0).unwrap(),
            &mut HashMap::with_capacity(2),
        )
        .unwrap();
        let mut stream = stream_snapshot(snapshot.bytes.unwrap());
        let mut wire = Vec::new();
        let mut a_count = 0;
        let mut cname_count = 0;
        let mut bare_srv = 0;
        let mut named_srv = 0;
        while stream.next(&mut wire).unwrap() {
            let message = Message::parse(&wire).unwrap();
            for rr in message.answers() {
                if rr.name.to_string() == "web.hidden.example.com." {
                    match rr.data().unwrap() {
                        Rdata::A(_) => {
                            assert_eq!(rr.ttl, 5);
                            a_count += 1;
                        }
                        Rdata::Cname(_) => {
                            assert_eq!(rr.ttl, 37);
                            cname_count += 1;
                        }
                        Rdata::Srv { port, weight, .. } => {
                            assert_eq!((rr.ttl, port, weight), (37, 80, 100));
                            bare_srv += 1;
                        }
                        _ => {}
                    }
                } else if rr.rtype == Type::SRV {
                    assert_eq!(rr.ttl, 37);
                    named_srv += 1;
                }
            }
        }
        assert_eq!((a_count, cname_count, bare_srv, named_srv), (2, 4, 1, 2));
    }

    #[test]
    fn non_headless_many_ports_and_ips_preserve_name_seen_order() {
        use pharos_kubernetes::object::Port;
        let plugin = plugin();
        let zone: Name = "example.com.".parse().unwrap();
        let base: Name = "web.hidden.example.com.".parse().unwrap();
        let mut service = fixture_service();
        service.external_ips = vec![
            "192.0.2.1".into(),
            "lb.example.net".into(),
            "192.0.2.2".into(),
        ];
        service.ports = vec![Port {
            name: "port0".into(),
            protocol: "TCP".into(),
            port: -1,
        }];
        service.ports.extend((0..200).map(|i| Port {
            name: if i % 2 == 0 {
                format!("port{}", i / 2)
            } else {
                format!("PORT{}", i / 2)
            },
            protocol: if i % 2 == 0 { "TCP" } else { "tcp" }.into(),
            port: 1000 + i,
        }));
        let mut snapshot = fixture_snapshot(&plugin, &zone);
        let mut seen = HashMap::with_capacity(service.ports.len());
        let capacity = seen.capacity();
        non_headless(
            &mut snapshot,
            &service,
            NameRef::parse(base.as_wire(), 0).unwrap(),
            &mut seen,
        )
        .unwrap();
        assert_eq!(seen.capacity(), capacity);
        let first = snapshot.bytes.clone().unwrap();
        snapshot.bytes.as_mut().unwrap().clear();
        snapshot.size = 0;
        non_headless(
            &mut snapshot,
            &service,
            NameRef::parse(base.as_wire(), 0).unwrap(),
            &mut seen,
        )
        .unwrap();
        assert_eq!(seen.capacity(), capacity);
        assert_eq!(snapshot.bytes.as_ref().unwrap(), &first);
        let mut stream = stream_snapshot(snapshot.bytes.unwrap());
        let mut wire = Vec::new();
        let mut actual = Vec::new();
        while stream.next(&mut wire).unwrap() {
            for rr in Message::parse(&wire).unwrap().answers() {
                actual.push(match rr.data().unwrap() {
                    Rdata::A(ip) => format!("{} A {ip}", rr.name),
                    Rdata::Cname(target) => format!("{} CNAME {target}", rr.name),
                    Rdata::Srv {
                        weight,
                        port,
                        target,
                        ..
                    } => {
                        format!("{} SRV {weight} {port} {target}", rr.name)
                    }
                    _ => panic!("unexpected record"),
                });
            }
        }
        let mut expected = Vec::new();
        for (ip_index, ip) in service.external_ips.iter().enumerate() {
            for (port_index, port) in service.ports.iter().enumerate() {
                if ip_index == 1 {
                    for _ in 0..2 {
                        expected.push(format!("{base} CNAME lb.example.net."));
                    }
                } else {
                    expected.push(format!("{base} A {ip}"));
                }
                if ip_index == 0 && port_index == 1 {
                    expected.push(format!("{base} SRV 100 1000 {base}"));
                }
                if ip_index == 0 && port_index > 0 && port_index % 2 == 1 {
                    expected.push(format!(
                        "_{}._tcp.{base} SRV 100 {} {base}",
                        port.name, port.port
                    ));
                }
            }
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn axfr_hostname_emits_cname_without_target_addresses() {
        let plugin = plugin();
        let zone: Name = "example.com.".parse().unwrap();
        let base: Name = "web.hidden.example.com.".parse().unwrap();
        let mut service = fixture_service();
        service.external_ips = vec!["lb.example.net".into()];
        let mut snapshot = fixture_snapshot(&plugin, &zone);
        non_headless(
            &mut snapshot,
            &service,
            NameRef::parse(base.as_wire(), 0).unwrap(),
            &mut HashMap::with_capacity(2),
        )
        .unwrap();
        let mut stream = stream_snapshot(snapshot.bytes.unwrap());
        let mut wire = Vec::new();
        let mut cnames = 0;
        while stream.next(&mut wire).unwrap() {
            for rr in Message::parse(&wire).unwrap().answers() {
                assert!(
                    !(rr.name.to_string() == "lb.example.net."
                        && matches!(rr.rtype, Type::A | Type::AAAA))
                );
                if let Rdata::Cname(target) = rr.data().unwrap() {
                    assert_eq!(rr.name.to_string(), "web.hidden.example.com.");
                    assert_eq!(target.to_string(), "lb.example.net.");
                    cnames += 1;
                }
            }
        }
        assert_eq!(cnames, 4);
    }

    #[test]
    fn headless_transfers_weighted_and_repeated_srv_records() {
        use pharos_kubernetes::object::{EndpointAddress, Endpoints, Port};
        let plugin = plugin();
        let endpoints = Endpoints {
            version: "1".into(),
            name: "slice".into(),
            namespace: "hidden".into(),
            service_name: "web".into(),
            addresses: ["192.0.2.1", "192.0.2.2"]
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
        let zone: Name = "example.com.".parse().unwrap();
        let base: Name = "web.hidden.example.com.".parse().unwrap();
        let mut snapshot = fixture_snapshot(&plugin, &zone);
        headless(
            &mut snapshot,
            || {
                endpoints
                    .addresses
                    .iter()
                    .flat_map(|address| endpoints.ports.iter().map(move |port| (address, port)))
            },
            NameRef::parse(base.as_wire(), 0).unwrap(),
            false,
            &mut HashMap::with_capacity(8),
        )
        .unwrap();
        let mut stream = stream_snapshot(snapshot.bytes.unwrap());
        let mut wire = Vec::new();
        let mut base = Vec::new();
        let mut endpoint = Vec::new();
        let mut named = Vec::new();
        while stream.next(&mut wire).unwrap() {
            let message = Message::parse(&wire).unwrap();
            for rr in message.answers().filter(|rr| rr.rtype == Type::SRV) {
                let Rdata::Srv {
                    weight,
                    port,
                    target,
                    ..
                } = rr.data().unwrap()
                else {
                    panic!("SRV")
                };
                let value = (weight, port, target.to_string());
                match rr.name.to_string().as_str() {
                    "web.hidden.example.com." => base.push(value),
                    "_http._tcp.web.hidden.example.com." => named.push(value),
                    _ => endpoint.push(value),
                }
            }
        }
        assert_eq!(base.len(), 4);
        assert!(base.iter().all(|v| v.0 == 50));
        assert_eq!(endpoint.len(), 4);
        assert!(endpoint.iter().all(|v| v.0 == 100));
        assert_eq!(named.len(), 2);
        assert!(named.iter().all(|v| v.0 == 50));
    }

    #[test]
    fn headless_base_address_survives_invalid_endpoint_hostname() {
        use pharos_kubernetes::object::{EndpointAddress, Port};
        let plugin = plugin();
        let zone: Name = "example.com.".parse().unwrap();
        let base: Name = "web.hidden.example.com.".parse().unwrap();
        let addresses: Vec<_> = ["a".repeat(64), "node".to_owned()]
            .into_iter()
            .map(|hostname| EndpointAddress {
                ip: "192.0.2.1".into(),
                hostname,
                node_name: String::new(),
                target_ref_name: String::new(),
            })
            .collect();
        let port = Port {
            name: "http".into(),
            protocol: "TCP".into(),
            port: 80,
        };
        for count in [1, 2] {
            let mut snapshot = fixture_snapshot(&plugin, &zone);
            headless(
                &mut snapshot,
                || addresses[..count].iter().map(|address| (address, &port)),
                NameRef::parse(base.as_wire(), 0).unwrap(),
                false,
                &mut HashMap::with_capacity(8),
            )
            .unwrap();
            let mut stream = stream_snapshot(snapshot.bytes.unwrap());
            let mut wire = Vec::new();
            let mut found = 0;
            while stream.next(&mut wire).unwrap() {
                for rr in Message::parse(&wire).unwrap().answers() {
                    if rr.name.to_string() == "web.hidden.example.com."
                        && matches!(rr.data().unwrap(), Rdata::A(_))
                    {
                        found += 1;
                    }
                }
            }
            assert_eq!(found, 1, "{count} endpoints");
        }
    }

    #[test]
    fn headless_many_repeated_endpoints_and_ports_preserve_order() {
        use pharos_kubernetes::object::{EndpointAddress, Port};
        let plugin = plugin();
        let zone: Name = "example.com.".parse().unwrap();
        let base: Name = "web.hidden.example.com.".parse().unwrap();
        let addresses: Vec<_> = (0..48)
            .map(|i| EndpointAddress {
                ip: format!("192.0.2.{}", i % 24 + 1),
                hostname: format!("node{}", i % 24),
                node_name: String::new(),
                target_ref_name: String::new(),
            })
            .collect();
        let ports: Vec<_> = [("http", 80), ("HTTP", 80), ("http", 81), ("metrics", 90)]
            .into_iter()
            .map(|(name, port)| Port {
                name: name.into(),
                protocol: "TCP".into(),
                port,
            })
            .collect();
        let mut snapshot = fixture_snapshot(&plugin, &zone);
        let mut seen = HashMap::with_capacity(addresses.len() * ports.len() * 4);
        let capacity = seen.capacity();
        headless(
            &mut snapshot,
            || {
                addresses
                    .iter()
                    .flat_map(|a| ports.iter().map(move |p| (a, p)))
            },
            NameRef::parse(base.as_wire(), 0).unwrap(),
            false,
            &mut seen,
        )
        .unwrap();
        assert_eq!(seen.capacity(), capacity);
        let mut stream = stream_snapshot(snapshot.bytes.unwrap());
        let mut wire = Vec::new();
        let mut actual = Vec::new();
        while stream.next(&mut wire).unwrap() {
            for rr in Message::parse(&wire).unwrap().answers() {
                let owner = rr.name.to_string();
                let value = match rr.data().unwrap() {
                    Rdata::A(ip) => format!("{owner} A {ip}"),
                    Rdata::Srv {
                        weight,
                        port,
                        target,
                        ..
                    } => {
                        format!("{owner} SRV {weight} {port} {target}")
                    }
                    _ => panic!("unexpected record"),
                };
                actual.push(value);
            }
        }
        let mut expected = Vec::new();
        for i in 0..48 {
            let endpoint = format!("node{}.web.hidden.example.com.", i % 24);
            let ip = format!("192.0.2.{}", i % 24 + 1);
            for (p, port) in ports.iter().enumerate() {
                if i < 24 && p == 0 {
                    expected.push(format!("{base} A {ip}"));
                }
                if i < 24 && p != 1 {
                    for _ in 0..2 {
                        expected.push(format!("{base} SRV 1 {} {endpoint}", port.port));
                    }
                }
                expected.push(format!("{endpoint} A {ip}"));
                for _ in 0..2 {
                    expected.push(format!("{endpoint} SRV 100 {} {endpoint}", port.port));
                }
                if i < 24 && p != 1 {
                    let name = port.name.to_ascii_lowercase();
                    let weight = if p == 3 { 2 } else { 1 };
                    expected.push(format!(
                        "_{name}._tcp.{base} SRV {weight} {} {endpoint}",
                        port.port
                    ));
                }
            }
        }
        assert_eq!(actual, expected);
    }

    #[test]
    fn headless_dedup_uses_host_text_and_resets_between_services() {
        use pharos_kubernetes::object::{EndpointAddress, Port};
        let plugin = plugin();
        let zone: Name = "example.com.".parse().unwrap();
        let addresses: Vec<_> = ["2001:db8::1", "2001:0db8::1", "2001:db8::1"]
            .into_iter()
            .map(|ip| EndpointAddress {
                ip: ip.into(),
                hostname: "node".into(),
                node_name: String::new(),
                target_ref_name: String::new(),
            })
            .collect();
        let port = Port {
            name: "http".into(),
            protocol: "TCP".into(),
            port: 80,
        };
        let mut snapshot = fixture_snapshot(&plugin, &zone);
        let mut seen = HashMap::with_capacity(12);
        for name in ["web.hidden.example.com.", "api.hidden.example.com."] {
            let base: Name = name.parse().unwrap();
            headless(
                &mut snapshot,
                || addresses.iter().map(|address| (address, &port)),
                NameRef::parse(base.as_wire(), 0).unwrap(),
                false,
                &mut seen,
            )
            .unwrap();
        }
        let mut stream = stream_snapshot(snapshot.bytes.unwrap());
        let mut wire = Vec::new();
        let mut addresses_per_service = [0, 0];
        while stream.next(&mut wire).unwrap() {
            for rr in Message::parse(&wire).unwrap().answers() {
                if rr.rtype == Type::AAAA {
                    match rr.name.to_string().as_str() {
                        "web.hidden.example.com." => addresses_per_service[0] += 1,
                        "api.hidden.example.com." => addresses_per_service[1] += 1,
                        _ => {}
                    }
                }
            }
        }
        assert_eq!(addresses_per_service, [2, 2]);
    }

    #[test]
    fn headless_group_deduplicates_hostname_srv_targets() {
        use pharos_kubernetes::object::{EndpointAddress, Port};
        let plugin = plugin();
        let zone: Name = "example.com.".parse().unwrap();
        let base: Name = "web.hidden.example.com.".parse().unwrap();
        let addresses: Vec<_> = ["node0", "node1"]
            .into_iter()
            .map(|hostname| EndpointAddress {
                ip: "target.example.net".into(),
                hostname: hostname.into(),
                node_name: String::new(),
                target_ref_name: String::new(),
            })
            .collect();
        let port = Port {
            name: "http".into(),
            protocol: "TCP".into(),
            port: 80,
        };
        let mut snapshot = fixture_snapshot(&plugin, &zone);
        headless(
            &mut snapshot,
            || addresses.iter().map(|address| (address, &port)),
            NameRef::parse(base.as_wire(), 0).unwrap(),
            false,
            &mut HashMap::with_capacity(8),
        )
        .unwrap();
        let mut stream = stream_snapshot(snapshot.bytes.unwrap());
        let mut wire = Vec::new();
        let mut count = 0;
        while stream.next(&mut wire).unwrap() {
            let message = Message::parse(&wire).unwrap();
            count += message
                .answers()
                .filter(|rr| {
                    rr.rtype == Type::SRV && rr.name.to_string() == "web.hidden.example.com."
                })
                .count();
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn headless_pod_name_with_dots_uses_coredns_domain_labels() {
        use pharos_kubernetes::object::{EndpointAddress, Port};
        let plugin = plugin();
        let zone: Name = "example.com.".parse().unwrap();
        let base: Name = "web.hidden.example.com.".parse().unwrap();
        let address = EndpointAddress {
            ip: "192.0.2.1".into(),
            hostname: String::new(),
            node_name: String::new(),
            target_ref_name: "pod.region".into(),
        };
        let port = Port {
            name: "http".into(),
            protocol: "TCP".into(),
            port: 80,
        };
        let mut snapshot = fixture_snapshot(&plugin, &zone);
        headless(
            &mut snapshot,
            || std::iter::once((&address, &port)),
            NameRef::parse(base.as_wire(), 0).unwrap(),
            true,
            &mut HashMap::with_capacity(4),
        )
        .unwrap();
        let mut stream = stream_snapshot(snapshot.bytes.unwrap());
        let mut wire = Vec::new();
        let mut found = false;
        while stream.next(&mut wire).unwrap() {
            let message = Message::parse(&wire).unwrap();
            found |= message.answers().any(|rr| {
                rr.rtype == Type::A && rr.name.to_string() == "pod.region.web.hidden.example.com."
            });
        }
        assert!(found);
    }

    #[test]
    fn invalid_nameserver_address_keeps_empty_aaaa_rdata() {
        let plugin = plugin();
        let zone: Name = "example.com.".parse().unwrap();
        let mut snapshot = fixture_snapshot(&plugin, &zone);
        snapshot.ip(snapshot.ns, None, 5).unwrap();
        let mut stream = stream_snapshot(snapshot.bytes.unwrap());
        let mut wire = Vec::new();
        assert!(stream.next(&mut wire).unwrap());
        let message = Message::parse(&wire).unwrap();
        let rr = message.answers().next().unwrap();
        assert_eq!(rr.rtype, Type::AAAA);
        assert!(rr.rdata.is_empty());
    }

    #[test]
    fn transfer_uses_configured_apex_and_ttl() {
        let mut plugin = plugin();
        let blocks = parse(
            "Corefile",
            ".:53 {\n k8s_external example.com {\n  apex external\n  ttl 30\n }\n}",
        )
        .unwrap();
        let config = super::super::setup::parse(
            &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
            &["."],
        )
        .unwrap();
        let kubernetes = plugin.kubernetes.take().unwrap();
        let mut plugin = External::new(config).unwrap();
        plugin.bind_kubernetes(&kubernetes);
        let zone: Name = "example.com.".parse().unwrap();
        let mut stream = plugin
            .transfer(request(&zone, Type::AXFR, 0, Protocol::Tcp))
            .unwrap()
            .unwrap();
        let mut wire = Vec::new();
        assert!(stream.next(&mut wire).unwrap());
        let message = Message::parse(&wire).unwrap();
        let soa = message.answers().next().unwrap();
        assert_eq!(soa.ttl, 30);
        let Rdata::Soa {
            mname,
            rname,
            minimum,
            ..
        } = soa.data().unwrap()
        else {
            panic!("SOA")
        };
        assert_eq!(mname.to_string(), "ns1.external.example.com.");
        assert_eq!(rname.to_string(), "hostmaster.external.example.com.");
        assert_eq!(minimum, 30);
    }

    #[test]
    fn snapshot_batches_large_zones_without_losing_records() {
        let plugin = plugin();
        let zone: Name = "example.com.".parse().unwrap();
        let mut snapshot = fixture_snapshot(&plugin, &zone);
        snapshot.soa(0).unwrap();
        for _ in 0..4000 {
            snapshot
                .ip(
                    NameRef::parse(zone.as_wire(), 0).unwrap(),
                    Some("192.0.2.1".parse().unwrap()),
                    5,
                )
                .unwrap();
        }
        snapshot.soa(0).unwrap();
        let mut stream = stream_snapshot(snapshot.bytes.unwrap());
        let mut wire = Vec::new();
        let mut messages = 0;
        let mut count = 0;
        while stream.next(&mut wire).unwrap() {
            assert!(wire.len() <= 64500);
            count += Message::parse(&wire).unwrap().answer_count() as usize;
            messages += 1;
        }
        assert_eq!(count, 4002);
        assert!(messages > 1);
    }

    #[tokio::test]
    async fn transfer_reads_unfiltered_services_and_headless_endpoints() {
        use pharos_server::{Lifecycle, Phase};
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
                            r#"[{"metadata":{"name":"web","namespace":"hidden"},"spec":{"clusterIP":"10.0.0.1","externalIPs":["192.0.2.1","lb.example.net"],"ports":[{"name":"http","protocol":"TCP","port":80}]}},{"metadata":{"name":"head","namespace":"hidden"},"spec":{"clusterIP":"None"}}]"#,
                        )
                    } else if request.contains("/endpointslices") {
                        (
                            "EndpointSliceList",
                            r#"[{"metadata":{"name":"head-1","namespace":"hidden","labels":{"kubernetes.io/service-name":"head"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.2"],"hostname":"node"}],"ports":[{"name":"http","protocol":"TCP","port":80}]}]"#,
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
            ".:53 {{\n kubernetes cluster.local {{\n  endpoint http://{server}\n  namespaces visible\n  ttl 37\n  startup_timeout 3s\n }}\n}}"
        );
        let blocks = parse("Corefile", &text).unwrap();
        let config = crate::kubernetes::setup::parse(
            &mut Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
            &["."],
        )
        .unwrap();
        let kubernetes = crate::kubernetes::Kubernetes::new(config).unwrap();
        let mut lifecycle = Lifecycle::default();
        kubernetes.register_hooks(&mut lifecycle);
        lifecycle.run(Phase::Startup).await.unwrap();
        let mut external = plugin();
        external.config.headless = true;
        external.bind_kubernetes(&kubernetes);
        let zone: Name = "example.com.".parse().unwrap();
        let mut stream = external
            .transfer(request(&zone, Type::AXFR, 0, Protocol::Tcp))
            .unwrap()
            .unwrap();
        let mut wire = Vec::new();
        let mut web = false;
        let mut head = false;
        let mut srv = false;
        let mut cname = false;
        while stream.next(&mut wire).unwrap() {
            let message = Message::parse(&wire).unwrap();
            for rr in message.answers() {
                match (rr.name.to_string().as_str(), rr.rtype) {
                    ("web.hidden.example.com.", Type::A) => web = true,
                    ("web.hidden.example.com.", Type::CNAME) => {
                        assert!(
                            matches!(rr.data().unwrap(), Rdata::Cname(target) if target.to_string() == "lb.example.net.")
                        );
                        cname = true;
                    }
                    ("lb.example.net.", Type::A | Type::AAAA) => {
                        panic!("unexpected target address")
                    }
                    ("node.head.hidden.example.com.", Type::A) => {
                        assert!(web);
                        head = true;
                    }
                    ("_http._tcp.head.hidden.example.com.", Type::SRV) => {
                        assert_eq!(rr.ttl, 37);
                        srv = true;
                    }
                    _ => {}
                }
            }
        }
        assert!(web && head && srv && cname);
        lifecycle.run(Phase::Shutdown).await.unwrap();
        task.abort();
    }
}

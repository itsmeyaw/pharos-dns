use std::{
    collections::HashMap,
    fmt::{self, Write},
    hash::{Hash, Hasher},
    net::IpAddr,
};

use super::{External, Zone};
use crate::kubernetes::Kubernetes;
use crate::{
    serial::serial_at_least,
    transfer::{TransferRequest, Transferer},
};
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
    let len = if super::is_fqdn(bytes) {
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
        // RFC 5936 §2.2.4: Authority stays empty; only Question and Answer are written.
        let mut b = MessageBuilder::new(
            &mut wire,
            1024,
            self.request.id,
            // RFC 5936 §2.2.1: response CD is always zero.
            0x8000 | if self.authoritative { 0x0400 } else { 0 } | (self.request.flags & 0x0100),
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
            // RFC 3596 §2.2: omit AAAA when no IPv6 address is available.
            None => Ok(()),
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
        self.record(owner, Type::CNAME, self.service_ttl, |w| {
            w.write_name(target)
        })
    }

    fn srv(
        &mut self,
        owner: NameRef<'_>,
        target: NameRef<'_>,
        port: i32,
        weight: u16,
    ) -> Result<(), Error> {
        // RFC 2782 §The format of the SRV RR: u16 priority, weight, port; uncompressed target.
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
    // RFC 2782 §The format of the SRV RR: Service and Proto use underscores and ignore case.
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
        // RFC 5936 §2.2: suppress repeated address RRs in the AXFR stream.
        if seen.insert(Seen::Address(CaseInsensitive(ip)), 0).is_none() {
            snapshot.address(base, ip)?;
        }
        for port in &service.ports {
            // KEP-752 §Proposal > Endpoint Port: omit nil ports, matching query answers.
            if !port.has_srv() {
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
                // Kubernetes DNS spec 1.1.0 §2.1: only DNS-eligible endpoints are transferred.
                .filter(|address| address.dns_eligible(service.tolerate_unready_endpoints))
                .flat_map(|address| ep.ports.iter().map(move |port| (address, port)))
        })
}

#[derive(Clone, Copy)]
struct CaseInsensitive<'a>(&'a str);

// RFC 1035 §2.3.3: DNS service and protocol labels compare case-insensitively.
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

#[derive(Clone, Copy)]
struct Target<'a> {
    address: &'a EndpointAddress,
    service: &'a Service,
    zone: NameRef<'a>,
    pod_names: bool,
}

impl Target<'_> {
    // RFC 1035 §2.3.4: 2304 bytes covers escaped input labels and the longest wire-format zone.
    fn presentation<'a>(&self, bytes: &'a mut [u8; 2304]) -> Option<&'a [u8]> {
        struct Output<'a> {
            bytes: &'a mut [u8],
            len: usize,
        }
        impl Output<'_> {
            fn append(&mut self, value: &[u8]) -> Option<()> {
                let end = self.len.checked_add(value.len())?;
                self.bytes.get_mut(self.len..end)?.copy_from_slice(value);
                self.len = end;
                Some(())
            }
        }
        impl Write for Output<'_> {
            fn write_str(&mut self, value: &str) -> fmt::Result {
                self.append(value.as_bytes()).ok_or(fmt::Error)
            }
        }
        let mut output = Output { bytes, len: 0 };
        if normalized_ip(&self.address.ip).is_none() {
            let host = self.address.ip.as_bytes();
            output.append(host)?;
            if !super::is_fqdn(host) {
                output.append(b".")?;
            }
        } else {
            let mut label_wire = [0; 64];
            let label = endpoint_label(self.address, self.pod_names, &mut label_wire);
            let mut components = label.rsplit(|&byte| byte == b'/');
            if label.is_empty() || label.last() == Some(&b'/') {
                components.next();
            }
            for component in components {
                output.append(component)?;
                output.append(b".")?;
            }
            output.append(self.service.name.as_bytes())?;
            output.append(b".")?;
            output.append(self.service.namespace.as_bytes())?;
            output.append(b".")?;
            // CoreDNS msg.Path and msg.Domain reverse slash-separated zone components.
            for label in self.zone.labels() {
                for component in label
                    .rsplit(|&byte| byte == b'/')
                    .filter(|part| !part.is_empty())
                {
                    for &byte in component {
                        if matches!(
                            byte,
                            b'.' | b' ' | b'\'' | b'@' | b';' | b'(' | b')' | b'"' | b'\\'
                        ) {
                            output.append(&[b'\\', byte])?;
                        } else if (b'!'..=b'~').contains(&byte) {
                            output.append(&[byte])?;
                        } else {
                            write!(output, "\\{byte:03}").ok()?;
                        }
                    }
                    output.append(b".")?;
                }
            }
        }
        Some(&output.bytes[..output.len])
    }
}

impl PartialEq for Target<'_> {
    fn eq(&self, other: &Self) -> bool {
        let mut left = [0; 2304];
        let mut right = [0; 2304];
        // RFC 1035 §2.3.3: DNS names ignore case, but CoreDNS SRV dedup compares target bytes.
        self.presentation(&mut left) == other.presentation(&mut right)
    }
}

impl Eq for Target<'_> {}

impl Hash for Target<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut bytes = [0; 2304];
        self.presentation(&mut bytes).hash(state);
    }
}

#[derive(Hash, PartialEq, Eq)]
enum Seen<'a> {
    Address(CaseInsensitive<'a>),
    EndpointAddress(Label<'a>, CaseInsensitive<'a>),
    Bare(Target<'a>, i32),
    EndpointBare(Target<'a>, i32),
    Named(CaseInsensitive<'a>, CaseInsensitive<'a>, i32, Label<'a>),
    Count(CaseInsensitive<'a>, CaseInsensitive<'a>),
}

fn headless<'a, I>(
    snapshot: &mut Snapshot<'_>,
    entries: impl Fn() -> I,
    base: NameRef<'_>,
    origin: (&'a Service, NameRef<'a>),
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
        // RFC 5936 §2.2: keep one copy of each transfer RR across repeated endpoints and ports.
        let previous_ip = seen
            .insert(Seen::Address(CaseInsensitive(&address.ip)), 0)
            .is_some();
        if !previous_ip {
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
        let duplicate_bare = target.is_some_and(|_| {
            seen.insert(
                Seen::Bare(
                    Target {
                        address,
                        service: origin.0,
                        zone: origin.1,
                        pod_names,
                    },
                    port.port,
                ),
                0,
            )
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
        if port.has_srv() {
            let mut host_wire = [0; 255];
            let target = if ip.is_some() {
                endpoint
            } else {
                hostname(&address.ip, 0, &mut host_wire)?
            };
            if !duplicate_bare {
                snapshot.srv(base, target, port.port, weight(total))?;
            }
        }
        let duplicate_endpoint_address = seen
            .insert(
                Seen::EndpointAddress(Label(address, pod_names), CaseInsensitive(&address.ip)),
                0,
            )
            .is_some();
        if !duplicate_endpoint_address {
            snapshot.address(endpoint, &address.ip)?;
        }
        if !port.has_srv() {
            continue;
        }
        let mut host_wire = [0; 255];
        let target = if ip.is_some() {
            endpoint
        } else {
            hostname(&address.ip, 0, &mut host_wire)?
        };
        let duplicate_endpoint_srv = seen
            .insert(
                Seen::EndpointBare(
                    Target {
                        address,
                        service: origin.0,
                        zone: origin.1,
                        pod_names,
                    },
                    port.port,
                ),
                0,
            )
            .is_some();
        if !duplicate_endpoint_srv {
            snapshot.srv(endpoint, target, port.port, 100)?;
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

// RFC 1995 §2: current IXFR and UDP IXFR return only the current SOA.
fn soa_only(request: TransferRequest<'_>, current: u32) -> bool {
    request.qtype == Type::IXFR && serial_at_least(request.serial, current)
        || request.qtype == Type::IXFR && request.protocol == Protocol::Udp
}

fn scratch_capacity<'a>(
    index: &'a Index,
    services: impl Iterator<Item = &'a Service>,
    request: TransferRequest<'_>,
    current: u32,
    headless: bool,
) -> Result<usize, Error> {
    if soa_only(request, current) {
        return Ok(0);
    }
    let mut capacity = 0;
    for service in services {
        let needed = if headless && service.external_ips.is_empty() && service.headless() {
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
    Ok(capacity)
}

fn generate<'a>(
    snapshot: &mut Snapshot<'a>,
    plugin: &External,
    kubernetes: &Kubernetes,
    index: &'a Index,
    seen: &mut HashMap<Seen<'a>, usize>,
) -> Result<(), Error> {
    let current = index.external_serial();
    // RFC 1995 §2: a current IXFR is a single SOA; UDP IXFR returns the current SOA.
    if snapshot.request.qtype == Type::IXFR
        && serial_at_least(snapshot.request.serial, current)
        && snapshot.request.protocol == Protocol::Tcp
    {
        snapshot.authoritative = false;
    }
    snapshot.soa(current)?;
    if soa_only(snapshot.request, current) {
        return Ok(());
    }
    // RFC 1995 §6: An unknown requested version falls back to a full zone transfer.
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
                let zone = snapshot.request.zone;
                headless(
                    snapshot,
                    || entries(index, service),
                    base,
                    (service, zone),
                    kubernetes.endpoint_pod_names(),
                    seen,
                )?;
            } else {
                non_headless(snapshot, service, base, seen)?;
            }
        }
    }
    // RFC 5936 §2.2: end the AXFR response with the same SOA that begins it.
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
    let capacity = scratch_capacity(
        index,
        index.services_unfiltered(),
        request,
        index.external_serial(),
        plugin.config.headless,
    )?;
    // shortcut: allocate transfer scratch once; reuse immutable snapshots for incremental streaming.
    let mut seen = HashMap::new();
    if capacity > 0 {
        seen.try_reserve(capacity)
            .map_err(|_| Error::ResponseBufferTooSmall)?;
    }
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
        // RFC 1035 §3.7.1: only emit the Internet-class data this zone stores.
        if request.qclass != Class::IN {
            return Ok(None);
        }
        let Some(zone) = self.zones.iter().find(|zone| {
            NameRef::parse(zone.name.as_wire(), 0).is_ok_and(|name| name == request.zone)
        }) else {
            return Ok(None);
        };
        let kubernetes = self.kubernetes.as_ref().ok_or(Error::InvalidQuery)?;
        let store = kubernetes
            .store()
            .unwrap_or_else(|| self.empty_store.clone());
        // RFC 5936 §3: encode records from one immutable Store snapshot.
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
mod tests;

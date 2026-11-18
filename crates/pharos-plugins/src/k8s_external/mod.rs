//! External Kubernetes DNS names.

mod lookup;
mod scratch;
pub mod setup;
#[cfg(feature = "plugin-transfer")]
mod transfer;

use pharos_proto::{Class, MessageBuilder, Name, NameError, NameRef, Rcode, Section, Type};
use pharos_server::{Context, LookupResponse, Next, Outcome, Plugin};

pub struct External {
    config: setup::Config,
    zones: Vec<Zone>,
    kubernetes: Option<crate::kubernetes::Kubernetes>,
    empty_store: pharos_kubernetes::store::Store,
    fallthrough: Vec<Name>,
}

impl std::fmt::Debug for External {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("External")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Zone {
    name: Name,
    apex: Option<Name>,
    ns: Option<Name>,
    host: Option<Name>,
}

impl External {
    fn new(config: setup::Config) -> Result<Self, NameError> {
        let zones = config
            .zones
            .iter()
            .map(|zone| {
                let name = zone.parse()?;
                let suffix = if zone == "." { "" } else { zone };
                let apex = format!("{}.{}", config.apex, suffix).parse().ok();
                let ns = format!("ns1.{}.{}", config.apex, suffix).parse().ok();
                let host = format!("hostmaster.{}.{}", config.apex, suffix)
                    .parse()
                    .ok();
                Ok(Zone {
                    name,
                    apex,
                    ns,
                    host,
                })
            })
            .collect::<Result<_, NameError>>()?;
        let fallthrough = config
            .fallthrough
            .domains
            .iter()
            .map(|zone| zone.parse())
            .collect::<Result<_, _>>()?;
        Ok(Self {
            config,
            zones,
            kubernetes: None,
            empty_store: pharos_kubernetes::store::Store::default(),
            fallthrough,
        })
    }

    pub(crate) fn bind_kubernetes(&mut self, kubernetes: &crate::kubernetes::Kubernetes) {
        self.kubernetes = Some(kubernetes.clone());
    }

    fn reverse_response(
        &self,
        index: &pharos_kubernetes::store::Index,
        cx: &mut Context<'_, '_>,
        zone: &Zone,
        ip: &str,
    ) -> Option<Outcome> {
        let q = cx.query.questions().next()?;
        let services = || {
            index
                .services_by_external_ip_unfiltered(ip)
                // Pharos divergence from CoreDNS: PTR follows the forward namespace filter, including `namespace_labels`.
                .filter(|service| index.namespace_exposed(&service.namespace))
        };
        let code = if services().next().is_some() {
            pharos_proto::Rcode::NOERROR
        } else {
            pharos_proto::Rcode::NXDOMAIN
        };
        if code == pharos_proto::Rcode::NXDOMAIN
            && self.fallthrough.iter().any(|zone| contains(q.name, zone))
        {
            return None;
        }
        let (Some(ns), Some(host)) = (&zone.ns, &zone.host) else {
            return Some(Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL));
        };
        let max = cx.max_response_size.max(512);
        if cx.response.capacity() < max {
            if cx.protocol == pharos_server::Protocol::Tcp {
                cx.response.reserve(max - cx.response.len());
            } else {
                return Some(Outcome::Error(pharos_server::Error::ResponseBufferTooSmall));
            }
        }
        let result = (|| {
            // RFC 1035 §§4.1.1–4.1.2: set authoritative flags and repeat the Question.
            let mut b = MessageBuilder::new(
                cx.response,
                max,
                cx.query.id(),
                0x8400 | (cx.query.flags() & 0x7910) | code.0,
            )?;
            b.question(q.name, q.qtype, q.qclass)?;
            let mut answers = 0usize;
            let first_zone = NameRef::parse(self.zones[0].name.as_wire(), 0).unwrap();
            for service in services() {
                let mut wire = [0; 255];
                let Some(target) = child_name(
                    &[service.name.as_bytes(), service.namespace.as_bytes()],
                    first_zone,
                    &mut wire,
                ) else {
                    continue;
                };
                // RFC 1035 §3.3.12: PTR RDATA identifies the target domain name.
                if b.record_with(
                    Section::Answer,
                    q.name,
                    Type::PTR,
                    Class::IN,
                    self.config.ttl,
                    |w| w.write_name(target),
                )? {
                    answers += 1;
                }
            }
            // RFC 2308 §3: Authoritative negative responses include the zone SOA.
            if answers == 0 {
                write_soa(
                    &mut b,
                    NameRef::parse(zone.name.as_wire(), 0).unwrap(),
                    ns,
                    host,
                    self.config.ttl,
                    index.external_serial(),
                    Section::Authority,
                )?;
            }
            let _ = b.finish();
            Ok::<_, pharos_proto::BuildError>(())
        })();
        Some(match result {
            Ok(()) => Outcome::Response,
            Err(error) => Outcome::Error(pharos_server::Error::Build(error)),
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the borrowed lookup state stays on the Query stack"
    )]
    fn service_response(
        &self,
        cx: &mut Context<'_, '_>,
        zone: &Zone,
        kubernetes: &crate::kubernetes::Kubernetes,
        store: &pharos_kubernetes::store::Store,
        snapshot: Option<&lookup::Snapshot>,
        request: Option<&lookup::Request<'_>>,
        code: pharos_proto::Rcode,
        chased: &[Chased],
    ) -> Outcome {
        let Some(q) = cx.query.questions().next() else {
            return Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL);
        };
        let (code, target_authority) = if q.qtype != Type::SRV {
            final_response(code, chased)
        } else {
            (code, None)
        };
        let (Some(ns), Some(host)) = (&zone.ns, &zone.host) else {
            return Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL);
        };
        let zone_ref = NameRef::parse(zone.name.as_wire(), 0).unwrap();
        let serial = store.with_read(|index| index.external_serial());
        let max = cx.max_response_size.max(512);
        if cx.response.capacity() < max {
            if cx.protocol == pharos_server::Protocol::Tcp {
                cx.response.reserve(max - cx.response.len());
            } else {
                return Outcome::Error(pharos_server::Error::ResponseBufferTooSmall);
            }
        }
        let result = (|| {
            // RFC 1035 §§4.1.1–4.1.2: set authoritative flags and repeat the Question.
            let mut truncated = false;
            let mut b = MessageBuilder::new(
                cx.response,
                max,
                cx.query.id(),
                0x8400 | (cx.query.flags() & 0x7910) | code.0,
            )?;
            b.question(q.name, q.qtype, q.qclass)?;
            let mut answers = 0usize;
            if let Some(request) = request
                && matches!(q.qtype, Type::A | Type::AAAA)
            {
                let mut error = None;
                let mut scratch = scratch::lease();
                store.with_read(|index| {
                    let mut ordinal = 0usize;
                    lookup::snapshot_or_lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
                        snapshot,
                        |address, _, _| {
                            let current = ordinal;
                            ordinal += 1;
                            let entry = chased_at(chased, current, address);
                            if error.is_some() {
                                return;
                            }
                            let ip = match address.parse::<std::net::IpAddr>() {
                                Ok(std::net::IpAddr::V6(ip)) => ip
                                    .to_ipv4_mapped()
                                    .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
                                Ok(ip) => ip,
                                Err(_) => {
                                    if let Some(entry) = entry {
                                        let mut key = [0; 2048];
                                        let Some(key) =
                                            target_key(request, None, address, zone_ref, &mut key)
                                        else {
                                            return;
                                        };
                                        // RFC 1034 §3.6.2: emit one CNAME RR per target name.
                                        if !scratch.extra.insert(
                                            key,
                                            &entry.ordinal.to_be_bytes(),
                                            0,
                                        ) {
                                            return;
                                        }
                                        truncated |= entry.answers.iter().flatten().any(|wire| {
                                            pharos_proto::Message::parse(wire)
                                                .is_ok_and(|message| message.tc())
                                        });
                                        match write_chased(
                                            &mut b,
                                            q.name,
                                            entry,
                                            kubernetes.ttl(),
                                            Section::Answer,
                                        ) {
                                            Ok(true) => answers += 1,
                                            Ok(false) => {}
                                            Err(err) => error = Some(err),
                                        }
                                    }
                                    return;
                                }
                            };
                            if !scratch.addresses.insert(scratch::Address::new(address)) {
                                return;
                            }
                            // RFC 1035 §3.4.1 and RFC 3596 §2.2: address records use network byte order.
                            let result = match ip {
                                std::net::IpAddr::V4(ip) if q.qtype == Type::A => b.record(
                                    Section::Answer,
                                    q.name,
                                    Type::A,
                                    Class::IN,
                                    self.config.ttl,
                                    &ip.octets(),
                                ),
                                std::net::IpAddr::V6(ip) if q.qtype == Type::AAAA => b.record(
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
                                Err(err) => error = Some(err),
                            }
                        },
                    );
                });
                if let Some(error) = error {
                    return Err(error);
                }
                if let Some(message) = target_authority.as_ref() {
                    // RFC 2308 §3: append negative Authority after all CNAME-cycle answers.
                    crate::dns::copy_authorities(&mut b, message)?;
                }
            }
            // RFC 3596 §3: SRV answers include available target addresses in Additional.
            if let Some(request) = request
                && q.qtype == Type::SRV
            {
                let mut error = None;
                let mut scratch = scratch::lease();
                for (index, entry) in chased.iter().enumerate() {
                    let name = NameRef::parse(entry.name.as_wire(), 0).ok();
                    let mut wire = [0; 255];
                    if let Some(key) = name.and_then(|name| canonical_wire(name, &mut wire)) {
                        // RFC 4343 §3.1: canonical target labels index each chased result once.
                        let inserted =
                            scratch
                                .targets
                                .insert(key, index, response_has_address_target(entry));
                        debug_assert!(inserted);
                    }
                }
                store.with_read(|index| {
                    let mut count = 0usize;
                    lookup::snapshot_or_lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
                        snapshot,
                        |_, _, _| count += 1,
                    );
                    let weight = (100 / count.max(1)).max(1) as u16;
                    lookup::snapshot_or_lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
                        snapshot,
                        // Kubernetes DNS spec 1.1.0 §2.3.2: unnamed ports have no SRV record.
                        // RFC 2782 §The format of the SRV RR: targets need addresses and cannot be aliases.
                        |address, port, endpoint| {
                            if !port.has_srv() || error.is_some() {
                                return;
                            }
                            let mut target_wire = [0; 255];
                            let Some(target) = service_target(
                                request,
                                endpoint,
                                address,
                                zone_ref,
                                &mut target_wire,
                            ) else {
                                return;
                            };
                            let entry = chased_for_target(&scratch.targets, chased, target);
                            if !cached_has_address_target(address, entry) {
                                return;
                            }
                            let mut key = [0; 2048];
                            let Some(key) =
                                target_key(request, endpoint, address, zone_ref, &mut key)
                            else {
                                return;
                            };
                            if !scratch.srv.insert(key, b"", port.port as u16) {
                                return;
                            }
                            // RFC 2782 §The format of the SRV RR: priority, weight, port, target.
                            match b.record_with(
                                Section::Answer,
                                q.name,
                                Type::SRV,
                                Class::IN,
                                kubernetes.ttl(),
                                |w| {
                                    w.write_bytes(&0u16.to_be_bytes())?;
                                    w.write_bytes(&weight.to_be_bytes())?;
                                    w.write_bytes(&(port.port as u16).to_be_bytes())?;
                                    w.write_uncompressed_name(target)
                                },
                            ) {
                                Ok(true) => answers += 1,
                                Ok(false) => {}
                                Err(err) => error = Some(err),
                            }
                        },
                    );
                    // RFC 2782 §The format of the SRV RR: Add available target addresses.
                    lookup::snapshot_or_lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
                        snapshot,
                        |address, port, endpoint| {
                            if !port.has_srv() || error.is_some() {
                                return;
                            }
                            let mut target_wire = [0; 255];
                            let Some(target) = service_target(
                                request,
                                endpoint,
                                address,
                                zone_ref,
                                &mut target_wire,
                            ) else {
                                return;
                            };
                            let entry = chased_for_target(&scratch.targets, chased, target);
                            if !cached_has_address_target(address, entry) {
                                return;
                            }
                            let mut key = [0; 2048];
                            let Some(key) =
                                target_key(request, endpoint, address, zone_ref, &mut key)
                            else {
                                return;
                            };
                            let ip = match address.parse::<std::net::IpAddr>() {
                                Ok(std::net::IpAddr::V6(ip)) => Some(
                                    ip.to_ipv4_mapped()
                                        .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
                                ),
                                Ok(ip) => Some(ip),
                                Err(_) => None,
                            };
                            let addr = if ip.is_some() {
                                address.as_bytes()
                            } else {
                                key
                            };
                            if !scratch.extra.insert(key, addr, 0) {
                                return;
                            }
                            let Some(ip) = ip else {
                                let Some((entry, _)) = entry else {
                                    return;
                                };
                                if let Err(err) = write_chased(
                                    &mut b,
                                    q.name,
                                    entry,
                                    kubernetes.ttl(),
                                    Section::Additional,
                                ) {
                                    error = Some(err);
                                }
                                return;
                            };
                            let result = match ip {
                                std::net::IpAddr::V4(ip) => b.record(
                                    Section::Additional,
                                    target,
                                    Type::A,
                                    Class::IN,
                                    self.config.ttl,
                                    &ip.octets(),
                                ),
                                std::net::IpAddr::V6(ip) => b.record(
                                    Section::Additional,
                                    target,
                                    Type::AAAA,
                                    Class::IN,
                                    self.config.ttl,
                                    &ip.octets(),
                                ),
                            };
                            if let Err(err) = result {
                                error = Some(err);
                            }
                        },
                    );
                });
                if let Some(error) = error {
                    return Err(error);
                }
            }
            // RFC 2308 §3: Authoritative negative responses include the zone SOA.
            if answers == 0 {
                write_soa(
                    &mut b,
                    zone_ref,
                    ns,
                    host,
                    self.config.ttl,
                    serial,
                    Section::Authority,
                )?;
            }
            let _ = b.finish();
            // RFC 1035 §4.1.1: preserve TC from a followed CNAME Response.
            if truncated {
                cx.response[2] |= 0x02;
            }
            Ok::<_, pharos_proto::BuildError>(())
        })();
        match result {
            Ok(()) => Outcome::Response,
            Err(error) => Outcome::Error(pharos_server::Error::Build(error)),
        }
    }
}

struct Chased {
    ordinal: usize,
    name: Name,
    answers: [Option<Vec<u8>>; 2],
}

#[cfg(test)]
fn final_rcode(initial: Rcode, chased: &[Chased]) -> Rcode {
    final_response(initial, chased).0
}

fn final_response<'a>(
    initial: Rcode,
    chased: &'a [Chased],
) -> (Rcode, Option<pharos_proto::Message<'a>>) {
    let mut final_code = initial;
    let mut authority = None;
    for entry in chased {
        let Some(wire) = entry.answers[0].as_deref() else {
            final_code = Rcode::SERVFAIL;
            authority = None;
            continue;
        };
        let Ok(message) = pharos_proto::Message::parse(wire) else {
            final_code = Rcode::SERVFAIL;
            authority = None;
            continue;
        };
        final_code = message.rcode();
        // RFC 6604 §3: successful chased answers produce a NOERROR response.
        if final_code == Rcode::NOERROR && message.answer_count() > 0 {
            return (Rcode::NOERROR, None);
        }
        authority = Some(message);
    }
    (final_code, authority)
}

fn chased_matches(address: &str, name: &Name) -> bool {
    let mut wire = [0; 255];
    let Ok(expected) = NameRef::parse(name.as_wire(), 0) else {
        return false;
    };
    // RFC 4343 §3.1: compare DNS labels with ASCII-only case folding.
    hostname(address, &mut wire).is_some_and(|target| {
        target.labels().count() == expected.labels().count()
            && target
                .labels()
                .zip(expected.labels())
                .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
    })
}

// RFC 4343 §3.1: canonical DNS-name keys fold only ASCII letter case.
fn canonical_wire<'a>(name: NameRef<'_>, wire: &'a mut [u8; 255]) -> Option<&'a [u8]> {
    let mut len = 0;
    for label in name.labels() {
        if len + label.len() + 2 > wire.len() {
            return None;
        }
        wire[len] = label.len() as u8;
        len += 1;
        for byte in label {
            wire[len] = byte.to_ascii_lowercase();
            len += 1;
        }
    }
    wire[len] = 0;
    Some(&wire[..len + 1])
}

// RFC 1034 §4.3.2: retain each CNAME target response with its query cycle.
fn chased_at<'a>(chased: &'a [Chased], ordinal: usize, address: &str) -> Option<&'a Chased> {
    let index = chased
        .binary_search_by_key(&ordinal, |entry| entry.ordinal)
        .ok()?;
    let entry = &chased[index];
    chased_matches(address, &entry.name).then_some(entry)
}

fn chased_for_target<'a>(
    targets: &scratch::Targets,
    chased: &'a [Chased],
    target: NameRef<'_>,
) -> Option<(&'a Chased, bool)> {
    // RFC 4343 §3.1: canonical target labels avoid per-callback wire reparsing.
    let mut wire = [0; 255];
    let key = canonical_wire(target, &mut wire)?;
    let (index, has_address) = targets.get(key)?;
    Some((chased.get(index)?, has_address))
}

// RFC 2782 §The format of the SRV RR: SRV targets must resolve to addresses and not aliases.
fn response_has_address_target(chased: &Chased) -> bool {
    let mut found_address = false;
    for wire in chased.answers.iter().flatten() {
        let Ok(message) = pharos_proto::Message::parse(wire) else {
            continue;
        };
        for record in message.answers() {
            if record.rtype == Type::CNAME {
                return false;
            }
            found_address |= matches!(record.rtype, Type::A | Type::AAAA);
        }
    }
    found_address
}

fn cached_has_address_target(address: &str, chased: Option<(&Chased, bool)>) -> bool {
    // RFC 2782 §The format of the SRV RR: use only targets with a non-alias address RRset.
    if address.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    chased.is_some_and(|(_, has_address)| has_address)
}

#[cfg(test)]
fn has_address_target(address: &str, chased: Option<&Chased>) -> bool {
    address.parse::<std::net::IpAddr>().is_ok() || chased.is_some_and(response_has_address_target)
}

fn write_chased(
    b: &mut MessageBuilder<'_>,
    owner: NameRef<'_>,
    entry: &Chased,
    ttl: u32,
    section: Section,
) -> Result<bool, pharos_proto::BuildError> {
    let mut written = false;
    if section == Section::Answer {
        let target = NameRef::parse(entry.name.as_wire(), 0).unwrap();
        // RFC 1035 §3.3.1: CNAME RDATA identifies the canonical name.
        written = b.record_with(section, owner, Type::CNAME, Class::IN, ttl, |w| {
            w.write_name(target)
        })?;
    }
    for wire in entry.answers.iter().flatten() {
        if let Ok(message) = pharos_proto::Message::parse(wire) {
            for record in message.answers() {
                if let Ok(data) = record.data() {
                    b.record_with(
                        section,
                        record.name,
                        record.rtype,
                        record.class,
                        record.ttl,
                        |w| data.write(w),
                    )?;
                }
            }
        }
    }
    Ok(written)
}

fn target_key<'a>(
    request: &lookup::Request<'_>,
    endpoint: Option<&[u8]>,
    address: &str,
    zone: NameRef<'_>,
    buffer: &'a mut [u8],
) -> Option<&'a [u8]> {
    let mut len = 0;
    let mut append = |bytes: &[u8]| {
        let end = len + bytes.len();
        buffer.get_mut(len..end)?.copy_from_slice(bytes);
        len = end;
        Some(())
    };
    if address.parse::<std::net::IpAddr>().is_err() {
        append(address.as_bytes())?;
        if !is_fqdn(address.as_bytes()) {
            append(b".")?;
        }
    } else {
        if let Some(endpoint) = endpoint.filter(|endpoint| !endpoint.is_empty()) {
            append(endpoint)?;
            append(b".")?;
        }
        for label in [request.service, request.namespace]
            .into_iter()
            .chain(zone.labels())
        {
            append(label)?;
            append(b".")?;
        }
    }
    Some(&buffer[..len])
}

fn service_target<'a>(
    request: &lookup::Request<'_>,
    endpoint: Option<&[u8]>,
    address: &str,
    zone: NameRef<'_>,
    wire: &'a mut [u8; 255],
) -> Option<NameRef<'a>> {
    if address.parse::<std::net::IpAddr>().is_err() {
        return hostname(address, wire);
    }
    let mut prefix = [0u8; 255];
    let mut text = [0u8; 1024];
    let endpoint = endpoint.unwrap_or_default();
    let labels = if endpoint.is_empty() {
        None
    } else {
        if endpoint.len() >= text.len() {
            return None;
        }
        text[..endpoint.len()].copy_from_slice(endpoint);
        let length = if is_fqdn(endpoint) {
            endpoint.len()
        } else {
            text[endpoint.len()] = b'.';
            endpoint.len() + 1
        };
        let parsed =
            Name::parse_absolute_into(std::str::from_utf8(&text[..length]).ok()?, &mut prefix)
                .ok()?;
        Some(NameRef::parse(parsed, 0).ok()?)
    };
    let mut pos = 0;
    // RFC 1035 §3.1: concatenate endpoint, service, namespace, and zone labels.
    for label in labels
        .iter()
        .flat_map(|name| name.labels())
        .chain([request.service, request.namespace])
        .chain(zone.labels())
    {
        if label.is_empty() || label.len() > 63 || pos + label.len() + 2 > wire.len() {
            return None;
        }
        wire[pos] = label.len() as u8;
        pos += 1;
        wire[pos..pos + label.len()].copy_from_slice(label);
        pos += label.len();
    }
    wire[pos] = 0;
    NameRef::parse(&wire[..=pos], 0).ok()
}

fn hostname<'a>(address: &str, wire: &'a mut [u8; 255]) -> Option<NameRef<'a>> {
    let mut text = [0u8; 1024];
    let bytes = address.as_bytes();
    if bytes.len() >= text.len() {
        return None;
    }
    text[..bytes.len()].copy_from_slice(bytes);
    let length = if is_fqdn(bytes) {
        bytes.len()
    } else {
        text[bytes.len()] = b'.';
        bytes.len() + 1
    };
    let result =
        Name::parse_absolute_into(std::str::from_utf8(&text[..length]).ok()?, wire).ok()?;
    NameRef::parse(result, 0).ok()
}

fn is_fqdn(bytes: &[u8]) -> bool {
    let Some((&b'.', prefix)) = bytes.split_last() else {
        return false;
    };
    // RFC 1035 §5.1: a terminal dot is literal when preceded by an odd number of escapes.
    prefix
        .iter()
        .rev()
        .take_while(|&&byte| byte == b'\\')
        .count()
        % 2
        == 0
}

fn child_name<'a>(
    labels: &[&[u8]],
    zone: NameRef<'_>,
    wire: &'a mut [u8; 255],
) -> Option<NameRef<'a>> {
    let mut pos = 0;
    // RFC 1035 §3.1: each wire name is limited to 255 octets.
    for label in labels
        .iter()
        .copied()
        .filter(|label| !label.is_empty())
        .chain(zone.labels())
    {
        if label.len() > 63 || pos + label.len() + 2 > wire.len() {
            return None;
        }
        wire[pos] = label.len() as u8;
        pos += 1;
        wire[pos..pos + label.len()].copy_from_slice(label);
        pos += label.len();
    }
    wire[pos] = 0;
    NameRef::parse(&wire[..=pos], 0).ok()
}

impl Plugin for External {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        match self.answer(cx).await {
            Some(outcome) => outcome,
            None => next.run(cx).await,
        }
    }
}

impl External {
    async fn answer(&self, cx: &mut Context<'_, '_>) -> Option<Outcome> {
        let q = cx.query.questions().next()?;
        // RFC 1034 §4.3.2: Answer from the nearest authoritative ancestor zone.
        let zone = self
            .zones
            .iter()
            .filter(|zone| contains(q.name, &zone.name))
            .max_by_key(|zone| zone.name.label_count())?;
        let zone_ref = NameRef::parse(zone.name.as_wire(), 0).unwrap();
        let is_apex = q.name == zone_ref;
        let subapex = self.zones.iter().any(|candidate| {
            candidate
                .apex
                .as_ref()
                .is_some_and(|name| contains(q.name, name))
        });
        if !is_apex && !subapex {
            let Some(kubernetes) = &self.kubernetes else {
                return Some(Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL));
            };
            let store = kubernetes
                .store()
                .unwrap_or_else(|| self.empty_store.clone());
            let mut wire = [0u8; 255];
            let mut n = 0;
            // RFC 1035 §2.3.3: DNS name comparisons ignore ASCII letter case.
            for label in q.name.labels() {
                wire[n] = label.len() as u8;
                n += 1;
                for byte in label {
                    wire[n] = byte.to_ascii_lowercase();
                    n += 1;
                }
            }
            let normalized = NameRef::parse(&wire[..=n], 0).unwrap();
            let mut labels = [&[][..]; 127];
            let relative = normalized.labels().count() - zone.name.label_count();
            for (slot, label) in labels.iter_mut().zip(normalized.labels()) {
                *slot = label;
            }
            // RFC 1035 §3.5 and RFC 3596 §2.5: Reverse names encode octets or nibbles in reverse.
            let reverse_ip = if q.qtype == Type::PTR {
                crate::kubernetes::reverse::address(&labels[..normalized.labels().count()])
                    .map(crate::kubernetes::scratch::IpText::new)
            } else {
                None
            };
            if let Some(ip) = &reverse_ip {
                return store
                    .with_read(|index| self.reverse_response(index, cx, zone, ip.as_str()));
            }
            let request = lookup::parse(&labels[..relative]);
            // shortcut: hostname targets and detached Self Lookup results allocate per Query; buffers and future are pooled, see #86.
            let mut chased: Vec<Chased> = Vec::new();
            let (snapshot, code) = match &request {
                Ok(request) if matches!(q.qtype, Type::A | Type::AAAA | Type::SRV) => store
                    .with_read(|index| {
                        let snapshot = lookup::capture(index, request, self.config.headless);
                        let mut scratch = scratch::lease();
                        let mut ordinal = 0;
                        let code = lookup::snapshot_or_lookup(
                            index,
                            request,
                            self.config.headless,
                            kubernetes.endpoint_pod_names(),
                            Some(&snapshot),
                            |address, port, _| {
                                let current = ordinal;
                                ordinal += 1;
                                if address.parse::<std::net::IpAddr>().is_ok()
                                    || q.qtype == Type::SRV && !port.has_srv()
                                {
                                    return;
                                }
                                let mut wire = [0; 255];
                                if let Some(target) =
                                    service_target(request, None, address, zone_ref, &mut wire)
                                    && let Ok(name) = target.to_string().parse::<Name>()
                                    && (q.qtype != Type::SRV || {
                                        let mut key = [0; 255];
                                        canonical_wire(target, &mut key)
                                            .is_some_and(|key| scratch.extra.insert(key, b"", 0))
                                    })
                                {
                                    chased.push(Chased {
                                        ordinal: current,
                                        name,
                                        answers: [None, None],
                                    });
                                }
                            },
                        );
                        (Some(snapshot), code)
                    }),
                Ok(request) => (
                    None,
                    store.with_read(|index| {
                        lookup::lookup(
                            index,
                            request,
                            self.config.headless,
                            kubernetes.endpoint_pod_names(),
                            |_, _, _| {},
                        )
                    }),
                ),
                Err(code) => (None, *code),
            };
            if code == pharos_proto::Rcode::NXDOMAIN
                && self.fallthrough.iter().any(|zone| contains(q.name, zone))
            {
                return None;
            }
            for entry in &mut chased {
                let lookup = cx
                    .self_lookup(
                        &entry.name,
                        if q.qtype == Type::SRV {
                            Type::A
                        } else {
                            q.qtype
                        },
                    )
                    .await;
                entry.answers[0] =
                    Some(lookup.map_or_else(|_| Vec::new(), LookupResponse::into_vec));
                if q.qtype == Type::SRV {
                    entry.answers[1] = cx
                        .self_lookup(&entry.name, Type::AAAA)
                        .await
                        .ok()
                        .map(LookupResponse::into_vec);
                }
            }
            return Some(self.service_response(
                cx,
                zone,
                kubernetes,
                &store,
                snapshot.as_ref(),
                request.as_ref().ok(),
                code,
                &chased,
            ));
        }
        let relative = q.name.labels().count() - zone.name.label_count();
        let ns_subdomain = subapex
            && relative == 2
            && q.name
                .labels()
                .next()
                .is_some_and(|label| label.eq_ignore_ascii_case(b"ns1"));
        let code = if subapex && !is_apex && (relative > 2 || relative == 2 && !ns_subdomain) {
            pharos_proto::Rcode::NXDOMAIN
        } else {
            pharos_proto::Rcode::NOERROR
        };
        let Some(kubernetes) = &self.kubernetes else {
            return Some(Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL));
        };
        let store = kubernetes
            .store()
            .unwrap_or_else(|| self.empty_store.clone());
        let serial = store.with_read(|index| index.external_serial());
        let (Some(ns), Some(host)) = (&zone.ns, &zone.host) else {
            return Some(Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL));
        };
        let max = cx.max_response_size.max(512);
        if cx.response.capacity() < max {
            if cx.protocol == pharos_server::Protocol::Tcp {
                cx.response.reserve(max - cx.response.len());
            } else {
                return Some(Outcome::Error(pharos_server::Error::ResponseBufferTooSmall));
            }
        }
        let result = (|| {
            // RFC 1035 §4.1.1: authoritative Responses preserve the query ID and question.
            let mut b = MessageBuilder::new(
                cx.response,
                max,
                cx.query.id(),
                0x8400 | (cx.query.flags() & 0x7910) | code.0,
            )?;
            b.question(q.name, q.qtype, q.qclass)?;
            if is_apex && q.qtype == Type::NS {
                // RFC 1035 §3.3.11: NS RDATA names the authoritative nameserver.
                let ns_ref = NameRef::parse(ns.as_wire(), 0).unwrap();
                b.record_with(
                    Section::Answer,
                    zone_ref,
                    Type::NS,
                    Class::IN,
                    self.config.ttl,
                    |w| w.write_name(ns_ref),
                )?;
                let mut err = None;
                // RFC 3596 §3: Include only available nameserver address records in Additional.
                store.with_read(|index| {
                    kubernetes.visit_external_ns(index, self.config.headless, |ip| {
                        let result = match ip {
                            Some(std::net::IpAddr::V4(ip)) => b.record(
                                Section::Additional,
                                ns_ref,
                                Type::A,
                                Class::IN,
                                self.config.ttl,
                                &ip.octets(),
                            ),
                            Some(std::net::IpAddr::V6(ip)) => b.record(
                                Section::Additional,
                                ns_ref,
                                Type::AAAA,
                                Class::IN,
                                self.config.ttl,
                                &ip.octets(),
                            ),
                            None => return,
                        };
                        if let Err(error) = result {
                            err = Some(error);
                        }
                    })
                });
                if let Some(error) = err {
                    return Err(error);
                }
            } else if ns_subdomain && matches!(q.qtype, Type::A | Type::AAAA) {
                // RFC 3596 §2.2: an AAAA RR must contain a 128-bit IPv6 address.
                let mut err = None;
                let mut answers = 0;
                store.with_read(|index| {
                    kubernetes.visit_external_ns(index, self.config.headless, |ip| {
                        let result = match ip {
                            Some(std::net::IpAddr::V4(ip)) if q.qtype == Type::A => b.record(
                                Section::Answer,
                                q.name,
                                Type::A,
                                Class::IN,
                                self.config.ttl,
                                &ip.octets(),
                            ),
                            Some(std::net::IpAddr::V6(ip)) if q.qtype == Type::AAAA => b.record(
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
                            Err(error) => err = Some(error),
                        }
                    })
                });
                if let Some(error) = err {
                    return Err(error);
                }
                // RFC 2181 §7.1: Put an authoritative SOA in the Authority section.
                if answers == 0 {
                    // RFC 2308 §2.2.1: Authoritative NODATA includes SOA without NS records.
                    write_soa(
                        &mut b,
                        zone_ref,
                        ns,
                        host,
                        self.config.ttl,
                        serial,
                        Section::Authority,
                    )?;
                }
            } else {
                // RFC 2308 §3: Authoritative negative responses include the zone SOA.
                write_soa(
                    &mut b,
                    zone_ref,
                    ns,
                    host,
                    self.config.ttl,
                    serial,
                    if is_apex && q.qtype == Type::SOA {
                        Section::Answer
                    } else {
                        Section::Authority
                    },
                )?;
            }
            let _ = b.finish();
            Ok::<_, pharos_proto::BuildError>(())
        })();
        Some(match result {
            Ok(()) => Outcome::Response,
            Err(error) => Outcome::Error(pharos_server::Error::Build(error)),
        })
    }
}

fn write_soa(
    b: &mut MessageBuilder<'_>,
    zone: NameRef<'_>,
    ns: &Name,
    host: &Name,
    ttl: u32,
    serial: u32,
    section: Section,
) -> Result<(), pharos_proto::BuildError> {
    // RFC 1035 §3.3.13: SOA RDATA holds the names, serial, and timers.
    b.record_with(section, zone, Type::SOA, Class::IN, ttl, |w| {
        w.write_name(NameRef::parse(ns.as_wire(), 0).unwrap())?;
        w.write_name(NameRef::parse(host.as_wire(), 0).unwrap())?;
        for number in [serial, 7200, 1800, 86400, ttl] {
            w.write_bytes(&number.to_be_bytes())?;
        }
        Ok(())
    })?;
    Ok(())
}

// RFC 1035 §2.3.3: DNS name comparisons ignore ASCII letter case.
fn contains(name: NameRef<'_>, zone: &Name) -> bool {
    let parent = NameRef::parse(zone.as_wire(), 0).unwrap();
    let count = name.labels().count();
    let parent_count = parent.labels().count();
    count >= parent_count
        && name
            .labels()
            .skip(count - parent_count)
            .zip(parent.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

#[cfg(test)]
mod tests;

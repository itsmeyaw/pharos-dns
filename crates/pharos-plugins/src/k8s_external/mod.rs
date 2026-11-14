//! External Kubernetes DNS names.

mod lookup;
mod scratch;
pub mod setup;
#[cfg(feature = "plugin-transfer")]
mod transfer;

use pharos_proto::{Class, MessageBuilder, Name, NameError, NameRef, Section, Type};
use pharos_server::{Context, Next, Outcome, Plugin};

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
        kubernetes: &crate::kubernetes::Kubernetes,
        ip: &str,
    ) -> Option<Outcome> {
        let q = cx.query.questions().next()?;
        let services = || {
            index
                .services_by_external_ip_unfiltered(ip)
                .filter(|service| {
                    !kubernetes.has_namespace_filter()
                        || index.namespace_exposed(&service.namespace)
                })
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
                    let mut chased = chased.iter().peekable();
                    lookup::snapshot_or_lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
                        snapshot,
                        |address, _, _| {
                            let current = ordinal;
                            ordinal += 1;
                            let entry = chased_at(&mut chased, current, address);
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
            }
            // RFC 3596 §3: SRV answers include available target addresses in Additional.
            if let Some(request) = request
                && q.qtype == Type::SRV
            {
                let mut error = None;
                let mut scratch = scratch::lease();
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
                        // KEP-752 §Endpoint Port: The EndpointSlice port applies to all endpoints.
                        |address, port, endpoint| {
                            if port.port < 0 || error.is_some() {
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
                    let mut ordinal = 0usize;
                    let mut chased = chased.iter().peekable();
                    // RFC 2782 §The format of the SRV RR: Add available target addresses.
                    lookup::snapshot_or_lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
                        snapshot,
                        |address, port, endpoint| {
                            let current = ordinal;
                            ordinal += 1;
                            let entry = chased_at(&mut chased, current, address);
                            if port.port < 0 || error.is_some() {
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
                                if let Some(entry) = entry
                                    && let Err(err) = write_chased(
                                        &mut b,
                                        q.name,
                                        entry,
                                        kubernetes.ttl(),
                                        Section::Additional,
                                    )
                                {
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

fn chased_at<'a>(
    chased: &mut std::iter::Peekable<std::slice::Iter<'a, Chased>>,
    ordinal: usize,
    address: &str,
) -> Option<&'a Chased> {
    while chased.peek().is_some_and(|entry| entry.ordinal < ordinal) {
        chased.next();
    }
    if chased.peek().is_some_and(|entry| entry.ordinal == ordinal) {
        chased.next().filter(|entry| {
            let mut wire = [0; 255];
            let Ok(expected) = NameRef::parse(entry.name.as_wire(), 0) else {
                return false;
            };
            // RFC 4343 §4.1: preserve the case of label octets when matching the captured target.
            hostname(address, &mut wire).is_some_and(|target| target.labels().eq(expected.labels()))
        })
    } else {
        None
    }
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
                return store.with_read(|index| {
                    self.reverse_response(index, cx, zone, kubernetes, ip.as_str())
                });
            }
            let request = lookup::parse(&labels[..relative]);
            // shortcut: hostname targets and Self Lookups allocate per Query until #86 pools buffers and futures.
            let mut chased = Vec::new();
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
                                    || q.qtype == Type::SRV && port.port < 0
                                {
                                    return;
                                }
                                let mut wire = [0; 255];
                                if let Some(target) =
                                    service_target(request, None, address, zone_ref, &mut wire)
                                    && let Ok(name) = target.to_string().parse::<Name>()
                                    && (q.qtype != Type::SRV || {
                                        let mut key = [0; 2048];
                                        target_key(request, None, address, zone_ref, &mut key)
                                            .is_some_and(|key| scratch.extra.insert(key, key, 0))
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
                entry.answers[0] = cx
                    .self_lookup(
                        &entry.name,
                        if q.qtype == Type::SRV {
                            Type::A
                        } else {
                            q.qtype
                        },
                    )
                    .await
                    .ok();
                if q.qtype == Type::SRV {
                    entry.answers[1] = cx.self_lookup(&entry.name, Type::AAAA).await.ok();
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
                // RFC 3596 §3: NS answers include available nameserver addresses in Additional.
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
                            None => b.record(
                                Section::Additional,
                                ns_ref,
                                Type::AAAA,
                                Class::IN,
                                self.config.ttl,
                                &[],
                            ),
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
                            None if q.qtype == Type::AAAA => b.record(
                                Section::Answer,
                                q.name,
                                Type::AAAA,
                                Class::IN,
                                self.config.ttl,
                                &[],
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
mod tests {
    use super::*;
    use pharos_corefile::{Cursor, parse};
    use pharos_proto::{Class, Message, MessageBuilder, NameRef, Rcode, Rdata, Type};
    use pharos_server::{Metadata, Protocol, Transport};

    struct Sentinel;
    impl Next for Sentinel {
        async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
            Outcome::Unanswered(Rcode::REFUSED)
        }
    }

    async fn assert_reverse_snapshot(
        kubernetes: &crate::kubernetes::Kubernetes,
        store: &pharos_kubernetes::store::Store,
    ) {
        assert!(kubernetes.has_namespace_filter());
        store.with_read(|index| {
            assert_eq!(
                index
                    .services_by_external_ip_unfiltered("192.0.2.1")
                    .count(),
                2
            );
            assert_eq!(
                index
                    .services_by_external_ip_unfiltered("192.0.2.3")
                    .count(),
                1
            );
            assert!(!index.namespace_exposed("secret"));
        });
        let blocks = parse(
            "Corefile",
            ".:53 {\n k8s_external example.com in-addr.arpa\n}",
        )
        .unwrap();
        let config = setup::parse(
            &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
            &["."],
        )
        .unwrap();
        let mut external = External::new(config).unwrap();
        external.bind_kubernetes(kubernetes);
        let zone: Name = "in-addr.arpa.".parse().unwrap();
        let name: Name = "1.2.0.192.in-addr.arpa.".parse().unwrap();
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::PTR,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        let empty = pharos_kubernetes::store::Store::default();
        for (index_store, fallthrough, expected) in [
            (store, false, Some(Rcode::NOERROR)),
            (&empty, false, Some(Rcode::NXDOMAIN)),
            (&empty, true, None),
            (store, true, Some(Rcode::NOERROR)),
        ] {
            external.fallthrough = if fallthrough {
                vec![zone.clone()]
            } else {
                vec![]
            };
            let mut response = Vec::with_capacity(512);
            let mut slots = [None; 8];
            let mut cx = Context {
                query: Message::parse(&query).unwrap(),
                client: "127.0.0.1:1234".parse().unwrap(),
                local: "127.0.0.1:53".parse().unwrap(),
                transport: Transport::Dns,
                protocol: Protocol::Udp,
                domain: &zone,
                metadata: Metadata::new(&mut slots),
                response: &mut response,
                max_response_size: 512,
            };
            let outcome = index_store.with_read(|index| {
                external.reverse_response(
                    index,
                    &mut cx,
                    &external.zones[1],
                    kubernetes,
                    "192.0.2.1",
                )
            });
            if let Some(code) = expected {
                assert!(matches!(outcome, Some(Outcome::Response)));
                let message = Message::parse(&response).unwrap();
                assert_eq!(message.rcode(), code);
                if code == Rcode::NOERROR {
                    assert_eq!(message.answer_count(), 1);
                    let Rdata::Ptr(target) = message.answers().next().unwrap().data().unwrap()
                    else {
                        panic!("expected PTR")
                    };
                    assert_eq!(target.to_string(), "web.prod.example.com.");
                } else {
                    assert_eq!(message.answer_count(), 0);
                    let Rdata::Soa { serial, .. } =
                        message.authorities().next().unwrap().data().unwrap()
                    else {
                        panic!("expected SOA")
                    };
                    assert_eq!(
                        serial,
                        index_store.with_read(|index| index.external_serial())
                    );
                }
            } else {
                assert!(outcome.is_none());
                assert!(response.is_empty());
            }
        }
        for (name, fallthrough, expected) in [
            ("1.2.0.192.in-addr.arpa.", false, Some(Rcode::NOERROR)),
            ("3.2.0.192.in-addr.arpa.", false, Some(Rcode::NXDOMAIN)),
            ("3.2.0.192.in-addr.arpa.", true, None),
        ] {
            external.fallthrough = if fallthrough {
                vec![zone.clone()]
            } else {
                vec![]
            };
            let name: Name = name.parse().unwrap();
            query.clear();
            let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
            builder
                .question(
                    NameRef::parse(name.as_wire(), 0).unwrap(),
                    Type::PTR,
                    Class::IN,
                )
                .unwrap();
            let _ = builder.finish();
            let mut response = Vec::with_capacity(512);
            let mut slots = [None; 8];
            let mut cx = Context {
                query: Message::parse(&query).unwrap(),
                client: "127.0.0.1:1234".parse().unwrap(),
                local: "127.0.0.1:53".parse().unwrap(),
                transport: Transport::Dns,
                protocol: Protocol::Udp,
                domain: &zone,
                metadata: Metadata::new(&mut slots),
                response: &mut response,
                max_response_size: 512,
            };
            let outcome = external.answer(&mut cx).await;
            if let Some(code) = expected {
                assert!(matches!(outcome, Some(Outcome::Response)));
                let message = Message::parse(&response).unwrap();
                assert_eq!(message.rcode(), code);
                assert_eq!(message.answer_count(), u16::from(code == Rcode::NOERROR));
            } else {
                assert!(outcome.is_none());
            }
        }
    }

    #[test]
    fn hostname_fqdn_handles_escaped_final_dot() {
        let mut wire = [0; 255];
        assert_eq!(
            hostname(r"example\.", &mut wire).unwrap().to_string(),
            r"example\.."
        );
        assert_eq!(
            hostname(r"example\\.", &mut wire).unwrap().to_string(),
            r"example\\."
        );
    }

    #[tokio::test]
    async fn headless_query_retains_service_and_slices_during_hostname_chase() {
        use pharos_corefile::configure;
        use pharos_server::{
            Action, Chain as ServerChain, Handler, ListenerKey, Phase, Router, Server,
        };
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::sync::{Notify, Semaphore, broadcast};

        enum TestChain {
            External(Box<External>),
            Target {
                started: Arc<Notify>,
                resume: Arc<Semaphore>,
            },
        }
        impl ServerChain for TestChain {
            async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
                match self {
                    Self::External(external) => external.serve(cx, Sentinel).await,
                    Self::Target { started, resume } => {
                        started.notify_one();
                        resume.acquire().await.unwrap().forget();
                        let q = cx.query.questions().next().unwrap();
                        let mut b =
                            MessageBuilder::new(cx.response, 65535, cx.query.id(), 0x8000).unwrap();
                        b.question(q.name, q.qtype, q.qclass).unwrap();
                        b.record(
                            Section::Answer,
                            q.name,
                            Type::A,
                            Class::IN,
                            30,
                            &[203, 0, 113, 1],
                        )
                        .unwrap();
                        let _ = b.finish();
                        Outcome::Response
                    }
                }
            }
            fn is_empty(&self) -> bool {
                false
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (services, _) = broadcast::channel::<&'static str>(4);
        let (slices, _) = broadcast::channel::<&'static str>(4);
        let service_ready = Arc::new(Notify::new());
        let slice_ready = Arc::new(Notify::new());
        let api = tokio::spawn({
            let services = services.clone();
            let slices = slices.clone();
            let service_ready = service_ready.clone();
            let slice_ready = slice_ready.clone();
            async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let services = services.clone();
                    let slices = slices.clone();
                    let service_ready = service_ready.clone();
                    let slice_ready = slice_ready.clone();
                    tokio::spawn(async move {
                        let mut request = [0; 4096];
                        let n = socket.read(&mut request).await.unwrap();
                        let request = String::from_utf8_lossy(&request[..n]);
                        let is_service = request.contains("/services");
                        let is_slice = request.contains("/endpointslices");
                        if request.contains("watch=true") {
                            if !is_service && !is_slice {
                                let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").await;
                                let _ = socket.read(&mut [0; 1]).await;
                                return;
                            }
                            let mut rx = if is_service {
                                services.subscribe()
                            } else {
                                slices.subscribe()
                            };
                            if socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").await.is_err() { return; }
                            if is_service {
                                service_ready.notify_one();
                            } else if is_slice {
                                slice_ready.notify_one();
                            }
                            while let Ok(event) = rx.recv().await {
                                let chunk = format!("{:x}\r\n{}\r\n", event.len(), event);
                                if socket.write_all(chunk.as_bytes()).await.is_err() {
                                    break;
                                }
                            }
                            return;
                        }
                        let (kind, items) = if is_service {
                            (
                                "ServiceList",
                                r#"[{"metadata":{"name":"head","namespace":"prod","resourceVersion":"1"},"spec":{"clusterIP":"None"}}]"#,
                            )
                        } else if is_slice {
                            (
                                "EndpointSliceList",
                                r#"[{"metadata":{"name":"head-1","namespace":"prod","resourceVersion":"1","labels":{"kubernetes.io/service-name":"head"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.1"],"hostname":"pod1"},{"addresses":["lb.target.test"],"hostname":"pod2"},{"addresses":["192.0.2.2"],"hostname":"pod3"}],"ports":[{"name":"http","protocol":"TCP","port":80},{"name":"https","protocol":"TCP","port":443}]}]"#,
                            )
                        } else {
                            (
                                "NamespaceList",
                                r#"[{"metadata":{"name":"prod","resourceVersion":"1"}}]"#,
                            )
                        };
                        let body = format!(
                            r#"{{"apiVersion":"v1","kind":"{kind}","metadata":{{"resourceVersion":"1"}},"items":{items}}}"#
                        );
                        let reply = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = socket.write_all(reply.as_bytes()).await;
                    });
                }
            }
        });
        let text = format!(
            ".:53 {{\n kubernetes cluster.local {{\n  endpoint http://{address}\n  startup_timeout 3s\n }}\n}}"
        );
        let chain =
            configure::<crate::Chain>(&parse("Corefile", &text).unwrap(), crate::directives())
                .unwrap()
                .remove(0)
                .config;
        chain.lifecycle.run(Phase::Startup).await.unwrap();
        let kubernetes = chain.kubernetes.as_ref().unwrap();
        let store = kubernetes.store().unwrap();
        let later_request = lookup::parse(&[b"later", b"prod"]).unwrap();
        let absent = store.with_read(|index| lookup::capture(index, &later_request, true));
        assert!(matches!(absent, lookup::Snapshot::MissingService));
        let blocks = parse(
            "Corefile",
            ".:53 {\n k8s_external example.org {\n  headless\n }\n}",
        )
        .unwrap();
        let config = setup::parse(
            &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
            &["."],
        )
        .unwrap();
        let mut external = External::new(config).unwrap();
        external.bind_kubernetes(kubernetes);
        let key = ListenerKey {
            transport: Transport::Dns,
            address: "127.0.0.1:53".parse().unwrap(),
        };
        let started = Arc::new(Notify::new());
        let resume = Arc::new(Semaphore::new(0));
        let mut router = Router::default();
        router.add(
            key,
            "example.org.".parse().unwrap(),
            Some(TestChain::External(Box::new(external))),
            vec![],
        );
        router.add(
            key,
            "target.test.".parse().unwrap(),
            Some(TestChain::Target {
                started: started.clone(),
                resume: resume.clone(),
            }),
            vec![],
        );
        let server = Arc::new(Server::new(router, key));
        let name: Name = "head.prod.example.org.".parse().unwrap();
        let mut query = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(65535);
        {
            let future = Handler::handle_shared(
                &server,
                &query,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Tcp,
                &mut response,
            );
            tokio::pin!(future);
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::select! { _ = started.notified() => {}, _ = &mut future => panic!("chase completed before mutation") }
        }).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                service_ready.notified().await;
                slice_ready.notified().await;
            })
            .await
            .unwrap();
            services.send("{\"type\":\"MODIFIED\",\"object\":{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"head\",\"namespace\":\"prod\",\"resourceVersion\":\"2\"},\"spec\":{\"clusterIP\":\"10.0.0.1\",\"externalIPs\":[\"198.51.100.1\"]}}}\n").unwrap();
            services.send("{\"type\":\"ADDED\",\"object\":{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"name\":\"later\",\"namespace\":\"prod\",\"resourceVersion\":\"3\"},\"spec\":{\"clusterIP\":\"10.0.0.2\",\"externalIPs\":[\"198.51.100.3\"],\"ports\":[{\"name\":\"http\",\"protocol\":\"TCP\",\"port\":80}]}}}\n").unwrap();
            slices.send("{\"type\":\"MODIFIED\",\"object\":{\"apiVersion\":\"discovery.k8s.io/v1\",\"kind\":\"EndpointSlice\",\"metadata\":{\"name\":\"head-1\",\"namespace\":\"prod\",\"resourceVersion\":\"2\",\"labels\":{\"kubernetes.io/service-name\":\"head\"}},\"addressType\":\"IPv4\",\"endpoints\":[{\"addresses\":[\"198.51.100.2\"]}],\"ports\":[{\"name\":\"http\",\"protocol\":\"TCP\",\"port\":80}]}}\n").unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                loop {
                    if store.with_read(|index| {
                        index
                            .service("prod", "head")
                            .is_some_and(|s| s.external_ips == ["198.51.100.1"])
                            && index.service("prod", "later").is_some()
                            && index
                                .endpoints("prod", "head")
                                .next()
                                .is_some_and(|ep| ep.addresses[0].ip == "198.51.100.2")
                    }) {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            store.with_read(|index| {
                assert_eq!(
                    lookup::lookup(index, &later_request, true, false, |_, _, _| {}),
                    Rcode::NOERROR
                );
                assert_eq!(
                    lookup::snapshot_or_lookup(
                        index,
                        &later_request,
                        true,
                        false,
                        Some(&absent),
                        |_, _, _| panic!("absent snapshot read added Service")
                    ),
                    Rcode::NXDOMAIN
                );
            });
            resume.add_permits(2);
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(3), &mut future)
                    .await
                    .unwrap(),
                Action::Respond
            );
        }
        let msg = Message::parse(&response).unwrap();
        let records: Vec<_> = msg
            .answers()
            .map(|rr| match rr.data().unwrap() {
                Rdata::A(ip) => format!("A {ip}"),
                Rdata::Cname(name) => format!("CNAME {name}"),
                other => panic!("unexpected record: {other:?}"),
            })
            .collect();
        assert_eq!(
            records,
            [
                "A 192.0.2.1",
                "CNAME lb.target.test.",
                "A 203.0.113.1",
                "CNAME lb.target.test.",
                "A 203.0.113.1",
                "A 192.0.2.2"
            ]
        );
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
        api.abort();
    }

    #[tokio::test]
    async fn mixed_addresses_and_chased_answers_follow_service_order() {
        use pharos_corefile::configure;
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
                            r#"[{"metadata":{"name":"web","namespace":"prod"},"spec":{"externalIPs":["192.0.2.1","lb.example.net","192.0.2.1","192.0.2.2"],"ports":[{"name":"http","protocol":"TCP","port":80},{"name":"https","protocol":"TCP","port":443}]}},{"metadata":{"name":"hidden","namespace":"secret"},"spec":{"externalIPs":["192.0.2.1","192.0.2.3"]}}]"#,
                        )
                    } else if request.contains("/endpointslices") {
                        ("EndpointSliceList", "[]")
                    } else {
                        (
                            "NamespaceList",
                            r#"[{"metadata":{"name":"prod"}},{"metadata":{"name":"secret"}}]"#,
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
            ".:53 {{\n kubernetes cluster.local {{\n  endpoint http://{server}\n  namespaces prod\n  startup_timeout 3s\n }}\n}} "
        );
        let chain =
            configure::<crate::Chain>(&parse("Corefile", &text).unwrap(), crate::directives())
                .unwrap()
                .remove(0)
                .config;
        chain.lifecycle.run(Phase::Startup).await.unwrap();
        let kubernetes = chain.kubernetes.as_ref().unwrap();
        let store = kubernetes.store().unwrap();
        assert_reverse_snapshot(kubernetes, &store).await;
        let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
        let config = setup::parse(
            &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
            &["."],
        )
        .unwrap();
        let external = External::new(config).unwrap();
        let zone: Name = "example.com.".parse().unwrap();
        let owner: Name = "web.prod.example.com.".parse().unwrap();
        let target: Name = "lb.example.net.".parse().unwrap();
        let request = lookup::parse(&[b"web", b"prod"]).unwrap();
        let mut chased_wire = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut chased_wire, 512, 1, 0x8000).unwrap();
        let target_ref = NameRef::parse(target.as_wire(), 0).unwrap();
        b.question(target_ref, Type::A, Class::IN).unwrap();
        b.record(
            Section::Answer,
            target_ref,
            Type::A,
            Class::IN,
            30,
            &[203, 0, 113, 1],
        )
        .unwrap();
        let _ = b.finish();
        let chased = [
            Chased {
                ordinal: 2,
                name: target.clone(),
                answers: [Some(chased_wire.clone()), None],
            },
            Chased {
                ordinal: 3,
                name: target,
                answers: [Some(chased_wire), None],
            },
        ];
        let mut query = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
        b.question(
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(4096);
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &zone,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 4096,
        };
        assert!(matches!(
            external.service_response(
                &mut cx,
                &external.zones[0],
                kubernetes,
                &store,
                None,
                Some(&request),
                Rcode::NOERROR,
                &chased
            ),
            Outcome::Response
        ));
        let message = Message::parse(&response).unwrap();
        let records: Vec<_> = message
            .answers()
            .map(|rr| (rr.rtype, rr.name.to_string()))
            .collect();
        assert_eq!(
            records,
            [
                (Type::A, "web.prod.example.com.".into()),
                (Type::CNAME, "web.prod.example.com.".into()),
                (Type::A, "lb.example.net.".into()),
                (Type::CNAME, "web.prod.example.com.".into()),
                (Type::A, "lb.example.net.".into()),
                (Type::A, "web.prod.example.com.".into())
            ]
        );
        let addresses: Vec<_> = message
            .answers()
            .filter_map(|rr| match rr.data().unwrap() {
                Rdata::A(ip) => Some(ip),
                _ => None,
            })
            .collect();
        assert_eq!(
            addresses,
            [
                "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap(),
                "203.0.113.1".parse().unwrap(),
                "203.0.113.1".parse().unwrap(),
                "192.0.2.2".parse().unwrap()
            ]
        );

        for (empty, code) in [
            (lookup::Snapshot::NamespaceOnly, Rcode::NOERROR),
            (lookup::Snapshot::MissingService, Rcode::NXDOMAIN),
            (lookup::Snapshot::MissingNamespace, Rcode::NXDOMAIN),
        ] {
            response.clear();
            let mut empty_slots = [None; 8];
            let mut cx = Context {
                query: Message::parse(&query).unwrap(),
                client: "127.0.0.1:1234".parse().unwrap(),
                local: "127.0.0.1:53".parse().unwrap(),
                transport: Transport::Dns,
                protocol: Protocol::Udp,
                domain: &zone,
                metadata: Metadata::new(&mut empty_slots),
                response: &mut response,
                max_response_size: 4096,
            };
            assert!(matches!(
                external.service_response(
                    &mut cx,
                    &external.zones[0],
                    kubernetes,
                    &store,
                    Some(&empty),
                    Some(&request),
                    code,
                    &[]
                ),
                Outcome::Response
            ));
            let message = Message::parse(&response).unwrap();
            assert_eq!(message.rcode(), code);
            assert_eq!(message.answer_count(), 0);
        }

        let mut stale_wire = chased[0].answers[0].clone().unwrap();
        stale_wire[2] |= 0x02;
        let mut stale = [
            Chased {
                ordinal: 2,
                name: "old.example.net.".parse().unwrap(),
                answers: [Some(stale_wire), None],
            },
            Chased {
                ordinal: 3,
                name: chased[1].name.clone(),
                answers: chased[1].answers.clone(),
            },
        ];
        response.clear();
        let mut stale_slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &zone,
            metadata: Metadata::new(&mut stale_slots),
            response: &mut response,
            max_response_size: 4096,
        };
        assert!(matches!(
            external.service_response(
                &mut cx,
                &external.zones[0],
                kubernetes,
                &store,
                None,
                Some(&request),
                Rcode::NOERROR,
                &stale,
            ),
            Outcome::Response
        ));
        let message = Message::parse(&response).unwrap();
        assert!(!message.tc(), "discarded stale lookup must not set TC");
        assert_eq!(
            message
                .answers()
                .filter(|rr| rr.rtype == Type::CNAME)
                .count(),
            1
        );
        assert!(message.answers().all(|rr| match rr.data().unwrap() {
            Rdata::Cname(target) => target.to_string() == "lb.example.net.",
            _ => true,
        }));

        stale[0].name = "lb.example.net.".parse().unwrap();
        response.clear();
        let mut valid_slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &zone,
            metadata: Metadata::new(&mut valid_slots),
            response: &mut response,
            max_response_size: 4096,
        };
        assert!(matches!(
            external.service_response(
                &mut cx,
                &external.zones[0],
                kubernetes,
                &store,
                None,
                Some(&request),
                Rcode::NOERROR,
                &stale
            ),
            Outcome::Response
        ));
        assert!(
            Message::parse(&response).unwrap().tc(),
            "followed lookup must preserve TC"
        );

        let srv_chased = [Chased {
            ordinal: 2,
            name: chased[0].name.clone(),
            answers: chased[0].answers.clone(),
        }];
        query.clear();
        let mut b = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
        b.question(
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::SRV,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        response.clear();
        let mut srv_slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &zone,
            metadata: Metadata::new(&mut srv_slots),
            response: &mut response,
            max_response_size: 4096,
        };
        assert!(matches!(
            external.service_response(
                &mut cx,
                &external.zones[0],
                kubernetes,
                &store,
                None,
                Some(&request),
                Rcode::NOERROR,
                &srv_chased
            ),
            Outcome::Response
        ));
        let message = Message::parse(&response).unwrap();
        let srv: Vec<_> = message
            .answers()
            .map(|rr| match rr.data().unwrap() {
                Rdata::Srv { target, port, .. } => (target.to_string(), port),
                _ => panic!("expected SRV"),
            })
            .collect();
        assert_eq!(
            srv,
            [
                ("web.prod.example.com.".into(), 80),
                ("web.prod.example.com.".into(), 443),
                ("lb.example.net.".into(), 80),
                ("lb.example.net.".into(), 443)
            ]
        );
        let extra: Vec<_> = message
            .additionals()
            .map(|rr| (rr.name.to_string(), rr.data().unwrap()))
            .collect();
        assert_eq!(
            extra,
            [
                (
                    "web.prod.example.com.".into(),
                    Rdata::A("192.0.2.1".parse().unwrap())
                ),
                (
                    "lb.example.net.".into(),
                    Rdata::A("203.0.113.1".parse().unwrap())
                ),
                (
                    "web.prod.example.com.".into(),
                    Rdata::A("192.0.2.2".parse().unwrap())
                )
            ]
        );

        let mut snapshot = store.with_read(|index| index.service_snapshot("prod", "web").unwrap());
        std::sync::Arc::make_mut(&mut snapshot).external_ips = vec![
            "198.51.100.1".into(),
            "lb.example.net".into(),
            "198.51.100.2".into(),
        ];
        query.clear();
        let mut b = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
        b.question(
            NameRef::parse(owner.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        response.clear();
        let mut snapshot_slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &zone,
            metadata: Metadata::new(&mut snapshot_slots),
            response: &mut response,
            max_response_size: 4096,
        };
        assert!(matches!(
            external.service_response(
                &mut cx,
                &external.zones[0],
                kubernetes,
                &store,
                Some(&lookup::Snapshot::Service(snapshot)),
                Some(&request),
                Rcode::NOERROR,
                &chased
            ),
            Outcome::Response
        ));
        let message = Message::parse(&response).unwrap();
        let addresses: Vec<_> = message
            .answers()
            .filter_map(|rr| match rr.data().unwrap() {
                Rdata::A(ip) => Some(ip),
                _ => None,
            })
            .collect();
        assert_eq!(
            addresses,
            [
                "198.51.100.1".parse::<std::net::Ipv4Addr>().unwrap(),
                "203.0.113.1".parse().unwrap(),
                "203.0.113.1".parse().unwrap(),
                "198.51.100.2".parse().unwrap()
            ]
        );
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
        task.abort();
    }

    #[test]
    fn chased_ordinals_reject_changed_or_missing_hosts() {
        let chased = [
            Chased {
                ordinal: 1,
                name: "old.example.".parse().unwrap(),
                answers: [None, None],
            },
            Chased {
                ordinal: 3,
                name: "same.example.".parse().unwrap(),
                answers: [None, None],
            },
            Chased {
                ordinal: 5,
                name: "later.example.".parse().unwrap(),
                answers: [None, None],
            },
        ];
        let mut cursor = chased.iter().peekable();
        assert!(chased_at(&mut cursor, 1, "new.example").is_none());
        assert!(chased_at(&mut cursor, 4, "other.example").is_none());
        assert_eq!(
            chased_at(&mut cursor, 5, "later.example")
                .unwrap()
                .name
                .to_string(),
            "later.example."
        );
    }

    #[test]
    fn chased_hosts_match_exact_wire_labels_without_copying_presentation() {
        let chased = [Chased {
            ordinal: 0,
            name: r"a\.b.Example.".parse().unwrap(),
            answers: [None, None],
        }];
        let matches = |address| chased_at(&mut chased.iter().peekable(), 0, address).is_some();
        assert!(matches(r"a\.b.Example"));
        assert!(matches(r"a\046b.Example."));
        assert!(!matches(r"a.b.Example"));
        assert!(!matches(r"a\.b.example"));
        assert!(!matches(r"a\.c.Example"));
        assert!(!matches(r"a\.b.Example.."));
    }

    #[test]
    fn chased_hosts_handle_long_escapes_and_duplicate_ports() {
        let label = "a".repeat(63);
        let host = format!("{label}.Example");
        let escaped = format!("{}.Example.", r"\097".repeat(63));
        let name: Name = format!("{host}.").parse().unwrap();
        let chased = [
            Chased {
                ordinal: 0,
                name: name.clone(),
                answers: [None, None],
            },
            Chased {
                ordinal: 1,
                name,
                answers: [None, None],
            },
        ];
        let mut cursor = chased.iter().peekable();
        assert!(chased_at(&mut cursor, 0, &escaped).is_some());
        assert!(chased_at(&mut cursor, 1, &host).is_some());
        assert!(chased_at(&mut chased.iter().peekable(), 0, &"x".repeat(8192)).is_none());
    }

    #[test]
    fn endpoint_target_interprets_dots_as_name_separators() {
        let request = lookup::parse(&[b"web", b"prod"]).unwrap();
        let zone: Name = "example.org.".parse().unwrap();
        let mut wire = [0; 255];
        let target = service_target(
            &request,
            Some(b"pod.name"),
            "192.0.2.1",
            NameRef::parse(zone.as_wire(), 0).unwrap(),
            &mut wire,
        )
        .unwrap();
        assert_eq!(target.to_string(), "pod.name.web.prod.example.org.");
    }

    // CoreDNS v1.15.0 plugin/k8s_external/apex_test.go, TestApex.
    #[tokio::test]
    async fn apex_soa_uses_external_zone_and_serial() {
        let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
        let config = setup::parse(
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
        let zone: Name = "example.com.".parse().unwrap();
        let zone_ref = NameRef::parse(zone.as_wire(), 0).unwrap();
        let mut request = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut request, 512, 1, 0).unwrap();
        b.question(zone_ref, Type::SOA, Class::IN).unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&request).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &zone,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert!(matches!(
            external.serve(&mut cx, Sentinel).await,
            Outcome::Response
        ));
        let message = Message::parse(&response).unwrap();
        let record = message.answers().next().unwrap();
        assert_eq!(record.ttl, 5);
        let Rdata::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } = record.data().unwrap()
        else {
            panic!("expected SOA")
        };
        assert_eq!(mname.to_string(), "ns1.dns.example.com.");
        assert_eq!(rname.to_string(), "hostmaster.dns.example.com.");
        assert_eq!(
            (serial, refresh, retry, expire, minimum),
            (0, 7200, 1800, 86400, 5)
        );
    }

    #[tokio::test]
    async fn apex_without_matching_type_returns_nodata_with_soa() {
        let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
        let config = setup::parse(
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
        let zone: Name = "example.com.".parse().unwrap();
        let zone_ref = NameRef::parse(zone.as_wire(), 0).unwrap();
        let mut request = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut request, 512, 1, 0).unwrap();
        b.question(zone_ref, Type::A, Class::IN).unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&request).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &zone,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert!(matches!(
            external.serve(&mut cx, Sentinel).await,
            Outcome::Response
        ));
        let message = Message::parse(&response).unwrap();
        assert_eq!(message.rcode(), Rcode::NOERROR);
        assert_eq!(message.answer_count(), 0);
        assert_eq!(message.authorities().next().unwrap().rtype, Type::SOA);
    }

    #[tokio::test]
    async fn apex_ns_has_external_nameserver_target() {
        let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
        let config = setup::parse(
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
        let zone: Name = "example.com.".parse().unwrap();
        let zone_ref = NameRef::parse(zone.as_wire(), 0).unwrap();
        let mut request = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut request, 512, 1, 0).unwrap();
        b.question(zone_ref, Type::NS, Class::IN).unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&request).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &zone,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert!(matches!(
            external.serve(&mut cx, Sentinel).await,
            Outcome::Response
        ));
        let message = Message::parse(&response).unwrap();
        let record = message.answers().next().unwrap();
        let Rdata::Ns(target) = record.data().unwrap() else {
            panic!("expected NS")
        };
        assert_eq!(target.to_string(), "ns1.dns.example.com.");
        assert_eq!(message.authorities().count(), 0);
    }

    #[tokio::test]
    async fn apex_subdomain_rejects_other_names() {
        let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
        let config = setup::parse(
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
        let zone: Name = "example.com.".parse().unwrap();
        let name: Name = "other.dns.example.com.".parse().unwrap();
        let mut request = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut request, 512, 1, 0).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&request).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &zone,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert!(matches!(
            external.serve(&mut cx, Sentinel).await,
            Outcome::Response
        ));
        let message = Message::parse(&response).unwrap();
        assert_eq!(message.rcode(), Rcode::NXDOMAIN);
        assert_eq!(message.authorities().next().unwrap().rtype, Type::SOA);
    }

    #[tokio::test]
    async fn unknown_namespace_is_nxdomain_not_fallthrough() {
        let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
        let config = setup::parse(
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
        let zone: Name = "example.com.".parse().unwrap();
        let name: Name = "web.unknown.example.com.".parse().unwrap();
        let mut request = Vec::with_capacity(512);
        let mut b = MessageBuilder::new(&mut request, 512, 1, 0).unwrap();
        b.question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
        let _ = b.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&request).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &zone,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert!(matches!(
            external.serve(&mut cx, Sentinel).await,
            Outcome::Response
        ));
        let message = Message::parse(&response).unwrap();
        assert_eq!(message.rcode(), Rcode::NXDOMAIN);
        assert_eq!(message.authorities().next().unwrap().rtype, Type::SOA);
    }
}

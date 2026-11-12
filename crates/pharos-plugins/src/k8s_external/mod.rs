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
        request: Option<&lookup::Request<'_>>,
        reverse_ip: Option<&str>,
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
            if let Some(ip) = reverse_ip {
                let mut error = None;
                let first_zone = NameRef::parse(self.zones[0].name.as_wire(), 0).unwrap();
                store.with_read(|index| {
                    for service in index
                        .services_by_external_ip_unfiltered(ip)
                        .filter(|service| {
                            !kubernetes.has_namespace_filter()
                                || index.namespace_exposed(&service.namespace)
                        })
                    {
                        let mut wire = [0; 255];
                        let Some(target) = child_name(
                            &[service.name.as_bytes(), service.namespace.as_bytes()],
                            first_zone,
                            &mut wire,
                        ) else {
                            continue;
                        };
                        // RFC 1035 §3.3.12: PTR RDATA identifies the target domain name.
                        match b.record_with(
                            Section::Answer,
                            q.name,
                            Type::PTR,
                            Class::IN,
                            self.config.ttl,
                            |w| w.write_name(target),
                        ) {
                            Ok(true) => answers += 1,
                            Ok(false) => {}
                            Err(err) => {
                                error = Some(err);
                                break;
                            }
                        }
                    }
                });
                if let Some(error) = error {
                    return Err(error);
                }
            }
            if let Some(request) = request
                && matches!(q.qtype, Type::A | Type::AAAA)
            {
                let mut error = None;
                let mut scratch = scratch::lease();
                store.with_read(|index| {
                    let mut ordinal = 0usize;
                    let mut chased = chased.iter().peekable();
                    lookup::lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
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
            if let Some(request) = request
                && q.qtype == Type::SRV
            {
                let mut error = None;
                let mut scratch = scratch::lease();
                store.with_read(|index| {
                    let mut count = 0usize;
                    lookup::lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
                        |_, _, _| count += 1,
                    );
                    let weight = (100 / count.max(1)).max(1) as u16;
                    lookup::lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
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
                            // RFC 2782 §3: SRV stores priority, weight, port, and target.
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
                    lookup::lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
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
    host: String,
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
        chased.next().filter(|entry| entry.host == address)
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
        if !address.ends_with('.') {
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
        let mut text = [0u8; 1024];
        let bytes = address.as_bytes();
        if bytes.len() >= text.len() {
            return None;
        }
        text[..bytes.len()].copy_from_slice(bytes);
        let length = if bytes.last() == Some(&b'.') {
            bytes.len()
        } else {
            text[bytes.len()] = b'.';
            bytes.len() + 1
        };
        let result =
            Name::parse_absolute_into(std::str::from_utf8(&text[..length]).ok()?, wire).ok()?;
        return NameRef::parse(result, 0).ok();
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
        let length = if endpoint.last() == Some(&b'.') {
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
            let reverse_ip = if q.qtype == Type::PTR {
                crate::kubernetes::reverse::address(&labels[..normalized.labels().count()])
                    .map(crate::kubernetes::scratch::IpText::new)
            } else {
                None
            };
            let request = lookup::parse(&labels[..relative]);
            let code = if let Some(ip) = &reverse_ip {
                if store.with_read(|index| {
                    index
                        .services_by_external_ip_unfiltered(ip.as_str())
                        .any(|service| {
                            !kubernetes.has_namespace_filter()
                                || index.namespace_exposed(&service.namespace)
                        })
                }) {
                    pharos_proto::Rcode::NOERROR
                } else {
                    pharos_proto::Rcode::NXDOMAIN
                }
            } else {
                match &request {
                    Ok(request) => store.with_read(|index| {
                        lookup::lookup(
                            index,
                            request,
                            self.config.headless,
                            kubernetes.endpoint_pod_names(),
                            |_, _, _| {},
                        )
                    }),
                    Err(code) => *code,
                }
            };
            if code == pharos_proto::Rcode::NXDOMAIN
                && self.fallthrough.iter().any(|zone| contains(q.name, zone))
            {
                return None;
            }
            // shortcut: hostname targets and Self Lookups allocate per Query until #86 pools buffers and futures.
            let mut chased = Vec::new();
            if reverse_ip.is_none()
                && matches!(q.qtype, Type::A | Type::AAAA | Type::SRV)
                && let Ok(request) = &request
            {
                store.with_read(|index| {
                    let mut scratch = scratch::lease();
                    let mut ordinal = 0;
                    lookup::lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
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
                                    host: address.to_owned(),
                                    name,
                                    answers: [None, None],
                                });
                            }
                        },
                    );
                });
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
            }
            return Some(self.service_response(
                cx,
                zone,
                kubernetes,
                &store,
                request.as_ref().ok(),
                reverse_ip.as_ref().map(|ip| ip.as_str()),
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
            } else {
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
                            r#"[{"metadata":{"name":"web","namespace":"prod"},"spec":{"externalIPs":["192.0.2.1","lb.example.net","192.0.2.1","192.0.2.2"],"ports":[{"name":"http","protocol":"TCP","port":80},{"name":"https","protocol":"TCP","port":443}]}}]"#,
                        )
                    } else if request.contains("/endpointslices") {
                        ("EndpointSliceList", "[]")
                    } else {
                        ("NamespaceList", r#"[{"metadata":{"name":"prod"}}]"#)
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
            ".:53 {{\n kubernetes cluster.local {{\n  endpoint http://{server}\n  startup_timeout 3s\n }}\n}} "
        );
        let chain =
            configure::<crate::Chain>(&parse("Corefile", &text).unwrap(), crate::directives())
                .unwrap()
                .remove(0)
                .config;
        chain.lifecycle.run(Phase::Startup).await.unwrap();
        let kubernetes = chain.kubernetes.as_ref().unwrap();
        let store = kubernetes.store().unwrap();
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
                host: "lb.example.net".into(),
                name: target.clone(),
                answers: [Some(chased_wire.clone()), None],
            },
            Chased {
                ordinal: 3,
                host: "lb.example.net".into(),
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
                Some(&request),
                None,
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

        let mut stale_wire = chased[0].answers[0].clone().unwrap();
        stale_wire[2] |= 0x02;
        let mut stale = [
            Chased {
                ordinal: 2,
                host: "old.example.net".into(),
                name: "old.example.net.".parse().unwrap(),
                answers: [Some(stale_wire), None],
            },
            Chased {
                ordinal: 3,
                host: chased[1].host.clone(),
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
                Some(&request),
                None,
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

        stale[0].host = "lb.example.net".into();
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
                Some(&request),
                None,
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
            host: chased[0].host.clone(),
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
                Some(&request),
                None,
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
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
        task.abort();
    }

    #[test]
    fn chased_ordinals_reject_changed_or_missing_hosts() {
        let chased = [
            Chased {
                ordinal: 1,
                host: "old.example".into(),
                name: "old.example.".parse().unwrap(),
                answers: [None, None],
            },
            Chased {
                ordinal: 3,
                host: "same.example".into(),
                name: "same.example.".parse().unwrap(),
                answers: [None, None],
            },
            Chased {
                ordinal: 5,
                host: "later.example".into(),
                name: "later.example.".parse().unwrap(),
                answers: [None, None],
            },
        ];
        let mut cursor = chased.iter().peekable();
        assert!(chased_at(&mut cursor, 1, "new.example").is_none());
        assert!(chased_at(&mut cursor, 4, "other.example").is_none());
        assert_eq!(
            chased_at(&mut cursor, 5, "later.example").unwrap().host,
            "later.example"
        );
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

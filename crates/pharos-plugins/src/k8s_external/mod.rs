//! External Kubernetes DNS names.

mod lookup;
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
            let truncated = chased.iter().any(|entry| {
                entry.answers.iter().flatten().any(|wire| {
                    pharos_proto::Message::parse(wire).is_ok_and(|message| message.tc())
                })
            });
            let mut b = MessageBuilder::new(
                cx.response,
                max,
                cx.query.id(),
                0x8400
                    | (cx.query.flags() & 0x7910)
                    | code.0
                    | if truncated && matches!(q.qtype, Type::A | Type::AAAA) {
                        0x0200
                    } else {
                        0
                    },
            )?;
            b.question(q.name, q.qtype, q.qclass)?;
            let mut answers = 0usize;
            // shortcut: duplicate suppression is quadratic in matching records; use pooled scratch for large Services.
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
                store.with_read(|index| {
                    let mut ordinal = 0usize;
                    lookup::lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
                        |address, _, _| {
                            let current = ordinal;
                            ordinal += 1;
                            let mut seen = false;
                            let mut previous = 0usize;
                            lookup::lookup(
                                index,
                                request,
                                self.config.headless,
                                kubernetes.endpoint_pod_names(),
                                |earlier, _, _| {
                                    if previous < current && earlier == address {
                                        seen = true;
                                    }
                                    previous += 1;
                                },
                            );
                            if seen || error.is_some() {
                                return;
                            }
                            let ip = match address.parse::<std::net::IpAddr>() {
                                Ok(std::net::IpAddr::V6(ip)) => ip
                                    .to_ipv4_mapped()
                                    .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
                                Ok(ip) => ip,
                                Err(_) => return,
                            };
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
                for entry in chased {
                    let target = NameRef::parse(entry.name.as_wire(), 0).unwrap();
                    // RFC 1035 §3.3.1: CNAME RDATA identifies the canonical name.
                    if b.record_with(
                        Section::Answer,
                        q.name,
                        Type::CNAME,
                        Class::IN,
                        kubernetes.ttl(),
                        |w| w.write_name(target),
                    )? {
                        answers += 1;
                    }
                    for wire in entry.answers.iter().flatten() {
                        if let Ok(message) = pharos_proto::Message::parse(wire) {
                            for record in message.answers() {
                                if let Ok(data) = record.data() {
                                    b.record_with(
                                        Section::Answer,
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
                }
            }
            if let Some(request) = request
                && q.qtype == Type::SRV
            {
                let mut error = None;
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
                    let mut ordinal = 0usize;
                    lookup::lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
                        |address, port, endpoint| {
                            let current = ordinal;
                            ordinal += 1;
                            if port.port < 0 || error.is_some() {
                                return;
                            }
                            let mut seen = false;
                            let mut previous = 0usize;
                            lookup::lookup(
                                index,
                                request,
                                self.config.headless,
                                kubernetes.endpoint_pod_names(),
                                |earlier, prior_port, prior_endpoint| {
                                    let same_target = if address.parse::<std::net::IpAddr>().is_ok()
                                    {
                                        earlier.parse::<std::net::IpAddr>().is_ok()
                                            && endpoint == prior_endpoint
                                    } else {
                                        earlier == address
                                    };
                                    if previous < current
                                        && same_target
                                        && prior_port.port == port.port
                                    {
                                        seen = true;
                                    }
                                    previous += 1;
                                },
                            );
                            if seen {
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
                    lookup::lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
                        |address, port, endpoint| {
                            let current = ordinal;
                            ordinal += 1;
                            if port.port < 0 || error.is_some() {
                                return;
                            }
                            let ip = match address.parse::<std::net::IpAddr>() {
                                Ok(std::net::IpAddr::V6(ip)) => ip
                                    .to_ipv4_mapped()
                                    .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
                                Ok(ip) => ip,
                                Err(_) => return,
                            };
                            let mut seen = false;
                            let mut previous = 0usize;
                            lookup::lookup(
                                index,
                                request,
                                self.config.headless,
                                kubernetes.endpoint_pod_names(),
                                |earlier, prior_port, prior_endpoint| {
                                    if previous < current
                                        && prior_port.port >= 0
                                        && endpoint == prior_endpoint
                                        && address == earlier
                                    {
                                        seen = true;
                                    }
                                    previous += 1;
                                },
                            );
                            if seen {
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
                for entry in chased {
                    for wire in entry.answers.iter().flatten() {
                        if let Ok(message) = pharos_proto::Message::parse(wire) {
                            for record in message.answers() {
                                if let Ok(data) = record.data() {
                                    b.record_with(
                                        Section::Additional,
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
            Ok::<_, pharos_proto::BuildError>(())
        })();
        match result {
            Ok(()) => Outcome::Response,
            Err(error) => Outcome::Error(pharos_server::Error::Build(error)),
        }
    }
}

struct Chased {
    name: Name,
    answers: [Option<Vec<u8>>; 2],
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
                    lookup::lookup(
                        index,
                        request,
                        self.config.headless,
                        kubernetes.endpoint_pod_names(),
                        |address, port, _| {
                            if address.parse::<std::net::IpAddr>().is_ok()
                                || q.qtype == Type::SRV && port.port < 0
                            {
                                return;
                            }
                            let mut wire = [0; 255];
                            if let Some(target) =
                                service_target(request, None, address, zone_ref, &mut wire)
                                && let Ok(name) = target.to_string().parse::<Name>()
                                && (q.qtype != Type::SRV
                                    || !chased.iter().any(|entry: &Chased| entry.name == name))
                            {
                                chased.push(Chased {
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

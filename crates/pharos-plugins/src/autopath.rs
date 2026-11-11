//! Server-side search path completion.

use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, Error as ServerError, Next, Outcome, Plugin, Protocol};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Debug)]
pub struct AutoPath {
    pub(crate) domains: Vec<Name>,
    pub(crate) search: Vec<Option<Name>>,
    pub(crate) provider: Option<String>,
    metrics: Vec<(SocketAddr, Arc<AtomicU64>)>,
    #[cfg(feature = "plugin-kubernetes")]
    kubernetes: Option<crate::kubernetes::Kubernetes>,
}

impl AutoPath {
    pub(crate) fn parse(cursor: &mut Cursor<'_>, domains: &[&str]) -> Result<Self, Error> {
        cursor.next();
        let args = cursor.remaining_args();
        let (source, zones) = args.split_last().ok_or_else(|| cursor.arg_err())?;
        let mut search = Vec::new();
        let provider = if let Some(provider) = source.strip_prefix('@') {
            Some(provider.to_owned())
        } else {
            let file =
                std::fs::read_to_string(source).map_err(|err| cursor.error(err.to_string()))?;
            search = parse_resolv(&file);
            search.push(None);
            None
        };
        let domains = origins_from_args_or_server_block(
            &zones.iter().map(String::as_str).collect::<Vec<_>>(),
            domains,
        );
        Ok(Self {
            domains: domains.iter().filter_map(|d| d.parse().ok()).collect(),
            search,
            provider,
            metrics: Vec::new(),
            #[cfg(feature = "plugin-kubernetes")]
            kubernetes: None,
        })
    }

    #[cfg(feature = "plugin-kubernetes")]
    pub(crate) fn bind_kubernetes(&mut self, kubernetes: Option<&crate::kubernetes::Kubernetes>) {
        if self.provider.as_deref() == Some("kubernetes") {
            self.kubernetes = kubernetes.cloned();
            if let Ok(file) = std::fs::read_to_string("/etc/resolv.conf") {
                self.search = parse_resolv(&file);
            }
            self.search.push(None);
        }
    }

    pub(crate) fn set_metrics(
        &mut self,
        registry: &pharos_server::metrics::Registry,
        listeners: &[pharos_server::ListenerKey],
    ) {
        for listener in listeners {
            let address = listener.address;
            let server = if address.ip().is_unspecified() {
                format!("dns://:{}", address.port())
            } else {
                format!("dns://{address}")
            };
            self.metrics.push((address, registry.autopath(&server)));
        }
    }

    fn count(&self, local: SocketAddr) {
        if let Some((_, counter)) = self.metrics.iter().find(|(address, _)| *address == local) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn parse_resolv(file: &str) -> Vec<Option<Name>> {
    let mut search = Vec::new();
    for line in file.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        match fields.first().copied() {
            Some("domain") => search = fields.get(1).into_iter().copied().collect(),
            Some("search") => search = fields[1..].to_vec(),
            _ => {}
        }
    }
    search
        .into_iter()
        .map(|suffix| {
            let mut suffix = suffix.to_lowercase();
            if !suffix.ends_with('.') {
                suffix.push('.');
            }
            suffix.parse().ok()
        })
        .collect()
}

impl Plugin for AutoPath {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let query = cx.query;
        let Some(question) = query.questions().next() else {
            return next.run(cx).await;
        };
        #[cfg(feature = "plugin-kubernetes")]
        let mut dynamic = [&[][..]; 3];
        #[cfg(not(feature = "plugin-kubernetes"))]
        let dynamic = [&[][..]; 3];
        #[cfg(feature = "plugin-kubernetes")]
        let mut dynamic_len = 0;
        #[cfg(not(feature = "plugin-kubernetes"))]
        let dynamic_len = 0;
        #[cfg(feature = "plugin-kubernetes")]
        let mut namespace_wire = [0u8; 255];
        #[cfg(feature = "plugin-kubernetes")]
        let mut service_wire = [0u8; 255];
        if self.provider.is_some() {
            #[cfg(feature = "plugin-kubernetes")]
            {
                let Some((pod, zone)) =
                    self.kubernetes.as_ref().and_then(|k| k.autopath_client(cx))
                else {
                    return next.run(cx).await;
                };
                let Some(namespace) = prefix_zone(
                    &[pod.namespace.as_bytes(), b"svc"],
                    zone,
                    &mut namespace_wire,
                ) else {
                    return next.run(cx).await;
                };
                let Some(service) = prefix_zone(&[b"svc"], zone, &mut service_wire) else {
                    return next.run(cx).await;
                };
                dynamic = [namespace, service, zone.as_wire()];
                dynamic_len = 3;
            }
            #[cfg(not(feature = "plugin-kubernetes"))]
            return next.run(cx).await;
        }
        let paths = dynamic[..dynamic_len].iter().copied().chain(
            self.search
                .iter()
                .map(|name| name.as_ref().map_or(&[0][..], Name::as_wire)),
        );
        let Some(first) = paths
            .clone()
            .next()
            .and_then(|name| NameRef::parse(name, 0).ok())
        else {
            return next.run(cx).await;
        };
        if cx.autopath_lookup_active()
            || !within_ref(question.name, first)
            || !self.domains.iter().any(|zone| within(question.name, zone))
        {
            return next.run(cx).await;
        }
        if first.labels().count() == question.name.labels().count() {
            return Outcome::Error(ServerError::InvalidQuery);
        }
        let outcome = next.run(cx).await;
        if matches!(outcome, Outcome::Error(_) | Outcome::Stream(_)) {
            return outcome;
        }
        if outcome == Outcome::Response {
            let Ok(first_response) = Message::parse(cx.response) else {
                return Outcome::Error(ServerError::InvalidQuery);
            };
            if first_response.rcode() != Rcode::NXDOMAIN {
                if first_response
                    .answers()
                    .any(|rr| different_name(rr.name, question.name))
                {
                    let mut scratch = [0u8; u16::MAX as usize];
                    let len = cx.response.len();
                    if len > scratch.len() {
                        return Outcome::Error(ServerError::InvalidQuery);
                    }
                    scratch[..len].copy_from_slice(cx.response);
                    let response = match Message::parse(&scratch[..len]) {
                        Ok(response) => response,
                        Err(_) => return Outcome::Error(ServerError::InvalidQuery),
                    };
                    if let Err(error) = rebuild(cx, &response) {
                        return Outcome::Error(error);
                    }
                }
                self.count(cx.local);
                return outcome;
            }
        }
        if paths.clone().count() == 1 {
            return outcome;
        }
        let original = if outcome == Outcome::Response {
            cx.response.clone()
        } else {
            Vec::new()
        };
        let first_labels = first.labels().count();
        let base_labels = question.name.labels().count().saturating_sub(first_labels);
        let mut wire = [0u8; 255];
        let mut used = 0;
        for label in question.name.labels().take(base_labels) {
            wire[used] = label.len() as u8;
            used += 1;
            wire[used..used + label.len()].copy_from_slice(label);
            used += label.len();
        }
        for suffix in paths.skip(1) {
            if used + suffix.len() > wire.len() {
                continue;
            }
            wire[used..used + suffix.len()].copy_from_slice(suffix);
            let Ok(name) = NameRef::parse(&wire[..used + suffix.len()], 0) else {
                continue;
            };
            // shortcut: search Self Lookup allocates; remove when #86 makes it allocation-free.
            let reply = match cx.autopath_lookup(&name.to_name(), question.qtype).await {
                Ok(reply) => reply,
                Err(ServerError::SelfLookupDropped) => continue,
                Err(error) => return Outcome::Error(error),
            };
            let Ok(response) = Message::parse(&reply) else {
                return Outcome::Error(ServerError::InvalidQuery);
            };
            if response.rcode() == Rcode::NXDOMAIN
                || (outcome != Outcome::Response && matches!(response.rcode().0, 1 | 2 | 4 | 5))
            {
                continue;
            }
            self.count(cx.local);
            return match rebuild(cx, &response) {
                Ok(()) => Outcome::Response,
                Err(error) => Outcome::Error(error),
            };
        }
        if outcome == Outcome::Response {
            cx.response.clear();
            cx.response.extend_from_slice(&original);
        }
        outcome
    }
}

fn within(name: NameRef<'_>, domain: &Name) -> bool {
    let suffix = NameRef::parse(domain.as_wire(), 0).unwrap();
    within_ref(name, suffix)
}

fn within_ref(name: NameRef<'_>, suffix: NameRef<'_>) -> bool {
    let count = name.labels().count();
    let suffix_count = suffix.labels().count();
    // RFC 4343 §3: DNS names compare ASCII case-insensitively, label by label.
    count >= suffix_count
        && name
            .labels()
            .skip(count - suffix_count)
            .zip(suffix.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn different_name(a: NameRef<'_>, b: NameRef<'_>) -> bool {
    a.labels().count() != b.labels().count()
        || !a
            .labels()
            .zip(b.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

#[cfg(feature = "plugin-kubernetes")]
fn prefix_zone<'a>(labels: &[&[u8]], zone: &Name, wire: &'a mut [u8; 255]) -> Option<&'a [u8]> {
    let mut used = 0;
    // RFC 1035 §3.1: labels and complete wire names have bounded lengths.
    for label in labels {
        if label.is_empty()
            || label.len() > 63
            || used + 1 + label.len() + zone.as_wire().len() > wire.len()
        {
            return None;
        }
        wire[used] = label.len() as u8;
        used += 1;
        wire[used..used + label.len()].copy_from_slice(label);
        used += label.len();
    }
    wire[used..used + zone.as_wire().len()].copy_from_slice(zone.as_wire());
    Some(&wire[..used + zone.as_wire().len()])
}

fn rebuild(cx: &mut Context<'_, '_>, response: &Message<'_>) -> Result<(), ServerError> {
    let question = cx
        .query
        .questions()
        .next()
        .ok_or(ServerError::InvalidQuery)?;
    let max = cx.max_response_size.max(512);
    if cx.response.capacity() < max {
        if cx.protocol == Protocol::Tcp {
            cx.response.reserve(max.saturating_sub(cx.response.len()));
        } else {
            return Err(ServerError::ResponseBufferTooSmall);
        }
    }
    // RFC 1035 §4.1.2: the Response retains the original Question.
    let mut b = MessageBuilder::new(cx.response, max, cx.query.id(), response.flags())
        .map_err(ServerError::Build)?;
    b.question(question.name, question.qtype, question.qclass)
        .map_err(ServerError::Build)?;
    if let Some(first) = response
        .answers()
        .find(|rr| different_name(rr.name, question.name))
    {
        b.record_with(
            Section::Answer,
            question.name,
            Type::CNAME,
            Class::IN,
            first.ttl,
            |w| w.write_name(first.name),
        )
        .map_err(ServerError::Build)?;
    }
    for (section, records) in [
        (Section::Answer, response.answers()),
        (Section::Authority, response.authorities()),
        (Section::Additional, response.additionals()),
    ] {
        for rr in records {
            let data = rr.data().map_err(|_| ServerError::InvalidQuery)?;
            b.record_with(section, rr.name, rr.rtype, rr.class, rr.ttl, |w| {
                data.write(w)
            })
            .map_err(ServerError::Build)?;
        }
    }
    let _ = b.finish();
    Ok(())
}

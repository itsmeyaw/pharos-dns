//! Outgoing Zone Transfers.

pub(crate) mod setup;
#[cfg(test)]
pub(crate) mod tests;

use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::{Class, Name, NameRef, Rcode, Rdata, Type};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol};
use std::{fmt::Write, net::IpAddr};

/// Supplies an authoritative Zone's records to the transfer Plugin.
pub trait Transferer {
    /// Bind the notifier used when this Plugin's authoritative data changes.
    fn bind_transfer(&self, _transfer: Option<&Transfer>) {}

    /// Return None if this Plugin is not authoritative for the requested Zone.
    fn transfer(
        &self,
        request: TransferRequest<'_>,
    ) -> Result<Option<pharos_server::Stream>, pharos_server::Error>;
}

/// Query metadata needed to generate a transfer stream.
#[derive(Clone, Copy)]
pub struct TransferRequest<'a> {
    pub zone: NameRef<'a>,
    pub serial: u32,
    pub id: u16,
    pub flags: u16,
    pub protocol: Protocol,
    pub qtype: Type,
    pub qclass: Class,
}

#[derive(Clone, Debug)]
pub struct Transfer {
    pub(crate) zones: Vec<TransferZone>,
}

#[derive(Clone, Debug)]
pub(crate) struct TransferZone {
    pub domains: Vec<Name>,
    pub destinations: Vec<Destination>,
    pub source: Option<IpAddr>,
}

#[derive(Clone, Debug)]
pub(crate) enum Destination {
    All,
    Address { host: String, port: String },
}

impl Transfer {
    /// Notify the configured Secondary Servers that a Zone changed.
    pub async fn notify(&self, zone: &Name) -> std::io::Result<()> {
        // CoreDNS longestMatch keeps the first of equally long Zones; max_by_key would keep the last.
        let Some(rule) = self
            .zones
            .iter()
            .flat_map(|rule| {
                rule.domains.iter().filter_map(move |domain| {
                    zone.is_subdomain_of(domain)
                        .then_some((domain.label_count(), rule))
                })
            })
            .rev()
            .max_by_key(|(count, _)| *count)
            .map(|(_, rule)| rule)
        else {
            return Ok(());
        };
        let mut errors = Vec::new();
        for destination in &rule.destinations {
            let Destination::Address { host, port } = destination else {
                continue;
            };
            let endpoint = if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            let result = async {
                let address = tokio::net::lookup_host(&endpoint)
                    .await?
                    .next()
                    .ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid destination")
                    })?;
                let mut random = [0; 2];
                getrandom::getrandom(&mut random)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                pharos_server::transfer::notify_from(
                    address,
                    rule.source,
                    zone,
                    u16::from_ne_bytes(random),
                    std::time::Duration::from_secs(2),
                )
                .await
            }
            .await;
            if let Err(error) = result {
                errors.push(format!("{endpoint}: {error}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other(errors.join("; ")))
        }
    }

    fn parse(cursor: &mut Cursor<'_>, server_domains: &[&str]) -> Result<Self, Error> {
        let mut zones = Vec::new();
        while cursor.next() {
            let args = cursor.remaining_args();
            let args = args.iter().map(String::as_str).collect::<Vec<_>>();
            let domains = origins_from_args_or_server_block(&args, server_domains)
                .iter()
                .map(|zone| {
                    zone.parse()
                        .map_err(|_| cursor.error("invalid transfer zone"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut destinations = Vec::new();
            let mut source = None;
            while cursor.next_block() {
                let property = cursor.val().to_owned();
                let args = cursor.remaining_args();
                match property.as_str() {
                    "to" if !args.is_empty() => {
                        for arg in args {
                            destinations.push(
                                destination(&arg)
                                    .ok_or_else(|| cursor.error("invalid transfer destination"))?,
                            );
                        }
                    }
                    "source" if args.len() == 1 && source.is_none() => {
                        source = Some(
                            args[0]
                                .parse()
                                .map_err(|_| cursor.error("invalid transfer source"))?,
                        );
                    }
                    _ => return Err(cursor.arg_err()),
                }
            }
            if destinations.is_empty() {
                return Err(cursor.error("transfer requires to"));
            }
            zones.push(TransferZone {
                domains,
                destinations,
                source,
            });
        }
        Ok(Self { zones })
    }

    /// Process a transfer using a statically dispatched authoritative Plugin.
    pub async fn serve_with<N: Next + Send, T: Transferer + Sync>(
        &self,
        cx: &mut Context<'_, '_>,
        next: N,
        provider: Option<&T>,
    ) -> Outcome {
        match self.process(cx, provider) {
            Some(outcome) => outcome,
            None => next.run(cx).await,
        }
    }

    fn process<T: Transferer>(
        &self,
        cx: &Context<'_, '_>,
        provider: Option<&T>,
    ) -> Option<Outcome> {
        let question = cx.query.questions().next()?;
        if !matches!(question.qtype, Type::AXFR | Type::IXFR) {
            return None;
        }
        // RFC 5936 §4.2: AXFR uses TCP rather than UDP.
        if question.qtype == Type::AXFR && cx.protocol == Protocol::Udp {
            return Some(Outcome::Unanswered(Rcode::REFUSED));
        }
        // CoreDNS longestMatch keeps the first of equally long Zones; max_by_key would keep the last.
        let rule = self
            .zones
            .iter()
            .flat_map(|zone| {
                zone.domains.iter().filter_map(move |domain| {
                    let base = NameRef::parse(domain.as_wire(), 0).ok()?;
                    let count = question.name.labels().count();
                    let base_count = base.labels().count();
                    (count >= base_count
                        && question
                            .name
                            .labels()
                            .skip(count - base_count)
                            .zip(base.labels())
                            .all(|(a, b)| a.eq_ignore_ascii_case(b)))
                    .then_some((base_count, zone))
                })
            })
            .rev()
            .max_by_key(|(count, _)| *count)
            .map(|(_, zone)| zone);
        let rule = rule?;
        let mut client = IpText {
            bytes: [0; 45],
            len: 0,
        };
        let ip = match cx.client.ip() {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
            ip => ip,
        };
        if write!(client, "{ip}").is_err() {
            return Some(Outcome::Unanswered(Rcode::REFUSED));
        }
        let allowed = rule
            .destinations
            .iter()
            .any(|destination| match destination {
                Destination::All => true,
                Destination::Address { host, .. } => host.as_bytes() == &client.bytes[..client.len],
            });
        if !allowed {
            return Some(Outcome::Unanswered(Rcode::REFUSED));
        }
        // RFC 1995 §3: an IXFR Query carries the current SOA in Authority.
        let serial = if question.qtype == Type::IXFR {
            let mut authority = cx.query.authorities();
            let serial = authority
                .next()
                .and_then(|record| match record.data().ok()? {
                    Rdata::Soa { serial, .. } => Some(serial),
                    _ => None,
                });
            match (serial, authority.next()) {
                (Some(serial), None) => serial,
                _ => return Some(Outcome::Unanswered(Rcode::SERVFAIL)),
            }
        } else {
            0
        };
        let provider = provider?;
        match provider.transfer(TransferRequest {
            zone: question.name,
            serial,
            id: cx.query.id(),
            flags: cx.query.flags(),
            protocol: cx.protocol,
            qtype: question.qtype,
            qclass: question.qclass,
        }) {
            Ok(Some(stream)) => Some(Outcome::Stream(stream)),
            Ok(None) => None,
            Err(error) => Some(Outcome::Error(error)),
        }
    }
}

struct IpText {
    bytes: [u8; 45],
    len: usize,
}

impl std::fmt::Write for IpText {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(std::fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(std::fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn destination(value: &str) -> Option<Destination> {
    if value == "*" {
        return Some(Destination::All);
    }
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        (host, if port.is_empty() { "53" } else { port })
    } else if ip_without_zone(value).parse::<IpAddr>().is_ok() {
        (value, "53")
    } else {
        let (host, port) = value.rsplit_once(':')?;
        (host, if port.is_empty() { "53" } else { port })
    };
    ip_without_zone(host).parse::<IpAddr>().ok()?;
    Some(Destination::Address {
        host: host.into(),
        port: port.into(),
    })
}

fn ip_without_zone(host: &str) -> &str {
    host.rsplit_once('%').map_or(host, |(address, _)| address)
}

impl Plugin for Transfer {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        self.serve_with(cx, next, None::<&NoTransferer>).await
    }
}

struct NoTransferer;
impl Transferer for NoTransferer {
    fn transfer(
        &self,
        _: TransferRequest<'_>,
    ) -> Result<Option<pharos_server::Stream>, pharos_server::Error> {
        Ok(None)
    }
}

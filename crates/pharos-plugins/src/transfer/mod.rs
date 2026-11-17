//! Outgoing Zone Transfers.

pub(crate) mod setup;
#[cfg(test)]
pub(crate) mod tests;

use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::{Class, Name, NameRef, Rcode, Rdata, Type};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol};
use std::net::IpAddr;

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
    Address { host: IpAddr, port: String },
    Network { address: IpAddr, prefix: u8 },
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
        let mut addressed = false;
        let mut cidr = false;
        // RFC 1996 §§4.5, 4.6: Send NOTIFY to each configured server destination.
        for destination in &rule.destinations {
            let (host, port) = match destination {
                Destination::Address { host, port } => (host, port),
                Destination::All => continue,
                Destination::Network { .. } => {
                    // RFC 1996 §2.1: the Notify Set lists servers; a CIDR range names none (warned at setup).
                    cidr = true;
                    continue;
                }
            };
            addressed = true;
            // RFC 5952 §6: Bracket IPv6 literals when combining them with port numbers.
            let endpoint = if host.is_ipv6() {
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
                // RFC 1996 §3.1: Send SOA NOTIFY to configured secondary servers for this zone.
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
        if errors.is_empty() && cidr && !addressed {
            Err(std::io::Error::other("CIDR is not a NOTIFY destination"))
        } else if errors.is_empty() {
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
                            // RFC 4007 §11.2: Do not discard a destination's zone identifier.
                            if arg.split_once('%').is_some_and(|(host, _)| {
                                host.trim_start_matches('[').parse::<IpAddr>().is_ok()
                            }) {
                                return Err(
                                    cursor.error("scoped transfer destinations are unsupported")
                                );
                            }
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
            for destination in &destinations {
                if let Destination::Network { address, prefix } = destination {
                    pharos_server::logging::log(
                        "WARN",
                        "transfer",
                        &format!("to {address}/{prefix} is an ACL only; NOTIFY skips it"),
                    );
                }
            }
            // RFC 5936 §5: Require an explicit transfer policy instead of open access.
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
        // RFC 4291 §2.5.5.2: IPv4-mapped addresses identify IPv4 peers.
        let ip = cx.client.ip().to_canonical();
        // RFC 5936 §5: Restrict AXFR access to explicitly configured client IP addresses.
        let allowed = rule
            .destinations
            .iter()
            .any(|destination| match destination {
                Destination::All => true,
                // RFC 5952 §4: Accept all legitimate IPv6 text representations.
                Destination::Address { host, .. } => host.to_canonical() == ip,
                Destination::Network { address, prefix } => in_network(ip, *address, *prefix),
            });
        if !allowed {
            // RFC 1035 §4.1.1: REFUSED means policy prevents this transfer.
            return Some(Outcome::Unanswered(Rcode::REFUSED));
        }
        // RFC 1995 §3: an IXFR Query carries the current SOA in Authority.
        let serial = if question.qtype == Type::IXFR {
            let mut authority = cx.query.authorities();
            let serial = authority
                .next()
                .and_then(|record| match record.data().ok()? {
                    Rdata::Soa { serial, .. }
                        if record.name == question.name && record.class == question.qclass =>
                    {
                        Some(serial)
                    }
                    _ => None,
                });
            match (serial, authority.next()) {
                (Some(serial), None) => serial,
                // RFC 1995 §3 defines no RCODE for a bad Authority SOA; SERVFAIL is a Pharos choice.
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

// RFC 5936 §5: An explicit wildcard permits AXFR access to all clients.
fn destination(value: &str) -> Option<Destination> {
    // RFC 5936 §5: Allow operators to explicitly open AXFR access to all clients.
    if value == "*" {
        return Some(Destination::All);
    }
    // RFC 5936 §5: A configured network prefix authorizes clients in that range.
    if let Some((address, prefix)) = value.rsplit_once('/') {
        let address = address.parse::<IpAddr>().ok()?;
        let prefix = prefix.parse::<u8>().ok()?;
        let max = if address.is_ipv4() { 32 } else { 128 };
        return (prefix <= max).then_some(Destination::Network { address, prefix });
    }
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        (host, if port.is_empty() { "53" } else { port })
    } else if value.parse::<IpAddr>().is_ok() {
        (value, "53")
    } else {
        let (host, port) = value.rsplit_once(':')?;
        (host, if port.is_empty() { "53" } else { port })
    };
    // RFC 4291 §2.2: Parse the address rather than comparing its text.
    let host = host.parse::<IpAddr>().ok()?;
    Some(Destination::Address {
        host,
        port: port.into(),
    })
}

// RFC 5936 §5: Match transfer clients against configured network prefixes.
fn in_network(address: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (address, network) {
        (IpAddr::V4(address), IpAddr::V4(network)) if prefix <= 32 => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(prefix))
                .unwrap_or_default();
            u32::from(address) & mask == u32::from(network) & mask
        }
        (IpAddr::V6(address), IpAddr::V6(network)) if prefix <= 128 => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(prefix))
                .unwrap_or_default();
            u128::from(address) & mask == u128::from(network) & mask
        }
        _ => false,
    }
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

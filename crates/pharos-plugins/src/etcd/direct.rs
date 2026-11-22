//! Responses written straight from the services the view holds.
//!
//! The lookups of `backend` build records first, which allocates. For a Query whose answer needs
//! nothing beyond the services read (no CNAME to chase, no Self Lookup, few enough services to
//! compare pairwise), this module writes the same Response from them, with names built on the
//! stack and the strings of the key taken from a pool. [`handles`] tells which Queries these are;
//! the rest take `backend`, which this module must agree with.

use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use pharos_proto::{BuildError, Class, MessageBuilder, Name, NameRef, Section, Type};

use super::{
    backend::{Services, srv_share, srv_weight},
    msg::{self, HostType, Service},
    scratch,
};

/// CoreDNS v1.15.0 plugin/etcd/xfr.go `MinTTL`: the SOA minimum, and with 300 the cap of the SOA TTL.
const SOA_MINIMUM: u32 = 30;

/// Services whose hosts or texts are compared with each other to drop duplicates; with more, the
/// Query takes `backend`, which hashes them.
const MAX_PAIRWISE: usize = 64;

/// The same for services whose derived names are compared, which costs a parse for each comparison.
const MAX_PAIRWISE_NAMES: usize = 16;

/// A name in wire form, on the stack.
struct Wire {
    bytes: [u8; 255],
    len: usize,
}

impl Wire {
    /// RFC 1035 §3.1: the wire form of the absolute presentation name `text`.
    fn parse(text: &str) -> Option<Self> {
        let mut bytes = [0; 255];
        let len = Name::parse_absolute_into(text, &mut bytes).ok()?.len();
        Some(Self { bytes, len })
    }

    /// RFC 1035 §3.1: `labels` followed by the name `zone`, when it fits in 255 octets.
    fn under(labels: &[&str], zone: &Name) -> Option<Self> {
        let mut bytes = [0; 255];
        let mut len = 0;
        for label in labels {
            let end = len + 1 + label.len();
            *bytes.get_mut(len)? = u8::try_from(label.len()).ok()?;
            bytes
                .get_mut(len + 1..end)?
                .copy_from_slice(label.as_bytes());
            len = end;
        }
        let end = len + zone.as_wire().len();
        bytes.get_mut(len..end)?.copy_from_slice(zone.as_wire());
        Some(Self { bytes, len: end })
    }

    fn name(&self) -> Option<NameRef<'_>> {
        NameRef::parse(&self.bytes[..self.len], 0).ok()
    }

    /// RFC 4343 §3.1: names are equal when their octets are, ignoring ASCII case; length octets are below 'A'.
    fn same(&self, other: &Self) -> bool {
        self.bytes[..self.len].eq_ignore_ascii_case(&other.bytes[..other.len])
    }
}

/// miekg/dns `Fqdn`: `host` as it is, or with a final dot added in `buf`.
fn fqdn_into<'s>(host: &'s str, buf: &'s mut String) -> &'s str {
    if msg::is_fqdn(host) {
        host
    } else {
        buf.clear();
        buf.push_str(host);
        buf.push('.');
        buf
    }
}

/// The name in the host of a service whose host is a name, as `backend::fqdn_name` reads it.
fn host_name(host: &str) -> Option<Wire> {
    let mut buf = scratch::lease();
    Wire::parse(fqdn_into(host, &mut buf))
}

/// The name that CoreDNS `NewSRV` makes of the key of a service whose host is an address: the
/// domain of the key, with `targetstrip` labels cut off when `strip` is set.
fn key_name(service: &Service, strip: bool) -> Option<Wire> {
    let (mut domain, mut buf) = (scratch::lease(), scratch::lease());
    msg::domain_into(&mut domain, &service.key);
    let text = fqdn_into(&domain, &mut buf);
    // CoreDNS v1.15.0 plugin/etcd/msg/service.go `NewSRV`: strip only when `targetstrip` is positive.
    let text = if strip && service.target_strip > 0 {
        msg::target_strip(text, service.target_strip)
    } else {
        text
    };
    Wire::parse(text)
}

fn within(services: &Services, limit: usize) -> bool {
    services.iter().nth(limit).is_none()
}

fn is_name(service: &Service) -> bool {
    matches!(service.host_type(), HostType::Cname)
}

/// Whether [`answers`] writes the Response to a Query for `qtype`, given what the first read found.
pub(super) fn handles(qtype: Type, services: Option<&Services>) -> bool {
    let Some(services) = services else {
        return qtype == Type::SOA;
    };
    // CoreDNS v1.15.0 plugin/backend_lookup.go: a host that is a name sends the lookup after its target.
    // shortcut: a chased CNAME chain is built as records by `backend`, because the CNAME is kept only if the chain answers; write it straight too if CNAME-heavy zones show up in profiles.
    let chases = |wanted: fn(&Service) -> bool| {
        services
            .iter()
            .any(|service| wanted(service) && is_name(service))
    };
    match qtype {
        Type::A | Type::AAAA | Type::TXT => within(services, MAX_PAIRWISE) && !chases(|_| true),
        Type::PTR => within(services, MAX_PAIRWISE),
        Type::CNAME => true,
        Type::MX => within(services, MAX_PAIRWISE_NAMES) && !chases(|service| service.mail),
        Type::SRV => within(services, MAX_PAIRWISE_NAMES) && !chases(|service| service.port != -1),
        _ => !chases(|_| true),
    }
}

/// CoreDNS v1.15.0 plugin/backend_lookup.go: write the records the lookup of `qtype` at `owner`
/// answers with, and return how many of the Answer section it wrote or tried to.
pub(super) fn answers(
    builder: &mut MessageBuilder<'_>,
    owner: NameRef<'_>,
    zone: &Name,
    qtype: Type,
    services: Option<&Services>,
) -> Result<usize, BuildError> {
    let Some(services) = services else {
        return soa(builder, zone, Section::Answer);
    };
    match qtype {
        Type::A | Type::AAAA => addresses(builder, owner, services, qtype),
        Type::TXT => texts(builder, owner, services),
        Type::CNAME => cname(builder, owner, services),
        Type::PTR => ptr(builder, owner, services),
        Type::MX => mx(builder, owner, services),
        Type::SRV => srv(builder, owner, services),
        // CoreDNS v1.15.0 plugin/etcd/handler.go: the fake A lookup of any other type answers nothing.
        _ => Ok(0),
    }
}

/// CoreDNS v1.15.0 plugin/backend_lookup.go `SOA`; the number of records tried, 0 when the names do not fit.
pub(super) fn soa(
    builder: &mut MessageBuilder<'_>,
    zone: &Name,
    section: Section,
) -> Result<usize, BuildError> {
    let (Some(mname), Some(rname)) = (
        Wire::under(&["ns", "dns"], zone),
        Wire::under(&["hostmaster"], zone),
    ) else {
        return Ok(0);
    };
    let (Some(mname), Some(rname)) = (mname.name(), rname.name()) else {
        return Ok(0);
    };
    let serial = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as u32);
    // RFC 1035 §3.3.13: SOA RDATA; CoreDNS v1.15.0 plugin/backend_lookup.go SOA sets the timers.
    builder.record_with(
        section,
        zone.as_name_ref(),
        Type::SOA,
        Class::IN,
        SOA_MINIMUM.min(300),
        |w| {
            w.write_name(mname)?;
            w.write_name(rname)?;
            for number in [serial, 7200, 1800, 86400, SOA_MINIMUM] {
                w.write_bytes(&number.to_be_bytes())?;
            }
            Ok(())
        },
    )?;
    Ok(1)
}

/// CoreDNS v1.15.0 plugin/backend_lookup.go `A` and `AAAA`: one record per distinct host.
fn addresses(
    builder: &mut MessageBuilder<'_>,
    owner: NameRef<'_>,
    services: &Services,
    qtype: Type,
) -> Result<usize, BuildError> {
    let mut count = 0;
    for (index, service) in services.iter().enumerate() {
        let fresh = || services.iter().take(index).all(|e| e.host != service.host);
        // RFC 1035 §3.4.1 and RFC 3596 §2.2: address records hold the address in network order.
        match (service.host_type(), qtype) {
            (HostType::A(ip), Type::A) if fresh() => {
                builder.record(
                    Section::Answer,
                    owner,
                    Type::A,
                    Class::IN,
                    service.ttl,
                    &ip.octets(),
                )?;
            }
            (HostType::Aaaa(ip), Type::AAAA) if fresh() => {
                builder.record(
                    Section::Answer,
                    owner,
                    Type::AAAA,
                    Class::IN,
                    service.ttl,
                    &ip.octets(),
                )?;
            }
            _ => continue,
        }
        count += 1;
    }
    Ok(count)
}

/// CoreDNS v1.15.0 plugin/backend_lookup.go `TXT`: one record per distinct text.
fn texts(
    builder: &mut MessageBuilder<'_>,
    owner: NameRef<'_>,
    services: &Services,
) -> Result<usize, BuildError> {
    let mut count = 0;
    for (index, service) in services.iter().enumerate() {
        if service.host_type() != HostType::Txt
            || services
                .iter()
                .take(index)
                .any(|e| e.text == service.text && e.host_type() == HostType::Txt)
        {
            continue;
        }
        // RFC 1035 §3.3.14: TXT RDATA is one or more character-strings.
        builder.record_with(
            Section::Answer,
            owner,
            Type::TXT,
            Class::IN,
            service.ttl,
            |w| {
                for chunk in msg::chunks255(service.text.as_bytes()) {
                    w.write_bytes(&[chunk.len() as u8])?;
                    w.write_bytes(chunk)?;
                }
                Ok(())
            },
        )?;
        count += 1;
    }
    Ok(count)
}

/// CoreDNS v1.15.0 plugin/backend_lookup.go `CNAME`: only the first service answers, and only when its host is a name.
fn cname(
    builder: &mut MessageBuilder<'_>,
    owner: NameRef<'_>,
    services: &Services,
) -> Result<usize, BuildError> {
    let Some(service) = services
        .iter()
        .next()
        .filter(|service| service.host.parse::<IpAddr>().is_err())
    else {
        return Ok(0);
    };
    let Some(target) = host_name(&service.host) else {
        return Ok(0);
    };
    let Some(target) = target.name() else {
        return Ok(0);
    };
    // RFC 1035 §3.3.1: the RDATA is a domain name.
    builder.record_with(
        Section::Answer,
        owner,
        Type::CNAME,
        Class::IN,
        service.ttl,
        |w| w.write_name(target),
    )?;
    Ok(1)
}

/// CoreDNS v1.15.0 plugin/backend_lookup.go `PTR`: one record per distinct host that is a name.
fn ptr(
    builder: &mut MessageBuilder<'_>,
    owner: NameRef<'_>,
    services: &Services,
) -> Result<usize, BuildError> {
    let mut count = 0;
    for (index, service) in services.iter().enumerate() {
        // The host of an earlier service that fails to parse as a name fails the same way here.
        if service.host.parse::<IpAddr>().is_ok()
            || services.iter().take(index).any(|e| e.host == service.host)
        {
            continue;
        }
        let Some(target) = host_name(&service.host) else {
            continue;
        };
        let Some(target) = target.name() else {
            continue;
        };
        // RFC 1035 §3.3.12: the RDATA is a domain name.
        builder.record_with(
            Section::Answer,
            owner,
            Type::PTR,
            Class::IN,
            service.ttl,
            |w| w.write_name(target),
        )?;
        count += 1;
    }
    Ok(count)
}

/// The exchange of a mail service whose host is an address, and the name that holds the address.
fn mx_names(service: &Service) -> Option<(Wire, Wire)> {
    if !service.mail || !matches!(service.host_type(), HostType::A(_) | HostType::Aaaa(_)) {
        return None;
    }
    Some((key_name(service, true)?, key_name(service, false)?))
}

/// CoreDNS v1.15.0 plugin/backend_lookup.go `MX`: the MX records, then the addresses of their exchanges.
fn mx(
    builder: &mut MessageBuilder<'_>,
    owner: NameRef<'_>,
    services: &Services,
) -> Result<usize, BuildError> {
    let mut count = 0;
    for (index, service) in services.iter().enumerate() {
        let Some((exchange, _)) = mx_names(service) else {
            continue;
        };
        let preference = service.priority as u16;
        let repeated = services.iter().take(index).any(|e| {
            mx_names(e).is_some_and(|(x, _)| x.same(&exchange) && e.priority as u16 == preference)
        });
        let Some(exchange) = exchange.name().filter(|_| !repeated) else {
            continue;
        };
        // RFC 1035 §3.3.9: MX RDATA is the preference and the exchange.
        builder.record_with(
            Section::Answer,
            owner,
            Type::MX,
            Class::IN,
            service.ttl,
            |w| {
                w.write_bytes(&preference.to_be_bytes())?;
                w.write_name(exchange)
            },
        )?;
        count += 1;
    }
    for (index, service) in services.iter().enumerate() {
        let Some((_, holder)) = mx_names(service) else {
            continue;
        };
        // CoreDNS v1.15.0 plugin/backend_lookup.go `MX`: the address is named by the key, without the strip.
        let repeated = services
            .iter()
            .take(index)
            .any(|e| mx_names(e).is_some_and(|(_, h)| h.same(&holder) && e.host == service.host));
        if !repeated {
            address_record(builder, &holder, service)?;
        }
    }
    Ok(count)
}

/// CoreDNS v1.15.0 plugin/backend_lookup.go `newAddress`: the address of `service`, named `name`, in Additional.
fn address_record(
    builder: &mut MessageBuilder<'_>,
    name: &Wire,
    service: &Service,
) -> Result<(), BuildError> {
    let Some(name) = name.name() else {
        return Ok(());
    };
    match service.host_type() {
        HostType::A(ip) => builder.record(
            Section::Additional,
            name,
            Type::A,
            Class::IN,
            service.ttl,
            &ip.octets(),
        ),
        HostType::Aaaa(ip) => builder.record(
            Section::Additional,
            name,
            Type::AAAA,
            Class::IN,
            service.ttl,
            &ip.octets(),
        ),
        HostType::Cname | HostType::Txt => Ok(false),
    }?;
    Ok(())
}

/// The target of a service with a port whose host is an address.
fn srv_target(service: &Service) -> Option<Wire> {
    // CoreDNS v1.15.0 plugin/backend_lookup.go `SRV`: port -1 marks a service without a port.
    if service.port == -1 || !matches!(service.host_type(), HostType::A(_) | HostType::Aaaa(_)) {
        return None;
    }
    key_name(service, true)
}

/// CoreDNS v1.15.0 plugin/backend_lookup.go `SRV`: the SRV records, then the addresses of their targets.
fn srv(
    builder: &mut MessageBuilder<'_>,
    owner: NameRef<'_>,
    services: &Services,
) -> Result<usize, BuildError> {
    let mut count = 0;
    for (index, service) in services.iter().enumerate() {
        let Some(target) = srv_target(service) else {
            continue;
        };
        let port = service.port as u16;
        let repeated = services
            .iter()
            .take(index)
            .any(|e| srv_target(e).is_some_and(|t| t.same(&target) && e.port as u16 == port));
        let Some(target) = target.name().filter(|_| !repeated) else {
            continue;
        };
        // The weight of a service is its share of the weights at its priority.
        let total = services
            .iter()
            .filter(|e| e.priority == service.priority)
            .fold(0i64, |total, e| total.wrapping_add(srv_weight(e)));
        let weight = srv_share(service, total);
        // RFC 2782 §The format of the SRV RR: the target is not compressed.
        builder.record_with(
            Section::Answer,
            owner,
            Type::SRV,
            Class::IN,
            service.ttl,
            |w| {
                w.write_bytes(&(service.priority as u16).to_be_bytes())?;
                w.write_bytes(&weight.to_be_bytes())?;
                w.write_bytes(&port.to_be_bytes())?;
                w.write_uncompressed_name(target)
            },
        )?;
        count += 1;
    }
    for (index, service) in services.iter().enumerate() {
        let Some(target) = srv_target(service) else {
            continue;
        };
        let repeated = services
            .iter()
            .take(index)
            .any(|e| srv_target(e).is_some_and(|t| t.same(&target) && e.host == service.host));
        if !repeated {
            address_record(builder, &target, service)?;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests;

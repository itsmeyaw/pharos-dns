//! Authoritative Zones loaded from master files.

pub(crate) mod setup;

use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::{
    MessageBuilder, Name, NameRef, Rcode, Section, Type,
    zone::{ZoneParser, ZoneRecord},
};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol};
use std::{io::BufReader, path::Path, sync::Arc};

/// Immutable authoritative Zone data, reusable by Zone-serving Plugins.
#[derive(Debug)]
pub struct Zone {
    apex: Name,
    records: Vec<ZoneRecord>,
}

impl Zone {
    /// Load a Zone from a master file.
    pub fn load(apex: Name, path: &Path) -> Result<Self, String> {
        let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
        let mut parser =
            ZoneParser::new(BufReader::new(file), apex.clone(), path.to_string_lossy());
        parser.set_include_allowed(true);
        let mut records = Vec::new();
        let mut soa = false;
        for record in parser {
            let record = record.map_err(|error| error.to_string())?;
            if record.rtype == Type::SOA {
                if record.owner != apex {
                    return Err("SOA owner does not match Zone apex".into());
                }
                soa = true;
            }
            if record.rtype == Type::NSEC3 || record.rtype == Type::NSEC3PARAM {
                return Err("NSEC3 zone is not supported".into());
            }
            records.push(record);
        }
        if !soa {
            return Err("Zone has no SOA".into());
        }
        Ok(Self { apex, records })
    }

    fn records_at<'a>(
        &'a self,
        name: &'a [u8],
        kind: Type,
    ) -> impl Iterator<Item = &'a ZoneRecord> {
        self.records
            .iter()
            .filter(move |rr| rr.rtype == kind && rr.owner.as_wire().eq_ignore_ascii_case(name))
    }

    fn exists(&self, name: &[u8]) -> bool {
        self.records
            .iter()
            .any(|rr| contains_wire(rr.owner.as_wire(), name))
    }
}

#[derive(Debug)]
pub struct File {
    zones: Vec<Arc<Zone>>,
    fallthrough: Vec<Name>,
}

impl File {
    fn parse(
        cursor: &mut Cursor<'_>,
        server_domains: &[&str],
        root: Option<&Path>,
    ) -> Result<Self, Error> {
        let mut zones = Vec::new();
        let mut fallthrough = Vec::new();
        while cursor.next() {
            let args = cursor.remaining_args();
            let path = args.first().ok_or_else(|| cursor.arg_err())?;
            let path = crate::resolve_path(path.into(), root);
            let names = args[1..].iter().map(String::as_str).collect::<Vec<_>>();
            for domain in origins_from_args_or_server_block(&names, server_domains) {
                let apex = domain.parse().map_err(|_| cursor.error("invalid Zone"))?;
                zones.push(Arc::new(
                    Zone::load(apex, &path).map_err(|error| cursor.error(error))?,
                ));
            }
            while cursor.next_block() {
                let option = cursor.val().to_owned();
                let args = cursor.remaining_args();
                match option.as_str() {
                    "fallthrough" => {
                        if args.is_empty() {
                            fallthrough.push(".".parse().map_err(|_| cursor.arg_err())?);
                        } else {
                            for domain in args {
                                let names = origins_from_args_or_server_block(&[&domain], &[]);
                                for name in names {
                                    fallthrough.push(name.parse().map_err(|_| cursor.arg_err())?);
                                }
                            }
                        }
                    }
                    "reload"
                        if !args.is_empty()
                            && crate::health::parse_duration(&args[0]).is_some() => {}
                    "reload_by_mtime" | "upstream" => {}
                    _ => return Err(cursor.arg_err()),
                }
            }
        }
        Ok(Self { zones, fallthrough })
    }
}

// RFC 1034 §3.1: a Zone contains names at or below its apex.
fn contains(name: &[u8], apex: &Name) -> bool {
    contains_wire(name, apex.as_wire())
}

fn contains_wire(name: &[u8], apex: &[u8]) -> bool {
    let mut suffix = name;
    loop {
        if suffix.eq_ignore_ascii_case(apex) {
            return true;
        }
        if suffix[0] == 0 {
            return false;
        }
        suffix = &suffix[usize::from(suffix[0]) + 1..];
    }
}

impl Plugin for File {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        let mut wire = [0u8; 255];
        let mut len = 0;
        for label in question.name.labels() {
            wire[len] = label.len() as u8;
            len += 1;
            wire[len..len + label.len()].copy_from_slice(label);
            len += label.len();
        }
        len += 1;
        let name = &wire[..len];
        let Some(zone) = self
            .zones
            .iter()
            .filter(|zone| contains(name, &zone.apex))
            .max_by_key(|zone| zone.apex.label_count())
        else {
            return next.run(cx).await;
        };
        if matches!(question.qtype, Type::AXFR | Type::IXFR) {
            return Outcome::Unanswered(Rcode::REFUSED);
        }
        // RFC 1034 §4.3.2: return the first Zone Cut between the apex and QNAME.
        let cut = zone
            .records
            .iter()
            .filter(|rr| {
                rr.rtype == Type::NS
                    && rr.owner != zone.apex
                    && contains_wire(name, rr.owner.as_wire())
                    && !(question.qtype == Type::DS
                        && rr.owner.as_wire().eq_ignore_ascii_case(name))
            })
            .min_by_key(|rr| rr.owner.label_count());
        let mut wildcard = [0u8; 255];
        let mut source = name;
        let exists = zone.exists(name);
        if !exists && cut.is_none() {
            // RFC 4592 §3.3.1: the closest encloser determines wildcard synthesis.
            let mut parent = name;
            while parent[0] != 0 && !zone.exists(parent) {
                parent = &parent[1 + usize::from(parent[0])..];
            }
            if parent.len() + 2 <= wildcard.len() {
                wildcard[0] = 1;
                wildcard[1] = b'*';
                wildcard[2..2 + parent.len()].copy_from_slice(parent);
                let candidate = &wildcard[..parent.len() + 2];
                if zone.exists(candidate) {
                    source = candidate;
                }
            }
        }
        let synthesized = !std::ptr::eq(source.as_ptr(), name.as_ptr());
        let mut chain = [None; 10];
        let mut count = 0;
        let mut target = source;
        if cut.is_none() && question.qtype != Type::CNAME {
            // RFC 1034 §3.6.2: follow a CNAME before answering the original QTYPE.
            while let Some(alias) = zone.records_at(target, Type::CNAME).next() {
                if count == chain.len() {
                    return Outcome::Unanswered(Rcode::SERVFAIL);
                }
                chain[count] = Some(alias);
                count += 1;
                target = &alias.rdata;
            }
        }
        let found = count > 0 || zone.records_at(target, question.qtype).next().is_some();
        if !exists
            && !synthesized
            && cut.is_none()
            && self.fallthrough.iter().any(|apex| contains(name, apex))
        {
            return next.run(cx).await;
        }
        let rcode = if exists || synthesized || cut.is_some() {
            Rcode::NOERROR
        } else {
            Rcode::NXDOMAIN
        };
        let max = cx.max_response_size.max(512);
        if cx.response.capacity() < max {
            if cx.protocol == Protocol::Tcp {
                cx.response.reserve(max.saturating_sub(cx.response.len()));
            } else {
                return Outcome::Error(pharos_server::Error::ResponseBufferTooSmall);
            }
        }
        let result = (|| -> Result<(), pharos_server::Error> {
            // RFC 1035 §4.1.1: authoritative Responses preserve Query flags and ID.
            let mut builder = MessageBuilder::new(
                cx.response,
                max,
                cx.query.id(),
                0x8000
                    | if cut.is_none() { 0x0400 } else { 0 }
                    | (cx.query.flags() & 0x7910)
                    | rcode.0,
            )
            .map_err(pharos_server::Error::Build)?;
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(pharos_server::Error::Build)?;
            for (index, rr) in chain[..count].iter().flatten().enumerate() {
                let owner = if index == 0 && synthesized {
                    question.name
                } else {
                    NameRef::parse(rr.owner.as_wire(), 0)
                        .map_err(|_| pharos_server::Error::InvalidQuery)?
                };
                builder
                    .record(
                        Section::Answer,
                        owner,
                        rr.rtype,
                        rr.class,
                        rr.ttl,
                        &rr.rdata,
                    )
                    .map_err(pharos_server::Error::Build)?;
            }
            for rr in zone
                .records_at(target, question.qtype)
                .filter(|_| cut.is_none())
            {
                let owner = if count == 0 && synthesized {
                    question.name
                } else {
                    NameRef::parse(rr.owner.as_wire(), 0)
                        .map_err(|_| pharos_server::Error::InvalidQuery)?
                };
                builder
                    .record(
                        Section::Answer,
                        owner,
                        rr.rtype,
                        rr.class,
                        rr.ttl,
                        &rr.rdata,
                    )
                    .map_err(pharos_server::Error::Build)?;
            }
            // RFC 2308 §3: negative Responses include the Zone SOA.
            let authority_type = if found || cut.is_some() {
                Type::NS
            } else {
                Type::SOA
            };
            let authority_owner = cut.map_or(zone.apex.as_wire(), |rr| rr.owner.as_wire());
            for rr in zone.records.iter().filter(|rr| {
                rr.owner.as_wire().eq_ignore_ascii_case(authority_owner)
                    && rr.rtype == authority_type
            }) {
                let owner = NameRef::parse(rr.owner.as_wire(), 0)
                    .map_err(|_| pharos_server::Error::InvalidQuery)?;
                builder
                    .record(
                        Section::Authority,
                        owner,
                        rr.rtype,
                        rr.class,
                        rr.ttl,
                        &rr.rdata,
                    )
                    .map_err(pharos_server::Error::Build)?;
            }
            // RFC 1034 §4.3.2: Referrals include available address glue.
            if let Some(cut) = cut {
                for ns in zone.records_at(cut.owner.as_wire(), Type::NS) {
                    for rr in zone.records.iter().filter(|rr| {
                        rr.owner.as_wire().eq_ignore_ascii_case(&ns.rdata)
                            && matches!(rr.rtype, Type::A | Type::AAAA)
                    }) {
                        let owner = NameRef::parse(rr.owner.as_wire(), 0)
                            .map_err(|_| pharos_server::Error::InvalidQuery)?;
                        builder
                            .record(
                                Section::Additional,
                                owner,
                                rr.rtype,
                                rr.class,
                                rr.ttl,
                                &rr.rdata,
                            )
                            .map_err(pharos_server::Error::Build)?;
                    }
                }
            }
            let _ = builder.finish();
            Ok(())
        })();
        result.map_or_else(Outcome::Error, |()| Outcome::Response)
    }
}

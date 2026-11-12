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
    let mut suffix = name;
    loop {
        if suffix.eq_ignore_ascii_case(apex.as_wire()) {
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
        let exists = zone
            .records
            .iter()
            .any(|rr| rr.owner.as_wire().eq_ignore_ascii_case(name));
        let found = zone
            .records
            .iter()
            .any(|rr| rr.owner.as_wire().eq_ignore_ascii_case(name) && rr.rtype == question.qtype);
        if !exists && self.fallthrough.iter().any(|apex| contains(name, apex)) {
            return next.run(cx).await;
        }
        let rcode = if exists {
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
                0x8400 | (cx.query.flags() & 0x7910) | rcode.0,
            )
            .map_err(pharos_server::Error::Build)?;
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(pharos_server::Error::Build)?;
            for rr in zone.records.iter().filter(|rr| {
                rr.owner.as_wire().eq_ignore_ascii_case(name) && rr.rtype == question.qtype
            }) {
                builder
                    .record(
                        Section::Answer,
                        question.name,
                        rr.rtype,
                        rr.class,
                        rr.ttl,
                        &rr.rdata,
                    )
                    .map_err(pharos_server::Error::Build)?;
            }
            // RFC 2308 §3: negative Responses include the Zone SOA.
            let authority_type = if found { Type::NS } else { Type::SOA };
            for rr in zone
                .records
                .iter()
                .filter(|rr| rr.owner == zone.apex && rr.rtype == authority_type)
            {
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
            let _ = builder.finish();
            Ok(())
        })();
        result.map_or_else(Outcome::Error, |()| Outcome::Response)
    }
}

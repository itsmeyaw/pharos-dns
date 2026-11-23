//! Cloud DNS record sets to a Zone.

use std::fmt::Write;

use pharos_proto::{
    Class, Name,
    zone::{ZoneParser, ZoneRecord},
};
use pharos_server::logging::log;

use super::api::Rrset;
use crate::zone::{Zone, contains};

// A single bad record set must not flood the log on every refresh.
const MAX_LOGGED_SKIPS: usize = 5;

/// Build the Zone for `apex` from every record set of one hosted zone (`label` names it in logs).
pub(super) fn build(apex: &Name, label: &str, rrsets: &[Rrset]) -> Result<Zone, String> {
    let root: Name = ".".parse().expect("the root name parses");
    let mut records = Vec::new();
    let mut skipped = 0_usize;
    for rrset in rrsets {
        match convert(apex, &root, rrset) {
            Ok(converted) => records.extend(converted),
            Err(reason) => {
                skipped += 1;
                if skipped <= MAX_LOGGED_SKIPS {
                    // The record data is not logged: only the zone, name, type and reason.
                    log(
                        "WARN",
                        "clouddns",
                        &format!(
                            "Skipping record set {} {} in {label}: {reason}",
                            rrset.name.escape_debug(),
                            rrset.rtype.escape_debug()
                        ),
                    );
                }
            }
        }
    }
    if skipped > MAX_LOGGED_SKIPS {
        log(
            "WARN",
            "clouddns",
            &format!("Skipped {skipped} record sets in {label}"),
        );
    }
    Zone::from_records(apex.clone(), records)
}

// RFC 1034 §3.1: a name is absolute when it ends in an unescaped dot (miekg/dns Fqdn).
fn fqdn(name: &str) -> String {
    let escapes = name.strip_suffix('.').map_or(0, |rest| {
        rest.bytes().rev().take_while(|byte| *byte == b'\\').count()
    });
    if name.ends_with('.') && escapes.is_multiple_of(2) {
        name.to_owned()
    } else {
        format!("{name}.")
    }
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns.go updateZoneFromRRS: one `NAME TTL IN TYPE VALUE` line per value.
// Deviation (ADR-0002): CoreDNS stops at the first unparsable value and ignores the error; this skips the record set.
fn convert(apex: &Name, root: &Name, rrset: &Rrset) -> Result<Vec<ZoneRecord>, String> {
    // A line break would start another master-file entry.
    if rrset.name.contains(['\n', '\r', '\0']) {
        return Err("invalid character".to_owned());
    }
    let owner: Name = fqdn(&rrset.name)
        .parse()
        .map_err(|_| "invalid name".to_owned())?;
    // RFC 1034 §4.2; RFC 2181 §6.1: a Zone holds only names at or below its apex.
    if !contains(owner.as_wire(), apex) {
        return Err("name is outside the zone".to_owned());
    }
    if rrset.rtype.is_empty() || !rrset.rtype.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err("invalid type".to_owned());
    }
    let mut text = String::new();
    for value in &rrset.rrdatas {
        if value.contains(['\n', '\r', '\0']) {
            return Err("invalid character".to_owned());
        }
        // CoreDNS v1.15.0 plugin/clouddns/clouddns.go updateZoneFromRRS: CNAME and PTR values are made absolute.
        let value = if matches!(rrset.rtype.as_str(), "CNAME" | "PTR") {
            fqdn(value)
        } else {
            value.clone()
        };
        let _ = writeln!(text, "{owner} {} IN {} {value}", rrset.ttl, rrset.rtype);
    }
    // miekg/dns NewRR parses relative names against the root, so rdata names stay as written, not under the apex.
    let mut converted = Vec::with_capacity(rrset.rrdatas.len());
    for record in ZoneParser::new(text.as_bytes(), root.clone(), "clouddns") {
        // The parser's message can quote the record data, which the log must not carry.
        let record = record.map_err(|_| "invalid record data".to_owned())?;
        if record.owner != owner || record.class != Class::IN || record.ttl != rrset.ttl {
            return Err("record does not match its record set".to_owned());
        }
        converted.push(record);
    }
    if converted.len() != rrset.rrdatas.len() {
        return Err("record data does not parse as one record per value".to_owned());
    }
    Ok(converted)
}

#[cfg(test)]
mod tests;

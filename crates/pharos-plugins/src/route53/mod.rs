//! Authoritative Zones served from AWS Route 53 hosted zones.

pub(crate) mod setup;
#[cfg(test)]
mod tests;

use pharos_corefile::Fallthrough;
use pharos_proto::{
    Name,
    zone::{ZoneParser, ZoneRecord},
};
use pharos_server::{Context, Next, Outcome, Plugin};
use std::{future::Future, path::PathBuf, time::Duration};

/// A secret that stays out of `Debug` output.
#[derive(Clone, Eq, PartialEq)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// One `route53` stanza as written in the Corefile; parsing never touches the network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// `ZONE:HOSTED_ZONE_ID` arguments grouped by ZONE in first-seen order.
    pub zones: Vec<(String, Vec<String>)>,
    /// `aws_access_key ID SECRET` (deprecated).
    pub access_key: Option<(String, Secret)>,
    /// `aws_endpoint URL`.
    pub endpoint: Option<String>,
    /// `credentials PROFILE`.
    pub profile: Option<String>,
    /// `credentials PROFILE FILE`, plus `~/.aws/config` when `AWS_SDK_LOAD_CONFIG` is truthy; `None` keeps the SDK default.
    pub shared_config_files: Option<Vec<PathBuf>>,
    pub fallthrough: Fallthrough,
    pub refresh: Duration,
}

/// The `route53` Plugin; serving Route 53 data is not wired yet, so a Query passes to the next Plugin.
#[derive(Debug)]
pub struct Route53;

impl Plugin for Route53 {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        next.run(cx).await
    }
}

/// Where the next page of `ListResourceRecordSets` starts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartRecord {
    pub name: String,
    pub rtype: String,
    pub identifier: Option<String>,
}

/// A Route 53 resource record set; an alias set has no `values` and yields no records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordSet {
    pub name: String,
    pub rtype: String,
    pub ttl: i64,
    pub values: Vec<String>,
}

/// One page of `ListResourceRecordSets`; `next` is set when the page is truncated.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Page {
    pub sets: Vec<RecordSet>,
    pub next: Option<StartRecord>,
}

/// The two Route 53 calls the Plugin makes; the AWS SDK and the tests each implement it.
pub trait Api: Send + Sync {
    /// CoreDNS v1.15.0 plugin/route53/route53.go New: `ListHostedZonesByName` for each ZONE:ID.
    fn check_hosted_zone(
        &self,
        dns: &str,
        hosted_zone_id: &str,
    ) -> impl Future<Output = Result<(), String>> + Send;

    /// CoreDNS v1.15.0 plugin/route53/route53.go updateZones: `ListResourceRecordSets` with MaxItems 1000.
    fn list_record_sets(
        &self,
        hosted_zone_id: &str,
        start: Option<&StartRecord>,
    ) -> impl Future<Output = Result<Page, String>> + Send;
}

// CoreDNS v1.15.0 plugin/route53/route53.go maybeUnescape: strconv.ParseInt(s, 8, 8) of the three octets after a backslash.
fn parse_octal_i8(text: &[u8]) -> Option<i8> {
    let (negative, digits) = match text.first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty() || !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
        return None;
    }
    let value = digits
        .iter()
        .fold(0i32, |value, digit| value * 8 + i32::from(digit - b'0'));
    i8::try_from(if negative { -value } else { value }).ok()
}

// Go's `%#03o`: a leading zero marker, zero padded to three characters.
fn go_octal(value: i32) -> String {
    let digits = format!("{:03o}", value.unsigned_abs());
    let sign = if value < 0 { "-" } else { "" };
    if digits.starts_with('0') {
        format!("{sign}{digits}")
    } else {
        format!("{sign}0{digits}")
    }
}

/// Converts the `\ooo` octal escapes Route 53 emits back to the ASCII character.
pub fn maybe_unescape(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut start = 0;
    // CoreDNS v1.15.0 plugin/route53/route53.go maybeUnescape: each backslash starts a three-octet escape.
    while let Some(offset) = bytes[start..].iter().position(|byte| *byte == b'\\') {
        let at = start + offset;
        out.push_str(&text[start..at]);
        let (first, last) = (at + 1, at + 4);
        if last > bytes.len() {
            return Err(format!(
                "invalid escape sequence: '\\{}'",
                String::from_utf8_lossy(&bytes[first..])
            ));
        }
        let Some(code) = parse_octal_i8(&bytes[first..last]) else {
            return Err(format!(
                "invalid escape sequence: '\\{}'",
                String::from_utf8_lossy(&bytes[first..last])
            ));
        };
        match u8::try_from(code) {
            // Route 53 lowercases names, so only a-z, 0-9, `-` and `.` are accepted besides the wildcard.
            Ok(byte @ (b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.')) => out.push(char::from(byte)),
            Ok(b'*') if out.is_empty() => out.push('*'),
            Ok(b'*') => return Err("`*' only supported as wildcard (leftmost label)".to_owned()),
            _ => {
                return Err(format!(
                    "invalid character: \\{}",
                    go_octal(i32::from(code))
                ));
            }
        }
        start = last;
    }
    out.push_str(&text[start..]);
    Ok(out)
}

// CoreDNS v1.15.0 plugin/route53/route53.go updateZoneFromRRS: dns.NewRR parses one record from the RFC 1035 line, relative names under the root.
fn parse_record(line: &str) -> Result<ZoneRecord, String> {
    let root: Name = ".".parse().map_err(|_| "invalid root name".to_owned())?;
    let mut records = ZoneParser::new(line.as_bytes(), root, "route53");
    let record = records
        .next()
        .ok_or_else(|| "no resource record".to_owned())?
        .map_err(|error| error.to_string())?;
    match records.next() {
        None => Ok(record),
        Some(_) => Err("more than one resource record".to_owned()),
    }
}

/// Appends the records of one record set; the first bad record ends the set but keeps the records before it.
pub fn append_records(set: &RecordSet, out: &mut Vec<ZoneRecord>) -> Result<(), String> {
    // CoreDNS v1.15.0 plugin/route53/route53.go updateZoneFromRRS: only ResourceRecords are read, so an alias set yields nothing.
    for value in &set.values {
        let name = maybe_unescape(&set.name)
            .map_err(|error| format!("failed to unescape `{}' name: {error}", set.name))?;
        let value = maybe_unescape(value)
            .map_err(|error| format!("failed to unescape `{value}' value: {error}"))?;
        let line = format!("{name} {} IN {} {value}", set.ttl, set.rtype);
        out.push(
            parse_record(&line)
                .map_err(|error| format!("failed to parse resource record: {error}"))?,
        );
    }
    Ok(())
}

/// Converts every record set of a page, logging and skipping the ones that fail.
pub fn convert_page(sets: &[RecordSet], out: &mut Vec<ZoneRecord>) {
    for set in sets {
        // CoreDNS v1.15.0 plugin/route53/route53.go updateZones: maybe an unsupported record type, so log and carry on.
        if let Err(error) = append_records(set, out) {
            pharos_server::logging::log(
                "WARN",
                "route53",
                &format!("Failed to process resource record set: {error}"),
            );
        }
    }
}

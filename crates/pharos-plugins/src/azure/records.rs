//! Azure DNS record set pages as `ZoneRecord`s, and a `Zone` built from them.

use std::net::{Ipv4Addr, Ipv6Addr};

use pharos_proto::{Class, Name, Type, zone::ZoneRecord};
use serde_json::{Map, Value};

use crate::zone::Zone;

/// One page of a record set listing.
#[derive(Debug)]
pub(super) struct Page {
    pub records: Vec<ZoneRecord>,
    /// The URL of the next page; `None` on the last page.
    pub next_link: Option<String>,
}

/// CoreDNS v1.15.0 plugin/azure/azure.go: Go's encoding/json matches keys without case, and the public API
/// (`ARecords`, `TTL`) and the private API (`aRecords`, `ttl`) spell them differently.
fn field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object
        .iter()
        .find(|(name, value)| name.eq_ignore_ascii_case(key) && !value.is_null())
        .map(|(_, value)| value)
}

fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{what} is not an object"))
}

fn array<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a [Value], String> {
    match field(object, key) {
        None => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(format!("{key} is not an array")),
    }
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    field(object, key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or invalid {key}"))
}

/// RFC 1035 §3.2: the numeric RDATA fields are unsigned of a fixed width; an out-of-range value is an error, not a wrap.
fn number<T: TryFrom<u64>>(object: &Map<String, Value>, key: &str) -> Result<T, String> {
    field(object, key)
        .and_then(Value::as_u64)
        .and_then(|value| T::try_from(value).ok())
        .ok_or_else(|| format!("missing or out-of-range {key}"))
}

/// miekg/dns `Fqdn`: a name without a trailing dot is absolute here, as every Azure name is.
fn name_wire(value: &str, root: &Name) -> Result<Vec<u8>, String> {
    Name::parse(value, root)
        .map(|name| name.as_wire().to_vec())
        .map_err(|error| format!("invalid name {value:?}: {error}"))
}

/// Parse one page of the listing; `private` selects the Private DNS shape, which has no NS record sets.
pub(super) fn parse_page(body: &[u8], private: bool) -> Result<Page, String> {
    let json: Value = serde_json::from_slice(body)
        .map_err(|error| format!("invalid record set page: {error}"))?;
    let page = object(&json, "record set page")?;
    let root: Name = ".".parse().map_err(|_| "invalid root name".to_owned())?;
    let mut records = Vec::new();
    // Azure DNS REST API 2018-05-01 RecordSetListResult: `value` holds the record sets; absent or null is an empty page.
    let sets = match field(page, "value") {
        None => &[][..],
        Some(Value::Array(sets)) => sets,
        Some(_) => return Err("record set page value is not an array".to_owned()),
    };
    for set in sets {
        record_set(set, private, &root, &mut records)?;
    }
    // autorest `hasNextLink`: a null or empty `nextLink` ends the listing.
    let next_link = match field(page, "nextLink") {
        None => None,
        Some(Value::String(link)) if link.is_empty() => None,
        Some(Value::String(link)) => Some(link.clone()),
        Some(_) => return Err("record set page nextLink is not a string".to_owned()),
    };
    Ok(Page { records, next_link })
}

fn record_set(
    set: &Value,
    private: bool,
    root: &Name,
    records: &mut Vec<ZoneRecord>,
) -> Result<(), String> {
    let set = object(set, "record set")?;
    let properties = field(set, "properties")
        .ok_or("record set has no properties")
        .and_then(|value| object(value, "record set properties").map_err(|_| "bad properties"))?;
    let fqdn = text(properties, "fqdn")?;
    convert(properties, fqdn, private, root, records)
        .map_err(|error| format!("record set {fqdn:?}: {error}"))
}

fn convert(
    properties: &Map<String, Value>,
    fqdn: &str,
    private: bool,
    root: &Name,
    records: &mut Vec<ZoneRecord>,
) -> Result<(), String> {
    let owner = Name::parse(fqdn, root).map_err(|error| format!("invalid fqdn: {error}"))?;
    let ttl: u32 = number(properties, "ttl")?;
    let mut push = |rtype: Type, rdata: Vec<u8>| {
        records.push(ZoneRecord {
            owner: owner.clone(),
            ttl,
            class: Class::IN,
            rtype,
            rdata,
        });
    };
    for item in array(properties, "ARecords")? {
        let item = object(item, "ARecords entry")?;
        // RFC 1035 §3.4.1: an A record is one IPv4 address.
        let address: Ipv4Addr = text(item, "ipv4Address")?
            .parse()
            .map_err(|_| "invalid ipv4Address".to_owned())?;
        push(Type::A, address.octets().to_vec());
    }
    for item in array(properties, "AAAARecords")? {
        let item = object(item, "AAAARecords entry")?;
        // RFC 3596 §2.2: an AAAA record is one IPv6 address.
        let address: Ipv6Addr = text(item, "ipv6Address")?
            .parse()
            .map_err(|_| "invalid ipv6Address".to_owned())?;
        push(Type::AAAA, address.octets().to_vec());
    }
    for item in array(properties, "MXRecords")? {
        let item = object(item, "MXRecords entry")?;
        // RFC 1035 §3.3.9: MX is a 16-bit preference and the exchange name.
        let mut rdata = number::<u16>(item, "preference")?.to_be_bytes().to_vec();
        rdata.extend(name_wire(text(item, "exchange")?, root)?);
        push(Type::MX, rdata);
    }
    for item in array(properties, "PTRRecords")? {
        let item = object(item, "PTRRecords entry")?;
        // RFC 1035 §3.3.12: PTR is one domain name.
        push(Type::PTR, name_wire(text(item, "ptrdname")?, root)?);
    }
    for item in array(properties, "SRVRecords")? {
        let item = object(item, "SRVRecords entry")?;
        // RFC 2782 §"The format of the SRV RR": priority, weight and port, then the target.
        let mut rdata = Vec::new();
        for key in ["priority", "weight", "port"] {
            rdata.extend(number::<u16>(item, key)?.to_be_bytes());
        }
        rdata.extend(name_wire(text(item, "target")?, root)?);
        push(Type::SRV, rdata);
    }
    for item in array(properties, "TXTRecords")? {
        let item = object(item, "TXTRecords entry")?;
        // RFC 1035 §3.3.14: TXT is one or more character-strings of at most 255 octets; Azure's `value` lists them.
        let strings = array(item, "value")?;
        if strings.is_empty() {
            return Err("TXT record has no strings".to_owned());
        }
        let mut rdata = Vec::new();
        for string in strings {
            let bytes = string
                .as_str()
                .ok_or("TXT value is not a string")?
                .as_bytes();
            let len = u8::try_from(bytes.len()).map_err(|_| "TXT string is over 255 bytes")?;
            rdata.push(len);
            rdata.extend_from_slice(bytes);
        }
        push(Type::TXT, rdata);
    }
    // CoreDNS v1.15.0 plugin/azure/azure.go updateZoneFromPrivateResourceSet: Private DNS has no NS handling.
    if !private {
        for item in array(properties, "NSRecords")? {
            let item = object(item, "NSRecords entry")?;
            // RFC 1035 §3.3.11: NS is one domain name.
            push(Type::NS, name_wire(text(item, "nsdname")?, root)?);
        }
    }
    if let Some(item) = field(properties, "SOARecord") {
        let item = object(item, "SOARecord")?;
        // RFC 1035 §3.3.13: SOA is MNAME, RNAME and five 32-bit fields.
        let mut rdata = name_wire(text(item, "host")?, root)?;
        rdata.extend(name_wire(text(item, "email")?, root)?);
        for key in [
            "serialNumber",
            "refreshTime",
            "retryTime",
            "expireTime",
            "minimumTTL",
        ] {
            rdata.extend(number::<u32>(item, key)?.to_be_bytes());
        }
        push(Type::SOA, rdata);
    }
    if let Some(item) = field(properties, "CNAMERecord") {
        let item = object(item, "CNAMERecord")?;
        // RFC 1035 §3.3.1: CNAME is one domain name.
        push(Type::CNAME, name_wire(text(item, "cname")?, root)?);
    }
    Ok(())
}

/// Length of the uncompressed wire name at the start of `wire`.
fn name_len(wire: &[u8]) -> usize {
    let mut at = 0;
    while let Some(&len) = wire.get(at) {
        at += 1 + usize::from(len);
        if len == 0 {
            break;
        }
    }
    at
}

/// Build the Zone of one hosted zone from every record of its listing.
pub(super) fn build_zone(apex: &Name, mut records: Vec<ZoneRecord>) -> Result<Zone, String> {
    // CoreDNS v1.15.0 plugin/azure/azure.go updateZone: a listing without an SOA is not a Zone.
    let soa = records
        .iter()
        .find(|record| record.rtype == Type::SOA && record.owner == *apex)
        .ok_or("zone has no SOA record")?;
    // RFC 2181 §6.1: Zone::from_records wants an apex NS RRset, and Azure Private DNS zones have none; the SOA's MNAME stands in.
    if !records
        .iter()
        .any(|record| record.rtype == Type::NS && record.owner == *apex)
    {
        let ns = ZoneRecord {
            owner: apex.clone(),
            ttl: soa.ttl,
            class: Class::IN,
            rtype: Type::NS,
            rdata: soa.rdata[..name_len(&soa.rdata)].to_vec(),
        };
        records.push(ns);
    }
    Zone::from_records(apex.clone(), records)
}

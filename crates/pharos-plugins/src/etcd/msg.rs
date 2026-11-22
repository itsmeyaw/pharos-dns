//! SkyDNS service records in etcd: their keys, JSON values, grouping and Host types.
//!
//! Ported from CoreDNS v1.15.0 plugin/etcd/msg. Nothing here performs I/O.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::Value;

/// A discoverable service stored under one etcd key: the rdata of an SRV record, with a twist.
///
/// CoreDNS v1.15.0 plugin/etcd/msg/service.go Service. `Host` is a domain name unless it
/// looks like an IP address.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Service {
    pub host: String,
    pub port: i64,
    pub priority: i64,
    pub weight: i64,
    pub text: String,
    /// Be an MX record; `priority` becomes the preference.
    pub mail: bool,
    pub ttl: u32,
    /// Labels stripped from the left of the synthesized target name.
    pub target_strip: i64,
    /// Services with an identical group are returned in the same answer.
    pub group: String,
    /// The etcd key the service was found under; never part of the JSON value.
    pub key: String,
}

/// The value stored under `key` could not be decoded as a [`Service`].
#[derive(Debug)]
pub struct DecodeError {
    key: String,
    reason: String,
}

impl fmt::Display for DecodeError {
    // CoreDNS v1.15.0 plugin/etcd/etcd.go loopNodes: errors read `KEY: REASON`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.key, self.reason)
    }
}

impl std::error::Error for DecodeError {}

impl Service {
    /// Decode the JSON `value` stored under `key`, like Go's `json.Unmarshal` into a `Service`.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] when `value` is not valid JSON, is neither an object nor
    /// `null`, or holds a field of the wrong type.
    pub fn from_json(key: &str, value: &[u8]) -> Result<Self, DecodeError> {
        let decoded = serde_json::from_slice::<Self>(value).map_err(|error| DecodeError {
            key: key.to_owned(),
            reason: error.to_string(),
        })?;
        Ok(Self {
            key: key.to_owned(),
            ..decoded
        })
    }

    /// What the `host` field encodes. CoreDNS v1.15.0 plugin/etcd/msg/type.go HostType.
    #[must_use]
    pub fn host_type(&self) -> HostType {
        // Go net.ParseIP: no zone, no leading zeros; an IPv4-mapped IPv6 address is an IPv4 one.
        match self.host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => HostType::A(ip),
            Ok(IpAddr::V6(ip)) => ip.to_ipv4_mapped().map_or(HostType::Aaaa(ip), HostType::A),
            Err(_) if self.text.is_empty() => HostType::Cname,
            Err(_) => HostType::Txt,
        }
    }
}

/// The DNS type of what a service's `host` field holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostType {
    /// `host` is an IPv4 address.
    A(Ipv4Addr),
    /// `host` is an IPv6 address.
    Aaaa(Ipv6Addr),
    /// `host` is a name.
    Cname,
    /// `host` is a name and the service has text, so it is also a TXT record.
    Txt,
}

impl<'de> Deserialize<'de> for Service {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ServiceVisitor)
    }
}

struct ServiceVisitor;

impl<'de> Visitor<'de> for ServiceVisitor {
    type Value = Service;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    // Go encoding/json: `null` leaves the value unchanged.
    fn visit_unit<E: de::Error>(self) -> Result<Service, E> {
        Ok(Service::default())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Service, A::Error> {
        let mut service = Service::default();
        // Go encoding/json: keys apply in order, so with two spellings of one field the last wins.
        while let Some((name, value)) = map.next_entry::<String, Value>()? {
            service.set(&name, value).map_err(de::Error::custom)?;
        }
        Ok(service)
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, _: A) -> Result<Service, A::Error> {
        Err(mismatch("array"))
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Service, E> {
        Err(mismatch("bool"))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Service, E> {
        Err(mismatch(format_args!("number {value}")))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Service, E> {
        Err(mismatch(format_args!("number {value}")))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Service, E> {
        Err(mismatch(format_args!("number {value}")))
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Service, E> {
        Err(mismatch("string"))
    }
}

fn mismatch<E: de::Error>(found: impl fmt::Display) -> E {
    E::custom(format_args!(
        "json: cannot unmarshal {found} into Go value of type msg.Service"
    ))
}

impl Service {
    /// Set the field `name` names from `value`, as Go's `json.Unmarshal` does.
    fn set(&mut self, name: &str, value: Value) -> Result<(), String> {
        match fold(name).as_str() {
            "host" => string(&mut self.host, "host", value),
            "port" => int(&mut self.port, "port", value),
            "priority" => int(&mut self.priority, "priority", value),
            "weight" => int(&mut self.weight, "weight", value),
            "text" => string(&mut self.text, "text", value),
            "mail" => boolean(&mut self.mail, "mail", value),
            "ttl" => unsigned(&mut self.ttl, "ttl", value),
            "targetstrip" => int(&mut self.target_strip, "targetstrip", value),
            "group" => string(&mut self.group, "group", value),
            // Go encoding/json: unknown fields, and `Key` (tagged `json:"-"`), are ignored.
            _ => Ok(()),
        }
    }
}

/// Go encoding/json matches field names ignoring case, with `ſ` folded to `s` and `K` (Kelvin) to `k`.
fn fold(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '\u{17f}' => 's',
            '\u{212a}' => 'k',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

fn mismatch_error(found: &str, field: &str, expected: &str) -> String {
    format!(
        "json: cannot unmarshal {found} into Go struct field Service.{field} of type {expected}"
    )
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// Go encoding/json: `null` is a no-op for every field type.
fn string(target: &mut String, field: &str, value: Value) -> Result<(), String> {
    match value {
        Value::String(text) => *target = text,
        Value::Null => {}
        other => return Err(mismatch_error(kind(&other), field, "string")),
    }
    Ok(())
}

fn boolean(target: &mut bool, field: &str, value: Value) -> Result<(), String> {
    match value {
        Value::Bool(flag) => *target = flag,
        Value::Null => {}
        other => return Err(mismatch_error(kind(&other), field, "bool")),
    }
    Ok(())
}

// Go encoding/json: an `int` takes only an integer literal that fits, not `1.5` or `1e2`.
fn int(target: &mut i64, field: &str, value: Value) -> Result<(), String> {
    match &value {
        Value::Number(number) => {
            *target = number
                .as_i64()
                .ok_or_else(|| mismatch_error(&format!("number {number}"), field, "int"))?;
        }
        Value::Null => {}
        other => return Err(mismatch_error(kind(other), field, "int")),
    }
    Ok(())
}

fn unsigned(target: &mut u32, field: &str, value: Value) -> Result<(), String> {
    match &value {
        Value::Number(number) => {
            *target = number
                .as_u64()
                .and_then(|number| u32::try_from(number).ok())
                .ok_or_else(|| mismatch_error(&format!("number {number}"), field, "uint32"))?;
        }
        Value::Null => {}
        other => return Err(mismatch_error(kind(other), field, "uint32")),
    }
    Ok(())
}

/// Keep the services of one group. CoreDNS v1.15.0 plugin/etcd/msg/service.go Group.
///
/// The group of the shortest key (one with a group attribute) wins; if several keys of that
/// length disagree on the group, nothing is filtered. Services without a group always stay.
#[must_use]
pub fn group(mut services: Vec<Service>) -> Vec<Service> {
    let Some(chosen) = chosen_group(services.iter()).map(str::to_owned) else {
        return services;
    };
    services.retain(|service| service.group.is_empty() || service.group == chosen);
    services
}

/// The group `services` are cut to, or `None` when [`group`] keeps them all.
pub(super) fn chosen_group<'a>(
    services: impl Iterator<Item = &'a Service> + Clone,
) -> Option<&'a str> {
    let first = services.clone().next()?;
    // Go: the shortest key with a group attribute sets the group for this set.
    let mut chosen = first.group.as_str();
    let mut slashes = count_slashes(&first.key);
    // Go Group fills `length[i]` only up to the `break`; later entries keep 0.
    let mut measured = usize::MAX;
    for (index, service) in services.clone().enumerate() {
        let count = count_slashes(&service.key);
        if count < slashes {
            if service.group.is_empty() {
                measured = index + 1;
                break;
            }
            slashes = count;
            chosen = service.group.as_str();
        }
    }
    if chosen.is_empty() {
        return None;
    }
    // Go: two grouped services on the shortest level that disagree leave the set as it is.
    let disagree = services.enumerate().any(|(index, service)| {
        let length = if index < measured {
            count_slashes(&service.key)
        } else {
            0
        };
        !service.group.is_empty() && length == slashes && service.group != chosen
    });
    (!disagree).then_some(chosen)
}

fn count_slashes(key: &str) -> usize {
    key.bytes().filter(|&byte| byte == b'/').count()
}

/// Convert a domain name to an etcd key: `service.staging.skydns.local.` under prefix
/// `skydns` is `/skydns/local/skydns/staging/service`.
///
/// CoreDNS v1.15.0 plugin/etcd/msg/path.go Path.
#[must_use]
pub fn path(name: &str, prefix: &str) -> String {
    let mut key = String::with_capacity(prefix.len() + 32);
    join(&mut key, prefix, labels_reversed(name));
    key
}

/// Like [`path`], but a name with a wildcard label (`*` or `any`) is cut before the first
/// wildcard counted from the root, and the flag says so.
///
/// CoreDNS v1.15.0 plugin/etcd/msg/path.go PathWithWildcard.
#[must_use]
pub fn path_with_wildcard(name: &str, prefix: &str) -> (String, bool) {
    let mut key = String::with_capacity(prefix.len() + 32);
    let wildcard = path_with_wildcard_into(&mut key, name, prefix);
    (key, wildcard)
}

/// [`path_with_wildcard`] into `key`, which is cleared first, so a caller can reuse its buffer.
pub(super) fn path_with_wildcard_into(key: &mut String, name: &str, prefix: &str) -> bool {
    let mut wildcard = false;
    let labels = labels_reversed(name).take_while(|label| {
        wildcard = matches!(*label, "*" | "any");
        !wildcard
    });
    // `take_while` is lazy: the flag is only final once the join has consumed the labels.
    join(key, prefix, labels);
    wildcard
}

/// Go `path.Join("/"+prefix+"/", labels...)`: elements joined with `/`, then lexically cleaned.
fn join<'a>(key: &mut String, prefix: &str, labels: impl Iterator<Item = &'a str>) {
    key.clear();
    // Go path.Clean on a rooted path: empty and `.` elements vanish, `..` removes the element
    // before it, and `..` at the root is dropped.
    let mut push = |element: &str| {
        for segment in element.split('/') {
            match segment {
                "" | "." => {}
                ".." => key.truncate(key.rfind('/').unwrap_or(0)),
                segment => {
                    key.push('/');
                    key.push_str(segment);
                }
            }
        }
    };
    push(prefix);
    labels.for_each(push);
    if key.is_empty() {
        key.push('/');
    }
}

/// The labels of `name` from the root down: Go `dns.SplitDomainName` reversed.
///
/// A final `.` ends the name, and a `.` preceded by an odd number of backslashes is part of a label.
pub(super) fn labels_reversed(name: &str) -> impl Iterator<Item = &str> {
    let bytes = name.as_bytes();
    let fqdn = is_fqdn(name);
    let mut end = if fqdn { bytes.len() - 1 } else { bytes.len() };
    // miekg/dns Split: the root name and the empty name have no labels.
    let mut done = name.is_empty() || name == ".";
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        // miekg/dns NextLabel: the last byte never separates, an escaped `.` does not either.
        let separator = (0..end.min(bytes.len().saturating_sub(1)))
            .rev()
            .find(|&index| bytes[index] == b'.' && !escaped(bytes, index));
        let start = separator.map_or(0, |index| index + 1);
        let label = &name[start..end];
        match separator {
            Some(index) => end = index,
            None => done = true,
        }
        Some(label)
    })
}

/// The domain name of an etcd key, the opposite of [`path`]: `/skydns/local/cluster/staging/service/`
/// is `service.staging.cluster.local.`.
///
/// CoreDNS v1.15.0 plugin/etcd/msg/path.go Domain. The first two elements (the empty one before
/// the leading `/`, and the prefix) are dropped, and a key too short to hold a name is the root.
#[must_use]
pub fn domain(key: &str) -> String {
    let mut name = String::new();
    domain_into(&mut name, key);
    name
}

/// [`domain`] into `name`, which is cleared first, so a caller can reuse its buffer.
pub(super) fn domain_into(name: &mut String, key: &str) {
    name.clear();
    let key = key.strip_suffix('/').unwrap_or(key);
    let mut elements = key.splitn(3, '/');
    let rest = elements.nth(2);
    let Some(rest) = rest else {
        name.push('.');
        return;
    };
    let mut labels = rest.rsplit('/');
    let last = labels.next_back().unwrap_or_default();
    for label in labels {
        name.push_str(label);
        name.push('.');
    }
    // CoreDNS v1.15.0 plugin/pkg/dnsutil/join.go Join: a final "." label is the root, else the name is made fully qualified.
    if last == "." {
        if name.is_empty() {
            name.push('.');
        }
    } else {
        name.push_str(last);
        if !is_fqdn(name) {
            name.push('.');
        }
    }
}

/// miekg/dns IsFqdn: ends in a `.` that is not escaped.
pub(super) fn is_fqdn(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes
        .len()
        .checked_sub(1)
        .is_some_and(|last| bytes[last] == b'.' && !escaped(bytes, last))
}

/// RFC 1035 §5.1: a character preceded by an odd number of backslashes is escaped.
fn escaped(bytes: &[u8], index: usize) -> bool {
    !bytes[..index]
        .iter()
        .rev()
        .take_while(|&&byte| byte == b'\\')
        .count()
        .is_multiple_of(2)
}

/// Split `text` into TXT character-strings. CoreDNS v1.15.0 plugin/etcd/msg/service.go split255.
///
/// Chunks are 255 bytes, cut without regard to UTF-8; as in CoreDNS, text of exactly 255 bytes
/// (or any multiple) ends with an empty chunk.
#[must_use]
pub fn split255(text: &[u8]) -> Vec<&[u8]> {
    chunks255(text).collect()
}

/// [`split255`] without the `Vec`.
pub(super) fn chunks255(text: &[u8]) -> impl Iterator<Item = &[u8]> {
    let long = text.len() >= 255;
    (!long)
        .then_some(text)
        .into_iter()
        .chain(text.chunks(255).filter(move |_| long))
        .chain((long && text.len().is_multiple_of(255)).then_some(&[][..]))
}

/// The name without its leftmost `count` labels, or all of `name` when it has no more labels
/// than that. CoreDNS v1.15.0 plugin/etcd/msg/service.go targetStrip.
#[must_use]
pub fn target_strip(name: &str, count: i64) -> &str {
    let (mut offset, mut end) = (0, false);
    for _ in 0..count {
        (offset, end) = next_label(name, offset);
        if end {
            break;
        }
    }
    if end { name } else { &name[offset..] }
}

/// miekg/dns NextLabel: the offset after the next unescaped `.` at or past `offset`, and whether
/// `name` ended instead. The last byte never separates.
fn next_label(name: &str, offset: usize) -> (usize, bool) {
    let bytes = name.as_bytes();
    let mut index = offset;
    while index + 1 < bytes.len() {
        if bytes[index] == b'.' && !escaped(bytes, index) {
            return (index + 1, false);
        }
        index += 1;
    }
    (index + 1, true)
}

#[cfg(test)]
mod tests;

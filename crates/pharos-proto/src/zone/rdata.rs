use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Name, Type};

/// Encodes presentation-format RDATA into uncompressed DNS wire format.
/// `fields` are whitespace-separated tokens with surrounding quotes removed and
/// backslash escapes preserved, as produced by the Zone lexer.
pub fn parse_rdata(rtype: Type, fields: &[&str], origin: &Name) -> Result<Vec<u8>, String> {
    // RFC 3597 §5: generic RDATA can represent any RR type, including known types.
    // shortcut: generic known-type data is not decoded; validate it for miekg parity.
    if fields.first() == Some(&r"\#") {
        if fields.len() < 2 {
            return Err("missing generic RDATA length".into());
        }
        let len: u16 = number(fields[1])?;
        let data = hex(&fields[2..].concat())?;
        return if data.len() == usize::from(len) {
            Ok(data)
        } else {
            Err("generic RDATA length mismatch".into())
        };
    }
    let mut out = Vec::new();
    match rtype {
        // RFC 1035 §3.4.1 and RFC 3596 §2.2: addresses are their raw network-order octets.
        Type::A => {
            count(fields, 1)?;
            out.extend(
                fields[0]
                    .parse::<Ipv4Addr>()
                    .map_err(|_| "invalid IPv4 address")?
                    .octets(),
            );
        }
        Type::AAAA => {
            count(fields, 1)?;
            out.extend(
                fields[0]
                    .parse::<Ipv6Addr>()
                    .map_err(|_| "invalid IPv6 address")?
                    .octets(),
            );
        }
        // RFC 1035 §3.3: domain names in RDATA are encoded as uncompressed names.
        // RFC 6672 §2.3: DNAME RDATA is also a domain name.
        Type::NS | Type::CNAME | Type::PTR | Type::DNAME => {
            count(fields, 1)?;
            name(&mut out, fields[0], origin)?;
        }
        Type::MX => {
            count(fields, 2)?;
            put16(&mut out, fields[0])?;
            name(&mut out, fields[1], origin)?;
        }
        Type::SOA => {
            count(fields, 7)?;
            name(&mut out, fields[0], origin)?;
            name(&mut out, fields[1], origin)?;
            put32(&mut out, fields[2])?;
            // RFC 2308 §4: SOA timers accept TTL unit suffixes; the serial remains decimal.
            for field in &fields[3..] {
                out.extend(
                    super::parse_ttl(field)
                        .ok_or("invalid SOA timer")?
                        .to_be_bytes(),
                );
            }
        }
        // RFC 4408 §3.1.1: the obsolete SPF RR type has the same format as TXT.
        Type::TXT | Type::SPF => {
            if fields.is_empty() {
                return Err("TXT requires a character-string".into());
            }
            for field in fields {
                character_string(&mut out, field)?;
            }
        }
        Type::HINFO => {
            count(fields, 2)?;
            for field in fields {
                character_string(&mut out, field)?;
            }
        }
        // RFC 2782 §3 and RFC 3403 §4: SRV and NAPTR contain fixed integers followed by names.
        Type::SRV => {
            count(fields, 4)?;
            for field in &fields[..3] {
                put16(&mut out, field)?;
            }
            name(&mut out, fields[3], origin)?;
        }
        Type::NAPTR => {
            count(fields, 6)?;
            put16(&mut out, fields[0])?;
            put16(&mut out, fields[1])?;
            for field in &fields[2..5] {
                character_string(&mut out, field)?;
            }
            name(&mut out, fields[5], origin)?;
        }
        // RFC 8659 §4: CAA has flags, a length-prefixed tag, and an unframed value.
        Type::CAA => {
            count(fields, 3)?;
            let tag = unescape(fields[1])?;
            if tag.is_empty() || !tag.iter().all(u8::is_ascii_alphanumeric) {
                return Err("invalid CAA tag".into());
            }
            out.push(number(fields[0])?);
            length_bytes(&mut out, &tag)?;
            out.extend(unescape(fields[2])?);
        }
        // RFC 7553 §4: URI has two 16-bit integers followed by target octets.
        Type::URI => {
            count(fields, 3)?;
            put16(&mut out, fields[0])?;
            put16(&mut out, fields[1])?;
            out.extend(unescape(fields[2])?);
        }
        // RFC 4034 §5 and RFC 7344 §4: DS/CDS digest is hexadecimal.
        Type::DS | Type::CDS => {
            if fields.len() < 4 {
                return Err("missing DS fields".into());
            }
            put16(&mut out, fields[0])?;
            out.push(number(fields[1])?);
            out.push(number(fields[2])?);
            out.extend(hex(&fields[3..].concat())?);
        }
        // RFC 4034 §2 and RFC 7344 §4: DNSKEY/CDNSKEY public keys use base64.
        Type::DNSKEY | Type::CDNSKEY => {
            if fields.len() < 4 {
                return Err("missing DNSKEY fields".into());
            }
            put16(&mut out, fields[0])?;
            out.push(number(fields[1])?);
            out.push(number(fields[2])?);
            out.extend(base64(&fields[3..].concat())?);
        }
        // RFC 6698 §2, RFC 8162 §2 and RFC 4255 §3: association data is hexadecimal.
        Type::TLSA | Type::SMIMEA | Type::SSHFP => {
            let prefix = if rtype == Type::SSHFP { 2 } else { 3 };
            if fields.len() <= prefix {
                return Err("missing association data".into());
            }
            for field in &fields[..prefix] {
                out.push(number(field)?);
            }
            out.extend(hex(&fields[prefix..].concat())?);
        }
        // RFC 8976 §2.1: ZONEMD uses a serial, scheme, algorithm, and hexadecimal digest.
        Type::ZONEMD => {
            if fields.len() < 4 {
                return Err("missing ZONEMD fields".into());
            }
            put32(&mut out, fields[0])?;
            out.push(number(fields[1])?);
            out.push(number(fields[2])?);
            let digest = hex(&fields[3..].concat())?;
            if digest.len() < 12 {
                return Err("ZONEMD digest too short".into());
            }
            out.extend(digest);
        }
        // RFC 4034 §3.1: signature times accept either decimal seconds or YYYYMMDDHHMMSS.
        Type::RRSIG => {
            if fields.len() < 9 {
                return Err("missing RRSIG fields".into());
            }
            out.extend(type_code(fields[0])?.to_be_bytes());
            out.push(number(fields[1])?);
            out.push(number(fields[2])?);
            put32(&mut out, fields[3])?;
            out.extend(timestamp(fields[4])?.to_be_bytes());
            out.extend(timestamp(fields[5])?.to_be_bytes());
            put16(&mut out, fields[6])?;
            name(&mut out, fields[7], origin)?;
            out.extend(base64(&fields[8..].concat())?);
        }
        // RFC 4034 §4.1.2 and RFC 5155 §3.2: NSEC bitmaps use ordered windows.
        Type::NSEC => {
            if fields.len() < 2 {
                return Err("missing NSEC name or bitmap".into());
            }
            name(&mut out, fields[0], origin)?;
            bitmap(&mut out, &fields[1..])?;
        }
        Type::NSEC3 | Type::NSEC3PARAM => {
            let required = if rtype == Type::NSEC3 { 5 } else { 4 };
            if fields.len() < required || (rtype == Type::NSEC3PARAM && fields.len() != required) {
                return Err("invalid NSEC3 fields".into());
            }
            out.push(number(fields[0])?);
            out.push(number(fields[1])?);
            put16(&mut out, fields[2])?;
            let salt = if fields[3] == "-" {
                Vec::new()
            } else {
                hex(fields[3])?
            };
            length_bytes(&mut out, &salt)?;
            if rtype == Type::NSEC3 {
                let hash = base32hex(fields[4])?;
                length_bytes(&mut out, &hash)?;
                bitmap(&mut out, &fields[5..])?;
            }
        }
        // RFC 9460 §2.2: parameters are serialized once each in numeric key order.
        Type::SVCB | Type::HTTPS => {
            if fields.len() < 2 {
                return Err("missing SVCB priority or target".into());
            }
            put16(&mut out, fields[0])?;
            name(&mut out, fields[1], origin)?;
            svc_params(&mut out, &fields[2..])?;
        }
        // RFC 8945 §4.2: TSIG contains a 48-bit time and 16-bit-length-prefixed byte strings.
        Type::TSIG => {
            if fields.len() < 7 || fields.len() > 9 {
                return Err("invalid TSIG fields".into());
            }
            name(&mut out, fields[0], origin)?;
            let time = timestamp64(fields[1])?;
            if time >= 1 << 48 {
                return Err("TSIG time out of range".into());
            }
            out.extend(&time.to_be_bytes()[2..]);
            put16(&mut out, fields[2])?;
            let mac_len = number::<u16>(fields[3])?;
            let has_mac_field = mac_len != 0 || fields[4].is_empty();
            let mac = if has_mac_field {
                hex(fields[4])?
            } else {
                Vec::new()
            };
            if usize::from(mac_len) != mac.len() {
                return Err("TSIG MAC length mismatch".into());
            }
            put16(&mut out, fields[3])?;
            out.extend(mac);
            let rest = &fields[4 + usize::from(has_mac_field)..];
            if !(3..=4).contains(&rest.len()) {
                return Err("invalid TSIG fields".into());
            }
            put16(&mut out, rest[0])?;
            put16(&mut out, rest[1])?;
            let other = hex(rest.get(3).copied().unwrap_or(""))?;
            if usize::from(number::<u16>(rest[2])?) != other.len() {
                return Err("TSIG other length mismatch".into());
            }
            put16(&mut out, rest[2])?;
            out.extend(other);
        }
        _ => {
            return Err(format!(
                "unsupported RDATA type {rtype}; use generic \\# format"
            ));
        }
    }
    if out.len() > usize::from(u16::MAX) {
        return Err("RDATA exceeds 65535 octets".into());
    }
    Ok(out)
}

fn count(fields: &[&str], expected: usize) -> Result<(), String> {
    if fields.len() == expected {
        Ok(())
    } else {
        Err(format!("expected {expected} fields, got {}", fields.len()))
    }
}

fn number<T: std::str::FromStr>(value: &str) -> Result<T, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid integer {value}"));
    }
    value
        .parse()
        .map_err(|_| format!("integer out of range: {value}"))
}

fn put16(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    out.extend(number::<u16>(value)?.to_be_bytes());
    Ok(())
}
fn put32(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    out.extend(number::<u32>(value)?.to_be_bytes());
    Ok(())
}
fn name(out: &mut Vec<u8>, value: &str, origin: &Name) -> Result<(), String> {
    out.extend(
        Name::parse(value, origin)
            .map_err(|e| e.to_string())?
            .as_wire(),
    );
    Ok(())
}

// RFC 1035 §5.1: backslash followed by three decimal digits represents one octet.
fn unescape(value: &str) -> Result<Vec<u8>, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        i += 1;
        let byte = *bytes.get(i).ok_or("trailing escape")?;
        if byte.is_ascii_digit() {
            let digits = bytes.get(i..i + 3).ok_or("incomplete decimal escape")?;
            if !digits.iter().all(u8::is_ascii_digit) {
                return Err("invalid decimal escape".into());
            }
            let n = u16::from(digits[0] - b'0') * 100
                + u16::from(digits[1] - b'0') * 10
                + u16::from(digits[2] - b'0');
            out.push(u8::try_from(n).map_err(|_| "decimal escape out of range")?);
            i += 3;
        } else {
            out.push(byte);
            i += 1;
        }
    }
    Ok(out)
}

fn length_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    out.push(u8::try_from(bytes.len()).map_err(|_| "character-string exceeds 255 octets")?);
    out.extend(bytes);
    Ok(())
}
fn character_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    length_bytes(out, &unescape(value)?)
}

fn hex(value: &str) -> Result<Vec<u8>, String> {
    let b = value.as_bytes();
    if !b.len().is_multiple_of(2) {
        return Err("odd hexadecimal length".into());
    }
    b.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |b: u8| {
                (b as char)
                    .to_digit(16)
                    .ok_or_else(|| "invalid hexadecimal".to_string())
            };
            Ok(((digit(pair[0])? << 4) | digit(pair[1])?) as u8)
        })
        .collect()
}

// RFC 4648 §4: base64 padding and unused bits must be valid.
fn base64(value: &str) -> Result<Vec<u8>, String> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("invalid base64 length".into());
    }
    let mut out = Vec::new();
    for (index, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let digit = |b| match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err("invalid base64"),
        };
        let a = digit(chunk[0])?;
        let b = digit(chunk[1])?;
        let last = index + 1 == bytes.len() / 4;
        out.push(a << 2 | b >> 4);
        if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' || b & 15 != 0 {
                return Err("invalid base64 padding".into());
            }
            continue;
        }
        let c = digit(chunk[2])?;
        out.push(b << 4 | c >> 2);
        if chunk[3] == b'=' {
            if !last || c & 3 != 0 {
                return Err("invalid base64 padding".into());
            }
            continue;
        }
        out.push(c << 6 | digit(chunk[3])?);
    }
    Ok(out)
}

// RFC 5155 §3.3: NSEC3 hashes use unpadded base32hex.
fn base32hex(value: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut bits = 0u32;
    let mut count = 0;
    for b in value.bytes() {
        let n = match b.to_ascii_uppercase() {
            b'0'..=b'9' => b - b'0',
            b'A'..=b'V' => b.to_ascii_uppercase() - b'A' + 10,
            _ => return Err("invalid base32hex".into()),
        };
        bits = (bits << 5) | u32::from(n);
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    if value.is_empty() || count >= 5 || bits != 0 {
        return Err("invalid base32hex padding".into());
    }
    Ok(out)
}

fn type_code(value: &str) -> Result<u16, String> {
    // RFC 3597 §5: unknown type mnemonics use TYPE followed by the decimal code.
    super::parse_type(value)
        .map(|rtype| rtype.0)
        .ok_or_else(|| format!("unknown type {value}"))
}

fn bitmap(out: &mut Vec<u8>, fields: &[&str]) -> Result<(), String> {
    let mut types = fields
        .iter()
        .map(|s| type_code(s))
        .collect::<Result<Vec<_>, _>>()?;
    types.sort_unstable();
    types.dedup();
    for window in 0..=255u16 {
        let start = out.len();
        for &ty in types.iter().filter(|ty| **ty >> 8 == window) {
            if out.len() == start {
                out.extend([window as u8, 0]);
            }
            let byte = usize::from((ty & 255) / 8);
            if out.len() < start + 3 + byte {
                out.resize(start + 3 + byte, 0);
            }
            out[start + 2 + byte] |= 0x80 >> (ty % 8);
            out[start + 1] = (byte + 1) as u8;
        }
    }
    Ok(())
}

// RFC 9460 §2.1: named SvcParam keys also have a keyNNNN presentation form.
fn svc_key(value: &str) -> Result<u16, String> {
    let lower = value.to_ascii_lowercase();
    let key = match lower.as_str() {
        "mandatory" => 0,
        "alpn" => 1,
        "no-default-alpn" => 2,
        "port" => 3,
        "ipv4hint" => 4,
        "ech" => 5,
        "ipv6hint" => 6,
        "dohpath" => 7,
        "ohttp" => 8,
        _ => number(lower.strip_prefix("key").ok_or("unknown SvcParam key")?)?,
    };
    if key == u16::MAX {
        return Err("reserved SvcParam key".into());
    }
    Ok(key)
}

// RFC 9460 Appendix A.1: list escaping is decoded after character-string escaping.
fn svc_list(value: &str) -> Result<Vec<Vec<u8>>, String> {
    let bytes = unescape(value)?;
    let mut parts = vec![Vec::new()];
    let mut pos = 0;
    while pos < bytes.len() {
        match bytes[pos] {
            b',' => parts.push(Vec::new()),
            b'\\' => {
                pos += 1;
                let byte = *bytes.get(pos).ok_or("trailing list escape")?;
                if byte != b',' && byte != b'\\' {
                    return Err("invalid list escape".into());
                }
                parts.last_mut().ok_or("empty list")?.push(byte);
            }
            b => parts.last_mut().ok_or("empty list")?.push(b),
        }
        pos += 1;
    }
    if parts.iter().any(Vec::is_empty) {
        return Err("empty list element".into());
    }
    Ok(parts)
}

fn svc_params(out: &mut Vec<u8>, fields: &[&str]) -> Result<(), String> {
    let mut params = Vec::new();
    for field in fields {
        let (key, value) = match field.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (*field, None),
        };
        let opaque = key.to_ascii_lowercase().starts_with("key");
        let key = svc_key(key)?;
        let mut data = Vec::new();
        if opaque {
            data.extend(unescape(value.unwrap_or(""))?);
            params.push((key, data));
            continue;
        }
        match key {
            // RFC 9460 §7.1: mandatory is a sorted, nonempty sequence of distinct keys.
            0 => {
                let mut keys = svc_list(value.ok_or("missing mandatory value")?)?
                    .iter()
                    .map(|k| {
                        std::str::from_utf8(k)
                            .map_err(|_| "invalid mandatory key".to_string())
                            .and_then(svc_key)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                keys.sort_unstable();
                if keys.is_empty() || keys[0] == 0 || keys.windows(2).any(|w| w[0] == w[1]) {
                    return Err("invalid mandatory keys".into());
                }
                for k in keys {
                    data.extend(k.to_be_bytes());
                }
            }
            // RFC 9460 §7.1.1: alpn is a list of nonempty length-prefixed protocol IDs.
            1 => {
                for bytes in svc_list(value.ok_or("missing alpn value")?)? {
                    length_bytes(&mut data, &bytes)?;
                }
            }
            2 | 8 => {
                if value.is_some_and(|v| !v.is_empty()) {
                    return Err("SvcParam must be empty".into());
                }
            }
            3 => put16(&mut data, value.ok_or("missing port")?)?,
            4 => {
                for ip in value.ok_or("missing IPv4 hints")?.split(',') {
                    data.extend(
                        ip.parse::<Ipv4Addr>()
                            .map_err(|_| "invalid IPv4 hint")?
                            .octets(),
                    );
                }
            }
            5 => data.extend(base64(value.ok_or("missing ECH value")?)?),
            6 => {
                for ip in value.ok_or("missing IPv6 hints")?.split(',') {
                    let ip = ip.parse::<Ipv6Addr>().map_err(|_| "invalid IPv6 hint")?;
                    if ip.to_ipv4_mapped().is_some() {
                        return Err("IPv4-mapped IPv6 hint".into());
                    }
                    data.extend(ip.octets());
                }
            }
            _ => {
                if let Some(value) = value {
                    data.extend(unescape(value)?);
                }
            }
        }
        params.push((key, data));
    }
    params.sort_unstable_by_key(|(key, _)| *key);
    if params.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err("duplicate SvcParam".into());
    }
    if params.iter().any(|(k, _)| *k == 2) && !params.iter().any(|(k, _)| *k == 1) {
        return Err("no-default-alpn requires alpn".into());
    }
    if let Some((_, mandatory)) = params.iter().find(|(key, _)| *key == 0) {
        for pair in mandatory.as_chunks::<2>().0 {
            let key = u16::from_be_bytes([pair[0], pair[1]]);
            if !params.iter().any(|(k, _)| *k == key) {
                return Err("mandatory SvcParam missing".into());
            }
        }
    }
    let start = out.len();
    for (key, value) in params {
        out.extend(key.to_be_bytes());
        out.extend(
            u16::try_from(value.len())
                .map_err(|_| "SvcParam too long")?
                .to_be_bytes(),
        );
        out.extend(value);
    }
    crate::SvcParams::parse(&out[start..]).map_err(|_| "invalid SvcParam encoding")?;
    Ok(())
}

// RFC 4034 §3.1.5: timestamps are UTC dates in YYYYMMDDHHMMSS form.
fn timestamp(value: &str) -> Result<u32, String> {
    u32::try_from(timestamp64(value)?).map_err(|_| "signature timestamp out of range".into())
}

fn timestamp64(value: &str) -> Result<u64, String> {
    if value.len() != 14 {
        return number(value);
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid signature timestamp".into());
    }
    let year: i64 = number(&value[0..4])?;
    let month: i64 = number(&value[4..6])?;
    let day: i64 = number(&value[6..8])?;
    let hour: i64 = number(&value[8..10])?;
    let minute: i64 = number(&value[10..12])?;
    let second: i64 = number(&value[12..14])?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day < 1
        || day > days[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err("invalid signature timestamp".into());
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let epoch_days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    let seconds = epoch_days * 86400 + hour * 3600 + minute * 60 + second;
    u64::try_from(seconds).map_err(|_| "timestamp before Unix epoch".into())
}

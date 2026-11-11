use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{Name, Type};

mod advanced;
mod legacy;

/// Encodes presentation-format RDATA into uncompressed DNS wire format.
/// `fields` are whitespace-separated tokens with surrounding quotes removed and
/// backslash escapes preserved, as produced by the Zone lexer.
pub fn parse_rdata(rtype: Type, fields: &[&str], origin: &Name) -> Result<Vec<u8>, String> {
    parse_rdata_located(rtype, fields, origin).map_err(|(_, message)| message)
}

pub(crate) fn parse_rdata_located(
    rtype: Type,
    fields: &[&str],
    origin: &Name,
) -> Result<Vec<u8>, (usize, String)> {
    let mut index = 0;
    parse_rdata_inner(rtype, fields, origin, &mut index).map_err(|message| (index, message))
}

fn parse_rdata_inner(
    rtype: Type,
    fields: &[&str],
    origin: &Name,
    index: &mut usize,
) -> Result<Vec<u8>, String> {
    macro_rules! at {
        ($i:expr, $expr:expr) => {{
            *index = $i;
            $expr
        }};
    }
    // RFC 3597 §5: generic RDATA can represent any RR type, including known types.
    if fields.first() == Some(&r"\#") {
        if fields.len() < 2 {
            *index = fields.len();
            return Err("missing generic RDATA length".into());
        }
        let len: u16 = at!(1, number(fields[1]))?;
        let data = at!(2.min(fields.len()), hex(&fields[2..].concat()))?;
        if data.len() != usize::from(len) {
            return Err("generic RDATA length mismatch".into());
        }
        return generic_rdata(rtype, &data);
    }
    if let Some(result) =
        legacy::parse(rtype, fields, origin).or_else(|| advanced::parse(rtype, fields, origin))
    {
        return result.map_err(|(field, message)| {
            *index = field;
            message
        });
    }
    let mut out = Vec::new();
    match rtype {
        // RFC 1035 §3.4.1 and RFC 3596 §2.2: addresses are their raw network-order octets.
        Type::A => {
            at!(fields.len().min(1), count(fields, 1))?;
            *index = 0;
            out.extend(
                fields[0]
                    .parse::<Ipv4Addr>()
                    .map_err(|_| "invalid IPv4 address")?
                    .octets(),
            );
        }
        Type::AAAA => {
            at!(fields.len().min(1), count(fields, 1))?;
            *index = 0;
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
            at!(fields.len().min(1), count(fields, 1))?;
            at!(0, name(&mut out, fields[0], origin))?;
        }
        Type::MX => {
            at!(fields.len().min(2), count(fields, 2))?;
            at!(0, put16(&mut out, fields[0]))?;
            at!(1, name(&mut out, fields[1], origin))?;
        }
        Type::SOA => {
            at!(fields.len().min(7), count(fields, 7))?;
            at!(0, name(&mut out, fields[0], origin))?;
            at!(1, name(&mut out, fields[1], origin))?;
            at!(2, put32(&mut out, fields[2]))?;
            // RFC 2308 §4: SOA timers accept TTL unit suffixes; the serial remains decimal.
            for (i, field) in fields[3..].iter().enumerate() {
                *index = i + 3;
                out.extend(
                    super::parse_ttl(field)
                        .ok_or("invalid SOA timer")?
                        .to_be_bytes(),
                );
            }
        }
        // RFC 4408 §3.1.1: the obsolete SPF RR type has the same format as TXT.
        Type::TXT | Type::SPF => {
            for (i, field) in fields.iter().enumerate() {
                let data = at!(i, unescape(field))?;
                if data.is_empty() {
                    out.push(0);
                } else {
                    for part in data.chunks(255) {
                        length_bytes(&mut out, part)?;
                    }
                }
            }
        }
        Type::HINFO => {
            let mut chunks = Vec::new();
            for (i, field) in fields.iter().enumerate() {
                let data = at!(i, unescape(field))?;
                if data.is_empty() {
                    chunks.push(Vec::new());
                } else {
                    chunks.extend(data.chunks(255).map(<[u8]>::to_vec));
                }
            }
            if chunks.len() == 1 {
                let parts: Vec<_> = fields[0].split_whitespace().collect();
                if parts.len() > 1 {
                    chunks = parts.into_iter().map(unescape).collect::<Result<_, _>>()?;
                }
            }
            let cpu = chunks.first().map_or(&[][..], Vec::as_slice);
            length_bytes(&mut out, cpu)?;
            let mut os = Vec::new();
            for (i, chunk) in chunks.iter().skip(1).enumerate() {
                if i != 0 {
                    os.push(b' ');
                }
                os.extend_from_slice(chunk);
            }
            length_bytes(&mut out, &os)?;
        }
        // RFC 2782 §3 and RFC 3403 §4: SRV and NAPTR contain fixed integers followed by names.
        Type::SRV => {
            at!(fields.len().min(4), count(fields, 4))?;
            for (i, field) in fields[..3].iter().enumerate() {
                at!(i, put16(&mut out, field))?;
            }
            at!(3, name(&mut out, fields[3], origin))?;
        }
        Type::NAPTR => {
            at!(fields.len().min(6), count(fields, 6))?;
            at!(0, put16(&mut out, fields[0]))?;
            at!(1, put16(&mut out, fields[1]))?;
            for (i, field) in fields[2..5].iter().enumerate() {
                at!(i + 2, character_string(&mut out, field))?;
            }
            at!(5, name(&mut out, fields[5], origin))?;
        }
        // RFC 8659 §4: CAA has flags, a length-prefixed tag, and an unframed value.
        Type::CAA => {
            at!(fields.len().min(3), count(fields, 3))?;
            let flag = at!(0, number(fields[0]))?;
            let tag = at!(1, unescape(fields[1]))?;
            if tag.is_empty() {
                return Err("invalid CAA tag".into());
            }
            out.push(flag);
            length_bytes(&mut out, &tag)?;
            let value = at!(2, unescape(fields[2]))?;
            if value.len() > 255 {
                return Err("CAA value exceeds 255 octets".into());
            }
            out.extend(value);
        }
        // RFC 7553 §4: URI has two 16-bit integers followed by target octets.
        Type::URI => {
            at!(fields.len().min(3), count(fields, 3))?;
            at!(0, put16(&mut out, fields[0]))?;
            at!(1, put16(&mut out, fields[1]))?;
            out.extend(at!(2, unescape(fields[2]))?);
        }
        // RFC 4034 §5 and RFC 7344 §4: DS/CDS digest is hexadecimal.
        Type::DS | Type::CDS => {
            if fields.len() < 3 {
                *index = fields.len();
                return Err("missing DS fields".into());
            }
            at!(0, put16(&mut out, fields[0]))?;
            out.push(at!(1, dnssec_algorithm(fields[1], true))?);
            out.push(at!(2, number(fields[2]))?);
            out.extend(at!(3.min(fields.len()), hex(&fields[3..].concat()))?);
        }
        // RFC 4034 §2 and RFC 7344 §4: DNSKEY/CDNSKEY public keys use base64.
        Type::DNSKEY | Type::CDNSKEY => {
            if fields.len() < 3 {
                *index = fields.len();
                return Err("missing DNSKEY fields".into());
            }
            at!(0, put16(&mut out, fields[0]))?;
            out.push(at!(1, number(fields[1]))?);
            out.push(at!(2, number(fields[2]))?);
            out.extend(at!(
                base64_error_index(fields, 3),
                base64(&fields[3..].concat())
            )?);
        }
        // RFC 6698 §2, RFC 8162 §2 and RFC 4255 §3: association data is hexadecimal.
        Type::TLSA | Type::SMIMEA | Type::SSHFP => {
            let prefix = if rtype == Type::SSHFP { 2 } else { 3 };
            if fields.len() <= prefix {
                *index = fields.len();
                return Err("missing association data".into());
            }
            for (i, field) in fields[..prefix].iter().enumerate() {
                out.push(at!(i, number(field))?);
            }
            out.extend(at!(prefix, hex(&fields[prefix..].concat()))?);
        }
        // RFC 8976 §2.1: ZONEMD uses a serial, scheme, algorithm, and hexadecimal digest.
        Type::ZONEMD => {
            if fields.len() < 3 {
                *index = fields.len();
                return Err("missing ZONEMD fields".into());
            }
            at!(0, put32(&mut out, fields[0]))?;
            out.push(at!(1, number(fields[1]))?);
            out.push(at!(2, number(fields[2]))?);
            let digest = at!(3.min(fields.len()), hex(&fields[3..].concat()))?;
            out.extend(digest);
        }
        // RFC 4034 §3.1: signature times accept either decimal seconds or YYYYMMDDHHMMSS.
        Type::RRSIG => {
            if fields.len() < 8 {
                *index = fields.len();
                return Err("missing RRSIG fields".into());
            }
            out.extend(at!(0, type_code(fields[0]))?.to_be_bytes());
            out.push(at!(1, dnssec_algorithm(fields[1], false))?);
            out.push(at!(2, number(fields[2]))?);
            at!(3, put32(&mut out, fields[3]))?;
            out.extend(at!(4, timestamp(fields[4]))?.to_be_bytes());
            out.extend(at!(5, timestamp(fields[5]))?.to_be_bytes());
            at!(6, put16(&mut out, fields[6]))?;
            at!(7, name(&mut out, fields[7], origin))?;
            out.extend(at!(
                base64_error_index(fields, 8),
                base64(&fields[8..].concat())
            )?);
        }
        // RFC 4034 §4.1.2 and RFC 5155 §3.2: NSEC bitmaps use ordered windows.
        Type::NSEC => {
            if fields.is_empty() {
                *index = fields.len();
                return Err("missing NSEC name or bitmap".into());
            }
            at!(0, name(&mut out, fields[0], origin))?;
            for (i, field) in fields[1..].iter().enumerate() {
                at!(i + 1, type_code(field))?;
            }
            bitmap(&mut out, &fields[1..])?;
        }
        Type::NSEC3 | Type::NSEC3PARAM => {
            let required = if rtype == Type::NSEC3 { 5 } else { 4 };
            if fields.len() < required || (rtype == Type::NSEC3PARAM && fields.len() != required) {
                *index = fields.len().min(required);
                return Err("invalid NSEC3 fields".into());
            }
            out.push(at!(0, number(fields[0]))?);
            out.push(at!(1, number(fields[1]))?);
            at!(2, put16(&mut out, fields[2]))?;
            *index = 3;
            let salt = if fields[3] == "-" {
                Vec::new()
            } else {
                hex(fields[3])?
            };
            length_bytes(&mut out, &salt)?;
            if rtype == Type::NSEC3 {
                let hash = at!(4, base32hex(fields[4]))?;
                out.push(20);
                out.extend(hash);
                for (i, field) in fields[5..].iter().enumerate() {
                    at!(i + 5, type_code(field))?;
                }
                bitmap(&mut out, &fields[5..])?;
            }
        }
        // RFC 9460 §2.2: parameters are serialized once each in numeric key order.
        Type::SVCB | Type::HTTPS => {
            if fields.len() < 2 {
                *index = fields.len();
                return Err("missing SVCB priority or target".into());
            }
            at!(0, put16(&mut out, fields[0]))?;
            at!(1, name(&mut out, fields[1], origin))?;
            *index = 2.min(fields.len());
            svc_params(&mut out, &fields[2..], index)?;
        }
        // RFC 8945 §4.2: TSIG contains a 48-bit time and 16-bit-length-prefixed byte strings.
        Type::TSIG => {
            if fields.len() < 7 || fields.len() > 9 {
                *index = fields.len().min(9);
                return Err("invalid TSIG fields".into());
            }
            at!(0, name(&mut out, fields[0], origin))?;
            let time = at!(1, timestamp64(fields[1]))?;
            if time >= 1 << 48 {
                return Err("TSIG time out of range".into());
            }
            out.extend(&time.to_be_bytes()[2..]);
            at!(2, put16(&mut out, fields[2]))?;
            let mac_len = at!(3, number::<u16>(fields[3]))?;
            let has_mac_field = mac_len != 0 || fields[4].is_empty();
            let mac = if has_mac_field {
                at!(4, hex(fields[4]))?
            } else {
                Vec::new()
            };
            if usize::from(mac_len) != mac.len() {
                return Err("TSIG MAC length mismatch".into());
            }
            at!(3, put16(&mut out, fields[3]))?;
            out.extend(mac);
            let rest_start = 4 + usize::from(has_mac_field);
            let rest = &fields[rest_start..];
            if !(3..=4).contains(&rest.len()) {
                *index = fields.len();
                return Err("invalid TSIG fields".into());
            }
            at!(rest_start, put16(&mut out, rest[0]))?;
            at!(rest_start + 1, put16(&mut out, rest[1]))?;
            let other = at!(
                rest_start + 3.min(rest.len()),
                hex(rest.get(3).copied().unwrap_or(""))
            )?;
            if usize::from(at!(rest_start + 2, number::<u16>(rest[2]))?) != other.len() {
                return Err("TSIG other length mismatch".into());
            }
            at!(rest_start + 2, put16(&mut out, rest[2]))?;
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

// RFC 3597 §5: known RDATA is unpacked and re-encoded in its type's wire format.
fn generic_rdata(rtype: Type, data: &[u8]) -> Result<Vec<u8>, String> {
    // Fields are integers, names, character strings, addresses, bitmaps, or opaque tails.
    let layout: &[u8] = match rtype.0 {
        1 => b"a",
        28 => b"v",
        2..=5 | 7..=9 | 12 | 23 | 39 => b"n",
        6 => b"nn44444",
        13 | 20 => b"ss",
        14 | 17 | 58 => b"nn",
        15 | 18 | 21 | 36 | 107 => b"2n",
        19 | 100 => b"s",
        27 => b"sss",
        16 | 56 | 99 | 258 | 261 => b"t",
        24 | 46 => b"2114442nr",
        25 | 43 | 48 | 57 | 59 | 60 | 32768 | 32769 => b"211r",
        26 => b"2nn",
        29 => b"1111444",
        30 | 47 => b"nb",
        31 | 32 | 49 | 61 | 10 => b"r",
        33 => b"222n",
        35 => b"22sssn",
        37 => b"221r",
        41 => b"o",
        42 => b"q",
        44 => b"11r",
        45 => b"111gr",
        50 => b"112llb",
        51 => b"112l",
        52 | 53 => b"111r",
        55 => b"112h",
        62 => b"42b",
        63 => b"411r",
        64 | 65 => b"2np",
        101 | 102 => b"4",
        104 | 106 => b"28",
        105 => b"2a",
        108 => b"6",
        109 => b"8",
        249 => b"n4422LL",
        250 => b"n62L22L",
        256 => b"22r",
        257 => b"1sr",
        260 => b"11g",
        128 | 255 => b"",
        _ => return Ok(data.to_vec()),
    };
    let mut out = Vec::new();
    let mut pos = 0;
    for &field in layout {
        let remaining = &data[pos..];
        let missing = remaining.is_empty();
        match field {
            b'1' | b'2' | b'4' | b'6' | b'8' => {
                let n = usize::from(field - b'0');
                if missing {
                    out.resize(out.len() + n, 0);
                } else {
                    out.extend_from_slice(remaining.get(..n).ok_or("truncated generic integer")?);
                    pos += n;
                }
            }
            b'a' | b'v' => {
                let n = if field == b'a' { 4 } else { 16 };
                if !missing {
                    out.extend_from_slice(remaining.get(..n).ok_or("truncated generic address")?);
                    pos += n;
                }
            }
            b'n' => {
                if !missing {
                    pos = generic_name(data, pos, &mut out)?;
                }
            }
            b's' | b'l' | b'L' => {
                let prefix = if field == b'L' { 2 } else { 1 };
                if missing {
                    out.resize(out.len() + prefix, 0);
                } else {
                    let size = if prefix == 1 {
                        usize::from(remaining[0])
                    } else {
                        let b = remaining.get(..2).ok_or("truncated generic length")?;
                        usize::from(u16::from_be_bytes([b[0], b[1]]))
                    };
                    // RFC 3597 §5: an omitted trailing field stays at its zero value.
                    let n = if field != b's' && remaining.len() == prefix {
                        prefix
                    } else {
                        prefix + size
                    };
                    out.extend_from_slice(remaining.get(..n).ok_or("truncated generic string")?);
                    pos += n;
                }
            }
            b't' => {
                while pos < data.len() {
                    let n = 1 + usize::from(data[pos]);
                    out.extend_from_slice(data.get(pos..pos + n).ok_or("truncated generic TXT")?);
                    pos += n;
                }
            }
            b'b' => {
                let mut last = None;
                while pos < data.len() {
                    let h = data.get(pos..pos + 2).ok_or("truncated generic bitmap")?;
                    let (window, len) = (h[0], usize::from(h[1]));
                    if len == 0 || len > 32 || last.is_some_and(|w| window <= w) {
                        return Err("invalid generic bitmap".into());
                    }
                    let bytes = data
                        .get(pos + 2..pos + 2 + len)
                        .ok_or("truncated generic bitmap")?;
                    if let Some(last_nonzero) = bytes.iter().rposition(|b| *b != 0) {
                        out.extend([window, (last_nonzero + 1) as u8]);
                        out.extend_from_slice(&bytes[..=last_nonzero]);
                    }
                    pos += 2 + len;
                    last = Some(window);
                }
            }
            b'p' => {
                let mut last = None;
                while pos < data.len() {
                    let header = data.get(pos..pos + 4).ok_or("truncated generic SVCB")?;
                    let key = u16::from_be_bytes([header[0], header[1]]);
                    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
                    let value = data
                        .get(pos + 4..pos + 4 + len)
                        .ok_or("truncated generic SVCB")?;
                    if key == u16::MAX || last.is_some_and(|prev| key <= prev) {
                        return Err("invalid generic SVCB key".into());
                    }
                    match key {
                        0 if len % 2 != 0 => return Err("invalid generic SVCB mandatory".into()),
                        1 => {
                            let mut i = 0;
                            while i < len {
                                i += 1 + usize::from(value[i]);
                                if i > len {
                                    return Err("invalid generic SVCB alpn".into());
                                }
                            }
                        }
                        2 | 8 if len != 0 => return Err("invalid generic SVCB flag".into()),
                        3 if len != 2 => return Err("invalid generic SVCB port".into()),
                        4 if len == 0 || len % 4 != 0 => {
                            return Err("invalid generic SVCB IPv4".into());
                        }
                        6 if len == 0
                            || len % 16 != 0
                            || value
                                .chunks(16)
                                .any(|ip| ip[..10] == [0; 10] && ip[10..12] == [255, 255]) =>
                        {
                            return Err("invalid generic SVCB IPv6".into());
                        }
                        _ => {}
                    }
                    out.extend_from_slice(header);
                    if key == 0 {
                        let mut codes = value.as_chunks::<2>().0.to_vec();
                        codes.sort_unstable();
                        for code in codes {
                            out.extend(code);
                        }
                    } else {
                        out.extend_from_slice(value);
                    }
                    pos += 4 + len;
                    last = Some(key);
                }
            }
            b'o' => {
                while pos < data.len() {
                    let h = data
                        .get(pos..pos + 4)
                        .ok_or("truncated generic EDNS option")?;
                    let code = u16::from_be_bytes([h[0], h[1]]);
                    let len = usize::from(u16::from_be_bytes([h[2], h[3]]));
                    let value = data
                        .get(pos + 4..pos + 4 + len)
                        .ok_or("truncated generic EDNS option")?;
                    if code == 8 {
                        let prefix = value.get(..4).ok_or("truncated generic ECS")?;
                        let family = u16::from_be_bytes([prefix[0], prefix[1]]);
                        let bits = match family {
                            0 => 0,
                            1 => 32,
                            2 => 128,
                            _ => return Err("invalid generic ECS family".into()),
                        };
                        if prefix[2] > bits || (family != 0 && prefix[3] > bits) {
                            return Err("invalid generic ECS prefix".into());
                        }
                        let size = usize::from(prefix[2]).div_ceil(8);
                        let mut normalized = vec![0; size];
                        let copy = normalized.len().min(value.len() - 4);
                        normalized[..copy].copy_from_slice(&value[4..4 + copy]);
                        if prefix[2] % 8 != 0 {
                            normalized[size - 1] &= 0xff << (8 - prefix[2] % 8);
                        }
                        out.extend([h[0], h[1], 0, (4 + size) as u8]);
                        out.extend_from_slice(prefix);
                        out.extend(normalized);
                    } else {
                        let option = &data[pos..pos + 4 + len];
                        crate::EdnsOptions::parse(option)
                            .map_err(|_| "invalid generic EDNS option")?;
                        if code == 9 && !value.is_empty() {
                            let expire = value.get(..4).ok_or("truncated generic EXPIRE")?;
                            out.extend([h[0], h[1], 0, 4]);
                            out.extend_from_slice(expire);
                        } else if code == 11 && value == [0, 0] {
                            out.extend([h[0], h[1], 0, 0]);
                        } else {
                            out.extend_from_slice(option);
                        }
                    }
                    pos += 4 + len;
                }
            }
            b'g' if !missing => match out[1] {
                1 | 2 => {
                    let n = if out[1] == 1 { 4 } else { 16 };
                    out.extend_from_slice(remaining.get(..n).ok_or("truncated generic gateway")?);
                    pos += n;
                }
                3 => {
                    pos = generic_name(data, pos, &mut out)?;
                }
                _ => {}
            },
            b'g' => {}
            b'h' if !missing => {
                let hit = usize::from(out[0]);
                let key = usize::from(u16::from_be_bytes([out[2], out[3]]));
                let size = hit + key;
                out.extend_from_slice(remaining.get(..size).ok_or("truncated generic HIP")?);
                pos += size;
                while pos < data.len() {
                    pos = generic_name(data, pos, &mut out)?;
                }
            }
            b'h' => {}
            b'q' => {
                while pos < data.len() {
                    let h = data.get(pos..pos + 4).ok_or("truncated generic APL")?;
                    let family = u16::from_be_bytes([h[0], h[1]]);
                    let max = match family {
                        1 => 4,
                        2 => 16,
                        _ => return Err("invalid generic APL family".into()),
                    };
                    let prefix = usize::from(h[2]);
                    let size = usize::from(h[3] & 0x7f);
                    if prefix > max * 8 || size > max {
                        return Err("invalid generic APL prefix".into());
                    }
                    let addr = data
                        .get(pos + 4..pos + 4 + size)
                        .ok_or("truncated generic APL address")?;
                    if addr.last() == Some(&0) {
                        return Err("invalid generic APL address".into());
                    }
                    let mut network = vec![0; prefix.div_ceil(8)];
                    let copy = network.len().min(addr.len());
                    network[..copy].copy_from_slice(&addr[..copy]);
                    if prefix % 8 != 0 && !network.is_empty() {
                        let last = network.len() - 1;
                        network[last] &= 0xff << (8 - prefix % 8);
                    }
                    while network.last() == Some(&0) {
                        network.pop();
                    }
                    out.extend([h[0], h[1], h[2], (h[3] & 0x80) | network.len() as u8]);
                    out.extend(network);
                    pos += 4 + size;
                }
            }
            b'r' => {
                if matches!(rtype, Type::CAA | Type::URI) {
                    // RFC 7553 §4.5 and RFC 8659 §4: values are octet strings.
                    let mut i = 0;
                    while i < remaining.len() {
                        if remaining[i] == b'\\' {
                            i += 1;
                            if i == remaining.len() {
                                break;
                            }
                            if let Some(digits) = remaining
                                .get(i..i + 3)
                                .filter(|d| d.iter().all(u8::is_ascii_digit))
                            {
                                let n = u16::from(digits[0] - b'0') * 100
                                    + u16::from(digits[1] - b'0') * 10
                                    + u16::from(digits[2] - b'0');
                                out.push(n as u8);
                                i += 3;
                                continue;
                            }
                        }
                        out.push(remaining[i]);
                        i += 1;
                    }
                } else {
                    out.extend_from_slice(remaining);
                }
                pos = data.len();
            }
            b' ' => {}
            _ => unreachable!(),
        }
    }
    Ok(out)
}

// RFC 1035 §4.1.4: decompress names before relocating generic RDATA.
fn generic_name(data: &[u8], mut pos: usize, out: &mut Vec<u8>) -> Result<usize, String> {
    let start = out.len();
    let mut end = None;
    let mut hops = 0;
    loop {
        let byte = *data.get(pos).ok_or("truncated generic name")?;
        match byte {
            0 => {
                out.push(0);
                return Ok(end.unwrap_or(pos + 1));
            }
            1..=63 => {
                let next = pos + 1 + usize::from(byte);
                if out.len() - start + usize::from(byte) + 1 >= 255 {
                    return Err("generic name too long".into());
                }
                out.extend_from_slice(data.get(pos..next).ok_or("truncated generic label")?);
                pos = next;
            }
            192..=255 => {
                let second = *data.get(pos + 1).ok_or("truncated generic pointer")?;
                end.get_or_insert(pos + 2);
                hops += 1;
                if hops > 126 {
                    return Err("too many generic name pointers".into());
                }
                pos = (usize::from(byte & 63) << 8) | usize::from(second);
            }
            _ => return Err("invalid generic name label".into()),
        }
    }
}

fn count(fields: &[&str], expected: usize) -> Result<(), String> {
    if fields.len() == expected {
        Ok(())
    } else {
        Err(format!("expected {expected} fields, got {}", fields.len()))
    }
}

fn base64_error_index(fields: &[&str], start: usize) -> usize {
    fields[start..]
        .iter()
        .position(|field| {
            field
                .bytes()
                .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'+' | b'/' | b'='))
        })
        .map_or_else(|| fields.len().saturating_sub(1).max(start), |i| start + i)
}

fn number<T: std::str::FromStr>(value: &str) -> Result<T, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid integer {value}"));
    }
    value
        .parse()
        .map_err(|_| format!("integer out of range: {value}"))
}

// RFC 4034 Appendix A.1: DNSSEC algorithms have registered mnemonic names.
fn dnssec_algorithm(value: &str, insensitive: bool) -> Result<u8, String> {
    if let Ok(n) = number(value) {
        return Ok(n);
    }
    let value = if insensitive {
        value.to_ascii_uppercase()
    } else {
        value.to_owned()
    };
    match value.as_str() {
        "RSAMD5" => Ok(1),
        "DH" => Ok(2),
        "DSA" => Ok(3),
        "RSASHA1" => Ok(5),
        "DSA-NSEC3-SHA1" => Ok(6),
        "RSASHA1-NSEC3-SHA1" => Ok(7),
        "RSASHA256" => Ok(8),
        "RSASHA512" => Ok(10),
        "ECC-GOST" => Ok(12),
        "ECDSAP256SHA256" => Ok(13),
        "ECDSAP384SHA384" => Ok(14),
        "ED25519" => Ok(15),
        "ED448" => Ok(16),
        "INDIRECT" => Ok(252),
        "PRIVATEDNS" => Ok(253),
        "PRIVATEOID" => Ok(254),
        _ => Err("invalid algorithm".into()),
    }
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
        if let Some(digits) = bytes
            .get(i..i + 3)
            .filter(|d| d.iter().all(u8::is_ascii_digit))
        {
            let n = u16::from(digits[0] - b'0') * 100
                + u16::from(digits[1] - b'0') * 10
                + u16::from(digits[2] - b'0');
            out.push(n as u8);
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

// RFC 4648 §3.5: Go's standard decoder accepts nonzero unused padding bits.
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
            if !last || chunk[3] != b'=' {
                return Err("invalid base64 padding".into());
            }
            continue;
        }
        let c = digit(chunk[2])?;
        out.push(b << 4 | c >> 2);
        if chunk[3] == b'=' {
            if !last {
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
    let key = match value {
        "mandatory" => 0,
        "alpn" => 1,
        "no-default-alpn" => 2,
        "port" => 3,
        "ipv4hint" => 4,
        "ech" => 5,
        "ipv6hint" => 6,
        "dohpath" => 7,
        "ohttp" => 8,
        _ => {
            let digits = value.strip_prefix("key").ok_or("unknown SvcParam key")?;
            if digits.starts_with('0') {
                return Err("invalid SvcParam key".into());
            }
            let key = number::<u16>(digits)?;
            if key <= 8 {
                return Err("registered SvcParam key".into());
            }
            key
        }
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

fn svc_params(out: &mut Vec<u8>, fields: &[&str], index: &mut usize) -> Result<(), String> {
    let mut params = Vec::new();
    for (i, field) in fields.iter().enumerate() {
        *index = i + 2;
        let (key, value) = match field.split_once('=') {
            Some((key, value)) => (key, Some(value)),
            None => (*field, None),
        };
        let opaque = key.starts_with("key");
        let key = svc_key(key)?;
        let mut data = Vec::new();
        if opaque {
            data.extend(unescape(value.unwrap_or(""))?);
            params.push((key, data));
            continue;
        }
        match key {
            // RFC 9460 §7.1: mandatory is serialized as a sorted sequence of keys.
            0 => {
                let mut keys = Vec::new();
                let mut rest = value.unwrap_or("");
                while !rest.is_empty() {
                    let (key, next) = rest.split_once(',').unwrap_or((rest, ""));
                    keys.push(svc_key(key).unwrap_or(u16::MAX));
                    rest = next;
                }
                keys.sort_unstable();
                for k in keys {
                    data.extend(k.to_be_bytes());
                }
            }
            // RFC 9460 §7.1.1: alpn is a list of nonempty length-prefixed protocol IDs.
            1 => {
                if let Some(value) = value.filter(|value| !value.is_empty()) {
                    for bytes in svc_list(value)? {
                        length_bytes(&mut data, &bytes)?;
                    }
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
            5 => data.extend(base64(value.unwrap_or(""))?),
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
    for (key, value) in params {
        out.extend(key.to_be_bytes());
        out.extend(
            u16::try_from(value.len())
                .map_err(|_| "SvcParam too long")?
                .to_be_bytes(),
        );
        out.extend(value);
    }
    Ok(())
}

// RFC 4034 §3.1.5: timestamps are UTC dates in YYYYMMDDHHMMSS form.
fn timestamp(value: &str) -> Result<u32, String> {
    if value.len() != 14 {
        return number(value);
    }
    // RFC 1982 §3.1: signature dates use 32-bit serial arithmetic.
    let seconds = timestamp_calendar(value)?;
    let period = 1_i64 << 31;
    let modulo = (seconds / period - 1).max(0);
    Ok((seconds - modulo * period) as u32)
}

fn timestamp64(value: &str) -> Result<u64, String> {
    if value.len() != 14 {
        return number(value);
    }
    u64::try_from(timestamp_calendar(value)?).map_err(|_| "timestamp before Unix epoch".into())
}

fn timestamp_calendar(value: &str) -> Result<i64, String> {
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
    Ok(epoch_days * 86400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn located_errors_identify_common_fields() {
        let origin = "example.".parse::<Name>().unwrap();
        for (rtype, fields, expected) in [
            (Type::A, vec!["999.1.1.1"], 0),
            (Type::MX, vec!["bad", "example."], 0),
            (Type::MX, vec!["10", "bad..name"], 1),
            (Type::SOA, vec![".", ".", "1", "2", "bad", "4", "5"], 4),
            (Type::DNSKEY, vec!["257", "3", "8", "AQID", "!!!!"], 4),
            (Type::SVCB, vec!["1", ".", "port=443", "ipv4hint=bad"], 3),
            (Type::SRV, vec!["1", "2", "3"], 3),
        ] {
            assert_eq!(
                parse_rdata_located(rtype, &fields, &origin).unwrap_err().0,
                expected
            );
        }
    }
}

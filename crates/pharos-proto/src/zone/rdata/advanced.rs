use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{Name, Type};

use super::{base64, bitmap, dnssec_algorithm, hex, name, number, put16, put32, type_code};

pub(super) fn parse(
    rtype: Type,
    fields: &[&str],
    origin: &Name,
) -> Option<Result<Vec<u8>, (usize, String)>> {
    let mut out = Vec::new();
    let mut index = 0;
    macro_rules! at {
        ($i:expr, $expr:expr) => {{
            index = $i;
            $expr
        }};
    }
    macro_rules! field {
        ($i:expr, $message:expr) => {
            fields.get($i).copied().ok_or_else(|| {
                index = $i;
                $message
            })?
        };
    }
    let result = (|| -> Result<bool, String> {
        // RFC 1035 §3.2.1: miekg packs zero-valued fields for an absent RDATA body.
        if fields.is_empty() {
            let size = match rtype {
                Type::LOC | Type::TKEY => 16,
                Type::HIP => 4,
                Type::CERT => 5,
                Type::CSYNC => 6,
                Type::IPSECKEY => 3,
                Type::AMTRELAY => 2,
                Type::APL => 0,
                _ => return Ok(false),
            };
            out.resize(size, 0);
            return Ok(true);
        }
        match rtype {
            // RFC 1876 §§2-3: LOC coordinates and precision are encoded in centimeters.
            Type::LOC => {
                let mut i = 0;
                let lat = coordinate(fields, &mut i, &mut index, 90, "N", "S")?;
                let lon = coordinate(fields, &mut i, &mut index, 180, "E", "W")?;
                let alt = at!(i, fields.get(i).ok_or("missing LOC altitude"))?;
                let alt = at!(i, loc_float(alt.strip_suffix(['m', 'M']).unwrap_or(alt)))?;
                i += 1;
                // RFC 1876 §2: match Go's architecture-dependent rounding and conversion.
                #[cfg(target_arch = "aarch64")]
                let adjusted = alt.mul_add(100.0, 10_000_000.0) + 0.5;
                // shortcut: Go GOAMD64=v3 may fuse this; match its build profile if configurable.
                #[cfg(not(target_arch = "aarch64"))]
                let adjusted = alt * 100.0 + 10_000_000.0 + 0.5;
                #[cfg(target_arch = "x86_64")]
                let altitude = if !adjusted.is_finite()
                    || adjusted >= 9_223_372_036_854_775_808.0
                    || adjusted < -9_223_372_036_854_775_808.0
                {
                    0
                } else {
                    adjusted as i64 as u32
                };
                #[cfg(not(target_arch = "x86_64"))]
                let altitude = adjusted as i64 as u32;
                let mut precision = [0x12, 0x16, 0x13];
                for (offset, (slot, field)) in precision.iter_mut().zip(&fields[i..]).enumerate() {
                    *slot = at!(i + offset, loc_precision(field))?;
                }
                out.extend([0, precision[0], precision[1], precision[2]]);
                out.extend(lat.to_be_bytes());
                out.extend(lon.to_be_bytes());
                out.extend(altitude.to_be_bytes());
            }
            // RFC 8005 §5: HIP stores the HIT and public-key lengths before their octets.
            Type::HIP => {
                let algorithm = at!(0, number(field!(0, "missing HIP algorithm")))?;
                let hit_field = field!(1, "missing HIP HIT");
                if hit_field.is_empty() {
                    index = 1;
                    return Err("missing HIP HIT".into());
                }
                let hit = at!(1, hex(hit_field))?;
                let key_field = field!(2, "missing HIP key");
                if key_field.is_empty() {
                    index = 2;
                    return Err("missing HIP key".into());
                }
                let key = at!(2, base64(key_field))?;
                out.push((hit_field.len() as u8) / 2);
                out.push(algorithm);
                out.extend((key.len() as u16).to_be_bytes());
                out.extend(hit);
                at!(1, check_size(&out))?;
                out.extend(key);
                at!(2, check_size(&out))?;
                for (offset, field) in fields[3..].iter().enumerate() {
                    at!(offset + 3, name(&mut out, field, origin))?;
                    at!(offset + 3, check_size(&out))?;
                }
            }
            // RFC 4398 §2: CERT contains a type, key tag, algorithm and base64 certificate.
            Type::CERT => {
                let cert_type = match field!(0, "missing CERT type") {
                    "PKIX" => 1,
                    "SPKI" => 2,
                    "PGP" => 3,
                    "IPIX" => 4,
                    "ISPKI" => 5,
                    "IPGP" => 6,
                    "ACPKIX" => 7,
                    "IACPKIX" => 8,
                    "URI" => 253,
                    "OID" => 254,
                    value => at!(0, number::<u16>(value))?,
                };
                out.extend(cert_type.to_be_bytes());
                at!(1, put16(&mut out, field!(1, "missing CERT key tag")))?;
                out.push(at!(
                    2,
                    dnssec_algorithm(field!(2, "missing CERT algorithm"), false)
                )?);
                let prefix = out.len();
                out.extend(base64_tail(fields, 3).map_err(|(field, error)| {
                    index = field;
                    error
                })?);
                check_tail_size(&out, prefix, fields, 3).map_err(|(field, error)| {
                    index = field;
                    error
                })?;
            }
            // RFC 7477 §2.1: CSYNC ends with an NSEC-format type bitmap.
            Type::CSYNC => {
                at!(0, put32(&mut out, field!(0, "missing CSYNC serial")))?;
                at!(1, put16(&mut out, field!(1, "missing CSYNC flags")))?;
                for (offset, field) in fields[2..].iter().enumerate() {
                    at!(offset + 2, type_code(field))?;
                }
                at!(fields.len(), bitmap(&mut out, &fields[2..]))?;
            }
            // RFC 4025 §2 and RFC 8777 §4: gateway type determines the address encoding.
            Type::IPSECKEY | Type::AMTRELAY => {
                out.push(at!(0, number(field!(0, "missing gateway precedence")))?);
                let (kind, gateway) = if rtype == Type::IPSECKEY {
                    let kind = at!(1, number(field!(1, "missing gateway type")))?;
                    out.push(kind);
                    out.push(at!(2, number(field!(2, "missing IPSECKEY algorithm")))?);
                    (kind, fields.get(3).copied().unwrap_or(""))
                } else {
                    index = 1;
                    let discovery = match field!(1, "missing AMTRELAY discovery") {
                        "0" => 0,
                        "1" => 0x80,
                        _ => return Err("invalid discovery".into()),
                    };
                    let kind: u8 = at!(2, number(field!(2, "missing gateway type")))?;
                    out.push(discovery | kind);
                    (kind & 0x7f, fields.get(3).copied().unwrap_or(""))
                };
                let mut addr = Vec::new();
                at!(3, gateway_wire(&mut addr, kind, gateway, origin))?;
                if rtype == Type::AMTRELAY && fields.len() > 4 {
                    index = 4;
                    return Err("extra AMTRELAY fields".into());
                }
                // miekg passes the discovery bit unmasked to its gateway packer.
                if rtype == Type::IPSECKEY || out[1] < 128 {
                    out.extend(addr);
                }
                if rtype == Type::IPSECKEY {
                    let prefix = out.len();
                    out.extend(base64_tail(fields, 4).map_err(|(field, error)| {
                        index = field;
                        error
                    })?);
                    check_tail_size(&out, prefix, fields, 4).map_err(|(field, error)| {
                        index = field;
                        error
                    })?;
                }
            }
            // RFC 3123 §4: APL prefixes are masked and stripped of trailing zero octets.
            Type::APL => {
                for (field_index, field) in fields.iter().enumerate() {
                    at!(field_index, apl(&mut out, field))?;
                    at!(field_index, check_size(&out))?;
                }
            }
            // RFC 2930 §2: TKEY's algorithm is followed by fixed fields and two opaque strings.
            Type::TKEY => {
                let algorithm = field!(0, "missing TKEY algorithm");
                if !algorithm.ends_with('.') {
                    index = 0;
                    return Err("TKEY algorithm must be absolute".into());
                }
                at!(0, name(&mut out, algorithm, origin))?;
                out.extend([0; 12]);
                let key_len: u8 = at!(1, number(field!(1, "missing TKEY key length")))?;
                out.extend(u16::from(key_len).to_be_bytes());
                out.extend(at!(2, hex(field!(2, "missing TKEY key")))?);
                at!(2, check_size(&out))?;
                let other_len: u8 = at!(3, number(field!(3, "missing TKEY other length")))?;
                out.extend(u16::from(other_len).to_be_bytes());
                at!(3, check_size(&out))?;
                out.extend(at!(4, hex(field!(4, "missing TKEY other data")))?);
                at!(4, check_size(&out))?;
            }
            _ => return Ok(false),
        }
        if out.len() > usize::from(u16::MAX) {
            index = fields.len().saturating_sub(1);
            return Err("RDATA exceeds 65535 octets".into());
        }
        Ok(true)
    })();
    match result {
        Ok(false) => None,
        Ok(true) => Some(Ok(out)),
        Err(e) => Some(Err((index, e))),
    }
}

// RFC 1035 §3.2.1: RDLENGTH is a 16-bit octet count.
fn check_size(out: &[u8]) -> Result<(), String> {
    if out.len() > usize::from(u16::MAX) {
        Err("RDATA exceeds 65535 octets".into())
    } else {
        Ok(())
    }
}

// RFC 4648 §4: each three decoded octets come from four encoded characters.
fn check_tail_size(
    out: &[u8],
    prefix: usize,
    fields: &[&str],
    start: usize,
) -> Result<(), (usize, String)> {
    check_size(out).map_err(|error| {
        let allowed = usize::from(u16::MAX) - prefix;
        let offset = (allowed / 3) * 4 + 1 + allowed % 3;
        (tail_field(fields, start, offset), error)
    })
}

fn tail_field(fields: &[&str], start: usize, offset: usize) -> usize {
    let mut end = 0;
    fields[start.min(fields.len())..]
        .iter()
        .position(|field| {
            end += field.len();
            offset < end
        })
        .map_or_else(|| fields.len().saturating_sub(1).max(start), |i| start + i)
}

// RFC 1876 §3: degrees may omit minutes and seconds, but require a hemisphere.
fn coordinate(
    fields: &[&str],
    i: &mut usize,
    error_index: &mut usize,
    max: u32,
    positive: &str,
    negative: &str,
) -> Result<u32, String> {
    *error_index = *i;
    let deg: u32 = number(fields.get(*i).ok_or("missing LOC degrees")?)?;
    if deg > max {
        return Err("invalid LOC degrees".into());
    }
    *i += 1;
    let mut value = deg * 3_600_000;
    *error_index = *i;
    let mut direction = *fields.get(*i).ok_or("missing LOC direction")?;
    let mut over_limit_index = *i;
    if !direction.eq_ignore_ascii_case(positive) && !direction.eq_ignore_ascii_case(negative) {
        let min: u32 = number(direction)?;
        if min > 59 {
            return Err("invalid LOC minutes".into());
        }
        *i += 1;
        *error_index = *i;
        let sec = loc_float(fields.get(*i).ok_or("missing LOC seconds")?)?;
        if sec < 0.0 || sec >= 60.0 {
            return Err("invalid LOC seconds".into());
        }
        if min == 0 {
            over_limit_index = *i;
        }
        value += min * 60_000 + (sec * 1000.0) as u32;
        *i += 1;
        *error_index = *i;
        direction = *fields.get(*i).ok_or("missing LOC direction")?;
    }
    if value > max * 3_600_000 {
        *error_index = over_limit_index;
        return Err("LOC coordinate out of range".into());
    }
    *i += 1;
    if direction.eq_ignore_ascii_case(positive) {
        Ok((1u32 << 31) + value)
    } else if direction.eq_ignore_ascii_case(negative) {
        Ok((1u32 << 31) - value)
    } else {
        Err("invalid LOC direction".into())
    }
}

// RFC 1876 §3: miekg reads coordinates and altitude using Go's floating-point syntax.
fn loc_float(field: &str) -> Result<f64, String> {
    let error = || "invalid LOC floating-point value".to_string();
    let unsigned = field.strip_prefix(['+', '-']).unwrap_or(field);
    if unsigned.eq_ignore_ascii_case("nan") && unsigned.len() != field.len() {
        return Err(error());
    }
    let hex = unsigned.starts_with("0x") || unsigned.starts_with("0X");
    if field.contains('_') {
        let bytes = field.as_bytes();
        let exponent = field.find(['p', 'P']).unwrap_or(field.len());
        for (i, &byte) in bytes.iter().enumerate() {
            if byte != b'_' {
                continue;
            }
            let digit = |b: u8| {
                if hex && i < exponent {
                    b.is_ascii_hexdigit()
                } else {
                    b.is_ascii_digit()
                }
            };
            let prefix =
                hex && i >= 2 && bytes[i - 1].eq_ignore_ascii_case(&b'x') && bytes[i - 2] == b'0';
            if i == 0
                || i + 1 == bytes.len()
                || !(digit(bytes[i - 1]) || prefix)
                || !digit(bytes[i + 1])
            {
                return Err(error());
            }
        }
    }
    let cleaned = field.replace('_', "");
    if hex {
        return loc_hex_float(&cleaned);
    }
    let value: f64 = cleaned.parse().map_err(|_| error())?;
    if value.is_infinite()
        && !unsigned.eq_ignore_ascii_case("inf")
        && !unsigned.eq_ignore_ascii_case("infinity")
    {
        return Err(error());
    }
    Ok(value)
}

// RFC 1876 §3: hexadecimal floats use round-to-nearest, ties-to-even binary64.
fn loc_hex_float(field: &str) -> Result<f64, String> {
    let error = || "invalid LOC hexadecimal float".to_string();
    let negative = field.starts_with('-');
    let unsigned = field.strip_prefix(['+', '-']).unwrap_or(field);
    let (digits, exponent) = unsigned[2..].split_once(['p', 'P']).ok_or_else(error)?;
    let exp_digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
    if exp_digits.is_empty() || !exp_digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(error());
    }
    let exponent = exponent
        .parse::<i64>()
        .unwrap_or(if exponent.starts_with('-') {
            i64::MIN
        } else {
            i64::MAX
        });
    let mut before = 0i64;
    let mut index = 0i64;
    let mut first = None;
    let mut point = false;
    let mut bits = 0u64;
    let mut count = 0;
    let mut sticky = false;
    for byte in digits.bytes() {
        if byte == b'.' && !point {
            point = true;
            continue;
        }
        let digit = (byte as char).to_digit(16).ok_or_else(error)?;
        if !point {
            before += 1;
        }
        if first.is_none() && digit != 0 {
            first = Some((index, 31 - digit.leading_zeros()));
        }
        if first.is_some() {
            for shift in (0..4).rev() {
                let bit = (digit >> shift) & 1;
                if count == 0 && bit == 0 {
                    continue;
                }
                if count < 54 {
                    bits = (bits << 1) | u64::from(bit);
                    count += 1;
                } else {
                    sticky |= bit != 0;
                }
            }
        }
        index += 1;
    }
    if index == 0 {
        return Err(error());
    }
    let sign = u64::from(negative) << 63;
    let Some((first_index, high_bit)) = first else {
        return Ok(f64::from_bits(sign));
    };
    let mut exp = exponent
        .saturating_add((before - first_index - 1).saturating_mul(4))
        .saturating_add(i64::from(high_bit));
    if exp > 1023 {
        return Err(error());
    }
    if exp < -1075 {
        return Ok(f64::from_bits(sign));
    }
    bits <<= 54 - count;
    let keep = if exp >= -1022 {
        53
    } else {
        (exp + 1075) as u32
    };
    let mut mantissa = bits >> (54 - keep);
    let guard = (bits >> (53 - keep)) & 1;
    let tail = bits & ((1u64 << (53 - keep)) - 1);
    if guard != 0 && (tail != 0 || sticky || mantissa & 1 != 0) {
        mantissa += 1;
    }
    if exp >= -1022 {
        if mantissa == 1 << 53 {
            mantissa >>= 1;
            exp += 1;
        }
        if exp > 1023 {
            return Err(error());
        }
        Ok(f64::from_bits(
            sign | (((exp + 1023) as u64) << 52) | (mantissa & ((1 << 52) - 1)),
        ))
    } else {
        Ok(f64::from_bits(sign | mantissa))
    }
}

// RFC 1876 §2: precision is a decimal mantissa and exponent in centimeters.
fn loc_precision(field: &str) -> Result<u8, String> {
    let field = field.strip_suffix(['m', 'M']).unwrap_or(field);
    let (meters, cm) = match field.split_once('.') {
        Some((m, c)) if !c.is_empty() && c.len() <= 2 => (m, c),
        Some(_) => return Err("invalid LOC precision".into()),
        None => (field, ""),
    };
    let meters: u64 = if meters.is_empty() && !cm.is_empty() {
        0
    } else {
        number(meters)?
    };
    let cm: u64 = if cm.is_empty() {
        0
    } else {
        number::<u64>(cm)? * if cm.len() == 1 { 10 } else { 1 }
    };
    if meters > 90_000_000 || (meters == 90_000_000 && cm != 0) {
        return Err("LOC precision out of range".into());
    }
    let (mut val, mut exp) = if meters > 0 { (meters, 2) } else { (cm, 0) };
    while val >= 10 {
        val /= 10;
        exp += 1;
    }
    Ok((val as u8) << 4 | exp)
}

// RFC 4025 §2.3: only gateway types 0-3 have defined encodings.
fn gateway_wire(out: &mut Vec<u8>, kind: u8, field: &str, origin: &Name) -> Result<(), String> {
    match kind {
        0 if field != "." => return Err("invalid empty gateway".into()),
        1 => {
            let ip: IpAddr = field.parse().map_err(|_| "invalid gateway IPv4")?;
            let ip = match ip {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(ip) => ip.to_ipv4_mapped().ok_or("invalid gateway IPv4")?,
            };
            out.extend(ip.octets());
        }
        2 => {
            let ip: Ipv6Addr = field.parse().map_err(|_| "invalid gateway IPv6")?;
            if ip.to_ipv4_mapped().is_some() {
                return Err("invalid gateway IPv6".into());
            }
            out.extend(ip.octets());
        }
        3 if field.is_empty() => return Err("invalid gateway name".into()),
        3 => name(out, field, origin)?,
        _ => {}
    }
    Ok(())
}

// RFC 3123 §§4.1-4.2: address family and prefix select the minimum address octets.
fn apl(out: &mut Vec<u8>, field: &str) -> Result<(), String> {
    let (family, cidr) = field.split_once(':').ok_or("invalid APL family")?;
    let (negated, family) = family
        .strip_prefix('!')
        .map_or((false, family), |f| (true, f));
    let family: u16 = number(family)?;
    let (address, prefix) = cidr.split_once('/').ok_or("missing APL prefix")?;
    let prefix: u8 = number(prefix)?;
    let bytes = match family {
        1 => address
            .parse::<Ipv4Addr>()
            .map_err(|_| "invalid APL IPv4")?
            .octets()
            .to_vec(),
        2 => address
            .parse::<Ipv6Addr>()
            .map_err(|_| "invalid APL IPv6")?
            .octets()
            .to_vec(),
        _ => return Err("invalid APL family".into()),
    };
    if usize::from(prefix) > bytes.len() * 8 {
        return Err("invalid APL prefix".into());
    }
    for bit in usize::from(prefix)..bytes.len() * 8 {
        if bytes[bit / 8] & (0x80 >> (bit % 8)) != 0 {
            return Err("APL address has host bits".into());
        }
    }
    let used = bytes
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |pos| pos + 1);
    out.extend(family.to_be_bytes());
    out.push(prefix);
    out.push((used as u8) | if negated { 0x80 } else { 0 });
    out.extend(&bytes[..used]);
    Ok(())
}

// RFC 4648 §3.2: identify the token containing invalid alphabet or padding bytes.
fn base64_tail(fields: &[&str], start: usize) -> Result<Vec<u8>, (usize, String)> {
    let start = start.min(fields.len());
    let data = fields[start..].concat();
    base64(&data).map_err(|error| {
        let bytes = data.as_bytes();
        let offset = bytes.iter().enumerate().find_map(|(i, &byte)| {
            let invalid = if byte == b'=' {
                i % 4 < 2
                    || (i % 4 == 2 && bytes.get(i + 1) != Some(&b'='))
                    || i / 4 + 1 < bytes.len().div_ceil(4)
            } else {
                !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'/')
            };
            invalid.then_some(i)
        });
        let field = offset
            .map(|offset| tail_field(fields, start, offset))
            .unwrap_or_else(|| fields.len().saturating_sub(1).max(start));
        (field, error)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1035 §3.2.1: RDLENGTH limits RDATA to 65535 octets.
    #[test]
    fn oversized_rdata_points_to_the_crossing_field() {
        let origin: Name = ".".parse().unwrap();
        let huge_hex = "ab".repeat(65_536);
        let hip = ["2", huge_hex.as_str(), "AQID", "extra."];
        assert_eq!(parse(Type::HIP, &hip, &origin).unwrap().unwrap_err().0, 1);
        let tkey = [".", "1", huge_hex.as_str(), "1", "ff"];
        assert_eq!(parse(Type::TKEY, &tkey, &origin).unwrap().unwrap_err().0, 2);
        let huge_base64 = "AAAA".repeat(21_845);
        let cert = ["PKIX", "1", "8", huge_base64.as_str(), "AAAA"];
        assert_eq!(parse(Type::CERT, &cert, &origin).unwrap().unwrap_err().0, 3);
        let apl = vec!["1:0.0.0.0/0"; 16_385];
        assert_eq!(
            parse(Type::APL, &apl, &origin).unwrap().unwrap_err().0,
            16_383
        );
    }
}

use crate::{Name, Type};

use super::{
    base64, bitmap, character_string, count, dnssec_algorithm, hex, length_bytes, name, number,
    put16, put32, type_code, unescape,
};

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
    let result = (|| -> Result<bool, String> {
        match rtype {
            // RFC 1035 §3.3 and RFC 1348 §3: these RDATA consist of one domain name.
            Type::NSAP_PTR | Type::MR | Type::MB | Type::MG | Type::MF | Type::MD => {
                at!(fields.len().min(1), count(fields, 1))?;
                at!(0, name(&mut out, fields[0], origin))?;
            }
            // RFC 1183 §2.2 and RFC 1035 §3.3.7: two domain names follow each other.
            Type::RP | Type::MINFO | Type::TALINK => {
                at!(fields.len().min(2), count(fields, 2))?;
                for (i, field) in fields.iter().enumerate() {
                    at!(i, name(&mut out, field, origin))?;
                }
            }
            // RFC 1183 §§1,3.3, RFC 2230 §2 and RFC 6742 §3.4: a preference precedes a name.
            Type::RT | Type::AFSDB | Type::KX | Type::LP => {
                at!(fields.len().min(2), count(fields, 2))?;
                at!(0, put16(&mut out, fields[0]))?;
                at!(1, name(&mut out, fields[1], origin))?;
            }
            // RFC 2163 §4: PX has a preference and two mapping names.
            Type::PX => {
                at!(fields.len().min(3), count(fields, 3))?;
                at!(0, put16(&mut out, fields[0]))?;
                at!(1, name(&mut out, fields[1], origin))?;
                at!(2, name(&mut out, fields[2], origin))?;
            }
            // RFC 1183 §§3.1-3.2: X25 and ISDN use character-strings.
            Type::X25 => {
                if fields.len() > 1 {
                    index = 1;
                    return Err("extra X25 fields".into());
                }
                at!(
                    0,
                    character_string(&mut out, fields.first().copied().unwrap_or(""))
                )?;
            }
            Type::ISDN => {
                let mut chunks = text_chunks(fields, &mut index)?;
                if chunks.len() == 1 && fields.len() == 1 {
                    let parts: Vec<_> = fields[0].split_whitespace().collect();
                    if parts.len() > 1 {
                        chunks = text_chunks(&parts, &mut index)?;
                        for (i, _) in &mut chunks {
                            *i = 0;
                        }
                    }
                }
                let address = chunks
                    .first()
                    .map_or(&[][..], |(_, chunk)| chunk.as_slice());
                index = 0;
                length_bytes(&mut out, address)?;
                let mut rest = Vec::new();
                for (n, (i, chunk)) in chunks.iter().skip(1).enumerate() {
                    index = *i;
                    if n != 0 {
                        rest.push(b' ');
                    }
                    rest.extend(chunk);
                    if rest.len() > 255 {
                        return Err("character-string exceeds 255 octets".into());
                    }
                }
                length_bytes(&mut out, &rest)?;
            }
            // RFC 1712 §3: longitude, latitude and altitude are character-strings.
            Type::GPOS => {
                at!(fields.len().min(3), count(fields, 3))?;
                for (i, field) in fields.iter().enumerate() {
                    at!(
                        i,
                        field.parse::<f64>().map_err(|_| "invalid GPOS coordinate")
                    )?;
                    character_string(&mut out, field)?;
                }
            }
            // RFC 7043 §§2.1-2.2: EUI addresses are fixed-size network-order octets.
            Type::EUI48 | Type::EUI64 => {
                at!(fields.len().min(1), count(fields, 1))?;
                index = 0;
                let expected = if rtype == Type::EUI48 { 6 } else { 8 };
                let parts: Vec<_> = fields[0].split('-').collect();
                if parts.len() != expected || parts.iter().any(|part| part.len() != 2) {
                    return Err("invalid EUI address".into());
                }
                out.extend(hex(&parts.concat())?);
            }
            // RFC 6742 §§3.1-3.3: ILNP records pair a preference with a fixed-size identifier.
            Type::NID | Type::L64 => {
                at!(fields.len().min(2), count(fields, 2))?;
                at!(0, put16(&mut out, fields[0]))?;
                index = 1;
                let b = fields[1].as_bytes();
                // miekg's stringToNodeID accepts trailing bytes and only requires one colon.
                if b.len() < 19 || (b[4] != b':' && b[9] != b':' && b[14] != b':') {
                    return Err("invalid NID/L64 identifier".into());
                }
                let mut digits = Vec::with_capacity(16);
                for range in [0..4, 5..9, 10..14, 15..19] {
                    digits.extend_from_slice(&b[range]);
                }
                out.extend(hex(
                    std::str::from_utf8(&digits).map_err(|_| "invalid identifier")?
                )?);
            }
            Type::L32 => {
                at!(fields.len().min(2), count(fields, 2))?;
                at!(0, put16(&mut out, fields[0]))?;
                index = 1;
                let ip: std::net::IpAddr = fields[1].parse().map_err(|_| "invalid L32 address")?;
                let ip = match ip {
                    std::net::IpAddr::V4(ip) => ip,
                    std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().ok_or("invalid L32 address")?,
                };
                out.extend(ip.octets());
            }
            // RFC 1035 §3.3: numeric fields are encoded in network byte order.
            Type::UID | Type::GID => {
                at!(fields.len().min(1), count(fields, 1))?;
                at!(0, put32(&mut out, fields[0]))?;
            }
            Type::UINFO => {
                let chunks = text_chunks(fields, &mut index)?;
                index = 0;
                length_bytes(
                    &mut out,
                    chunks
                        .first()
                        .map_or(&[][..], |(_, chunk)| chunk.as_slice()),
                )?;
            }
            // RFC 1035 §3.3.14 and RFC 9606 §2: TXT-style data uses character-strings.
            Type::AVC | Type::NINFO | Type::RESINFO => {
                for (i, chunk) in text_chunks(fields, &mut index)? {
                    index = i;
                    length_bytes(&mut out, &chunk)?;
                    if out.len() > usize::from(u16::MAX) {
                        return Err("RDATA exceeds 65535 octets".into());
                    }
                }
            }
            // RFC 4701 §3 and RFC 7929 §2: presentation data is base64.
            Type::DHCID | Type::OPENPGPKEY => out.extend(binary(fields, 0, true, 0, &mut index)?),
            // RFC 2535 §3.1: KEY and RKEY use DNSKEY's wire layout.
            Type::RKEY | Type::KEY => {
                if fields.len() < 3 {
                    index = fields.len();
                    return Err("missing key fields".into());
                }
                at!(0, put16(&mut out, fields[0]))?;
                out.push(at!(1, number(fields[1]))?);
                out.push(at!(2, number(fields[2]))?);
                out.extend(binary(fields, 3, true, out.len(), &mut index)?);
            }
            // RFC 4431 §3 and RFC 4034 §5.1: DLV and TA share the DS wire layout.
            Type::DLV | Type::TA => {
                if fields.len() < 3 {
                    index = fields.len();
                    return Err("missing digest fields".into());
                }
                at!(0, put16(&mut out, fields[0]))?;
                out.push(at!(1, dnssec_algorithm(fields[1], true))?);
                out.push(at!(2, number(fields[2]))?);
                out.extend(binary(fields, 3, false, out.len(), &mut index)?);
            }
            // RFC 2535 §4.1: SIG uses the same field layout as RRSIG.
            Type::SIG => {
                out =
                    super::parse_rdata_located(Type::RRSIG, &fields[..fields.len().min(8)], origin)
                        .map_err(|(i, error)| {
                            index = i;
                            error
                        })?;
                out.extend(binary(fields, 8, true, out.len(), &mut index)?);
            }
            // RFC 4034 §4.1.2: miekg encodes NXT using NSEC's windowed bitmap.
            Type::NXT => {
                if fields.is_empty() {
                    index = fields.len();
                    return Err("missing NXT name".into());
                }
                at!(0, name(&mut out, fields[0], origin))?;
                for (i, field) in fields.iter().enumerate().skip(1) {
                    at!(i, type_code(field))?;
                }
                bitmap(&mut out, &fields[1..])?;
            }
            // RFC 1035 §3.2.1: RDATA is an octet sequence; Nimrod presents these fields as hex.
            Type::EID | Type::NIMLOC => out.extend(binary(fields, 0, false, 0, &mut index)?),
            _ => return Ok(false),
        }
        if out.len() > usize::from(u16::MAX) {
            return Err("RDATA exceeds 65535 octets".into());
        }
        Ok(true)
    })();
    match result {
        Ok(false) => None,
        Ok(true) => Some(Ok(out)),
        Err(error) => Some(Err((index, error))),
    }
}

// RFC 1035 §3.3.14: a TXT character-string contains at most 255 octets.
fn text_chunks(fields: &[&str], index: &mut usize) -> Result<Vec<(usize, Vec<u8>)>, String> {
    let mut chunks = Vec::new();
    for (i, field) in fields.iter().enumerate() {
        *index = i;
        let bytes = unescape(field)?;
        if bytes.is_empty() {
            chunks.push((i, Vec::new()));
        } else {
            chunks.extend(bytes.chunks(255).map(|chunk| (i, chunk.to_vec())));
        }
    }
    Ok(chunks)
}

// RFC 4648 §§4,8: encoded data can span fields, but invalid octets retain their source field.
fn binary(
    fields: &[&str],
    start: usize,
    is_base64: bool,
    prefix: usize,
    index: &mut usize,
) -> Result<Vec<u8>, String> {
    let joined = fields[start..].concat();
    let bytes = joined.as_bytes();
    let field_at = |offset: usize| {
        let mut end = 0;
        for (i, field) in fields.iter().enumerate().skip(start) {
            end += field.len();
            if offset < end {
                return i;
            }
        }
        fields.len().saturating_sub(1).max(start)
    };
    *index = fields.len().saturating_sub(1).max(start);
    let decoded = if is_base64 {
        base64(&joined)
    } else {
        hex(&joined)
    };
    let data = decoded.inspect_err(|_| {
        let invalid = bytes.iter().enumerate().find_map(|(pos, &b)| {
            if is_base64 {
                if !b.is_ascii_alphanumeric() && !matches!(b, b'+' | b'/' | b'=') {
                    return Some(pos);
                }
                if b == b'=' {
                    if pos % 4 < 2 || pos + 2 < bytes.len() {
                        return Some(pos);
                    }
                    if pos % 4 == 2 && bytes.get(pos + 1).is_some_and(|b| *b != b'=') {
                        return Some(pos + 1);
                    }
                }
            } else if !b.is_ascii_hexdigit() {
                return Some(pos);
            }
            None
        });
        if let Some(offset) = invalid {
            *index = field_at(offset);
        }
    })?;
    if data.len() + prefix > usize::from(u16::MAX) {
        let allowed = usize::from(u16::MAX) - prefix;
        let offset = if is_base64 {
            (allowed / 3) * 4 + (allowed % 3) + 1
        } else {
            allowed * 2 + 1
        };
        *index = field_at(offset);
        return Err("RDATA exceeds 65535 octets".into());
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_and_extra_fields_report_the_boundary() {
        let origin = "example.".parse().unwrap();
        for (rtype, fields, expected) in [
            (Type::PX, &[][..], 0),
            (Type::PX, &["1", "host"][..], 2),
            (Type::PX, &["1", "host", ".", "extra"][..], 3),
            (Type::KEY, &["1", "3"][..], 2),
            (Type::SIG, &["A", "8"][..], 2),
        ] {
            assert_eq!(
                parse(rtype, fields, &origin).unwrap().unwrap_err().0,
                expected,
                "{rtype}"
            );
        }
    }

    #[test]
    fn oversized_and_fragmented_data_report_the_responsible_field() {
        let origin = "example.".parse().unwrap();
        let hex = "AA".repeat(65535);
        let b64 = "AAAA".repeat(21845);
        let long = "x".repeat(255);
        for (rtype, fields, expected) in [
            (Type::EID, &[hex.as_str(), "AA"][..], 1),
            (Type::DHCID, &[b64.as_str(), "AAAA"][..], 1),
            (Type::DHCID, &["AQ==", "AAAA"][..], 0),
            (Type::ISDN, &["x", long.as_str(), "x"][..], 2),
        ] {
            assert_eq!(
                parse(rtype, fields, &origin).unwrap().unwrap_err().0,
                expected,
                "{rtype}"
            );
        }
    }
}

use pharos_proto::{Class, NameRef, Type, zone::ZoneRecord};
use std::io::{self, ErrorKind};

fn invalid() -> io::Error {
    io::Error::new(ErrorKind::InvalidData, "invalid stored Zone records")
}

fn uncompressed_name(data: &[u8], offset: usize) -> io::Result<usize> {
    let name = NameRef::parse(data, offset).map_err(|_| invalid())?;
    // RFC 1035 §4.1.4: a stored wire RR cannot retain Message-relative compression pointers.
    if name.wire_len() != name.labels().map(|label| label.len() + 1).sum::<usize>() + 1 {
        return Err(invalid());
    }
    offset
        .checked_add(name.wire_len())
        .filter(|end| *end <= data.len())
        .ok_or_else(invalid)
}

// RFC 1035 §3.3.13: SOA RDATA is two names followed by five 32-bit fields.
fn validate_names(kind: Type, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let (mut cursor, count, tail) = match kind {
        Type::NS
        | Type::CNAME
        | Type::DNAME
        | Type::PTR
        | Type::MD
        | Type::MF
        | Type::MB
        | Type::MG
        | Type::MR
        | Type::NSAP_PTR => (0, 1, Some(0)),
        Type::MINFO | Type::RP => (0, 2, Some(0)),
        // RFC 1035 §3.3.13: SOA RDATA has two domain names followed by five 32-bit values.
        Type::SOA => (0, 2, Some(20)),
        Type::MX | Type::AFSDB | Type::RT | Type::KX | Type::LP => (2, 1, Some(0)),
        Type::PX => (2, 2, Some(0)),
        Type::SRV => (6, 1, Some(0)),
        Type::SVCB | Type::HTTPS => (2, 1, None),
        Type::NAPTR => {
            let mut offset = 4usize;
            for _ in 0..3 {
                let len = usize::from(*data.get(offset).ok_or_else(invalid)?);
                offset = offset
                    .checked_add(1 + len)
                    .filter(|end| *end <= data.len())
                    .ok_or_else(invalid)?;
            }
            (offset, 1, Some(0))
        }
        Type::IPSECKEY => {
            let gateway = *data.get(1).ok_or_else(invalid)?;
            match gateway {
                0 if data.len() >= 3 => return Ok(()),
                1 if data.len() >= 7 => return Ok(()),
                2 if data.len() >= 19 => return Ok(()),
                3 => (3, 1, None),
                _ => return Err(invalid()),
            }
        }
        Type::AMTRELAY => {
            let relay = *data.get(1).ok_or_else(invalid)? & 0x7f;
            match relay {
                0 if data.len() == 2 => return Ok(()),
                1 if data.len() == 6 => return Ok(()),
                2 if data.len() == 18 => return Ok(()),
                3 => (2, 1, Some(0)),
                _ => return Err(invalid()),
            }
        }
        Type::HIP => {
            let header = data.get(..4).ok_or_else(invalid)?;
            let mut offset = 4usize
                .checked_add(usize::from(header[0]))
                .and_then(|n| {
                    n.checked_add(usize::from(u16::from_be_bytes([header[2], header[3]])))
                })
                .filter(|end| *end <= data.len())
                .ok_or_else(invalid)?;
            while offset < data.len() {
                offset = uncompressed_name(data, offset)?;
            }
            return Ok(());
        }
        _ => return Ok(()),
    };
    for _ in 0..count {
        cursor = uncompressed_name(data, cursor)?;
    }
    if tail.is_some_and(|tail| cursor.checked_add(tail) != Some(data.len())) {
        return Err(invalid());
    }
    Ok(())
}

// RFC 1035 §4.1.3: store consecutive uncompressed resource records, not a DNS Message.
pub(super) fn encode(records: &[ZoneRecord]) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    for rr in records {
        let len = u16::try_from(rr.rdata.len()).map_err(|_| invalid())?;
        result.extend_from_slice(rr.owner.as_wire());
        result.extend_from_slice(&rr.rtype.0.to_be_bytes());
        result.extend_from_slice(&rr.class.0.to_be_bytes());
        result.extend_from_slice(&rr.ttl.to_be_bytes());
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&rr.rdata);
    }
    Ok(result)
}

// RFC 1035 §§3.1 and 4.1.3: stored owners and fixed RR fields must fit completely.
pub(super) fn decode(
    data: &[u8],
    max_records: usize,
    max_bytes: usize,
) -> io::Result<Vec<ZoneRecord>> {
    if data.is_empty() || data.len() > max_bytes {
        return Err(invalid());
    }
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        if records.len() == max_records {
            return Err(invalid());
        }
        let owner = NameRef::parse(data, offset).map_err(|_| invalid())?;
        if owner.wire_len() != owner.labels().map(|label| label.len() + 1).sum::<usize>() + 1 {
            return Err(invalid());
        }
        offset = offset.checked_add(owner.wire_len()).ok_or_else(invalid)?;
        let fixed = data
            .get(offset..offset.checked_add(10).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        let kind = Type(u16::from_be_bytes([fixed[0], fixed[1]]));
        let class = Class(u16::from_be_bytes([fixed[2], fixed[3]]));
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let len = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        offset += 10;
        let end = offset.checked_add(len).ok_or_else(invalid)?;
        let rdata = data.get(offset..end).ok_or_else(invalid)?.to_vec();
        validate_names(kind, &rdata)?;
        records.push(ZoneRecord {
            owner: owner.to_name(),
            ttl,
            class,
            rtype: kind,
            rdata,
        });
        offset = end;
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use pharos_proto::{Name, zone::ZoneParser};

    #[test]
    fn uncompressed_records_round_trip_and_enforce_limits() {
        let origin: Name = "example.org.".parse().unwrap();
        let records = ZoneParser::new("@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\nwww 60 IN A 192.0.2.1\n".as_bytes(), origin, "test")
            .collect::<Result<Vec<_>, _>>().unwrap();
        let bytes = encode(&records).unwrap();
        assert_eq!(decode(&bytes, 2, bytes.len()).unwrap(), records);
        assert!(decode(&bytes, 1, bytes.len()).is_err());
        assert!(decode(&bytes, 2, bytes.len() - 1).is_err());
        assert!(decode(&bytes[..bytes.len() - 1], 2, bytes.len()).is_err());
    }

    #[test]
    fn decodes_records_from_coredns_database() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/dynupdate/coredns.db"
        );
        let file = std::fs::File::open(path).unwrap();
        let store = super::super::bbolt::Store::open(file).unwrap();
        let (origin, data) = store.read().unwrap();
        assert_eq!(origin, b"example.org.");
        let records = decode(&data, 10000, 8 << 20).unwrap();
        assert_eq!(records.len(), 6);
        assert!(
            records.iter().any(
                |rr| rr.owner.to_string() == "host3.example.org." && rr.rdata == [192, 0, 2, 3]
            )
        );
    }

    #[test]
    fn coredns_decode_records_fuzz_seeds_remain_bounded() {
        for data in [Vec::new(), vec![0xc0, 0, 0, 1]] {
            assert!(decode(&data, 64, 4096).is_err());
        }
        let mut state = 0x739d_229bu32;
        for len in 0..1024 {
            let mut data = vec![0; len % 512];
            for byte in &mut data {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            let result = std::panic::catch_unwind(|| decode(&data, 64, 4096));
            if let Ok(Ok(records)) = result {
                assert!(!records.is_empty() && records.len() <= 64);
            } else {
                assert!(result.is_ok(), "decoder panicked on {len}");
            }
        }
    }

    #[test]
    fn stored_embedded_names_must_be_uncompressed() {
        use pharos_proto::{Class, Type, zone::ZoneRecord};
        let owner: Name = "ptr.example.org.".parse().unwrap();
        for kind in [Type::PTR, Type::MB, Type::RP] {
            let rr = ZoneRecord {
                owner: owner.clone(),
                rtype: kind,
                class: Class::IN,
                ttl: 60,
                rdata: vec![0xc0, 0],
            };
            let data = encode(&[rr]).unwrap();
            assert!(decode(&data, 10, 4096).is_err(), "{kind}");
        }
    }
}

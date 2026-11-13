use pharos_proto::{Class, NameRef, Type, zone::ZoneRecord};
use std::io::{self, ErrorKind};

fn invalid() -> io::Error {
    io::Error::new(ErrorKind::InvalidData, "invalid stored Zone records")
}

// RFC 1035 §4.1.3: store consecutive uncompressed resource records, not a DNS Message.
fn encode(records: &[ZoneRecord]) -> io::Result<Vec<u8>> {
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
fn decode(data: &[u8], max_records: usize, max_bytes: usize) -> io::Result<Vec<ZoneRecord>> {
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
}

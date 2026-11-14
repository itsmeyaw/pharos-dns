use std::{
    fmt::Write as _,
    fs::OpenOptions,
    io::{BufReader, Write as _},
    path::Path,
};

use pharos_proto::{
    Name, Rdata, Type,
    zone::{ZoneParser, ZoneRecord},
};

pub(super) fn needs_resign(path: &Path, now: u32) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return true;
    };
    let root: Name = ".".parse().expect("root");
    let mut parser = ZoneParser::new(BufReader::new(file), root, path.to_string_lossy());
    parser.set_include_allowed(true);
    let mut count = 0;
    for record in parser {
        let Ok(record) = record else {
            return true;
        };
        if record.rtype == Type::RRSIG {
            let Some(data) = record.rdata.get(..18) else {
                return true;
            };
            if data[..2] != Type::SOA.0.to_be_bytes() {
                continue;
            }
            let expiration = u32::from_be_bytes(data[8..12].try_into().unwrap());
            let inception = u32::from_be_bytes(data[12..16].try_into().unwrap());
            // RFC 6781 §4.4.2.2: Re-sign when under seven days of validity remain.
            if inception > now
                || now - inception > 6 * 86400
                || expiration.saturating_sub(now) < 7 * 86400
            {
                return true;
            }
        }
        count += 1;
        if count > 100 {
            return true;
        }
    }
    false
}

pub(super) fn write(directory: &Path, target: &Path, records: &[ZoneRecord]) -> Result<(), String> {
    let mut random = [0u8; 8];
    getrandom::getrandom(&mut random).map_err(|error| error.to_string())?;
    let temp = directory.join(format!("signed-{:016x}", u64::from_ne_bytes(random)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| error.to_string())?;
        for record in records
            .iter()
            .filter(|rr| rr.rtype == Type::SOA)
            .chain(records.iter().filter(|rr| rr.rtype != Type::SOA))
        {
            if matches!(record.rtype, Type::CAA | Type::URI) {
                // RFC 8659 §4 and RFC 7553 §4.4 and §4.5: These fields contain literal octets.
                // CoreDNS writes plain octets as-is and reads backslashes as escapes, so only other octets are escaped.
                let octets = |bytes: &[u8], plain: bool| {
                    if plain {
                        return bytes.iter().map(|&b| char::from(b)).collect::<String>();
                    }
                    let mut text = String::new();
                    for byte in bytes {
                        let _ = write!(text, "\\{byte:03}");
                    }
                    text
                };
                let plain_text = |bytes: &[u8]| {
                    bytes
                        .iter()
                        .all(|&b| matches!(b, b' '..=b'~') && !matches!(b, b'"' | b'\\' | b';'))
                };
                let text = if record.rtype == Type::CAA {
                    let flags = *record.rdata.first().ok_or("truncated CAA")?;
                    let length = usize::from(*record.rdata.get(1).ok_or("truncated CAA")?);
                    let tag = record.rdata.get(2..2 + length).ok_or("truncated CAA tag")?;
                    let value = &record.rdata[2 + length..];
                    let plain_tag = !tag.is_empty() && tag.iter().all(u8::is_ascii_alphanumeric);
                    format!(
                        "CAA {flags} {} \"{}\"",
                        octets(tag, plain_tag),
                        octets(value, plain_text(value))
                    )
                } else {
                    let prefix = record.rdata.get(..4).ok_or("truncated URI")?;
                    let priority = u16::from_be_bytes([prefix[0], prefix[1]]);
                    let weight = u16::from_be_bytes([prefix[2], prefix[3]]);
                    let target = &record.rdata[4..];
                    format!(
                        "URI {priority} {weight} \"{}\"",
                        octets(target, plain_text(target))
                    )
                };
                writeln!(
                    file,
                    "{} {} CLASS{} {text}",
                    record.owner, record.ttl, record.class.0
                )
                .map_err(|error| error.to_string())?;
                continue;
            }
            // RFC 3597 §5: generic RDATA presents arbitrary records as wire-format hexadecimal.
            let mut line = String::new();
            writeln!(
                line,
                "{} {} CLASS{} TYPE{} {}",
                record.owner,
                record.ttl,
                record.class.0,
                record.rtype.0,
                Rdata::Unknown(record.rtype, &record.rdata)
            )
            .map_err(|error| error.to_string())?;
            file.write_all(line.as_bytes())
                .map_err(|error| error.to_string())?;
        }
        file.flush().map_err(|error| error.to_string())?;
        std::fs::rename(&temp, target).map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resign_checks_soa_signature_age_and_expiration() {
        let dir = std::env::temp_dir().join(format!("pharos-sign-resign-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("zone");
        let now = 1_600_000_000_u32;
        for (inception, expiration, expected) in [
            (now - 86400, now + 8 * 86400, false),
            (now - 6 * 86400, now + 7 * 86400, false),
            (now - 6 * 86400 - 1, now + 7 * 86400, true),
            (now - 86400, now + 7 * 86400 - 1, true),
            (now + 1, now + 8 * 86400, true),
            (now - 7 * 86400, now + 8 * 86400, true),
            (now - 86400, now + 6 * 86400, true),
        ] {
            let mut data = vec![0, 6, 13, 2, 0, 0, 0, 60];
            data.extend_from_slice(&expiration.to_be_bytes());
            data.extend_from_slice(&inception.to_be_bytes());
            data.extend_from_slice(&[0, 1, 0, 1]);
            let record = ZoneRecord {
                owner: "example.org.".parse().unwrap(),
                ttl: 60,
                class: pharos_proto::Class::IN,
                rtype: Type::RRSIG,
                rdata: data,
            };
            write(&dir, &path, &[record]).unwrap();
            assert_eq!(needs_resign(&path, now), expected);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn written_caa_and_uri_preserve_literal_backslashes() {
        let dir = std::env::temp_dir().join(format!("pharos-sign-escapes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("zone");
        let owner: Name = "example.org.".parse().unwrap();
        let records = [
            ZoneRecord {
                owner: owner.clone(),
                ttl: 60,
                class: pharos_proto::Class::IN,
                rtype: Type::CAA,
                rdata: b"\x00\x05issuea\\123z".to_vec(),
            },
            ZoneRecord {
                owner: owner.clone(),
                ttl: 60,
                class: pharos_proto::Class::IN,
                rtype: Type::URI,
                rdata: b"\x00\x01\x00\x02a\\123z".to_vec(),
            },
        ];
        write(&dir, &path, &records).unwrap();
        let parsed: Vec<_> = ZoneParser::new(
            BufReader::new(std::fs::File::open(&path).unwrap()),
            owner,
            path.to_string_lossy(),
        )
        .map(Result::unwrap)
        .collect();
        assert_eq!(parsed, records);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn written_plain_caa_and_uri_match_coredns_text() {
        let dir = std::env::temp_dir().join(format!("pharos-sign-plain-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("zone");
        let owner: Name = "example.org.".parse().unwrap();
        let records = [
            ZoneRecord {
                owner: owner.clone(),
                ttl: 60,
                class: pharos_proto::Class::IN,
                rtype: Type::CAA,
                rdata: b"\x00\x05issueletsencrypt.org".to_vec(),
            },
            ZoneRecord {
                owner: owner.clone(),
                ttl: 60,
                class: pharos_proto::Class::IN,
                rtype: Type::URI,
                rdata: b"\x00\x01\x00\x02https://example.org/".to_vec(),
            },
        ];
        write(&dir, &path, &records).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "example.org. 60 CLASS1 CAA 0 issue \"letsencrypt.org\"\nexample.org. 60 CLASS1 URI 1 2 \"https://example.org/\"\n"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn coredns_resign_scans_at_most_100_records() {
        let dir =
            std::env::temp_dir().join(format!("pharos-sign-resign-limit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("zone");
        let row = "example.org. 60 IN A 192.0.2.1\n";
        std::fs::write(&path, row.repeat(100)).unwrap();
        assert!(!needs_resign(&path, 1_600_000_000));
        std::fs::write(&path, row.repeat(101)).unwrap();
        assert!(needs_resign(&path, 1_600_000_000));
        std::fs::remove_dir_all(dir).unwrap();
    }
}

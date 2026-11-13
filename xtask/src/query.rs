use std::fmt;

use pharos_proto::{
    Class, EdnsOptions, MessageBuilder, Name, NameRef, Opt, Section, TsigAlgorithm, TsigKey, Type,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TsigCase {
    Valid,
    BadKey,
    BadSig,
    BadTime,
}

#[derive(Debug)]
pub(crate) struct Query {
    original: String,
    name: Name,
    qtype: Type,
    class: Class,
    pub(crate) transport: Transport,
    recursion: bool,
    opcode: u8,
    edns: bool,
    dnssec: bool,
    nsid: bool,
    options: Vec<(u16, Vec<u8>)>,
    bufsize: u16,
    edns_version: u8,
    tsig: Option<(Name, Vec<u8>, TsigCase)>,
    ixfr_serial: Option<u32>,
    additions: Vec<(Name, Type, u32, Vec<u8>)>,
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.original)
    }
}

fn decimal<T: std::str::FromStr>(value: &str) -> Option<T> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn record_type(value: &str) -> Option<Type> {
    macro_rules! types {
        ($($name:ident),* $(,)?) => {
            match value {
                $(stringify!($name) => Some(Type::$name),)*
                "NSAP-PTR" => Some(Type::NSAP_PTR),
                _ => value.strip_prefix("TYPE").and_then(decimal).map(Type),
            }
        };
    }
    types!(
        NONE, A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, PTR, HINFO, MINFO, MX, TXT, RP, AFSDB,
        X25, ISDN, RT, SIG, KEY, PX, GPOS, AAAA, LOC, NXT, EID, NIMLOC, SRV, ATMA, NAPTR, KX, CERT,
        DNAME, OPT, APL, DS, SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM, TLSA,
        SMIMEA, HIP, NINFO, RKEY, TALINK, CDS, CDNSKEY, OPENPGPKEY, CSYNC, ZONEMD, SVCB, HTTPS,
        SPF, UINFO, UID, GID, UNSPEC, NID, L32, L64, LP, EUI48, EUI64, NXNAME, TKEY, TSIG, IXFR,
        AXFR, MAILB, MAILA, ANY, URI, CAA, AVC, AMTRELAY, RESINFO, TA, DLV, RESERVED,
    )
}

pub(crate) fn parse(line: &str) -> Result<Query, String> {
    let mut parts = line.split_whitespace();
    let name = parts.next().ok_or("missing name")?;
    let qtype = parts.next().ok_or("missing type")?;
    let class = parts.next().ok_or("missing class")?;
    let transport = parts.next().ok_or("missing transport")?;
    let root = ".".parse::<Name>().map_err(|err| err.to_string())?;
    let name = Name::parse(name, &root).map_err(|err| format!("invalid name: {err}"))?;
    let qtype =
        record_type(&qtype.to_ascii_uppercase()).ok_or_else(|| format!("invalid type: {qtype}"))?;
    let class = match class.to_ascii_uppercase().as_str() {
        "IN" => Some(Class::IN),
        "CS" => Some(Class::CS),
        "CH" => Some(Class::CH),
        "HS" => Some(Class::HS),
        "NONE" => Some(Class::NONE),
        "ANY" => Some(Class::ANY),
        value => value.strip_prefix("CLASS").and_then(decimal).map(Class),
    }
    .ok_or_else(|| format!("invalid class: {class}"))?;
    let transport = match transport.to_ascii_lowercase().as_str() {
        "udp" => Transport::Udp,
        "tcp" => Transport::Tcp,
        _ => return Err(format!("invalid transport: {transport}")),
    };
    let mut query = Query {
        original: line.to_owned(),
        name,
        qtype,
        class,
        transport,
        recursion: true,
        opcode: 0,
        edns: false,
        dnssec: false,
        nsid: false,
        options: Vec::new(),
        bufsize: 1232,
        edns_version: 0,
        tsig: None,
        ixfr_serial: None,
        additions: Vec::new(),
    };
    for flag in parts {
        let lower = flag.to_ascii_lowercase();
        match lower.as_str() {
            "+dnssec" => {
                query.dnssec = true;
                query.edns = true;
            }
            "+nsid" => {
                query.nsid = true;
                query.edns = true;
            }
            "+norec" => query.recursion = false,
            _ if lower.starts_with("+add=") => {
                let mut values = flag[5..].split(':');
                let (Some(owner), Some(kind), Some(ttl), Some(hex), None) = (
                    values.next(),
                    values.next(),
                    values.next(),
                    values.next(),
                    values.next(),
                ) else {
                    return Err(format!("invalid flag: {flag}"));
                };
                let owner =
                    Name::parse(owner, &root).map_err(|_| format!("invalid flag: {flag}"))?;
                let kind = record_type(&kind.to_ascii_uppercase())
                    .ok_or_else(|| format!("invalid flag: {flag}"))?;
                let ttl = decimal(ttl).ok_or_else(|| format!("invalid flag: {flag}"))?;
                let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
                if !remainder.is_empty() {
                    return Err(format!("invalid flag: {flag}"));
                }
                let data = pairs
                    .iter()
                    .map(|pair| {
                        std::str::from_utf8(pair)
                            .ok()
                            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                            .ok_or_else(|| format!("invalid flag: {flag}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if data.len() > usize::from(u16::MAX) {
                    return Err(format!("invalid flag: {flag}"));
                }
                query.additions.push((owner, kind, ttl, data));
            }
            _ if lower.starts_with("+ixfr=") => {
                if query.qtype != Type::IXFR || query.ixfr_serial.is_some() {
                    return Err(format!("invalid flag: {flag}"));
                }
                query.ixfr_serial =
                    Some(decimal(&lower[6..]).ok_or_else(|| format!("invalid flag: {flag}"))?);
            }
            _ if lower.starts_with("+tsig=") => {
                let mut values = flag[6..].split(':');
                let (Some(name), Some(secret)) = (values.next(), values.next()) else {
                    return Err(format!("invalid flag: {flag}"));
                };
                let mode = match values.next() {
                    None | Some("valid") => TsigCase::Valid,
                    Some("badkey") => TsigCase::BadKey,
                    Some("badsig") => TsigCase::BadSig,
                    Some("badtime") => TsigCase::BadTime,
                    _ => return Err(format!("invalid flag: {flag}")),
                };
                if values.next().is_some() || query.tsig.is_some() {
                    return Err(format!("invalid flag: {flag}"));
                }
                let name = Name::parse(name, &root).map_err(|e| e.to_string())?;
                let secret = pharos_proto::decode_secret(secret).map_err(|e| e.to_string())?;
                query.tsig = Some((name, secret, mode));
            }
            _ if lower.starts_with("+bufsize=") => {
                query.bufsize =
                    decimal(&lower[9..]).ok_or_else(|| format!("invalid flag: {flag}"))?;
                query.edns = true;
            }
            _ if lower.starts_with("+ednsversion=") => {
                query.edns_version =
                    decimal(&lower[13..]).ok_or_else(|| format!("invalid flag: {flag}"))?;
                query.edns = true;
            }
            _ if lower.starts_with("+ednsoption=") => {
                let (code, hex) = lower[12..]
                    .split_once(':')
                    .ok_or_else(|| format!("invalid flag: {flag}"))?;
                let code = decimal::<u16>(code).ok_or_else(|| format!("invalid flag: {flag}"))?;
                let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
                if !remainder.is_empty() {
                    return Err(format!("invalid flag: {flag}"));
                }
                let data = pairs
                    .iter()
                    .map(|pair| {
                        let text = std::str::from_utf8(pair)
                            .map_err(|_| format!("invalid flag: {flag}"))?;
                        u8::from_str_radix(text, 16).map_err(|_| format!("invalid flag: {flag}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if data.len() > usize::from(u16::MAX) {
                    return Err(format!("invalid flag: {flag}"));
                }
                query.options.push((code, data));
                query.edns = true;
            }
            _ if lower.starts_with("+opcode=") => {
                query.opcode = match &lower[8..] {
                    "query" => Some(0),
                    "iquery" => Some(1),
                    "status" => Some(2),
                    "notify" => Some(4),
                    "update" => Some(5),
                    "stateful" => Some(6),
                    value => decimal::<u8>(value).filter(|number| *number <= 15),
                }
                .ok_or_else(|| format!("invalid flag: {flag}"))?;
            }
            _ => return Err(format!("invalid flag: {flag}")),
        }
    }
    if !query.additions.is_empty() && query.opcode != 5 {
        return Err("+add requires UPDATE".into());
    }
    Ok(query)
}

impl Query {
    pub(crate) fn check_response_tsig(
        &self,
        query: &[u8],
        response: &[u8],
    ) -> Result<bool, String> {
        let Some((name, secret, mode)) = &self.tsig else {
            return Ok(false);
        };
        let request = pharos_proto::TsigRecord::parse(query).map_err(|e| e.to_string())?;
        let record = pharos_proto::TsigRecord::parse(response).map_err(|e| e.to_string())?;
        let expected = match mode {
            TsigCase::BadKey => 17,
            TsigCase::BadSig => 16,
            TsigCase::BadTime => 18,
            TsigCase::Valid => 0,
        };
        if record.error != expected
            || record.owner != request.owner
            || record.algorithm != request.algorithm
            || record.original_id != request.original_id
            || record.fudge != request.fudge
        {
            return Err(format!(
                "unexpected TSIG response fields: error {} expected {expected}",
                record.error
            ));
        }
        if expected == 16 || expected == 17 {
            if !record.mac.is_empty() || !record.other.is_empty() {
                return Err("authentication error has nonempty MAC or other data".into());
            }
        } else {
            if (expected == 18 && record.other.len() != 6)
                || (expected == 0 && !record.other.is_empty())
            {
                return Err("unexpected TSIG other data".into());
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let checked_time = if expected == 18 {
                if record.time_signed != request.time_signed {
                    return Err("BADTIME did not echo Query time".into());
                }
                let mut server_time = [0; 8];
                server_time[2..].copy_from_slice(record.other);
                if now.abs_diff(u64::from_be_bytes(server_time)) > 300 {
                    return Err("BADTIME server time is outside fudge".into());
                }
                request.time_signed
            } else {
                now
            };
            let key = TsigKey::new(name.clone(), TsigAlgorithm::Sha256, secret);
            // RFC 8945 §4.3.1: verify the Response against the Query MAC.
            key.verify(response, checked_time, Some(request.mac), 0)
                .map_err(|e| format!("invalid response signature: {e}"))?;
        }
        Ok(true)
    }
    pub(crate) fn wire(&self) -> Result<Vec<u8>, String> {
        let mut wire = Vec::new();
        let flags = (u16::from(self.opcode) << 11) | if self.recursion { 0x0100 } else { 0 };
        let mut builder =
            MessageBuilder::new(&mut wire, 65535, 0, flags).map_err(|err| err.to_string())?;
        let name = NameRef::parse(self.name.as_wire(), 0).map_err(|err| err.to_string())?;
        if !builder
            .question(name, self.qtype, self.class)
            .map_err(|err| err.to_string())?
        {
            return Err("query exceeds DNS message size".into());
        }
        if let Some(serial) = self.ixfr_serial {
            // RFC 1995 §3: an IXFR Query carries the requester's SOA in Authority.
            let mut soa = [0u8; 22];
            soa[2..6].copy_from_slice(&serial.to_be_bytes());
            if !builder
                .record(Section::Authority, name, Type::SOA, self.class, 0, &soa)
                .map_err(|err| err.to_string())?
            {
                return Err("query exceeds DNS message size".into());
            }
        }
        // RFC 2136 §2.5: additions appear in the Update section using the Zone class.
        for (owner, kind, ttl, data) in &self.additions {
            let owner = NameRef::parse(owner.as_wire(), 0).map_err(|error| error.to_string())?;
            if !builder
                .record(Section::Authority, owner, *kind, self.class, *ttl, data)
                .map_err(|error| error.to_string())?
            {
                return Err("query exceeds DNS message size".into());
            }
        }
        if self.edns {
            // RFC 5001 §2.2: a Query requests NSID with an empty option payload.
            let mut raw_options = Vec::new();
            if self.nsid {
                raw_options.extend_from_slice(&[0, 3, 0, 0]);
            }
            // RFC 6891 §6.1.2: each option is encoded as code, length, and data.
            for (code, data) in &self.options {
                raw_options.extend_from_slice(&code.to_be_bytes());
                raw_options.extend_from_slice(&(data.len() as u16).to_be_bytes());
                raw_options.extend_from_slice(data);
            }
            let options = EdnsOptions::parse(&raw_options).map_err(|err| err.to_string())?;
            let opt = Opt::new(
                self.bufsize,
                0,
                self.edns_version,
                if self.dnssec { 0x8000 } else { 0 },
                options,
            );
            let mut encoded = Vec::new();
            opt.encode(&mut encoded).map_err(|err| err.to_string())?;
            builder
                .reserve(encoded.len())
                .map_err(|err| err.to_string())?;
            builder
                .finish_with_opt(&encoded)
                .map_err(|err| err.to_string())?;
        } else {
            let _ = builder.finish();
        }
        if let Some((name, secret, mode)) = &self.tsig {
            let key = TsigKey::new(name.clone(), TsigAlgorithm::Sha256, secret);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            // RFC 8945 §4.3: sign the complete Query before transmitting it.
            key.sign(
                &mut wire,
                if *mode == TsigCase::BadTime {
                    now.saturating_sub(600)
                } else {
                    now
                },
                300,
                None,
            )
            .map_err(|e| e.to_string())?;
            if *mode == TsigCase::BadSig {
                let mac_len = pharos_proto::TsigRecord::parse(&wire)
                    .map_err(|e| e.to_string())?
                    .mac
                    .len();
                let first_mac_byte = wire.len() - 6 - mac_len;
                wire[first_mac_byte] ^= 1;
            }
        }
        Ok(wire)
    }
}

#[cfg(test)]
mod tests {
    use super::{Transport, parse};
    use pharos_proto::{Class, Message, Opcode, Type};

    #[test]
    fn builds_signed_update_with_authority_record() {
        let query = parse("example.org. SOA IN udp +opcode=UPDATE +add=host.example.org.:A:60:c000020a +tsig=key.:c2VjcmV0").unwrap();
        let wire = query.wire().unwrap();
        let message = Message::parse(&wire).unwrap();
        assert_eq!(message.opcode(), Opcode::UPDATE);
        let record = message.authorities().next().unwrap();
        assert_eq!(record.name.to_string(), "host.example.org.");
        assert_eq!(
            (record.rtype, record.class, record.ttl, record.rdata),
            (Type::A, Class::IN, 60, [192, 0, 2, 10].as_slice())
        );
        assert_eq!(message.additionals().last().unwrap().rtype, Type::TSIG);
        assert!(
            parse("example.org. SOA IN udp +opcode=UPDATE +add=host.example.org.:A:bad:c000020a")
                .is_err()
        );
    }

    #[test]
    fn ixfr_serial_adds_a_signed_authority_soa() {
        let query = parse("example. IXFR IN tcp +ixfr=123 +tsig=key.:c2VjcmV0").unwrap();
        let wire = query.wire().unwrap();
        let message = Message::parse(&wire).unwrap();
        assert_eq!(message.authority_count(), 1);
        assert!(matches!(
            message.authorities().next().unwrap().data(),
            Ok(pharos_proto::Rdata::Soa { serial: 123, .. })
        ));
        assert_eq!(message.additionals().last().unwrap().rtype, Type::TSIG);
        assert!(parse("example. A IN tcp +ixfr=1").is_err());
        assert!(parse("example. IXFR IN tcp +ixfr=x").is_err());
        assert!(parse("example. IXFR IN tcp +ixfr=1 +ixfr=2").is_err());
    }

    #[test]
    fn builds_signed_queries_and_failure_variants() {
        let key = pharos_proto::TsigKey::new(
            "key.".parse().unwrap(),
            pharos_proto::TsigAlgorithm::Sha256,
            b"secret",
        );
        for (flag, expected) in [
            ("+tsig=key.:c2VjcmV0", Ok(())),
            (
                "+tsig=key.:c2VjcmV0:badtime",
                Err(pharos_proto::TsigError::BadTime),
            ),
            (
                "+tsig=key.:c2VjcmV0:badsig",
                Err(pharos_proto::TsigError::BadSig),
            ),
        ] {
            let wire = parse(&format!("example. A IN udp {flag}"))
                .unwrap()
                .wire()
                .unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            assert!(Message::parse(&wire).unwrap().rd(), "{flag}");
            assert_eq!(
                key.verify(&wire, now, None, 0).map(|_| ()),
                expected,
                "{flag}"
            );
        }
    }

    #[test]
    fn response_authentication_rejects_tampering() {
        let query = parse("example. A IN udp +tsig=key.:c2VjcmV0").unwrap();
        let wire = query.wire().unwrap();
        let request_mac = pharos_proto::TsigRecord::parse(&wire).unwrap().mac;
        let key = pharos_proto::TsigKey::new(
            "key.".parse().unwrap(),
            pharos_proto::TsigAlgorithm::Sha256,
            b"secret",
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut response = Vec::new();
        response.extend_from_slice(&[0, 0, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0]);
        key.sign(&mut response, now, 300, Some(request_mac))
            .unwrap();
        assert!(query.check_response_tsig(&wire, &response).is_ok());
        response[3] ^= 1;
        assert!(query.check_response_tsig(&wire, &response).is_err());
    }

    #[test]
    fn builds_queries_with_custom_edns_options() {
        let query = parse("example. A IN udp +ednsoption=65518:61626364").unwrap();
        let wire = query.wire().unwrap();
        let message = Message::parse(&wire).unwrap();
        assert_eq!(
            message.opt().unwrap().options().as_bytes(),
            b"\xff\xee\0\x04abcd"
        );
        for flag in [
            "+ednsoption=65536:00",
            "+ednsoption=1:0",
            "+ednsoption=1:gg",
        ] {
            assert!(
                parse(&format!("example. A IN udp {flag}")).is_err(),
                "{flag}"
            );
        }
    }

    #[test]
    fn builds_plain_query_and_preserves_original_line() {
        let line = "Example.COM A IN udp";
        let query = parse(line).unwrap();
        assert_eq!(query.transport, Transport::Udp);
        assert_eq!(query.to_string(), line);
        let wire = query.wire().unwrap();
        let message = Message::parse(&wire).unwrap();
        assert_eq!(message.question_count(), 1);
        assert!(message.rd());
        assert_eq!(message.opcode(), Opcode::QUERY);
        assert!(message.opt().is_none());
        let question = message.questions().next().unwrap();
        assert_eq!(question.name.to_string(), "Example.COM.");
        assert_eq!(question.qtype, Type::A);
        assert_eq!(question.qclass, Class::IN);
    }

    #[test]
    fn builds_edns_query_with_flags_and_numeric_codes() {
        let query = parse(
            ". TYPE65400 CLASS65000 tcp +dnssec +bufsize=4096 +norec +opcode=STATUS +ednsversion=1",
        )
        .unwrap();
        assert_eq!(query.transport, Transport::Tcp);
        let wire = query.wire().unwrap();
        let message = Message::parse(&wire).unwrap();
        assert!(!message.rd());
        assert_eq!(message.opcode(), Opcode::STATUS);
        let question = message.questions().next().unwrap();
        assert_eq!(question.qtype, Type(65400));
        assert_eq!(question.qclass, Class(65000));
        let opt = message.opt().unwrap();
        assert_eq!(opt.udp_payload_size(), 4096);
        assert_eq!(opt.version(), 1);
        assert!(opt.dnssec_ok());
    }

    #[test]
    fn supports_common_names_and_numeric_opcodes() {
        for (record, expected) in [
            ("AAAA", Type::AAAA),
            ("MX", Type::MX),
            ("TXT", Type::TXT),
            ("HTTPS", Type::HTTPS),
            ("ANY", Type::ANY),
        ] {
            let query = parse(&format!("example. {record} CH UDP +opcode=15")).unwrap();
            let wire = query.wire().unwrap();
            let message = Message::parse(&wire).unwrap();
            assert_eq!(message.opcode(), Opcode(15));
            let question = message.questions().next().unwrap();
            assert_eq!(question.qtype, expected);
            assert_eq!(question.qclass, Class::CH);
        }
    }

    #[test]
    fn individual_edns_flags_create_opt() {
        for flag in ["+dnssec", "+nsid", "+bufsize=512", "+ednsversion=0"] {
            let wire = parse(&format!("example. A IN udp {flag}"))
                .unwrap()
                .wire()
                .unwrap();
            assert!(Message::parse(&wire).unwrap().opt().is_some(), "{flag}");
        }
    }

    #[test]
    fn nsid_flag_adds_empty_nsid_option() {
        let wire = parse("example. A IN udp +nsid").unwrap().wire().unwrap();
        let message = Message::parse(&wire).unwrap();
        assert_eq!(
            message.opt().unwrap().options().iter().collect::<Vec<_>>(),
            [pharos_proto::EdnsOption::Nsid(&[])]
        );
    }

    #[test]
    fn accepts_numeric_boundaries_and_defaults() {
        let query = parse(". type65535 class0 tcp +ednsversion=255 +opcode=0").unwrap();
        let wire = query.wire().unwrap();
        let message = Message::parse(&wire).unwrap();
        let opt = message.opt().unwrap();
        assert_eq!(opt.udp_payload_size(), 1232);
        assert_eq!(opt.version(), 255);
        assert!(!opt.dnssec_ok());
        let question = message.questions().next().unwrap();
        assert_eq!(question.qtype, Type(65535));
        assert_eq!(question.qclass, Class(0));
    }

    #[test]
    fn rejects_invalid_queries() {
        for line in [
            "",
            "example. A IN",
            "a..b A IN udp",
            "example. WAT IN udp",
            "example. A WAT udp",
            "example. TYPE65536 IN udp",
            "example. TYPE+1 IN udp",
            "example. A CLASS65536 udp",
            "example. A IN sctp",
            "example. A IN udp +unknown",
            "example. A IN udp +bufsize=",
            "example. A IN udp +bufsize=65536",
            "example. A IN udp +ednsversion=256",
            "example. A IN udp +ednsversion=-1",
            "example. A IN udp +opcode=16",
            "example. A IN udp +opcode=NOPE",
            "example. A IN udp +dnssec=1",
            "example. A IN udp +norec extra",
            "example. A IN udp +tsig=key.",
            "example. A IN udp +tsig=key.:c2VjcmV0:unknown",
            "example. A IN udp +tsig=key.:c2VjcmV0:valid:extra",
        ] {
            assert!(parse(line).is_err(), "accepted {line:?}");
        }
    }
}

use std::fmt;

use pharos_proto::{Class, EdnsOptions, MessageBuilder, Name, NameRef, Opt, Type};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
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
    bufsize: u16,
    edns_version: u8,
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
        bufsize: 1232,
        edns_version: 0,
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
    Ok(query)
}

impl Query {
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
        if self.edns {
            // RFC 5001 §2.2: a Query requests NSID with an empty option payload.
            let options = EdnsOptions::parse(if self.nsid { &[0, 3, 0, 0] } else { &[] })
                .map_err(|err| err.to_string())?;
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
        Ok(wire)
    }
}

#[cfg(test)]
mod tests {
    use super::{Transport, parse};
    use pharos_proto::{Class, Message, Opcode, Type};

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
        ] {
            assert!(parse(line).is_err(), "accepted {line:?}");
        }
    }
}

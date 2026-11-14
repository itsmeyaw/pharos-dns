#![forbid(unsafe_code)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use pharos_proto::{EdnsOptions, Message, MessageMut, Rdata, Type};

fuzz_target!(|wire: &[u8]| {
    for rtype in [
        Type::A,
        Type::AAAA,
        Type::NS,
        Type::CNAME,
        Type::PTR,
        Type::MX,
        Type::SOA,
        Type::TXT,
        Type::HINFO,
        Type::CAA,
        Type::URI,
        Type::SRV,
        Type::NAPTR,
        Type::DS,
        Type::CDS,
        Type::DNSKEY,
        Type::CDNSKEY,
        Type::RRSIG,
        Type::NSEC,
        Type::NSEC3,
        Type::NSEC3PARAM,
        Type::SVCB,
        Type::HTTPS,
        Type::TLSA,
        Type::SSHFP,
        Type::ZONEMD,
        Type::TSIG,
        Type(731),
    ] {
        if let Ok(data) = Rdata::parse(rtype, wire) {
            let _ = data.to_string();
        }
    }
    // RFC 6891 §6.1.2: EDNS options encode code, length, and opaque data as big-endian octets.
    if let Ok(options) = EdnsOptions::parse(wire) {
        assert_eq!(options.as_bytes(), wire);
        assert!(options.iter().eq(options.iter()));
        let mut raw = wire;
        for option in options.iter() {
            assert_eq!(option.code(), u16::from_be_bytes([raw[0], raw[1]]));
            let len = usize::from(u16::from_be_bytes([raw[2], raw[3]]));
            raw = &raw[4 + len..];
        }
        assert!(raw.is_empty());
    }
    if let Ok(message) = Message::parse(wire) {
        assert_eq!(
            message.questions().count(),
            usize::from(message.question_count())
        );
        for record in message
            .answers()
            .chain(message.authorities())
            .chain(message.additionals())
        {
            assert_eq!(
                &wire[record.rdata_offset..record.rdata_offset + record.rdata.len()],
                record.rdata
            );
            let _ = record.name.to_name();
            if let Ok(data) = record.data() {
                let _ = data.to_string();
            }
            if record.rtype == Type::TSIG {
                if let Ok(display) = record.display_tsig() {
                    let _ = display.to_string();
                }
            }
        }
        if let Some(opt) = message.opt() {
            let options = opt.options();
            assert!(
                options
                    .iter()
                    .eq(EdnsOptions::parse(options.as_bytes()).unwrap().iter())
            );
        }
        let mut copy = wire.to_vec();
        MessageMut::parse(&mut copy)
            .unwrap()
            .rewrite_ttls(|ttl| ttl.saturating_sub(1));
    }
});

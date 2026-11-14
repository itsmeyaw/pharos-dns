#![forbid(unsafe_code)]
#![no_main]

use domain::base::{Message as DomainMessage, opt::UnknownOptData};
use libfuzzer_sys::fuzz_target;
use pharos_proto::{EdnsOptions, Message, MessageError, NameError};

fuzz_target!(|wire: &[u8]| {
    let pharos = Message::parse(wire);
    let Ok(domain) = DomainMessage::from_octets(wire) else {
        assert!(
            pharos.is_err(),
            "domain rejected a Message accepted by Pharos"
        );
        return;
    };
    let Ok((mut questions, answers, authorities, additionals)) = domain.sections() else {
        assert!(
            pharos.is_err(),
            "domain rejected a Message accepted by Pharos"
        );
        return;
    };
    if questions.clone().any(|item| item.is_err())
        || answers
            .clone()
            .chain(authorities.clone())
            .chain(additionals.clone())
            .any(|item| item.is_err())
    {
        assert!(
            pharos.is_err(),
            "domain rejected a Message accepted by Pharos"
        );
        return;
    }
    // Domain validates record boundaries but not OPT placement, owner, or payloads.
    // RFC 6891 §6.1.1: OPT appears only once, only in Additional, and has the root owner name.
    let mut opt_count = 0;
    let mut invalid_opt = false;
    for (additional, mut records) in [
        (false, answers.clone()),
        (false, authorities.clone()),
        (true, additionals.clone()),
    ] {
        while let Some(record) = records.next() {
            let record = record.unwrap();
            if record.rtype().to_int() == 41 {
                opt_count += 1;
                let end = records.pos();
                let data = &wire[end - usize::from(record.rdlen())..end];
                invalid_opt |= !additional
                    || opt_count > 1
                    || record
                        .owner()
                        .iter()
                        .any(|label| !label.as_slice().is_empty())
                    || EdnsOptions::parse(data).is_err();
            }
        }
    }
    // Domain accepts forward/overlapping pointers and longer pointer chains.
    // RFC 1035 §4.1.4: Compressed names use pointers to prior occurrences in the DNS message.
    let pharos = match pharos {
        Err(MessageError::Name(NameError::PointerNotBackwards | NameError::PointerLimit)) => return,
        Err(MessageError::InvalidOpt) if invalid_opt => return,
        result => result.expect("domain accepted a Message rejected by Pharos"),
    };
    assert!(!invalid_opt, "Pharos accepted an invalid OPT");
    // RFC 1035 §4.1.1: DNS headers carry the identifier, flags, and section counts.
    assert_eq!(pharos.id(), domain.header().id());
    assert_eq!(
        pharos.flags().to_be_bytes(),
        domain.header().as_slice()[2..4]
    );
    // RFC 6891 §6.1.3: The OPT TTL carries the extended RCODE, EDNS version, and flags.
    match (pharos.opt(), domain.opt()) {
        (Some(ours), Some(theirs)) => {
            assert_eq!(ours.udp_payload_size(), theirs.udp_payload_size());
            assert_eq!(ours.extended_rcode(), theirs.rcode(domain.header()).ext());
            assert_eq!(ours.version(), theirs.version());
            assert_eq!(ours.flags(), theirs.as_record().ttl().as_secs() as u16);
            assert_eq!(ours.dnssec_ok(), theirs.dnssec_ok());
            let options = ours.options();
            let mut raw = options.as_bytes();
            let mut ours = options.iter();
            for option in theirs.opt().iter::<UnknownOptData<&[u8]>>() {
                let option = option.unwrap();
                let data = option.as_slice();
                assert_eq!(ours.next().unwrap().code(), option.code().to_int());
                assert_eq!(&raw[..2], &option.code().to_int().to_be_bytes());
                assert_eq!(
                    &raw[2..4],
                    &u16::try_from(data.len()).unwrap().to_be_bytes()
                );
                assert_eq!(&raw[4..4 + data.len()], data);
                raw = &raw[4 + data.len()..];
            }
            assert!(ours.next().is_none());
            assert!(raw.is_empty());
        }
        (None, None) => {}
        _ => panic!("OPT presence differs"),
    }
    assert_eq!(
        (
            pharos.question_count(),
            pharos.answer_count(),
            pharos.authority_count(),
            pharos.additional_count()
        ),
        (
            domain.header_counts().qdcount(),
            domain.header_counts().ancount(),
            domain.header_counts().nscount(),
            domain.header_counts().arcount()
        )
    );
    // RFC 1035 §4.1.2: Each question contains QNAME, QTYPE, and QCLASS.
    let mut offset = 12;
    for question in pharos.questions() {
        assert_eq!(questions.pos(), offset);
        let other = questions.next().unwrap().unwrap();
        assert!(
            question.name.labels().eq(other
                .qname()
                .iter()
                .filter(|label| !label.as_slice().is_empty())
                .map(|label| label.as_slice()))
        );
        assert_eq!(
            (question.qtype.0, question.qclass.0),
            (other.qtype().to_int(), other.qclass().to_int())
        );
        offset += question.name.wire_len() + 4;
        assert_eq!(questions.pos(), offset);
    }
    // RFC 1035 §4.1.3: Each RR carries owner, type, class, TTL, RDLENGTH, and bounded RDATA.
    for (mut theirs, ours) in [
        (answers, pharos.answers()),
        (authorities, pharos.authorities()),
        (additionals, pharos.additionals()),
    ] {
        for record in ours {
            assert_eq!(theirs.pos(), offset);
            let other = theirs.next().unwrap().unwrap();
            assert!(
                record.name.labels().eq(other
                    .owner()
                    .iter()
                    .filter(|label| !label.as_slice().is_empty())
                    .map(|label| label.as_slice()))
            );
            assert_eq!(
                (record.rtype.0, record.class.0, record.ttl),
                (
                    other.rtype().to_int(),
                    other.class().to_int(),
                    other.ttl().as_secs()
                )
            );
            offset = record.rdata_offset + record.rdata.len();
            assert_eq!(theirs.pos(), offset);
            assert_eq!(usize::from(other.rdlen()), record.rdata.len());
            assert_eq!(
                &wire[offset - usize::from(other.rdlen())..offset],
                record.rdata
            );
        }
    }
});

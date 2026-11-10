#![forbid(unsafe_code)]
#![no_main]

use domain::base::Message as DomainMessage;
use libfuzzer_sys::fuzz_target;
use pharos_proto::{Message, MessageError, NameError};

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
    // Domain accepts forward/overlapping pointers and longer pointer chains.
    let pharos = match pharos {
        Err(MessageError::Name(NameError::PointerNotBackwards | NameError::PointerLimit)) => return,
        result => result.expect("domain accepted a Message rejected by Pharos"),
    };
    assert_eq!(pharos.id(), domain.header().id());
    assert_eq!(
        pharos.flags().to_be_bytes(),
        domain.header().as_slice()[2..4]
    );
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

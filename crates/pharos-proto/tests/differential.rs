#![forbid(unsafe_code)]

use domain::base::{Message as DomainMessage, opt::UnknownOptData};
use domain::{base::name::ParsedName, rdata::AllRecordData};
use hickory_proto::{
    op::{Header, Message as HickoryMessage, Query},
    rr::{Name as HickoryName, Record as HickoryRecord},
    serialize::binary::{BinDecodable, BinDecoder},
};
use pharos_proto::{
    Class, EdnsOptions, Message, MessageBuilder, MessageError, Name, NameRef, Section, Type,
};
use proptest::prelude::*;

#[derive(Debug, PartialEq, Eq)]
struct Question {
    start: usize,
    end: usize,
    name: Vec<Vec<u8>>,
    kind: u16,
    class: u16,
}

#[derive(Debug, PartialEq, Eq)]
struct Record {
    start: usize,
    end: usize,
    name: Vec<Vec<u8>>,
    kind: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct Parsed {
    header: [u8; 12],
    questions: Vec<Question>,
    sections: [Vec<Record>; 3],
}

// Hickory rejects this overlapping pointer; domain accepts it. Pharos must reject it.
const OVERLAPPING_POINTER: &[u8] = &[
    0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 1, 0, 1, 1, b'9', 0, 0, 1, 0, 1, 0xc0, 12, 0xfd, 0xe8, 0, 1,
    0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0xfd, 0xe8, 0, 1, 0, 0, 0, 0, 0, 9, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 5, 0xfd, 0xe8, 0, 1, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn pharos(wire: &[u8]) -> Result<Parsed, String> {
    let message = Message::parse(wire).map_err(|e| e.to_string())?;
    let mut header = [0; 12];
    for (index, value) in [
        message.id(),
        message.flags(),
        message.question_count(),
        message.answer_count(),
        message.authority_count(),
        message.additional_count(),
    ]
    .into_iter()
    .enumerate()
    {
        header[index * 2..index * 2 + 2].copy_from_slice(&value.to_be_bytes());
    }
    let mut offset = 12;
    let questions = message
        .questions()
        .map(|q| {
            let start = offset;
            offset += q.name.wire_len() + 4;
            Question {
                start,
                end: offset,
                name: q.name.labels().map(<[u8]>::to_vec).collect(),
                kind: q.qtype.0,
                class: q.qclass.0,
            }
        })
        .collect();
    let mut sections = [Vec::new(), Vec::new(), Vec::new()];
    for (output, records) in sections.iter_mut().zip([
        message.answers(),
        message.authorities(),
        message.additionals(),
    ]) {
        for record in records {
            let start = offset;
            offset = record.rdata_offset + record.rdata.len();
            output.push(Record {
                start,
                end: offset,
                name: record.name.labels().map(<[u8]>::to_vec).collect(),
                kind: record.rtype.0,
                class: record.class.0,
                ttl: record.ttl,
                rdata: record.rdata.to_vec(),
            });
        }
    }
    Ok(Parsed {
        header,
        questions,
        sections,
    })
}

fn domain(wire: &[u8]) -> Result<Parsed, String> {
    let message = DomainMessage::from_octets(wire).map_err(|e| e.to_string())?;
    let mut questions = Vec::new();
    let mut question_section = message.question();
    loop {
        let start = question_section.pos();
        let Some(question) = question_section.next() else {
            break;
        };
        let question = question.map_err(|e| e.to_string())?;
        questions.push(Question {
            start,
            end: question_section.pos(),
            name: question
                .qname()
                .iter()
                .filter(|l| !l.as_slice().is_empty())
                .map(|l| l.as_slice().to_vec())
                .collect(),
            kind: question.qtype().to_int(),
            class: question.qclass().to_int(),
        });
    }
    let mut section = question_section.answer().map_err(|e| e.to_string())?;
    let mut sections = [Vec::new(), Vec::new(), Vec::new()];
    for (index, output) in sections.iter_mut().enumerate() {
        loop {
            let start = section.pos();
            let Some(record) = section.next() else { break };
            let record = record.map_err(|e| e.to_string())?;
            let end = section.pos();
            let data_start = end - usize::from(record.rdlen());
            output.push(Record {
                start,
                end,
                name: record
                    .owner()
                    .iter()
                    .filter(|l| !l.as_slice().is_empty())
                    .map(|l| l.as_slice().to_vec())
                    .collect(),
                kind: record.rtype().to_int(),
                class: record.class().to_int(),
                ttl: record.ttl().as_secs(),
                rdata: wire[data_start..end].to_vec(),
            });
        }
        if index != 2 {
            section = section.next_section().map_err(|e| e.to_string())?.unwrap();
        }
    }
    Ok(Parsed {
        header: message.header_section().as_slice().try_into().unwrap(),
        questions,
        sections,
    })
}

fn hickory(wire: &[u8]) -> Result<Parsed, String> {
    // Full Message parsing checks opcode, EDNS and typed RDATA, not just boundaries.
    HickoryMessage::from_vec(wire).map_err(|e| e.to_string())?;
    hickory_fields(wire)
}

fn hickory_fields(wire: &[u8]) -> Result<Parsed, String> {
    let mut decoder = BinDecoder::new(wire);
    let header = Header::read(&mut decoder).map_err(|e| e.to_string())?;
    let mut questions = Vec::new();
    for _ in 0..header.counts.queries {
        let start = decoder.index();
        let q = Query::read(&mut decoder).map_err(|e| e.to_string())?;
        questions.push(Question {
            start,
            end: decoder.index(),
            name: q.name().iter().map(<[u8]>::to_vec).collect(),
            kind: q.query_type().into(),
            class: q.query_class().into(),
        });
    }
    let mut sections = [Vec::new(), Vec::new(), Vec::new()];
    for (output, count) in sections.iter_mut().zip([
        header.counts.answers,
        header.counts.authorities,
        header.counts.additionals,
    ]) {
        for _ in 0..count {
            let start = decoder.index();
            // Use a second decoder to locate the original RDATA, not re-encoded data.
            let mut raw = decoder.clone(u16::try_from(start).map_err(|e| e.to_string())?);
            HickoryName::read(&mut raw).map_err(|e| e.to_string())?;
            let kind = raw.read_u16().map_err(|e| e.to_string())?.unverified();
            let class = raw.read_u16().map_err(|e| e.to_string())?.unverified();
            let ttl = raw.read_u32().map_err(|e| e.to_string())?.unverified();
            let len = usize::from(raw.read_u16().map_err(|e| e.to_string())?.unverified());
            let data_start = raw.index();
            let rdata = raw
                .read_slice(len)
                .map_err(|e| e.to_string())?
                .unverified()
                .to_vec();
            let record = HickoryRecord::read(&mut decoder).map_err(|e| e.to_string())?;
            let end = decoder.index();
            if end != data_start + len {
                return Err("Hickory record consumed a different RDLENGTH".into());
            }
            if u16::from(record.record_type()) != kind
                || record.ttl != ttl
                // Hickory normalizes the OPT UDP payload size to at least 512.
                || (kind != 41 && u16::from(record.dns_class) != class)
            {
                return Err("Hickory record fields disagree with its wire decoder".into());
            }
            output.push(Record {
                start,
                end,
                name: record.name.iter().map(<[u8]>::to_vec).collect(),
                kind,
                class,
                ttl,
                rdata,
            });
        }
    }
    let mut parsed_header = [0; 12];
    let flags = (u16::from(header.message_type == hickory_proto::op::MessageType::Response) << 15)
        | (u16::from(u8::from(header.op_code)) << 11)
        | (u16::from(header.authoritative) << 10) | (u16::from(header.truncation) << 9)
        | (u16::from(header.recursion_desired) << 8) | (u16::from(header.recursion_available) << 7)
        | (u16::from(wire[3] & 0x40)) // Hickory does not retain the reserved Z bit.
        | (u16::from(header.authentic_data) << 5) | (u16::from(header.checking_disabled) << 4)
        | u16::from(header.response_code.low());
    for (index, value) in [
        header.id,
        flags,
        header.counts.queries,
        header.counts.answers,
        header.counts.authorities,
        header.counts.additionals,
    ]
    .into_iter()
    .enumerate()
    {
        parsed_header[index * 2..index * 2 + 2].copy_from_slice(&value.to_be_bytes());
    }
    Ok(Parsed {
        header: parsed_header,
        questions,
        sections,
    })
}

fn compare(wire: &[u8]) -> Result<(), String> {
    let actual = pharos(wire);
    let domain = domain(wire);
    let hickory = hickory(wire);
    match (&actual, &domain, &hickory) {
        (Ok(a), Ok(b), Ok(c)) if a == b && a == c => Ok(()),
        (Err(_), Err(_), Err(_)) => Ok(()),
        // Domain accepts a pointer whose target overlaps that pointer.
        (Err(error), Ok(_), Err(hickory_error))
            if error == "invalid name: compression pointer is not backwards"
                && hickory_error.starts_with("overlapping labels") =>
        {
            Ok(())
        }
        // Hickory enforces UPDATE semantics; Pharos and domain parse raw RDATA.
        (Ok(a), Ok(b), Err(error))
            if a == b
                && error == "unexpected record with length 0 in non-update message"
                && a.header[2] & 0x78 != 0x28
                && a.sections
                    .iter()
                    .flatten()
                    .any(|record| record.kind != 41 && record.rdata.is_empty())
                && hickory_fields(wire).as_ref() == Ok(a) =>
        {
            Ok(())
        }
        _ => Err(format!(
            "wire={wire:02x?}\npharos={actual:?}\ndomain={domain:?}\nhickory={hickory:?}"
        )),
    }
}

fn built_message(labels: &[String], id: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
    let text = if labels.is_empty() {
        ".".to_owned()
    } else {
        format!("{}.", labels.join("."))
    };
    let name: Name = text.parse().unwrap();
    let name = NameRef::parse(name.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 4096, id, 0x8180).unwrap();
    assert!(builder.question(name, Type(1), Class(1)).unwrap());
    assert!(builder.question(name, Type(28), Class(1)).unwrap());
    for section in [Section::Answer, Section::Authority, Section::Additional] {
        assert!(
            builder
                .record(section, name, Type(65000), Class(1), ttl, data)
                .unwrap()
        );
        assert!(
            builder
                .record(section, name, Type(1), Class(1), ttl, &[192, 0, 2, 1])
                .unwrap()
        );
        assert!(
            builder
                .record(section, name, Type(28), Class(1), ttl, &[0; 16])
                .unwrap()
        );
    }
    let _ = builder.finish();
    wire
}

fn opt_message(size: u16, ttl: u32, options: &[u8]) -> Vec<u8> {
    let mut wire = vec![0; 12];
    wire[11] = 1;
    wire.extend_from_slice(&[0, 0, 41]);
    wire.extend_from_slice(&size.to_be_bytes());
    wire.extend_from_slice(&ttl.to_be_bytes());
    wire.extend_from_slice(&u16::try_from(options.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(options);
    wire
}

fn compare_opt(wire: &[u8]) {
    let message = Message::parse(wire).unwrap();
    let domain = DomainMessage::from_octets(wire).unwrap();
    match (message.opt(), domain.opt()) {
        (None, None) => {}
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
        _ => panic!("OPT presence differs: {wire:02x?}"),
    }
}

proptest! {
    #[test]
    fn generated_opt_fields_and_raw_options(
        size in any::<u16>(), ttl in any::<u32>(),
        options in prop::collection::vec((any::<u16>(), prop::collection::vec(any::<u8>(), 0..20)), 0..8),
    ) {
        let mut raw = Vec::new();
        for (code, data) in options {
            // Use unknown codes: domain validates framing, not known option payloads.
            let code = 65000 + code % 500;
            raw.extend_from_slice(&code.to_be_bytes());
            raw.extend_from_slice(&(data.len() as u16).to_be_bytes());
            raw.extend_from_slice(&data);
        }
        compare_opt(&opt_message(size, ttl, &raw));
    }

    #[test]
    fn generated_messages_and_truncations(
        labels in prop::collection::vec("[a-zA-Z0-9]{1,10}", 0..5),
        id in any::<u16>(), ttl in any::<u32>(),
        data in prop::collection::vec(any::<u8>(), 1..30), cut in any::<usize>(),
    ) {
        let wire = built_message(&labels, id, ttl, &data);
        prop_assert!(compare(&wire).is_ok(), "{}", compare(&wire).unwrap_err());
        let truncated = &wire[..cut % wire.len()];
        prop_assert!(compare(truncated).is_ok(), "{}", compare(truncated).unwrap_err());
    }

    #[test]
    fn mutated_messages(
        labels in prop::collection::vec("[a-z0-9]{1,8}", 1..4),
        id in any::<u16>(), ttl in any::<u32>(),
        data in prop::collection::vec(any::<u8>(), 1..20),
        mutation in 0u8..6, value in any::<u8>(),
    ) {
        let mut wire = built_message(&labels, id, ttl, &data);
        let message = Message::parse(&wire).unwrap();
        let answer = message.answers().next().unwrap();
        let rdata_offset = answer.rdata_offset;
        let second_question = 12 + message.questions().next().unwrap().name.wire_len() + 4;
        match mutation {
            0 => wire[0] = value,
            1 => wire[12] = 0x40, // reserved label type
            2 => wire[5] = 0xff, // impossible Question count
            3 => wire[rdata_offset - 2..rdata_offset].copy_from_slice(&u16::MAX.to_be_bytes()),
            4 => wire[rdata_offset] = value,
            _ => wire[second_question + 1] = value,
        }
        let result = compare(&wire);
        prop_assert!(result.is_ok(), "{}", result.unwrap_err());
    }
}

#[test]
fn opt_reference_fields_and_options() {
    compare_opt(&[0; 12]);
    compare_opt(&opt_message(0, 0x7f02_c055, &[]));
    compare_opt(&opt_message(
        1232,
        0x0100_8055,
        &[
            0, 3, 0, 2, 0xaa, 0xbb, // NSID
            0, 10, 0, 0, // empty cookie
            0, 11, 0, 2, 0, 42, // TCP keepalive
            0, 12, 0, 2, 0, 0, // padding
            0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2, // client subnet
            0, 15, 0, 3, 0, 1, b'x', // EDE
            0xfd, 0xe8, 0, 1, 0xff, // unknown
            0xfd, 0xe8, 0, 0, // duplicate, empty unknown
        ],
    ));
}

#[test]
fn domain_only_checks_opt_framing_not_payload_or_placement() {
    for (options, domain_accepts) in [
        (&[0][..], false),
        (&[0, 3, 0][..], false),
        (&[0, 3, 0, 2, 1][..], false),
        (&[0, 15, 0, 1, 0][..], true),
        (&[0, 11, 0, 1, 0][..], true),
        (&[0, 8, 0, 1, 0][..], true),
    ] {
        let wire = opt_message(512, 0, options);
        assert_eq!(Message::parse(&wire).unwrap_err(), MessageError::InvalidOpt);
        assert!(EdnsOptions::parse(options).is_err());
        assert_eq!(
            DomainMessage::from_octets(&wire).unwrap().opt().is_some(),
            domain_accepts
        );
    }
    let valid = opt_message(512, 0, &[]);
    let mut misplaced = valid.clone();
    misplaced[7] = 1;
    misplaced[11] = 0;
    let mut duplicate = valid.clone();
    duplicate[11] = 2;
    duplicate.extend_from_slice(&valid[12..]);
    let mut non_root = valid.clone();
    non_root.splice(12..13, [1, b'x', 0]);
    for wire in [misplaced, duplicate, non_root] {
        assert_eq!(Message::parse(&wire).unwrap_err(), MessageError::InvalidOpt);
        assert!(domain(&wire).is_ok());
    }
}

#[test]
fn seed_corpus() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "bin") {
            names.push(path.file_name().unwrap().to_owned());
            let wire = std::fs::read(&path).unwrap();
            assert!(pharos(&wire).is_ok(), "{}", path.display());
            assert!(domain(&wire).is_ok(), "{}", path.display());
            assert!(hickory(&wire).is_ok(), "{}", path.display());
            assert!(
                compare(&wire).is_ok(),
                "{}: {}",
                path.display(),
                compare(&wire).unwrap_err()
            );
        }
    }
    for name in [
        "coredns-doh-query.bin",
        "miekg-a-query.bin",
        "miekg-dynamic-update.bin",
        "miekg-edns-esu.bin",
        "miekg-servfail-response.bin",
        "miekg-soa-response.bin",
    ] {
        assert!(
            names.iter().any(|entry| entry == name),
            "missing seed Message {name}"
        );
    }
}

#[test]
fn hickory_empty_rdata_disagreement_is_narrow() {
    let wire = built_message(&[], 0, 0, &[]);
    assert!(hickory(&wire).unwrap_err().contains("length 0"));
    assert!(compare(&wire).is_ok());
    let valid = built_message(&[], 0, 0, &[42]);
    assert!(hickory(&valid).is_ok());
    assert!(compare(&valid).is_ok());

    let name: Name = ".".parse().unwrap();
    let name = NameRef::parse(name.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0x8180).unwrap();
    assert!(
        builder
            .record(Section::Answer, name, Type(1), Class(1), 0, &[1, 2, 3])
            .unwrap()
    );
    let _ = builder.finish();
    assert!(pharos(&wire).is_ok());
    assert!(domain(&wire).is_ok());
    assert!(hickory(&wire).is_err());
    assert!(
        compare(&wire).is_err(),
        "malformed A RDATA must not be allow-listed"
    );
}

#[test]
fn overlapping_compression_pointer_is_rejected() {
    let result = compare(OVERLAPPING_POINTER);
    assert!(result.is_ok(), "{}", result.unwrap_err());
}

#[test]
fn forward_compression_pointer_is_rejected() {
    let wire = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 18, 0, 1, 0, 1, 0];
    let result = compare(&wire);
    assert!(result.is_ok(), "{}", result.unwrap_err());
}

#[test]
fn supported_typed_rdata_agrees_with_domain() {
    let owner: Name = "example.com.".parse().unwrap();
    let owner = NameRef::parse(owner.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 4096, 0, 0).unwrap();
    builder.question(owner, Type::A, Class::IN).unwrap();
    for (rtype, bytes) in [(Type::A, vec![192, 0, 2, 1]), (Type::AAAA, vec![0; 16])] {
        builder
            .record(Section::Answer, owner, rtype, Class::IN, 0, &bytes)
            .unwrap();
    }
    for rtype in [Type::NS, Type::CNAME, Type::PTR] {
        builder
            .record_with(Section::Answer, owner, rtype, Class::IN, 0, |w| {
                w.write_name(owner)
            })
            .unwrap();
    }
    builder
        .record_with(Section::Answer, owner, Type::MX, Class::IN, 0, |w| {
            w.write_bytes(&10u16.to_be_bytes())?;
            w.write_name(owner)
        })
        .unwrap();
    builder
        .record_with(Section::Answer, owner, Type::SOA, Class::IN, 0, |w| {
            w.write_name(owner)?;
            w.write_name(owner)?;
            for n in [1u32, 2, 3, 4, 5] {
                w.write_bytes(&n.to_be_bytes())?;
            }
            Ok(())
        })
        .unwrap();
    let _ = builder.finish();
    let pharos = Message::parse(&wire).unwrap();
    let domain = DomainMessage::from_octets(wire.as_slice()).unwrap();
    let domain_answers = domain.question().answer().unwrap().collect::<Vec<_>>();
    assert_eq!(domain_answers.len(), usize::from(pharos.answer_count()));
    // Domain omits the trailing root dot in ParsedName's Display.
    macro_rules! compare_name {
        ($a:expr, $b:expr) => {
            assert_eq!(
                $a.labels().map(<[u8]>::to_vec).collect::<Vec<_>>(),
                $b.iter()
                    .filter(|l| !l.as_slice().is_empty())
                    .map(|l| l.as_slice().to_vec())
                    .collect::<Vec<_>>()
            )
        };
    }
    for (actual, expected) in pharos.answers().zip(domain_answers) {
        let actual = actual.data().unwrap();
        let expected = expected
            .unwrap()
            .to_any_record::<AllRecordData<_, ParsedName<_>>>()
            .unwrap()
            .into_data();
        match (actual, expected) {
            (pharos_proto::Rdata::A(a), AllRecordData::A(b)) => assert_eq!(a, b.addr()),
            (pharos_proto::Rdata::Aaaa(a), AllRecordData::Aaaa(b)) => assert_eq!(a, b.addr()),
            (pharos_proto::Rdata::Ns(a), AllRecordData::Ns(b)) => {
                compare_name!(a, b.nsdname())
            }
            (pharos_proto::Rdata::Cname(a), AllRecordData::Cname(b)) => {
                compare_name!(a, b.cname())
            }
            (pharos_proto::Rdata::Ptr(a), AllRecordData::Ptr(b)) => {
                compare_name!(a, b.ptrdname())
            }
            (
                pharos_proto::Rdata::Mx {
                    preference,
                    exchange,
                },
                AllRecordData::Mx(b),
            ) => {
                assert_eq!(preference, b.preference());
                compare_name!(exchange, b.exchange());
            }
            (
                pharos_proto::Rdata::Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                },
                AllRecordData::Soa(b),
            ) => {
                compare_name!(mname, b.mname());
                compare_name!(rname, b.rname());
                assert_eq!(
                    (serial, refresh, retry, expire, minimum),
                    (
                        b.serial().into_int(),
                        b.refresh().as_secs(),
                        b.retry().as_secs(),
                        b.expire().as_secs(),
                        b.minimum().as_secs()
                    )
                );
            }
            pair => panic!("typed RDATA mismatch: {pair:?}"),
        }
    }
}

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
    fn generated_unknown_rdata_agrees_with_domain(
        number in prop_oneof![Just(0u16), Just(11u16), Just(731u16), Just(62347u16), 65000u16..=u16::MAX],
        bytes in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let root: Name = ".".parse().unwrap();
        let root = NameRef::parse(root.as_wire(), 0).unwrap();
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        assert!(builder.record(Section::Answer, root, Type(number), Class::IN, 0, &bytes).unwrap());
        let _ = builder.finish();
        let ours = Message::parse(&wire).unwrap().answers().next().unwrap().data().unwrap();
        let domain = DomainMessage::from_octets(wire.as_slice()).unwrap();
        let theirs = domain.question().answer().unwrap().next().unwrap().unwrap()
            .to_any_record::<AllRecordData<_, ParsedName<_>>>().unwrap().into_data();
        match (ours, theirs) {
            (pharos_proto::Rdata::Unknown(rtype, data), AllRecordData::Unknown(b)) => {
                prop_assert_eq!(rtype.0, number);
                prop_assert_eq!(rtype.0, b.rtype().to_int());
                prop_assert_eq!(data, *b.data());
                prop_assert_eq!(data, bytes.as_slice());
            }
            pair => prop_assert!(false, "unknown RDATA mismatch: {pair:?}"),
        }
    }

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
    for (rtype, bytes) in [
        (Type::A, vec![192, 0, 2, 1]),
        (Type::AAAA, vec![0; 16]),
        (Type::TXT, b"\x03abc\x00\x02\x00\xff".to_vec()),
        (Type::HINFO, b"\x03CPU\x02OS".to_vec()),
        (Type::CAA, b"\x80\x05issueexample.org".to_vec()),
        (Type::URI, b"\x00\x0a\x00\x01https://example.org/".to_vec()),
        (Type::DS, vec![0x12, 0x34, 8, 2, 0xab, 0xcd]),
        (Type::CDS, vec![0x12, 0x34, 8, 2, 0xab, 0xcd]),
        (Type::DNSKEY, vec![1, 0, 3, 8, 1, 2, 3]),
        (Type::CDNSKEY, vec![1, 0, 3, 8, 1, 2, 3]),
        (Type::TLSA, vec![3, 1, 1, 0xab, 0xcd]),
        (Type::TLSA, vec![3, 1, 1]),
        (Type::SSHFP, vec![1, 2, 0xab, 0xcd]),
        (Type::SSHFP, vec![1, 2]),
        (
            Type::ZONEMD,
            [vec![0, 0, 0, 1, 1, 1], vec![0xab; 12]].concat(),
        ),
        (
            Type::TSIG,
            vec![
                0, 0, 0, 0, 0, 0, 1, 0, 10, 0, 2, 0xab, 0xcd, 0x12, 0x34, 0, 18, 0, 1, 0xef,
            ],
        ),
        (
            Type::RRSIG,
            vec![
                0, 1, 8, 2, 0, 0, 0x0e, 0x10, 0, 0, 0, 2, 0, 0, 0, 1, 0x12, 0x34, 0, 1, 2, 3,
            ],
        ),
        (Type::NSEC, vec![0, 0, 1, 0x40, 1, 1, 0x80]),
        (
            Type::NSEC3,
            vec![1, 0, 0, 10, 2, 10, 11, 1, 0x66, 0, 1, 0x40],
        ),
        (Type::NSEC3PARAM, vec![1, 0, 0, 10, 2, 10, 11]),
        (
            Type::SVCB,
            b"\x00\x10\x00\x00\x01\x00\x03\x02h2\x00\x03\x00\x02\x01\xbb\xfd\xe8\x00\x02hi"
                .to_vec(),
        ),
        (
            Type::HTTPS,
            b"\x00\x01\x03dns\x07example\x00\x00\x07\x00\x10/dns-query{?dns}".to_vec(),
        ),
        (Type(65000), vec![0, 255, 42]),
    ] {
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
    for (rtype, prefix) in [
        (Type::SRV, &b"\x00\x0a\x00\x05\x21\x24"[..]),
        (Type::NAPTR, &b"\x00\x64\x00\x32\x01s\x07SIP+D2U\x00"[..]),
    ] {
        builder
            .record_with(Section::Answer, owner, rtype, Class::IN, 0, |w| {
                w.write_bytes(prefix)?;
                w.write_uncompressed_name(owner)
            })
            .unwrap();
    }
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
    macro_rules! compare_ds {
        ($key:expr, $alg:expr, $kind:expr, $digest:expr, $b:expr) => {{
            assert_eq!(
                ($key, $alg, $kind),
                (
                    $b.key_tag(),
                    $b.algorithm().to_int(),
                    $b.digest_type().to_int()
                )
            );
            assert_eq!($digest, *$b.digest());
        }};
    }
    macro_rules! compare_key {
        ($flags:expr, $protocol:expr, $alg:expr, $key:expr, $b:expr) => {{
            assert_eq!(
                ($flags, $protocol, $alg),
                ($b.flags(), $b.protocol(), $b.algorithm().to_int())
            );
            assert_eq!($key, *$b.public_key());
        }};
    }
    macro_rules! compare_svcb {
        ($priority:expr, $target:expr, $params:expr, $b:expr) => {{
            assert_eq!($priority, $b.priority());
            compare_name!($target, $b.target());
            assert_eq!($params, $b.params().as_slice());
        }};
    }
    for (actual, expected) in pharos.answers().zip(domain_answers) {
        let actual = actual.data().unwrap();
        let expected = expected
            .unwrap()
            .to_any_record::<AllRecordData<_, ParsedName<_>>>()
            .unwrap()
            .into_data();
        match (actual, expected) {
            (
                pharos_proto::Rdata::Tlsa {
                    usage,
                    selector,
                    matching_type,
                    certificate,
                },
                AllRecordData::Tlsa(b),
            ) => {
                assert_eq!(
                    (usage, selector, matching_type),
                    (
                        b.usage().to_int(),
                        b.selector().to_int(),
                        b.matching_type().to_int()
                    )
                );
                assert_eq!(certificate, *b.data());
            }
            (
                pharos_proto::Rdata::Sshfp {
                    algorithm,
                    fingerprint_type,
                    fingerprint,
                },
                AllRecordData::Sshfp(b),
            ) => {
                assert_eq!(
                    (algorithm, fingerprint_type),
                    (b.algorithm().to_int(), b.fingerprint_type().to_int())
                );
                assert_eq!(fingerprint, *b.fingerprint());
            }
            (
                pharos_proto::Rdata::Zonemd {
                    serial,
                    scheme,
                    hash_algorithm,
                    digest,
                },
                AllRecordData::Zonemd(b),
            ) => {
                assert_eq!(
                    (serial, scheme, hash_algorithm),
                    (
                        b.serial().into_int(),
                        b.scheme().to_int(),
                        b.algorithm().to_int()
                    )
                );
                assert_eq!(digest, *b.digest());
            }
            (
                pharos_proto::Rdata::Tsig {
                    algorithm,
                    time_signed,
                    fudge,
                    mac,
                    original_id,
                    error,
                    other,
                },
                AllRecordData::Tsig(b),
            ) => {
                compare_name!(algorithm, b.algorithm());
                assert_eq!(
                    (time_signed, fudge, original_id, error),
                    (
                        u64::from(b.time_signed()),
                        b.fudge(),
                        b.original_id(),
                        b.error().to_int()
                    )
                );
                assert_eq!(mac, *b.mac());
                assert_eq!(other, *b.other());
            }
            (
                pharos_proto::Rdata::Svcb {
                    priority,
                    target,
                    params,
                },
                AllRecordData::Svcb(b),
            ) => compare_svcb!(priority, target, params, b),
            (
                pharos_proto::Rdata::Https {
                    priority,
                    target,
                    params,
                },
                AllRecordData::Https(b),
            ) => compare_svcb!(priority, target, params, b),
            (
                pharos_proto::Rdata::Ds {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                },
                AllRecordData::Ds(b),
            ) => compare_ds!(key_tag, algorithm, digest_type, digest, b),
            (
                pharos_proto::Rdata::Cds {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                },
                AllRecordData::Cds(b),
            ) => compare_ds!(key_tag, algorithm, digest_type, digest, b),
            (
                pharos_proto::Rdata::Dnskey {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                },
                AllRecordData::Dnskey(b),
            ) => compare_key!(flags, protocol, algorithm, public_key, b),
            (
                pharos_proto::Rdata::Cdnskey {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                },
                AllRecordData::Cdnskey(b),
            ) => compare_key!(flags, protocol, algorithm, public_key, b),
            (
                pharos_proto::Rdata::Rrsig {
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    key_tag,
                    signer,
                    signature,
                },
                AllRecordData::Rrsig(b),
            ) => {
                assert_eq!(
                    (
                        type_covered.0,
                        algorithm,
                        labels,
                        original_ttl,
                        expiration,
                        inception,
                        key_tag
                    ),
                    (
                        b.type_covered().to_int(),
                        b.algorithm().to_int(),
                        b.labels(),
                        b.original_ttl().as_secs(),
                        b.expiration().into_int(),
                        b.inception().into_int(),
                        b.key_tag()
                    )
                );
                compare_name!(signer, b.signer_name());
                assert_eq!(signature, *b.signature());
            }
            (pharos_proto::Rdata::Nsec { next, bitmap }, AllRecordData::Nsec(b)) => {
                compare_name!(next, b.next_name());
                assert_eq!(bitmap, b.types().as_slice());
            }
            (
                pharos_proto::Rdata::Nsec3 {
                    hash_algorithm,
                    flags,
                    iterations,
                    salt,
                    next_owner,
                    bitmap,
                },
                AllRecordData::Nsec3(b),
            ) => {
                assert_eq!(
                    (hash_algorithm, flags, iterations),
                    (b.hash_algorithm().to_int(), b.flags(), b.iterations())
                );
                assert_eq!(salt, b.salt().as_slice());
                assert_eq!(next_owner, b.next_owner().as_slice());
                assert_eq!(bitmap, b.types().as_slice());
            }
            (
                pharos_proto::Rdata::Nsec3param {
                    hash_algorithm,
                    flags,
                    iterations,
                    salt,
                },
                AllRecordData::Nsec3param(b),
            ) => {
                assert_eq!(
                    (hash_algorithm, flags, iterations),
                    (b.hash_algorithm().to_int(), b.flags(), b.iterations())
                );
                assert_eq!(salt, b.salt().as_slice());
            }
            (pharos_proto::Rdata::A(a), AllRecordData::A(b)) => assert_eq!(a, b.addr()),
            (pharos_proto::Rdata::Aaaa(a), AllRecordData::Aaaa(b)) => assert_eq!(a, b.addr()),
            (pharos_proto::Rdata::Txt(a), AllRecordData::Txt(b)) => {
                let actual = pharos_proto::Rdata::parse(Type::TXT, a).unwrap();
                assert_eq!(actual.to_string(), r#""abc" "" "\000\255""#);
                assert_eq!(
                    b.iter().collect::<Vec<_>>(),
                    vec![&b"abc"[..], &b""[..], &b"\x00\xff"[..]]
                );
            }
            (pharos_proto::Rdata::Hinfo { cpu, os }, AllRecordData::Hinfo(b)) => {
                assert_eq!(cpu, b.cpu().as_slice());
                assert_eq!(os, b.os().as_slice());
            }
            (pharos_proto::Rdata::Caa { flags, tag, value }, AllRecordData::Caa(b)) => {
                assert_eq!(flags, b.flags().bits());
                assert_eq!(tag, b.tag().to_string().as_bytes());
                assert_eq!(value, *b.value());
            }
            (
                pharos_proto::Rdata::Uri {
                    priority,
                    weight,
                    target,
                },
                AllRecordData::Unknown(b),
            ) => {
                assert_eq!(
                    b.data(),
                    &b"\x00\x0a\x00\x01https://example.org/".as_slice()
                );
                assert_eq!(
                    (priority, weight, target),
                    (10, 1, &b"https://example.org/"[..])
                );
            }
            (pharos_proto::Rdata::Unknown(rtype, bytes), AllRecordData::Unknown(b)) => {
                assert_eq!(rtype, Type(65000));
                assert_eq!(rtype.0, b.rtype().to_int());
                assert_eq!(bytes, *b.data());
            }
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
                pharos_proto::Rdata::Srv {
                    priority,
                    weight,
                    port,
                    target,
                },
                AllRecordData::Srv(b),
            ) => {
                assert_eq!(
                    (priority, weight, port),
                    (b.priority(), b.weight(), b.port())
                );
                compare_name!(target, b.target());
            }
            (
                pharos_proto::Rdata::Naptr {
                    order,
                    preference,
                    flags,
                    services,
                    regexp,
                    replacement,
                },
                AllRecordData::Naptr(b),
            ) => {
                assert_eq!((order, preference), (b.order(), b.preference()));
                assert_eq!(flags, b.flags().as_slice());
                assert_eq!(services, b.services().as_slice());
                assert_eq!(regexp, b.regexp().as_slice());
                compare_name!(replacement, b.replacement());
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

#[test]
fn domain_checks_svcb_framing_but_not_parameter_values_or_reserved_keys() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    for params in [
        &b"\x00\x00\x00\x00"[..],                 // empty mandatory
        &b"\x00\x00\x00\x04\x00\x03\x00\x01"[..], // unordered mandatory
        &b"\x00\x01\x00\x01\x00"[..],             // empty ALPN ID
        &b"\x00\x03\x00\x01\x00"[..],             // short port
        &b"\xff\xff\x00\x00"[..],                 // reserved key
    ] {
        let mut data = vec![0, 1, 0];
        data.extend_from_slice(params);
        assert!(pharos_proto::Rdata::parse(Type::SVCB, &data).is_err());
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder
            .record(Section::Answer, root, Type::SVCB, Class::IN, 0, &data)
            .unwrap();
        let msg = DomainMessage::from_octets(&builder.finish()[..]).unwrap();
        let record = msg.question().answer().unwrap().next().unwrap().unwrap();
        assert!(
            record
                .to_any_record::<AllRecordData<_, ParsedName<_>>>()
                .is_ok()
        );
    }
}

#[test]
fn domain_accepts_noncanonical_and_disordered_bitmap_windows() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    for bitmap in [
        &[0, 1, 0][..],
        &[0, 2, 0x40, 0][..],
        &[1, 1, 0x80, 0, 1, 0x40][..],
        &[0, 1, 0x40, 0, 1, 0x80][..],
    ] {
        let mut rdata = vec![0];
        rdata.extend_from_slice(bitmap);
        assert!(pharos_proto::Rdata::parse(Type::NSEC, &rdata).is_err());
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder
            .record(Section::Answer, root, Type::NSEC, Class::IN, 0, &rdata)
            .unwrap();
        let _ = builder.finish();
        let msg = DomainMessage::from_octets(wire.as_slice()).unwrap();
        let record = msg.question().answer().unwrap().next().unwrap().unwrap();
        assert!(
            record
                .to_any_record::<AllRecordData<_, ParsedName<_>>>()
                .is_ok()
        );
    }
}

#[test]
fn domain_requires_at_least_twelve_zonemd_digest_octets() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    for len in 0..=12 {
        let mut data = vec![0; 6];
        data.extend(vec![0xab; len]);
        assert_eq!(
            pharos_proto::Rdata::parse(Type::ZONEMD, &data).is_ok(),
            len >= 12
        );
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder
            .record(Section::Answer, root, Type::ZONEMD, Class::IN, 0, &data)
            .unwrap();
        let msg = DomainMessage::from_octets(&builder.finish()[..]).unwrap();
        let record = msg.question().answer().unwrap().next().unwrap().unwrap();
        assert_eq!(
            record
                .to_any_record::<AllRecordData<_, ParsedName<_>>>()
                .is_ok(),
            len >= 12
        );
    }
}

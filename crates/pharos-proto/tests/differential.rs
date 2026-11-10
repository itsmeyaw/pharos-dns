#![forbid(unsafe_code)]

use domain::base::Message as DomainMessage;
use hickory_proto::{
    op::{Header, Message as HickoryMessage, Query},
    rr::{Name as HickoryName, Record as HickoryRecord},
    serialize::binary::{BinDecodable, BinDecoder},
};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
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

proptest! {
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

use pharos_proto::{BuildError, Class, Message, MessageBuilder, Name, NameRef, Section, Type};

fn name(value: &str) -> Name {
    value.parse().unwrap()
}

fn borrowed(value: &Name) -> NameRef<'_> {
    NameRef::parse(value.as_wire(), 0).unwrap()
}

#[test]
fn builds_ordered_sections_and_reuses_buffer() {
    let mut wire = Vec::with_capacity(512);
    wire.extend_from_slice(b"old contents");
    let capacity = wire.capacity();
    let n = name("www.example.com.");
    let mut b = MessageBuilder::new(&mut wire, 512, 0x1234, 0x8180).unwrap();
    assert!(b.question(borrowed(&n), Type(1), Class(1)).unwrap());
    for section in [Section::Answer, Section::Authority, Section::Additional] {
        assert!(
            b.record(
                section,
                borrowed(&n),
                Type(1),
                Class(1),
                60,
                &[127, 0, 0, 1]
            )
            .unwrap()
        );
    }
    assert_eq!(
        b.record(Section::Answer, borrowed(&n), Type(1), Class(1), 0, &[]),
        Err(BuildError::SectionOrder)
    );
    let wire = b.finish();
    assert_eq!(wire.capacity(), capacity);
    let message = Message::parse(wire).unwrap();
    assert_eq!((message.id(), message.flags()), (0x1234, 0x8180));
    assert_eq!(
        (
            message.question_count(),
            message.answer_count(),
            message.authority_count(),
            message.additional_count()
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(message.answers().next().unwrap().rdata, &[127, 0, 0, 1]);
    assert_eq!(&wire[33..35], &[0xc0, 0x0c]);
}

#[test]
fn compresses_suffixes_and_accepts_compressed_input() {
    let source = b"\x07example\x03com\0\x03www\xc0\x00";
    let first = NameRef::parse(source, 0).unwrap();
    let second = NameRef::parse(source, 13).unwrap();
    let mut wire = Vec::new();
    let mut b = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    assert!(b.question(first, Type(1), Class(1)).unwrap());
    assert!(b.question(second, Type(1), Class(1)).unwrap());
    let wire = b.finish();
    assert_eq!(&wire[29..35], b"\x03www\xc0\x0c");
    let parsed = Message::parse(wire).unwrap();
    assert_eq!(
        parsed.questions().nth(1).unwrap().name.to_string(),
        "www.example.com."
    );
}

#[test]
fn mandatory_overflow_rolls_back_sets_tc_and_stops() {
    for section in [Section::Answer, Section::Authority] {
        let n = name("example.com.");
        let mut wire = Vec::new();
        let mut b = MessageBuilder::new(&mut wire, 40, 7, 0x8000).unwrap();
        assert!(b.question(borrowed(&n), Type(1), Class(1)).unwrap());
        assert!(
            !b.record(section, borrowed(&n), Type(1), Class(1), 0, &[1, 2, 3, 4])
                .unwrap()
        );
        assert!(
            !b.record(Section::Additional, borrowed(&n), Type(1), Class(1), 0, &[])
                .unwrap()
        );
        let message = Message::parse(b.finish()).unwrap();
        assert!(message.tc());
        assert_eq!(
            (
                message.answer_count(),
                message.authority_count(),
                message.additional_count()
            ),
            (0, 0, 0)
        );
    }
}

#[test]
fn optional_overflow_discards_all_additionals_without_tc() {
    let n = name(".");
    let mut wire = Vec::new();
    let mut b = MessageBuilder::new(&mut wire, 35, 0, 0x8000).unwrap();
    assert!(
        b.record(Section::Additional, borrowed(&n), Type(1), Class(1), 0, &[])
            .unwrap()
    );
    assert!(
        !b.record(
            Section::Additional,
            borrowed(&n),
            Type(1),
            Class(1),
            0,
            &[0; 5]
        )
        .unwrap()
    );
    let wire = b.finish();
    let message = Message::parse(wire).unwrap();
    assert_eq!(wire.len(), 12);
    assert_eq!(message.additional_count(), 0);
    assert!(!message.tc());
}

#[test]
fn rdata_writer_compresses_names_and_rolls_back_errors() {
    let n = name("example.com.");
    let target = name("ns.example.com.");
    let mut wire = Vec::new();
    let mut b = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    assert!(b.question(borrowed(&n), Type(2), Class(1)).unwrap());
    assert_eq!(
        b.record_with(
            Section::Answer,
            borrowed(&target),
            Type(2),
            Class(1),
            1,
            |w| {
                w.write_name(borrowed(&target))?;
                Err(BuildError::InvalidRdata)
            }
        ),
        Err(BuildError::InvalidRdata)
    );
    assert!(
        b.record_with(Section::Answer, borrowed(&n), Type(2), Class(1), 1, |w| {
            w.write_bytes(&[1, 2])?;
            w.write_name(borrowed(&target))
        })
        .unwrap()
    );
    let wire = b.finish();
    let message = Message::parse(wire).unwrap();
    let record = message.answers().next().unwrap();
    assert_eq!(record.rdata, b"\x01\x02\x02ns\xc0\x0c");
    assert_eq!(
        NameRef::parse(wire, record.rdata_offset + 2)
            .unwrap()
            .to_string(),
        "ns.example.com."
    );
}

#[test]
fn rejects_invalid_limits_and_oversized_rdata_without_mutation() {
    let mut wire = vec![1, 2, 3];
    assert!(matches!(
        MessageBuilder::new(&mut wire, 11, 0, 0),
        Err(BuildError::InvalidMaxSize)
    ));
    assert!(matches!(
        MessageBuilder::new(&mut wire, 65_536, 0, 0),
        Err(BuildError::InvalidMaxSize)
    ));
    let n = name(".");
    let mut b = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    assert_eq!(
        b.record(
            Section::Answer,
            borrowed(&n),
            Type(1),
            Class(1),
            0,
            &[0; 65_536]
        ),
        Err(BuildError::RdataTooLong)
    );
    assert!(
        b.record(Section::Answer, borrowed(&n), Type(1), Class(1), 0, &[])
            .unwrap()
    );
    assert_eq!(Message::parse(b.finish()).unwrap().answer_count(), 1);
}

#[test]
fn compression_preserves_case_and_never_targets_offsets_above_14_bits() {
    let root = name(".");
    let lower = name("example.com.");
    let upper = name("Example.com.");
    let mut wire = Vec::new();
    let mut b = MessageBuilder::new(&mut wire, 65535, 0, 0).unwrap();
    assert!(b.question(borrowed(&lower), Type(1), Class(1)).unwrap());
    assert!(b.question(borrowed(&upper), Type(1), Class(1)).unwrap());
    assert!(
        b.record(
            Section::Answer,
            borrowed(&root),
            Type(1),
            Class(1),
            0,
            &[0; 16384]
        )
        .unwrap()
    );
    let late = name("late.test.");
    for _ in 0..2 {
        assert!(
            b.record(Section::Answer, borrowed(&late), Type(1), Class(1), 0, &[])
                .unwrap()
        );
    }
    let wire = b.finish();
    let message = Message::parse(wire).unwrap();
    assert_eq!(
        message.questions().nth(1).unwrap().name.to_string(),
        "Example.com."
    );
    let late_record = message.answers().nth(2).unwrap();
    let start = late_record.rdata_offset - 10 - late_record.name.wire_len();
    assert!(start >= 0x4000);
    assert_eq!(late_record.name.wire_len(), late.as_wire().len());
    assert_eq!(&wire[start..start + late.as_wire().len()], late.as_wire());
}

#[test]
fn question_and_rdata_overflow_are_rolled_back() {
    let n = name("example.com.");
    let mut wire = Vec::new();
    let mut b = MessageBuilder::new(&mut wire, 12, 0, 0).unwrap();
    assert!(!b.question(borrowed(&n), Type(1), Class(1)).unwrap());
    let wire = b.finish();
    assert_eq!(wire.len(), 12);
    assert!(Message::parse(wire).unwrap().tc());

    let mut b = MessageBuilder::new(wire, 40, 0, 0).unwrap();
    assert!(
        !b.record_with(Section::Answer, borrowed(&n), Type(1), Class(1), 0, |w| {
            w.write_bytes(&[0; 20])
        })
        .unwrap()
    );
    let wire = b.finish();
    assert_eq!(wire.len(), 12);
    assert!(Message::parse(wire).unwrap().tc());
}

use pharos_proto::{BuildError, Class, Message, MessageBuilder, Name, NameRef, Section, Type};

fn name(value: &str) -> Name {
    value.parse().unwrap()
}

fn borrowed(value: &Name) -> NameRef<'_> {
    NameRef::parse(value.as_wire(), 0).unwrap()
}

#[test]
fn rdata_can_disable_compression_for_zone_storage() {
    let n = name("example.com.");
    let mut bytes = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut bytes, 512, 1, 0).unwrap();
    b.record_with(Section::Answer, borrowed(&n), Type::CNAME, Class::IN, 30, |writer| {
        writer.disable_compression();
        pharos_proto::Rdata::Cname(borrowed(&n)).write(writer)
    }).unwrap();
    let _ = b.finish();
    assert_eq!(Message::parse(&bytes).unwrap().answers().next().unwrap().rdata, n.as_wire());
}

#[test]
fn fixed_storage_builds_questions_and_compressed_rdata() {
    use pharos_proto::{FixedBuffer, Rdata};
    let n = name("www.example.com.");
    let mut storage = [0; 512];
    let mut fixed = FixedBuffer::new(&mut storage);
    let mut b = MessageBuilder::new(&mut fixed, 512, 1, 0x8180).unwrap();
    b.question(borrowed(&n), Type::A, Class::IN).unwrap();
    b.record_with(
        Section::Answer,
        borrowed(&n),
        Type::CNAME,
        Class::IN,
        30,
        |w| Rdata::Cname(borrowed(&n)).write(w),
    )
    .unwrap();
    let wire = b.finish();
    let parsed = Message::parse(wire).unwrap();
    assert_eq!(parsed.questions().next().unwrap().name, borrowed(&n));
    let Rdata::Cname(target) = parsed.answers().next().unwrap().data().unwrap() else {
        panic!("expected CNAME")
    };
    assert_eq!(target, borrowed(&n));
}

#[test]
fn fixed_storage_respects_capacity_and_truncation() {
    use pharos_proto::FixedBuffer;
    let mut small = [0; 511];
    let mut small = FixedBuffer::new(&mut small);
    assert!(matches!(
        MessageBuilder::new(&mut small, 512, 1, 0),
        Err(BuildError::InvalidMaxSize)
    ));
    let n = name("example.");
    let mut storage = [0; 512];
    let mut fixed = FixedBuffer::new(&mut storage);
    let mut b = MessageBuilder::new(&mut fixed, 512, 1, 0x8180).unwrap();
    b.question(borrowed(&n), Type::A, Class::IN).unwrap();
    assert!(
        !b.record(
            Section::Answer,
            borrowed(&n),
            Type::TXT,
            Class::IN,
            30,
            &[0; 500]
        )
        .unwrap()
    );
    let parsed = Message::parse(b.finish()).unwrap();
    assert!(parsed.tc());
    assert_eq!(parsed.answer_count(), 0);
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
        let mut b = MessageBuilder::new(&mut wire, 512, 7, 0x8000).unwrap();
        assert!(b.question(borrowed(&n), Type(1), Class(1)).unwrap());
        assert!(
            !b.record(section, borrowed(&n), Type(1), Class(1), 0, &[1; 480])
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
fn additional_overflow_keeps_previous_records_sets_tc_and_stops() {
    let n = name(".");
    let mut wire = Vec::new();
    let mut b = MessageBuilder::new(&mut wire, 512, 0, 0x8000).unwrap();
    assert!(
        b.record(
            Section::Additional,
            borrowed(&n),
            Type(1),
            Class(1),
            0,
            &[1; 478]
        )
        .unwrap()
    );
    assert!(
        !b.record(
            Section::Additional,
            borrowed(&n),
            Type(1),
            Class(1),
            0,
            &[2]
        )
        .unwrap()
    );
    assert!(
        !b.record(Section::Additional, borrowed(&n), Type(1), Class(1), 0, &[])
            .unwrap()
    );
    let wire = b.finish();
    let message = Message::parse(wire).unwrap();
    assert_eq!(wire.len(), 501);
    assert_eq!(message.additional_count(), 1);
    assert_eq!(message.additionals().next().unwrap().rdata, &[1; 478]);
    assert!(message.tc());
}

#[test]
fn maximum_below_512_is_clamped() {
    let n = name(".");
    for max_size in [0, 11, 511] {
        let mut wire = Vec::new();
        let mut b = MessageBuilder::new(&mut wire, max_size, 0, 0).unwrap();
        assert!(
            b.record(
                Section::Answer,
                borrowed(&n),
                Type(1),
                Class(1),
                0,
                &[0; 489]
            )
            .unwrap()
        );
        assert!(
            !b.record(Section::Additional, borrowed(&n), Type(1), Class(1), 0, &[])
                .unwrap()
        );
        let wire = b.finish();
        assert_eq!(wire.len(), 512);
        assert!(Message::parse(wire).unwrap().tc());
    }
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
    let n = name(".");
    let mut wire = Vec::new();
    let mut b = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    for _ in 0..100 {
        assert!(b.question(borrowed(&n), Type(1), Class(1)).unwrap());
    }
    assert!(!b.question(borrowed(&n), Type(1), Class(1)).unwrap());
    let wire = b.finish();
    assert_eq!(wire.len(), 512);
    let message = Message::parse(wire).unwrap();
    assert!(message.tc());
    assert_eq!(message.question_count(), 100);

    let mut b = MessageBuilder::new(wire, 512, 0, 0).unwrap();
    assert!(
        !b.record_with(Section::Answer, borrowed(&n), Type(1), Class(1), 0, |w| {
            w.write_bytes(&[0; 490])
        })
        .unwrap()
    );
    let wire = b.finish();
    assert_eq!(wire.len(), 12);
    assert!(Message::parse(wire).unwrap().tc());
}

#[test]
fn reserves_space_for_opt_even_after_truncation() {
    let root = name(".");
    let opt = b"\0\0\x29\x02\x00\0\0\0\0\0\0";
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 7, 0x8000).unwrap();
    builder.reserve(opt.len()).unwrap();
    assert!(
        builder
            .record(
                Section::Answer,
                borrowed(&root),
                Type::A,
                Class::IN,
                0,
                &[1; 478]
            )
            .unwrap()
    );
    assert!(
        !builder
            .record(
                Section::Additional,
                borrowed(&root),
                Type::A,
                Class::IN,
                0,
                &[]
            )
            .unwrap()
    );
    assert!(
        !builder
            .record(
                Section::Additional,
                borrowed(&root),
                Type::A,
                Class::IN,
                0,
                &[]
            )
            .unwrap()
    );
    let wire = builder.finish_with_opt(opt).unwrap();
    assert_eq!(wire.len(), 512);
    let message = Message::parse(wire).unwrap();
    assert!(message.tc());
    assert_eq!(message.answer_count(), 1);
    assert_eq!(message.additional_count(), 1);
    assert_eq!(message.additionals().next().unwrap().rtype, Type::OPT);
}

#[test]
fn reserved_opt_is_bounded_and_validated() {
    let opt = b"\0\0\x29\x02\x00\0\0\0\0\0\0";
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    assert_eq!(builder.reserve(501), Err(BuildError::SizeLimit));
    builder.reserve(opt.len()).unwrap();
    assert!(builder.finish_with_opt(&opt[..10]).is_err());

    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    builder.reserve(opt.len() - 1).unwrap();
    assert!(builder.finish_with_opt(opt).is_err());

    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    builder.reserve(opt.len()).unwrap();
    let mut bad = *opt;
    bad[2] = 1;
    assert!(builder.finish_with_opt(&bad).is_err());
}

#[test]
fn failed_opt_finalization_keeps_a_valid_message() {
    let root = name(".");
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 7, 0).unwrap();
    builder
        .question(borrowed(&root), Type::A, Class::IN)
        .unwrap();
    builder.reserve(11).unwrap();
    assert_eq!(
        builder.finish_with_opt(&[0; 11]),
        Err(BuildError::InvalidRdata)
    );
    let message = Message::parse(&wire).unwrap();
    assert_eq!(message.question_count(), 1);
    assert_eq!(message.additional_count(), 0);
}

#[test]
fn reserved_opt_can_finish_without_truncation() {
    let opt = b"\0\0\x29\x02\x00\0\0\0\0\0\0";
    let root = name(".");
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
    builder.reserve(5).unwrap();
    builder.reserve(6).unwrap();
    assert!(
        builder
            .question(borrowed(&root), Type::A, Class::IN)
            .unwrap()
    );
    let message = Message::parse(builder.finish_with_opt(opt).unwrap()).unwrap();
    assert!(!message.tc());
    assert_eq!(message.question_count(), 1);
    assert_eq!(message.additional_count(), 1);
    assert_eq!(message.additionals().next().unwrap().rtype, Type::OPT);
}

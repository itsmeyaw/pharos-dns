#![forbid(unsafe_code)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use pharos_proto::{Message, MessageBuilder, Section};

fuzz_target!(|input: &[u8]| {
    let Ok(original) = Message::parse(input) else {
        return;
    };
    let mut wire = Vec::new();
    let mut builder =
        MessageBuilder::new(&mut wire, 65535, original.id(), original.flags()).unwrap();
    let mut complete = true;
    for question in original.questions() {
        complete &= builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
    }
    for (section, records) in [
        (Section::Answer, original.answers()),
        (Section::Authority, original.authorities()),
        (Section::Additional, original.additionals()),
    ] {
        for record in records {
            complete &= builder
                .record(
                    section,
                    record.name,
                    record.rtype,
                    record.class,
                    record.ttl,
                    record.rdata,
                )
                .unwrap();
        }
    }
    let rebuilt = Message::parse(builder.finish()).unwrap();
    if !complete {
        return;
    }
    assert_eq!(
        (rebuilt.id(), rebuilt.flags()),
        (original.id(), original.flags())
    );
    assert_eq!(
        (
            rebuilt.question_count(),
            rebuilt.answer_count(),
            rebuilt.authority_count(),
            rebuilt.additional_count()
        ),
        (
            original.question_count(),
            original.answer_count(),
            original.authority_count(),
            original.additional_count()
        )
    );
    for (left, right) in original.questions().zip(rebuilt.questions()) {
        assert_eq!(
            left.name.to_name().as_wire(),
            right.name.to_name().as_wire()
        );
        assert_eq!((left.qtype, left.qclass), (right.qtype, right.qclass));
    }
    for (left, right) in original
        .answers()
        .chain(original.authorities())
        .chain(original.additionals())
        .zip(
            rebuilt
                .answers()
                .chain(rebuilt.authorities())
                .chain(rebuilt.additionals()),
        )
    {
        assert_eq!(
            left.name.to_name().as_wire(),
            right.name.to_name().as_wire()
        );
        assert_eq!(
            (left.rtype, left.class, left.ttl, left.rdata),
            (right.rtype, right.class, right.ttl, right.rdata)
        );
    }
});

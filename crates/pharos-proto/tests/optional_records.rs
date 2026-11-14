use pharos_proto::{BuildError, Class, Message, MessageBuilder, Name, NameRef, Section, Type};

#[test]
fn optional_rrset_overflow_rolls_back_data_and_tc() {
    let owner: Name = "optional.example.".parse().unwrap();
    let owner = NameRef::parse(owner.as_wire(), 0).unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x8400).unwrap();
    builder.question(owner, Type::A, Class::IN).unwrap();
    builder
        .record(
            Section::Answer,
            owner,
            Type::A,
            Class::IN,
            60,
            &[192, 0, 2, 1],
        )
        .unwrap();
    let included = builder
        .try_optional(|builder| {
            for octet in 0..40 {
                if !builder.record(
                    Section::Additional,
                    owner,
                    Type::A,
                    Class::IN,
                    60,
                    &[192, 0, 2, octet],
                )? {
                    return Ok::<_, BuildError>(None);
                }
            }
            Ok(Some(()))
        })
        .unwrap();
    assert_eq!(included, None);
    let response = Message::parse(builder.finish()).unwrap();
    assert_eq!(response.answers().count(), 1);
    assert_eq!(response.additionals().count(), 0);
    assert!(!response.tc());
}

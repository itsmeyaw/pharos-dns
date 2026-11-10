use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
use proptest::prelude::*;

proptest! {
    #[test]
    fn message_round_trip(
        labels in prop::collection::vec("[a-zA-Z0-9]{1,10}", 0..5),
        id in any::<u16>(), flags in any::<u16>(),
        qtype in any::<u16>(), class in any::<u16>(),
        answers in prop::collection::vec((any::<u16>().prop_filter("OPT belongs in Additional", |kind| *kind != Type::OPT.0), any::<u16>(), any::<u32>(), prop::collection::vec(any::<u8>(), 0..24)), 0..10),
    ) {
        let text = if labels.is_empty() { ".".to_owned() } else { format!("{}.", labels.join(".")) };
        let name: Name = text.parse().unwrap();
        let borrowed = NameRef::parse(name.as_wire(), 0).unwrap();
        let mut wire = Vec::with_capacity(2048);
        let mut builder = MessageBuilder::new(&mut wire, 2048, id, flags).unwrap();
        prop_assert!(builder.question(borrowed, Type(qtype), Class(class)).unwrap());
        for (kind, class, ttl, rdata) in &answers {
            prop_assert!(builder.record(Section::Answer, borrowed, Type(*kind), Class(*class), *ttl, rdata).unwrap());
        }
        let message = Message::parse(builder.finish()).unwrap();
        prop_assert_eq!(message.id(), id);
        prop_assert_eq!(message.flags(), flags);
        let question = message.questions().next().unwrap();
        prop_assert_eq!(question.name, name.clone());
        prop_assert_eq!(question.qtype, Type(qtype));
        prop_assert_eq!(question.qclass, Class(class));
        prop_assert_eq!(usize::from(message.answer_count()), answers.len());
        for (record, (kind, class, ttl, rdata)) in message.answers().zip(&answers) {
            prop_assert_eq!(record.name, name.clone());
            prop_assert_eq!(record.rtype, Type(*kind));
            prop_assert_eq!(record.class, Class(*class));
            prop_assert_eq!(record.ttl, *ttl);
            prop_assert_eq!(record.rdata, rdata.as_slice());
        }
    }
}

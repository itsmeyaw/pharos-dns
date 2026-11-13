// Shared fixtures for the pharos-proto vs hickory-proto comparison.
use hickory_proto::op::{Message as HMessage, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name as HName, RData, Record, RecordType};
use pharos_proto::{Class, MessageBuilder, NameRef, Section, Type};

pub const QUERY: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\0\x00\x01\x00\x01";

pub fn pharos_response() -> Vec<u8> {
    let name = NameRef::parse(QUERY, 12).unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 0x1234, 0x8180).unwrap();
    builder.question(name, Type(1), Class(1)).unwrap();
    for i in 0..5 {
        builder
            .record(
                Section::Answer,
                name,
                Type(1),
                Class(1),
                60,
                &[192, 0, 2, i],
            )
            .unwrap();
    }
    let _ = builder.finish();
    wire
}

pub fn hickory_name() -> HName {
    HName::from_ascii("www.example.com.").unwrap()
}

pub fn hickory_response(name: &HName) -> HMessage {
    let mut msg = HMessage::response(0x1234, OpCode::Query);
    msg.add_query(Query::query(name.clone(), RecordType::A));
    for i in 0..5 {
        msg.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::A(A::new(192, 0, 2, i)),
        ));
    }
    msg
}

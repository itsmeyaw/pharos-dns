use pharos_proto::{Class, Message, Name, Type};

#[test]
fn new_question_preserves_header_and_edns() {
    let wire = b"\x12\x34\x01\x30\0\x01\0\0\0\0\0\x01\x07example\x03com\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\x80\0\0\x06\xfd\xe9\0\x02\xc0\x01";
    let original = Message::parse(wire).unwrap();
    let name: Name = "ExAmPlE.Org.".parse().unwrap();
    let rewritten = original.with_question(&name, Type::MX).unwrap();
    let query = Message::parse(&rewritten).unwrap();
    assert_eq!(query.id(), 0x1234);
    assert_eq!(query.flags(), 0x0130);
    let question = query.questions().next().unwrap();
    assert_eq!(question.name.to_string(), "ExAmPlE.Org.");
    assert_eq!(question.qtype, Type::MX);
    assert_eq!(question.qclass, Class::IN);
    let opt = query.opt().unwrap();
    assert_eq!(opt.udp_payload_size(), 1232);
    assert!(opt.dnssec_ok());
    assert_eq!(opt.options().as_bytes(), b"\xfd\xe9\0\x02\xc0\x01");
    assert_eq!(
        original.questions().next().unwrap().name.to_string(),
        "example.com."
    );
}

#[test]
fn new_question_preserves_records_with_compressed_names() {
    let wire = b"\0\x01\x01\0\0\x01\0\x01\0\0\0\0\x01a\x07example\0\0\x01\0\x01\xc0\x0c\0\x05\0\x01\0\0\0\x3c\0\x04\x01b\xc0\x0e";
    let original = Message::parse(wire).unwrap();
    let rewritten = original
        .with_question(&"longer.other.".parse().unwrap(), Type::A)
        .unwrap();
    let query = Message::parse(&rewritten).unwrap();
    let answer = query.answers().next().unwrap();
    assert_eq!(answer.name.to_string(), "a.example.");
    assert!(
        matches!(answer.data().unwrap(), pharos_proto::Rdata::Cname(name) if name.to_string() == "b.example.")
    );
    assert_eq!(answer.ttl, 60);
    assert!(query.opt().is_none());
}

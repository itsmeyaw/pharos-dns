use pharos_proto::Message;

#[test]
fn authenticated_query_view_does_not_mutate_wire() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let original = Message::parse(wire).unwrap();
    let authenticated = original.with_ad();
    assert!(!original.ad());
    assert!(authenticated.ad());
    assert_eq!(authenticated.as_wire(), wire);
}

#[test]
fn reads_a_query_and_rejects_truncation() {
    let wire = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\0\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    assert_eq!(message.id(), 0x1234);
    assert!(message.rd());
    assert_eq!(message.question_count(), 1);
    let question = message.questions().next().unwrap();
    assert_eq!(question.name.to_string(), "www.example.com.");
    for end in 0..wire.len() {
        assert!(Message::parse(&wire[..end]).is_err());
    }
}

#[test]
fn patches_header_and_record_ttls_without_touching_opt() {
    use pharos_proto::MessageMut;
    let mut wire = b"\x00\x01\x81\x80\x00\x00\x00\x01\x00\x00\x00\x01\0\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\0\0\x01\0\x00\x29\x04\xd0\x01\x00\x80\x00\x00\x00".to_vec();
    let mut message = MessageMut::parse(&mut wire).unwrap();
    message.set_id(99);
    message.set_flags(0x8200);
    message.rewrite_ttls(|ttl| ttl / 2);
    let parsed = Message::parse(&wire).unwrap();
    assert_eq!(parsed.id(), 99);
    assert!(parsed.tc());
    assert_eq!(parsed.answers().next().unwrap().ttl, 30);
    assert_eq!(parsed.additionals().next().unwrap().ttl, 0x01008000);
}

#[test]
fn hostile_counts_and_compression_are_rejected() {
    for wire in [
        &b"\0\0\0\0\xff\xff\0\0\0\0\0\0"[..],
        &b"\0\0\0\0\0\x01\0\0\0\0\0\0\xc0\x0c\0\x01\0\x01"[..],
        &b"\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\x01\0\x01\0\0\0\0\0\x02\x01"[..],
    ] {
        assert!(Message::parse(wire).is_err());
    }
}

#[test]
fn reads_flags_counts_and_record_offsets() {
    let wire = b"\xab\xcd\xff\xff\x00\x01\x00\x01\x00\x01\x00\x01\x01x\0\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x78\x00\x04\x7f\x00\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x00\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x02\x00\x00";
    let message = Message::parse(wire).unwrap();
    assert_eq!(message.id(), 0xabcd);
    assert!(message.qr() && message.aa() && message.tc() && message.rd());
    assert!(message.ra() && message.z() && message.ad() && message.cd());
    assert_eq!(
        (
            message.question_count(),
            message.answer_count(),
            message.authority_count(),
            message.additional_count()
        ),
        (1, 1, 1, 1)
    );
    let answer = message.answers().next().unwrap();
    assert_eq!(answer.name.to_string(), "x.");
    assert_eq!(answer.ttl, 120);
    assert_eq!(answer.rdata, &[127, 0, 0, 1]);
    assert_eq!(
        &wire[answer.rdata_offset..answer.rdata_offset + 4],
        answer.rdata
    );
    assert_eq!(message.authorities().next().unwrap().ttl, 1);
    assert_eq!(message.additionals().next().unwrap().ttl, 2);
}

#[test]
fn rejects_compression_bombs() {
    let mut wire = vec![0; 12];
    wire[7] = 2; // Answer count
    wire.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 2, 0]); // root, RR header, 512-byte RDATA
    for n in 0..256 {
        let target: usize = if n == 0 { 12 } else { 23 + 2 * (n - 1) };
        wire.push(0xc0 | (target >> 8) as u8);
        wire.push(target as u8);
    }
    let target = 23 + 2 * 255;
    wire.extend_from_slice(&[0xc0 | (target >> 8) as u8, target as u8]);
    wire.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert!(Message::parse(&wire).is_err());
}

proptest::proptest! {
    #[test]
    fn arbitrary_messages_never_panic(wire in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
        if let Ok(message) = Message::parse(&wire) {
            for q in message.questions() { for _ in q.name.labels() {} }
            for r in message.answers().chain(message.authorities()).chain(message.additionals()) {
                for _ in r.name.labels() {}
                let _ = (r.rdata, r.ttl_offset);
            }
            let mut mutable = wire.clone();
            let mut editor = pharos_proto::MessageMut::parse(&mut mutable).unwrap();
            editor.rewrite_ttls(|ttl| ttl.saturating_sub(1));
        }
    }
}

#[test]
fn rewriting_ttl_does_not_panic_when_compression_points_into_a_ttl() {
    let mut wire =
        b"\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\x01\0\x01\0\0\0\x01\0\0\xc0\x11\0\x01\0\x01\0\0\0\x02\0\0"
            .to_vec();
    let mut message = pharos_proto::MessageMut::parse(&mut wire).unwrap();
    message.rewrite_ttls(|_| 0xff000000);
}

#[test]
fn accepts_trailing_bytes_like_coredns() {
    let wire = b"\0\0\0\0\0\0\0\0\0\0\0\0\xff";
    let message = Message::parse(wire).unwrap();
    assert_eq!(message.question_count(), 0);
    assert_eq!(message.answer_count(), 0);
}

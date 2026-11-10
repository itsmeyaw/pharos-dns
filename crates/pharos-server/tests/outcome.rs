#![forbid(unsafe_code)]

use pharos_proto::{Class, Message, MessageBuilder, NameRef, Rcode, Section, Type};
use pharos_server::{Action, Error, Outcome, Protocol, finish_outcome};

fn query(edns: bool) -> Vec<u8> {
    let mut wire = vec![
        0x12,
        0x34,
        1,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        u8::from(edns),
        1,
        b'a',
        0,
        0,
        1,
        0,
        1,
    ];
    if edns {
        wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0]);
    }
    wire
}

fn response(count: usize) -> Vec<u8> {
    let mut wire = Vec::with_capacity(65535);
    let name = NameRef::parse(&[1, b'a', 0], 0).unwrap();
    let mut builder = MessageBuilder::new(&mut wire, 65535, 0x1234, 0x8180).unwrap();
    builder.question(name, Type::A, Class::IN).unwrap();
    for _ in 0..count {
        builder
            .record(Section::Answer, name, Type::TXT, Class::IN, 10, &[42; 150])
            .unwrap();
    }
    let _ = builder.finish();
    wire
}

#[test]
fn truncates_at_record_boundary_and_preserves_compression() {
    let wire = query(false);
    let query = Message::parse(&wire).unwrap();
    let mut response = response(8);
    assert_eq!(
        finish_outcome(
            query,
            Protocol::Udp,
            Outcome::Response,
            &mut response,
            |_| panic!()
        ),
        Action::Respond
    );
    let message = Message::parse(&response).unwrap();
    assert!(response.len() <= 512);
    assert!(message.tc());
    assert_eq!(message.answer_count(), 3);
    assert_eq!(message.authority_count(), 0);
    assert_eq!(message.additional_count(), 0);
    assert!(message.answers().all(|rr| rr.name.to_string() == "a."));
}

#[test]
fn edns_response_opt_is_copied_and_small_response_is_unchanged() {
    let wire = query(true);
    let query = Message::parse(&wire).unwrap();
    let mut response = response(8);
    assert_eq!(
        finish_outcome(
            query,
            Protocol::Udp,
            Outcome::Response,
            &mut response,
            |_| panic!()
        ),
        Action::Respond
    );
    let message = Message::parse(&response).unwrap();
    assert!(response.len() <= 1232);
    assert!(message.tc());
    assert_eq!(message.opt().unwrap().udp_payload_size(), 1232);
    assert!(message.opt().unwrap().dnssec_ok());

    let wire = self::query(false);
    let mut small = self::response(1);
    let original = small.clone();
    finish_outcome(
        Message::parse(&wire).unwrap(),
        Protocol::Udp,
        Outcome::Response,
        &mut small,
        |_| panic!(),
    );
    assert_eq!(small, original);
}

#[test]
fn errors_are_logged_and_answered_and_other_codes_are_dropped() {
    let wire = query(false);
    let query = Message::parse(&wire).unwrap();
    let mut response = Vec::with_capacity(512);
    let mut logged = None;
    assert_eq!(
        finish_outcome(
            query,
            Protocol::Udp,
            Outcome::Error(Error::NoNextPlugin),
            &mut response,
            |e| logged = Some(e)
        ),
        Action::Respond
    );
    assert_eq!(logged, Some(Error::NoNextPlugin));
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
    for code in [
        Rcode::SERVFAIL,
        Rcode::REFUSED,
        Rcode::FORMERR,
        Rcode::NOTIMP,
    ] {
        assert_eq!(
            finish_outcome(
                query,
                Protocol::Udp,
                Outcome::Unanswered(code),
                &mut response,
                |_| panic!()
            ),
            Action::Respond
        );
        assert_eq!(Message::parse(&response).unwrap().rcode(), code);
    }
    assert_eq!(
        finish_outcome(
            query,
            Protocol::Udp,
            Outcome::Unanswered(Rcode::NXDOMAIN),
            &mut response,
            |_| panic!()
        ),
        Action::Drop
    );
    assert_eq!(
        finish_outcome(
            query,
            Protocol::Udp,
            Outcome::Drop,
            &mut response,
            |_| panic!()
        ),
        Action::Drop
    );
}

#[test]
fn nonfinal_opt_keeps_its_options_and_discards_following_records() {
    let wire = query(true);
    let query = Message::parse(&wire).unwrap();
    let mut response = response(1);
    response[11] = 2;
    response.extend_from_slice(&[0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 5, 0, 3, 0, 1, b'x']);
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1]);
    assert_eq!(
        finish_outcome(
            query,
            Protocol::Udp,
            Outcome::Response,
            &mut response,
            |_| panic!()
        ),
        Action::Respond
    );
    let message = Message::parse(&response).unwrap();
    assert!(message.tc());
    assert_eq!(message.additional_count(), 1);
    let opt = message.opt().unwrap();
    assert_eq!(opt.udp_payload_size(), 1232);
    assert_eq!(opt.options().as_bytes(), &[0, 3, 0, 1, b'x']);
}

#[test]
fn response_opt_is_removed_when_query_has_no_edns() {
    let wire = query(false);
    let mut response = response(1);
    response[11] = 1;
    response.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0]);
    assert_eq!(
        finish_outcome(
            Message::parse(&wire).unwrap(),
            Protocol::Udp,
            Outcome::Response,
            &mut response,
            |_| panic!()
        ),
        Action::Respond
    );
    let result = Message::parse(&response).unwrap();
    assert!(result.opt().is_none());
    assert!(!result.tc());
}

#[test]
fn unanswered_tcp_response_can_append_edns_to_an_empty_buffer() {
    let mut wire = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 14];
    wire.extend_from_slice(b"abcdefghijklmn");
    wire.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0]);
    let mut response = Vec::new();
    let mut logged = false;
    let action = finish_outcome(
        Message::parse(&wire).unwrap(),
        Protocol::Tcp,
        Outcome::Unanswered(Rcode::REFUSED),
        &mut response,
        |_| logged = true,
    );
    assert_eq!(action, Action::Respond);
    assert!(!logged);
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.rcode(), Rcode::REFUSED);
    assert_eq!(message.opt().unwrap().udp_payload_size(), 1232);
}

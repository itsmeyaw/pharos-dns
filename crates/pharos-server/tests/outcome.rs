#![forbid(unsafe_code)]

use pharos_proto::{Class, Message, MessageBuilder, NameRef, Rcode, Section, Type};
use pharos_server::{Action, Error, Outcome, Protocol, finish_outcome, response_limit};

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

fn response_with_two_rrsets() -> Vec<u8> {
    let mut wire = Vec::with_capacity(65535);
    let first = NameRef::parse(&[1, b'a', 0], 0).unwrap();
    let second = NameRef::parse(&[1, b'b', 0], 0).unwrap();
    let mut builder = MessageBuilder::new(&mut wire, 65535, 0x1234, 0x8180).unwrap();
    builder.question(first, Type::A, Class::IN).unwrap();
    builder
        .record(Section::Answer, first, Type::TXT, Class::IN, 10, &[1; 10])
        .unwrap();
    for _ in 0..8 {
        builder
            .record(
                Section::Answer,
                second,
                Type::TXT,
                Class::IN,
                10,
                &[42; 150],
            )
            .unwrap();
    }
    let _ = builder.finish();
    wire
}

#[test]
fn truncation_does_not_emit_a_partial_required_rrset() {
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
    assert_eq!(message.answer_count(), 0);
    assert_eq!(message.authority_count(), 0);
    assert_eq!(message.additional_count(), 0);
}

#[test]
fn truncation_keeps_earlier_complete_rrsets() {
    let mut response = response_with_two_rrsets();
    assert_eq!(
        finish_outcome(
            Message::parse(&query(false)).unwrap(),
            Protocol::Udp,
            Outcome::Response,
            &mut response,
            |_| panic!()
        ),
        Action::Respond
    );
    let message = Message::parse(&response).unwrap();
    assert!(message.tc());
    assert_eq!(message.answer_count(), 1);
    assert_eq!(message.answers().next().unwrap().name.to_string(), "a.");
}

fn truncated(sections: &[(Section, &[u8], usize)]) -> Message<'static> {
    let mut wire = Vec::with_capacity(65535);
    let question = NameRef::parse(&[1, b'q', 0], 0).unwrap();
    let mut builder = MessageBuilder::new(&mut wire, 65535, 0x1234, 0x8180).unwrap();
    builder.question(question, Type::A, Class::IN).unwrap();
    for (section, name, len) in sections {
        let name = NameRef::parse(name, 0).unwrap();
        builder
            .record(*section, name, Type::TXT, Class::IN, 10, &vec![7; *len])
            .unwrap();
    }
    let _ = builder.finish();
    let query = query(false);
    finish_outcome(
        Message::parse(&query).unwrap(),
        Protocol::Udp,
        Outcome::Response,
        &mut wire,
        |_| panic!(),
    );
    assert!(wire.len() <= 512);
    // Leak the small buffer so the parsed Message can outlive this helper.
    Message::parse(Box::leak(wire.into_boxed_slice())).unwrap()
}

const A: &[u8] = &[1, b'a', 0];
const B: &[u8] = &[1, b'b', 0];
const UPPER_A: &[u8] = &[1, b'A', 0];

// RFC 2181 §9: An RRset interleaved with another and split by the cutoff is dropped whole.
#[test]
fn truncation_drops_an_interleaved_rrset_split_by_the_cutoff() {
    let message = truncated(&[
        (Section::Answer, A, 200),
        (Section::Answer, B, 200),
        (Section::Answer, A, 200),
    ]);
    assert!(message.tc());
    assert_eq!(message.answer_count(), 0);
}

// RFC 2181 §9: An RRset repeated in Answer and Authority is one set for truncation.
#[test]
fn truncation_groups_an_rrset_across_answer_and_authority() {
    let message = truncated(&[
        (Section::Answer, A, 200),
        (Section::Answer, B, 200),
        (Section::Authority, A, 200),
    ]);
    assert!(message.tc());
    assert_eq!((message.answer_count(), message.authority_count()), (0, 0));
}

// RFC 4343 §3: Owner names that differ only in case belong to one RRset.
#[test]
fn truncation_groups_case_variant_owner_names() {
    let message = truncated(&[
        (Section::Answer, A, 200),
        (Section::Answer, B, 200),
        (Section::Answer, UPPER_A, 200),
    ]);
    assert!(message.tc());
    assert_eq!(message.answer_count(), 0);
}

// RFC 2181 §9: Truncation inside Authority keeps earlier complete Answer RRsets.
#[test]
fn authority_rrset_split_by_the_cutoff_is_dropped() {
    let message = truncated(&[
        (Section::Answer, A, 50),
        (Section::Authority, B, 200),
        (Section::Authority, B, 200),
        (Section::Authority, B, 200),
    ]);
    assert!(message.tc());
    assert_eq!((message.answer_count(), message.authority_count()), (1, 0));
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
    assert_eq!(message.opt().unwrap().udp_payload_size(), 4096);
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
    assert!(!message.tc());
    assert_eq!(message.additional_count(), 1);
    let opt = message.opt().unwrap();
    assert_eq!(opt.udp_payload_size(), 4096);
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
fn response_opt_advertises_server_capacity_and_respects_client_limit() {
    let mut wire = query(true);
    wire[22..24].copy_from_slice(&512_u16.to_be_bytes());
    let query = Message::parse(&wire).unwrap();
    let mut response = response(0);
    finish_outcome(
        query,
        Protocol::Udp,
        Outcome::Response,
        &mut response,
        |_| panic!(),
    );
    let message = Message::parse(&response).unwrap();
    assert!(response.len() <= 512);
    assert_eq!(message.opt().unwrap().udp_payload_size(), 4096);
}

#[test]
fn udp_response_limit_honors_client_and_server_caps() {
    for (edns, requested, expected) in [
        (false, 0, 512),
        (true, 128, 512),
        (true, 1232, 1232),
        (true, u16::MAX, 4096),
    ] {
        let mut wire = query(edns);
        if edns {
            wire[22..24].copy_from_slice(&requested.to_be_bytes());
        }
        assert_eq!(
            response_limit(Message::parse(&wire).unwrap(), Protocol::Udp),
            expected
        );
    }
}

#[test]
fn echoes_ecs_and_preserves_requested_upstream_ad() {
    let mut wire = query(true);
    let ecs = [0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2];
    wire[28..30].copy_from_slice(&(ecs.len() as u16).to_be_bytes());
    wire.extend_from_slice(&ecs);
    let query = Message::parse(&wire).unwrap();
    let mut response = response(0);
    response[3] |= 0x20;
    finish_outcome(
        query,
        Protocol::Udp,
        Outcome::Response,
        &mut response,
        |_| panic!(),
    );
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.opt().unwrap().options().as_bytes(), &ecs);
    assert!(message.ad());
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
    assert_eq!(message.opt().unwrap().udp_payload_size(), 4096);
}

#[test]
fn signed_response_reserves_room_before_truncation() {
    use pharos_proto::{TsigAlgorithm, TsigKey};
    use pharos_server::{TsigSigning, finish_outcome_signed};
    use std::sync::Arc;
    let key = Arc::new(TsigKey::new(
        "key.".parse().unwrap(),
        TsigAlgorithm::Sha256,
        b"secret",
    ));
    let mut wire = query(false);
    key.sign(&mut wire, 1_000, 300, None).unwrap();
    let mac = key.verify(&wire, 1_000, None, 0).unwrap().mac;
    let query = Message::parse(&wire).unwrap();
    let mut response = response(8);
    response[3] |= 0x20;
    let signing = TsigSigning::Signed {
        key: Arc::clone(&key),
        time: 1_000,
        fudge: 300,
        reserved: 5 + 26 + 13 + 32,
    };
    assert_eq!(
        finish_outcome_signed(
            query,
            Protocol::Udp,
            Outcome::Response,
            &mut response,
            Some(signing),
            |e| panic!("{e}")
        ),
        Action::Respond
    );
    assert!(response.len() <= 512);
    assert!(Message::parse(&response).unwrap().tc());
    assert_eq!(Message::parse(&response).unwrap().answer_count(), 0);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOERROR);
    assert!(Message::parse(&response).unwrap().ad());
    key.verify(&response, 1_000, Some(mac), 0).unwrap();
}

#[test]
fn signing_failure_never_emits_unsigned_response() {
    use pharos_proto::{TsigAlgorithm, TsigKey};
    use pharos_server::{TsigSigning, finish_outcome_signed};
    use std::sync::Arc;
    let mut wire = query(false);
    let key = Arc::new(TsigKey::new(
        "key.".parse().unwrap(),
        TsigAlgorithm::Sha256,
        b"secret",
    ));
    key.sign(&mut wire, 1_000, 300, None).unwrap();
    let mut response = response(1);
    let signing = TsigSigning::Signed {
        key,
        time: 1_000,
        fudge: 300,
        reserved: 513,
    };
    assert_eq!(
        finish_outcome_signed(
            Message::parse(&wire).unwrap(),
            Protocol::Udp,
            Outcome::Response,
            &mut response,
            Some(signing),
            |_| {}
        ),
        Action::Drop
    );
}

#[test]
fn unsigned_finalization_still_removes_tsig_following_opt() {
    let wire = query(true);
    let mut response = response(1);
    response[11] = 1;
    response.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    let key = pharos_proto::TsigKey::new(
        "key.".parse().unwrap(),
        pharos_proto::TsigAlgorithm::Sha256,
        b"secret",
    );
    key.sign(&mut response, 1_000, 300, Some(&[0; 32])).unwrap();
    finish_outcome(
        Message::parse(&wire).unwrap(),
        Protocol::Udp,
        Outcome::Response,
        &mut response,
        |e| panic!("{e}"),
    );
    let message = Message::parse(&response).unwrap();
    assert!(!message.tc());
    assert_eq!(message.additional_count(), 1);
    assert!(message.opt().is_some());
}

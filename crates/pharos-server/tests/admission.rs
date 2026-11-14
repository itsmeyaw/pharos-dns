#![forbid(unsafe_code)]

use pharos_proto::{Message, Rcode};
use pharos_server::{Admission, admit, admit_with_update};

fn valid() -> Vec<u8> {
    vec![
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
    ]
}

#[test]
fn rejects_invalid_queries_and_honors_class_flag() {
    let mut response = Vec::with_capacity(512);
    for wire in [&[][..], &[0][..], &[0, 1][..], &[0, 1, 1][..]] {
        assert!(matches!(admit(wire, false, &mut response), Admission::Drop));
    }
    assert!(matches!(
        admit(&[0; 11], false, &mut response),
        Admission::Respond
    ));
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::FORMERR);
    let mut wire = valid();
    wire[2] = 0x10;
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Respond
    ));
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOTIMP);
    wire = valid();
    wire.truncate(15);
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Respond
    ));
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::FORMERR);
    wire = valid();
    *wire.last_mut().unwrap() = 3;
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Respond
    ));
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
    assert!(matches!(
        admit(&wire, true, &mut response),
        Admission::Query(_)
    ));
}

#[test]
fn bad_edns_version_is_answered_before_chain() {
    let mut wire = valid();
    wire[11] = 1;
    wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 1, 0x80, 0, 0, 0]);
    let mut response = Vec::with_capacity(512);
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Respond
    ));
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::BADVERS);
}

#[test]
fn accepts_zero_question_queries_and_ignores_reserved_z() {
    let mut wire = valid();
    wire[5] = 0;
    let mut response = Vec::with_capacity(512);
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Query(_)
    ));

    let mut wire = valid();
    wire[3] |= 0x40;
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Query(_)
    ));
}

#[test]
fn error_responses_copy_only_rd_cd_and_keep_opcode() {
    let mut wire = valid();
    wire[2..4].copy_from_slice(&0x03b0_u16.to_be_bytes());
    wire[5] = 2;
    let mut response = Vec::with_capacity(512);
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Respond
    ));
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.flags() & 0x03b0, 0x0110);

    let mut wire = valid();
    wire[2] = 0x10;
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Respond
    ));
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.opcode().0, 2);
}

#[test]
fn error_response_includes_opt_for_unsupported_opcode_and_bad_options() {
    let mut wire = valid();
    wire[2] = 0x18;
    wire[11] = 1;
    wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    let mut response = Vec::with_capacity(512);
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Respond
    ));
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.rcode(), Rcode::NOTIMP);
    assert!(message.opt().is_some());
    assert_eq!(message.question_count(), 1);

    let mut wire = valid();
    wire[11] = 1;
    wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 1, 0xff]);
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Respond
    ));
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.rcode(), Rcode::FORMERR);
    assert!(message.opt().is_some());
}

#[test]
fn notify_ignores_authority_and_additional_sections() {
    let mut wire = valid();
    wire[2..4].copy_from_slice(&0x2000_u16.to_be_bytes());
    wire[7] = 2;
    wire[9] = 20;
    wire[11] = 20;
    for _ in 0..2 {
        wire.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1]);
    }
    wire.push(0xff);
    let mut response = Vec::with_capacity(512);
    let Admission::Query(query) = admit(&wire, false, &mut response) else {
        panic!("valid NOTIFY must reach the handler")
    };
    assert_eq!(query.answer_count(), 2);
    assert_eq!(query.authority_count(), 0);
    assert_eq!(query.additional_count(), 0);
}

#[test]
fn notify_ignores_valid_authority_and_additional_records() {
    let mut wire = valid();
    wire[2..4].copy_from_slice(&0x2000_u16.to_be_bytes());
    wire[8..12].copy_from_slice(&[0, 1, 0, 1]);
    for address in [[192, 0, 2, 1], [192, 0, 2, 2]] {
        wire.extend_from_slice(&[
            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, address[0], address[1], address[2],
            address[3],
        ]);
    }
    let mut response = Vec::with_capacity(512);
    let Admission::Query(query) = admit(&wire, false, &mut response) else {
        panic!("valid NOTIFY must reach the handler")
    };
    assert_eq!(query.authority_count(), 0);
    assert_eq!(query.additional_count(), 0);
    assert_eq!(query.authorities().count(), 0);
    assert_eq!(query.additionals().count(), 0);
}

#[test]
fn notify_requires_a_question_but_allows_multiple_questions() {
    let mut response = Vec::with_capacity(512);
    let mut wire = valid();
    wire[2..4].copy_from_slice(&0x2000_u16.to_be_bytes());
    wire[4..6].copy_from_slice(&0_u16.to_be_bytes());
    wire.truncate(12);
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Respond
    ));
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::FORMERR);

    wire = valid();
    wire[2..4].copy_from_slice(&0x2000_u16.to_be_bytes());
    wire[4..6].copy_from_slice(&2_u16.to_be_bytes());
    let question = wire[12..].to_vec();
    wire.extend_from_slice(&question);
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Query(_)
    ));
}

#[test]
fn rejects_tsig_before_final_additional_record() {
    let mut wire = valid();
    wire[10..12].copy_from_slice(&2_u16.to_be_bytes());
    wire.extend_from_slice(&[0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 0]);
    wire.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 1]);
    let mut response = Vec::with_capacity(512);
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Respond
    ));
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::FORMERR);
}

#[test]
fn dso_unidirectional_messages_are_suppressed_and_dso_errors_clear_reserved_bits() {
    let mut wire = [0, 0, 0x30, 0x30, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut response = Vec::with_capacity(512);
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Drop
    ));

    wire[1] = 1;
    wire[5] = 1;
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Respond
    ));
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.id(), 1);
    assert_eq!(message.flags(), 0xb001);

    wire[5] = 0;
    assert!(matches!(
        admit(&wire, false, &mut response),
        Admission::Respond
    ));
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.rcode(), Rcode::NOTIMP);
    assert_eq!(message.flags(), 0xb004);
}

#[test]
fn malformed_update_formerr_preserves_opcode() {
    let mut wire = valid();
    wire[2] = 0x28;
    wire[5] = 2;
    let mut response = Vec::with_capacity(512);
    assert!(matches!(
        admit_with_update(&wire, false, true, &mut response),
        Admission::Respond
    ));
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.opcode().0, 5);
    assert_eq!(message.rcode(), Rcode::FORMERR);
}

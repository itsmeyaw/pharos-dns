#![forbid(unsafe_code)]

use pharos_proto::{Message, Rcode};
use pharos_server::{Admission, admit};

fn valid() -> Vec<u8> {
    vec![
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
    ]
}

#[test]
fn rejects_invalid_queries_and_honors_class_flag() {
    let mut response = Vec::with_capacity(512);
    assert!(matches!(
        admit(&[0; 11], false, &mut response),
        Admission::Drop
    ));
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

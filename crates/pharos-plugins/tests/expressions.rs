#![forbid(unsafe_code)]

use pharos_plugins::expression::{Expression, Query, Scratch, Value};
use pharos_proto::Message;
use pharos_server::{Metadata, Protocol};

const WIRE: &[u8] =
    b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";

#[test]
fn boolean_literals_are_compiled_and_evaluated_against_borrowed_query() {
    let message = Message::parse(WIRE).unwrap();
    let query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut buffer = [0; 2048];
    let mut scratch = Scratch::new(&mut buffer);
    for (source, expected) in [("true", true), ("false", false)] {
        let expression = Expression::compile(source).unwrap();
        assert_eq!(
            expression
                .evaluate(&query, &metadata, &mut scratch)
                .unwrap(),
            Value::Bool(expected)
        );
    }
    assert!(Expression::compile("undefined").is_err());
}

#[test]
fn arithmetic_comparisons_and_logical_operators_follow_precedence() {
    let message = Message::parse(WIRE).unwrap();
    let query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut buffer = [0; 2048];
    let mut scratch = Scratch::new(&mut buffer);
    for source in [
        "1 + 2 * 3 == 7 && !false",
        "not (4 <= 3) and 5 - 2 == 3",
        "true || 1 / 0 == 1",
        "'abc' < 'b'",
        "2 * (3 + 4) == 14",
    ] {
        assert_eq!(
            Expression::compile(source)
                .unwrap()
                .evaluate(&query, &metadata, &mut scratch)
                .unwrap(),
            Value::Bool(true),
            "{source}"
        );
    }
    for source in ["1 +", "true and 1", "1 + 'x'", "(true"] {
        assert!(Expression::compile(source).is_err(), "{source}");
    }
}

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

#[test]
fn query_and_metadata_functions_read_borrowed_data() {
    let message = Message::parse(WIRE).unwrap();
    let query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    let mut slots = [None];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert("test/region", "eu"));
    let mut buffer = [0; 2048];
    let mut scratch = Scratch::new(&mut buffer);
    for source in [
        "name() == 'example.org.'",
        "type() == 'A' && class() == 'IN'",
        "metadata('test/region') == 'eu'",
        "metadata('missing') == ''",
        "client_ip() == '10.0.0.1' && port() == '1234'",
        "server_ip() == '127.0.0.1' && server_port() == '53'",
        "proto() == 'udp' && id() == 1053 && opcode() == 0 && !do()",
        "size() == 29 && bufsize() == 512",
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
    assert!(Expression::compile("name(1)").is_err());
    assert!(Expression::compile("metadata()").is_err());
}

#[test]
fn query_size_expands_compressed_names_like_coredns() {
    let mut wire = WIRE.to_vec();
    wire[5] = 2;
    wire.extend_from_slice(b"\xc0\x0c\x00\x01\x00\x01");
    let message = Message::parse(&wire).unwrap();
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
    assert_eq!(
        Expression::compile("size()")
            .unwrap()
            .evaluate(&query, &metadata, &mut scratch)
            .unwrap(),
        Value::Int(46)
    );
}

#[test]
fn list_membership_and_string_operators_follow_expr() {
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
        "type() in ['A', 'AAAA']",
        "name() contains 'ample'",
        "name() startsWith 'example'",
        "name() endsWith '.org.'",
        "2 in [1, 2, 3]",
        "not (3 in [])",
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
    for source in ["1 in '123'", "1 contains 'x'", "'a' in [1]"] {
        assert!(Expression::compile(source).is_err(), "{source}");
    }
}

#[test]
fn coredns_name_regex_is_compiled_at_setup() {
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
    let expression = Expression::compile(r"name() matches '^example\\.org\\.$'").unwrap();
    assert_eq!(
        expression
            .evaluate(&query, &metadata, &mut scratch)
            .unwrap(),
        Value::Bool(true)
    );
    assert!(Expression::compile("name() matches '['").is_err());
    assert!(Expression::compile("name() matches metadata('pattern')").is_err());
}

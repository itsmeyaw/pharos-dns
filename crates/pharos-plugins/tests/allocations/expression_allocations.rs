#![forbid(unsafe_code)]

use pharos_plugins::expression::{Expression, Query, Scratch, Value};
use pharos_proto::Message;
use pharos_server::{Metadata, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region};

#[test]
fn query_functions_and_regex_do_not_allocate() {
    if crate::run_isolated(
        "expression::expression_allocations::query_functions_and_regex_do_not_allocate",
    ) {
        return;
    }
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    let mut slots = [None];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert("test/region", "eu"));
    let expression = Expression::compile(r"name() matches '^example\\.org\\.$' && metadata('test/region') == 'eu' && type() in ['A', 'AAAA']").unwrap();
    let mut bytes = [0; 2048];
    let mut scratch = Scratch::new(&mut bytes);
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    let value = expression
        .evaluate(&query, &metadata, &mut scratch)
        .unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(value, Value::Bool(true));
}

#[test]
fn replace_and_any_do_not_allocate() {
    if crate::run_isolated("expression::expression_allocations::replace_and_any_do_not_allocate") {
        return;
    }
    let wire =
        b"\x04\x1d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let mut query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    query.groups = &[("ip", "192-168-1-2")];
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let expression = Expression::compile(
        "any(['10.0.0.0/8', '192.168.0.0/16'], incidr(replace(group('ip'), '-', '.'), #))",
    )
    .unwrap();
    let mut bytes = [0; 2048];
    let mut scratch = Scratch::new(&mut bytes);
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    let value = expression
        .evaluate(&query, &metadata, &mut scratch)
        .unwrap();
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert_eq!(value, Value::Bool(true));
}

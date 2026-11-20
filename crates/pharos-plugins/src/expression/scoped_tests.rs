use super::*;

#[test]
fn variable_slice_can_grow_after_scoped_evaluation() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let message = Message::parse(wire).unwrap();
    let query = Query::new(
        &message,
        "127.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    let mut metadata_slots = [];
    let metadata = Metadata::new(&mut metadata_slots);
    let first = Expression::compile("name").unwrap();
    let second = Expression::compile_with_variables("f", &[("f", ValueType::Function)]).unwrap();
    let mut variables = Vec::with_capacity(2);
    let mut buffer = [0; 16];
    let scoped = ScopedQuery::new(&query, &variables);
    let (function, rest) = first
        .evaluate_scoped_split(&scoped, &metadata, &mut buffer)
        .unwrap();
    variables.push(("f", function));
    let scoped = ScopedQuery::new(&query, &variables);
    let (copy, _) = second
        .evaluate_scoped_split(&scoped, &metadata, rest)
        .unwrap();
    variables.push(("copy", copy));
    assert!(matches!(variables[1].1, Value::Function(_)));
}

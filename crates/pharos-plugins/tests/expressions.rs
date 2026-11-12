#![forbid(unsafe_code)]

use pharos_plugins::expression::{Expression, Query, Scratch, Value, ValueType};
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

#[test]
fn incidr_handles_ipv4_ipv6_and_reports_invalid_arguments() {
    let message = Message::parse(WIRE).unwrap();
    let query = Query::new(
        &message,
        "10.1.2.3:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut buffer = [0; 2048];
    let mut scratch = Scratch::new(&mut buffer);
    for source in [
        "incidr(client_ip(), '10.0.0.0/8')",
        "incidr('2001:db8::1', '2001:db8::/32')",
        "incidr('192.0.2.1', '0.0.0.0/0')",
        "incidr('::ffff:192.0.2.1', '192.0.2.0/24')",
        "incidr('192.0.2.1', '::ffff:192.0.2.0/120')",
        "not incidr('192.0.2.1', '2001:db8::/32')",
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
    for source in [
        "incidr('invalid', '10.0.0.0/8')",
        "incidr('10.0.0.1', '10.0.0.0/33')",
    ] {
        assert!(
            Expression::compile(source)
                .unwrap()
                .evaluate(&query, &metadata, &mut scratch)
                .is_err(),
            "{source}"
        );
    }
    assert!(Expression::compile("incidr(1, '10.0.0.0/8')").is_err());
}

#[test]
fn template_capture_groups_variables_and_int_conversion() {
    let message = Message::parse(WIRE).unwrap();
    let mut query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    query.matches = &["2.example.", "2"];
    query.groups = &[("n", "2")];
    query.variables = &[("num", Value::Int(2))];
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut buffer = [0; 2048];
    let mut scratch = Scratch::new(&mut buffer);
    for source in [
        "group('n') == '2' && group(0) == '2.example.'",
        "group('1') == '2' && group('01') == ''",
        "int(group('n')) == num && num > 1",
        "group('missing') + group(9) == ''",
        "'x' + group('n') == 'x2'",
    ] {
        let expression =
            Expression::compile_with_variables(source, &[("num", ValueType::Int)]).unwrap();
        assert_eq!(
            expression
                .evaluate(&query, &metadata, &mut scratch)
                .unwrap(),
            Value::Bool(true),
            "{source}"
        );
    }
    assert!(Expression::compile("num > 1").is_err());
    assert!(
        Expression::compile("int('invalid')")
            .unwrap()
            .evaluate(&query, &metadata, &mut scratch)
            .is_err()
    );
}

#[test]
fn documented_template_replace_and_any_expression() {
    let message = Message::parse(WIRE).unwrap();
    let mut query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    query.groups = &[("ip", "192-168-1-2")];
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut buffer = [0; 2048];
    let mut scratch = Scratch::new(&mut buffer);
    let ip = Expression::compile("replace(group('ip'), '-', '.')").unwrap();
    assert_eq!(
        ip.evaluate(&query, &metadata, &mut scratch).unwrap(),
        Value::String("192.168.1.2")
    );
    query.variables = &[("ip", Value::String("192.168.1.2"))];
    let expr = Expression::compile_with_variables(
        "any(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'], incidr(ip, #))",
        &[("ip", ValueType::String)],
    )
    .unwrap();
    assert_eq!(
        expr.evaluate(&query, &metadata, &mut scratch).unwrap(),
        Value::Bool(true)
    );
    assert!(Expression::compile("#").is_err());
    assert!(Expression::compile("any([1], #)").is_err());
}

#[test]
fn replace_and_any_handle_unicode_empty_lists_and_nested_predicates() {
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
        "replace('áx', '', '-') == '-á-x-'",
        "replace('aaa', 'aa', 'b') == 'ba'",
        "not any([], true)",
        "any([1, 2], # == 2 && any([3], # == 3))",
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
}

#[test]
fn replace_optional_count_matches_expr_builtin() {
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
        "replace('foo,bar,baz,goo', ',', ';', 2) == 'foo;bar;baz,goo'",
        "replace('abc', '', '-', 2) == '-a-bc'",
        "replace('abc', 'b', 'x', 0) == 'abc'",
        "replace('aaa', 'a', 'b', -1) == 'bbb'",
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
}

#[test]
fn chained_variables_keep_borrowed_string_results_in_separate_scratch() {
    let message = Message::parse(WIRE).unwrap();
    let mut query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    query.groups = &[("ip", "192-168-1-2")];
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut first = [0; 2048];
    let mut first_scratch = Scratch::new(&mut first);
    let ip = Expression::compile("replace(group('ip'), '-', '.')").unwrap();
    assert_eq!(ip.value_type(), ValueType::String);
    let value = ip.evaluate(&query, &metadata, &mut first_scratch).unwrap();
    let variables = [("ip", value)];
    let mut next = Query::new(&message, query.client, query.local, query.protocol);
    next.variables = &variables;
    let expression = Expression::compile_with_variables(
        "incidr(ip, '192.168.0.0/16')",
        &[("ip", ip.value_type())],
    )
    .unwrap();
    let mut second = [0; 2048];
    let mut second_scratch = Scratch::new(&mut second);
    assert_eq!(
        expression
            .evaluate(&next, &metadata, &mut second_scratch)
            .unwrap(),
        Value::Bool(true)
    );
}

#[test]
fn negated_membership_and_string_operators_match_expr() {
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
        "3 not in [1, 2]",
        "'abc' not contains 'z'",
        "'abc' not startsWith 'z'",
        "'abc' not endsWith 'z'",
        "name() not matches '^other'",
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
}

#[test]
fn query_functions_handle_ipv6_tcp_edns_and_small_scratch() {
    let mut wire = WIRE.to_vec();
    wire[10..12].copy_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(b"\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00");
    let message = Message::parse(&wire).unwrap();
    let query = Query::new(
        &message,
        "[2001:db8::1]:1234".parse().unwrap(),
        "[::1]:53".parse().unwrap(),
        Protocol::Tcp,
    );
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut buffer = [0; 2048];
    let mut scratch = Scratch::new(&mut buffer);
    let expr = Expression::compile("client_ip() == '2001:db8::1' && server_ip() == '::1' && proto() == 'tcp' && do() && bufsize() == 65535").unwrap();
    assert_eq!(
        expr.evaluate(&query, &metadata, &mut scratch).unwrap(),
        Value::Bool(true)
    );
    let mut small = [0; 2];
    let mut small_scratch = Scratch::new(&mut small);
    assert!(
        Expression::compile("name()")
            .unwrap()
            .evaluate(&query, &metadata, &mut small_scratch)
            .is_err()
    );
    assert_eq!(
        Expression::compile("true")
            .unwrap()
            .evaluate(&query, &metadata, &mut small_scratch)
            .unwrap(),
        Value::Bool(true)
    );
}

#[test]
fn numeric_literals_and_division_match_expr_float_semantics() {
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
        "1 / 2 == 0.5",
        "1 + .5 == 1.5",
        "2 * 1.5 == 3",
        "int(2.9) == 2",
        "1e2 / 4 == 25",
        "1 / 0 > 10",
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
}

#[test]
fn numeric_literal_bases_and_separators_match_expr() {
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
    let expression = Expression::compile(
        "0xff == 255 && 0b10 == 2 && 0o10 == 8 && 1_000 == 1000 && 01 == 1 && 1_2.5 == 12.5",
    )
    .unwrap();
    assert_eq!(
        expression
            .evaluate(&query, &metadata, &mut scratch)
            .unwrap(),
        Value::Bool(true)
    );
    assert!(Expression::compile("0b22").is_err());
}

#[test]
fn quoted_and_raw_string_literals_decode_expr_escapes() {
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
        r"'\x41\u0042\U00000043\u{44}\105' == 'ABCDE'",
        r"`literal\n` == 'literal\\n'",
        r"`a``b` == 'a`b'",
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
    for source in [r"'\xZZ'", r"'\u{110000}'", "'unterminated"] {
        assert!(Expression::compile(source).is_err());
    }
}

#[test]
fn query_functions_normalize_mapped_addresses_and_keep_ipv6_scope() {
    let message = Message::parse(WIRE).unwrap();
    let query = Query::new(
        &message,
        "[::ffff:192.0.2.1]:1234".parse().unwrap(),
        "[fe80::1%3]:53".parse().unwrap(),
        Protocol::Udp,
    );
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut buffer = [0; 2048];
    let mut scratch = Scratch::new(&mut buffer);
    let expr =
        Expression::compile("client_ip() == '192.0.2.1' && server_ip() == 'fe80::1%3'").unwrap();
    assert_eq!(
        expr.evaluate(&query, &metadata, &mut scratch).unwrap(),
        Value::Bool(true)
    );
}

#[test]
fn typed_operators_reject_invalid_comparisons_at_startup() {
    for source in ["true < false", "true > false", "[1] == [1]", "'x' + 2"] {
        assert!(Expression::compile(source).is_err(), "{source}");
    }
}

#[test]
fn excessively_deep_or_large_expressions_fail_at_setup() {
    let nested = format!("{}true{}", "(".repeat(300), ")".repeat(300));
    assert!(Expression::compile(&nested).is_err());
    let long = format!("{}true", "true || ".repeat(600));
    assert!(Expression::compile(&long).is_err());
}

#[test]
fn disabled_metadata_is_not_exposed_to_expressions() {
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
    metadata.set_enabled(false);
    let mut buffer = [0; 2048];
    let mut scratch = Scratch::new(&mut buffer);
    let expression = Expression::compile("metadata('test/region') == ''").unwrap();
    assert_eq!(
        expression
            .evaluate(&query, &metadata, &mut scratch)
            .unwrap(),
        Value::Bool(true)
    );
}

#[test]
fn signed_remainder_extreme_matches_go_int() {
    let message = Message::parse(WIRE).unwrap();
    let mut query = Query::new(
        &message,
        "10.0.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    query.variables = &[("n", Value::Int(i64::MIN))];
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut buffer = [0; 2048];
    let mut scratch = Scratch::new(&mut buffer);
    let expression =
        Expression::compile_with_variables("n % -1 == 0", &[("n", ValueType::Int)]).unwrap();
    assert_eq!(
        expression
            .evaluate(&query, &metadata, &mut scratch)
            .unwrap(),
        Value::Bool(true)
    );
}

#[test]
fn membership_in_mixed_literal_lists_compares_each_value() {
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
        "'x' in [1, 'x', false]",
        "not ('z' in [1, 'x'])",
        "1 in ['x', 1.0]",
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
}

#[test]
fn logical_operators_short_circuit_runtime_errors() {
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
    for (source, expected) in [
        ("true || incidr('bad', '10.0.0.0/8')", true),
        ("false && 1 % 0 == 1", false),
    ] {
        assert_eq!(
            Expression::compile(source)
                .unwrap()
                .evaluate(&query, &metadata, &mut scratch)
                .unwrap(),
            Value::Bool(expected),
            "{source}"
        );
    }
    assert!(
        Expression::compile("1 % 0")
            .unwrap()
            .evaluate(&query, &metadata, &mut scratch)
            .is_err()
    );
}

#[test]
fn nil_literal_and_mixed_list_membership_are_supported() {
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
    let expression =
        Expression::compile("nil == nil && nil in [1, nil] && nil != 'x' && nil not in [1]")
            .unwrap();
    assert_eq!(
        expression
            .evaluate(&query, &metadata, &mut scratch)
            .unwrap(),
        Value::Bool(true)
    );
    assert_eq!(
        Expression::compile("nil").unwrap().value_type(),
        ValueType::Nil
    );
}

#[test]
fn coredns_chained_integer_variables_evaluate_in_order() {
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
    let a = Expression::compile("1").unwrap();
    let a_value = a.evaluate(&query, &metadata, &mut scratch).unwrap();
    let vars = [("a", a_value)];
    let mut query_b = Query::new(&message, query.client, query.local, query.protocol);
    query_b.variables = &vars;
    let b = Expression::compile_with_variables("a + 1", &[("a", a.value_type())]).unwrap();
    let mut other_buffer = [0; 2048];
    let mut other_scratch = Scratch::new(&mut other_buffer);
    let b_value = b.evaluate(&query_b, &metadata, &mut other_scratch).unwrap();
    let vars = [("a", a_value), ("b", b_value)];
    let mut last = Query::new(&message, query.client, query.local, query.protocol);
    last.variables = &vars;
    let c = Expression::compile_with_variables(
        "b * 10",
        &[("a", a.value_type()), ("b", b.value_type())],
    )
    .unwrap();
    let mut third_buffer = [0; 2048];
    let mut third_scratch = Scratch::new(&mut third_buffer);
    assert_eq!(
        c.evaluate(&last, &metadata, &mut third_scratch).unwrap(),
        Value::Int(20)
    );
}

#![forbid(unsafe_code)]

use pharos_plugins::expression::{Expression, Query, Scratch, Value, ValueType};
use pharos_plugins::gotemplate::{Data, Template};
use pharos_proto::Message;
use pharos_server::{Metadata, Protocol};

#[test]
fn view_readme_expressions_match_ipv4_ipv6_type_and_name() {
    // CoreDNS v1.15.0 plugin/view/README.md, Examples and Expressions.
    let wire = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03Abc\x03www\x07Example\x03Com\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut bytes = [0; 2048];
    let mut scratch = Scratch::new(&mut bytes);
    for (source, client, expected) in [
        (
            "incidr(client_ip(), '127.0.0.0/24')",
            "127.0.0.42:1000",
            true,
        ),
        (
            "incidr(client_ip(), '127.0.0.0/24')",
            "127.0.1.42:1000",
            false,
        ),
        (
            "incidr(client_ip(), '192.168.0.0/16')",
            "192.168.7.8:1000",
            true,
        ),
        (
            "incidr(client_ip(), '2001:0DB8::/32')",
            "[2001:db8::1]:1000",
            true,
        ),
        ("type() in ['A', 'AAAA']", "127.0.0.1:1000", true),
        (
            r"name() matches '^abc\\..*\\.example\\.com\\.$'",
            "127.0.0.1:1000",
            true,
        ),
        (
            "(type() == 'A' && name() == 'example.com.') || client_ip() == '1.2.3.4'",
            "1.2.3.4:1000",
            true,
        ),
    ] {
        let query = Query::new(
            &message,
            client.parse().unwrap(),
            "127.0.0.1:53".parse().unwrap(),
            Protocol::Udp,
        );
        assert_eq!(
            Expression::compile(source)
                .unwrap()
                .evaluate(&query, &metadata, &mut scratch)
                .unwrap(),
            Value::Bool(expected),
            "{source} / {client}"
        );
    }
    let expression = Expression::compile("type() in ['A', 'AAAA']").unwrap();
    for (qtype, expected) in [(28u16, true), (16, false)] {
        let mut wire = wire.to_vec();
        let offset = wire.len() - 4;
        wire[offset..offset + 2].copy_from_slice(&qtype.to_be_bytes());
        let message = Message::parse(&wire).unwrap();
        let query = Query::new(
            &message,
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:53".parse().unwrap(),
            Protocol::Udp,
        );
        assert_eq!(
            expression
                .evaluate(&query, &metadata, &mut scratch)
                .unwrap(),
            Value::Bool(expected)
        );
    }
}

#[test]
fn view_test_expressions_return_the_upstream_values() {
    // CoreDNS v1.15.0 plugin/view/view_test.go, TestFilter_ErrorPaths.
    let wire =
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let query = Query::new(
        &message,
        "127.0.0.1:1000".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut bytes = [0; 1024];
    let mut scratch = Scratch::new(&mut bytes);
    for (source, expected) in [
        ("name() == 'example.com.'", Value::Bool(true)),
        ("name() == 'notexample.com.'", Value::Bool(false)),
        ("1", Value::Int(1)),
    ] {
        assert_eq!(
            Expression::compile(source)
                .unwrap()
                .evaluate(&query, &metadata, &mut scratch)
                .unwrap(),
            expected
        );
    }
    assert!(
        Expression::compile("incidr('invalid', '1.2.3.0/24')")
            .unwrap()
            .evaluate(&query, &metadata, &mut scratch)
            .is_err()
    );
}

#[test]
fn template_readme_record_examples_render_expected_records() {
    // CoreDNS v1.15.0 plugin/template/README.md, Examples.
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("ip-10-11-12-13.example.", &metadata);
    data.zone = "example.";
    data.class = "IN";
    data.matches = &["example.com.dc1.example.com.", "dc1.example.com."];
    data.groups = &[("a", "10"), ("b", "11"), ("c", "12"), ("d", "13")];
    data.variables = &[("ip", Value::String("192.168.1.2"))];
    for (source, expected) in [
        (
            "invalid. 60 {{ .Class }} SOA ns.invalid. hostmaster.invalid. (1 60 60 60 60)",
            "invalid. 60 IN SOA ns.invalid. hostmaster.invalid. (1 60 60 60 60)",
        ),
        (
            "{{ .Zone }} 60 IN SOA ns.example.com hostmaster.example.com (1 60 60 60 60)",
            "example. 60 IN SOA ns.example.com hostmaster.example.com (1 60 60 60 60)",
        ),
        (
            "{{ index .Match 1 }} 60 IN SOA ns.{{ index .Match 1 }} hostmaster.{{ index .Match 1 }} (1 60 60 60 60)",
            "dc1.example.com. 60 IN SOA ns.dc1.example.com. hostmaster.dc1.example.com. (1 60 60 60 60)",
        ),
        (
            "{{ .Name }} 60 IN A {{ .Group.a }}.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}",
            "ip-10-11-12-13.example. 60 IN A 10.11.12.13",
        ),
        (
            "{{ .Name }} 60 IN PTR ip-{{ .Group.a }}-{{ .Group.b }}-{{ .Group.c }}-{{ .Group.d }}.example.",
            "ip-10-11-12-13.example. 60 IN PTR ip-10-11-12-13.example.",
        ),
        (
            "{{ .Name }} 60 IN A {{ .Var.ip }}",
            "ip-10-11-12-13.example. 60 IN A 192.168.1.2",
        ),
        (
            "{{ .Name }} 60 IN A {{ .Group.a}}.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}",
            "ip-10-11-12-13.example. 60 IN A 10.11.12.13",
        ),
        (
            "{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}",
            "ip-10-11-12-13.example. 60 IN A 10.11.12.13",
        ),
        (
            "{{ .Name }} 60 IN MX 10 {{ .Name }}",
            "ip-10-11-12-13.example. 60 IN MX 10 ip-10-11-12-13.example.",
        ),
        (
            "example. 60 IN NS ns0.example.",
            "example. 60 IN NS ns0.example.",
        ),
        (
            "example. 60 IN NS ns1.example.",
            "example. 60 IN NS ns1.example.",
        ),
        (
            "ns0.example. 60 IN A 203.0.113.8",
            "ns0.example. 60 IN A 203.0.113.8",
        ),
        (
            "ns1.example. 60 IN A 198.51.100.8",
            "ns1.example. 60 IN A 198.51.100.8",
        ),
        (
            "foogle.com 60 IN CNAME google.com",
            "foogle.com 60 IN CNAME google.com",
        ),
    ] {
        let mut output = String::new();
        Template::compile(source)
            .unwrap()
            .render(&data, &mut output)
            .unwrap();
        assert_eq!(output, expected, "{source}");
    }
}

#[test]
fn template_readme_hexadecimal_address_example() {
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("ip0a7b7b7b.example.", &metadata);
    data.groups = &[("b", "7b"), ("c", "7b"), ("d", "7b")];
    let source = "{{ .Name }} 60 IN A 10.{{ parseInt .Group.b 16 8 }}.{{ parseInt .Group.c 16 8 }}.{{ parseInt .Group.d 16 8 }}";
    let mut output = String::new();
    Template::compile(source)
        .unwrap()
        .render(&data, &mut output)
        .unwrap();
    assert_eq!(output, "ip0a7b7b7b.example. 60 IN A 10.123.123.123");
}

#[test]
fn coredns_captured_variable_expression_and_answer_are_connected() {
    // CoreDNS v1.15.0 plugin/template/expr_test.go, UsesVars and UsesGroup.
    let wire =
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x012\x07example\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let mut query = Query::new(
        &message,
        "10.240.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    query.matches = &["2.example.", "2"];
    query.groups = &[("n", "2")];
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut bytes = [0; 1024];
    let mut scratch = Scratch::new(&mut bytes);
    let Value::Int(value) = Expression::compile("int(group('n'))")
        .unwrap()
        .evaluate(&query, &metadata, &mut scratch)
        .unwrap()
    else {
        panic!("expected integer capture");
    };
    let variables = [("num", Value::Int(value))];
    query.variables = &variables;
    for source in ["num > 1", "group('n') == '2' && group(0) == '2.example.'"] {
        let expression =
            Expression::compile_with_variables(source, &[("num", ValueType::Int)]).unwrap();
        assert_eq!(
            expression
                .evaluate(&query, &metadata, &mut scratch)
                .unwrap(),
            Value::Bool(true)
        );
    }
    for (source, expected) in [
        ("num * 2", Value::Int(4)),
        ("'x' + group('n')", Value::String("x2")),
        ("group('n') != ''", Value::Bool(true)),
    ] {
        assert_eq!(
            Expression::compile_with_variables(source, &[("num", ValueType::Int)])
                .unwrap()
                .evaluate(&query, &metadata, &mut scratch)
                .unwrap(),
            expected,
            "{source}"
        );
    }
    let mut data = Data::new("2.example.", &metadata);
    data.variables = &variables;
    data.groups = query.groups;
    for source in [
        "{{ .Name }} 60 IN A 10.0.0.{{ .Var.num }}",
        "{{ .Name }} 60 IN A 10.0.0.{{ .Group.n }}",
    ] {
        let mut output = String::new();
        Template::compile(source)
            .unwrap()
            .render(&data, &mut output)
            .unwrap();
        assert_eq!(output, "2.example. 60 IN A 10.0.0.2");
    }
}

#[test]
fn coredns_setup_template_variants_and_bad_field() {
    // CoreDNS v1.15.0 plugin/template/setup_test.go, template setup cases.
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("ip.example.", &metadata);
    data.matches = &["whole", "example."];
    data.groups = &[("a", "10"), ("b", "7b"), ("c", "7b"), ("d", "7b")];
    for (source, expected) in [
        (
            "{{ index .Match 1 }} 60 IN SOA ns.{{ index .Match 1 }} hostmaster.example.com (1 60 60 60 60)",
            "example. 60 IN SOA ns.example. hostmaster.example.com (1 60 60 60 60)",
        ),
        (
            "{{ .Name }} 3600 IN A 10.{{ parseInt .Group.b 16 8 }}.{{ parseInt .Group.c 16 8 }}.{{ parseInt .Group.d 16 8 }}",
            "ip.example. 3600 IN A 10.123.123.123",
        ),
        (
            "{{ .Name }} 60 CH TXT \"test\"",
            "ip.example. 60 CH TXT \"test\"",
        ),
    ] {
        let mut output = String::new();
        Template::compile(source)
            .unwrap()
            .render(&data, &mut output)
            .unwrap();
        assert_eq!(output, expected, "{source}");
    }
    let bad = Template::compile(
        "{{ .Name }} A {{ .Group.a }}.{{ .Group.b }}.{{ .Group.c }}.{{ .Grup.d }}.",
    )
    .unwrap();
    assert!(bad.render(&data, &mut String::new()).is_err());
}

#[test]
fn coredns_expression_tests_cover_query_metadata_group_and_errors() {
    // CoreDNS v1.15.0 plugin/template/{expr,var,setup}_test.go and plugin/view/*_test.go.
    let wire =
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x07example\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let mut query = Query::new(
        &message,
        "10.240.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    query.variables = &[("a", Value::Int(1))];
    let mut slots = [None];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert("test/region", "eu"));
    let mut bytes = [0; 2048];
    let mut scratch = Scratch::new(&mut bytes);
    for (source, expected) in [
        ("name() == 'a.example.'", Value::Bool(true)),
        ("name() == 'b.example.'", Value::Bool(false)),
        ("type() == 'A'", Value::Bool(true)),
        ("incidr(client_ip(), '10.0.0.0/8')", Value::Bool(true)),
        ("incidr(client_ip(), '192.0.2.0/24')", Value::Bool(false)),
        ("metadata('test/region') == 'eu'", Value::Bool(true)),
        ("metadata('test/region') == 'us'", Value::Bool(false)),
        ("a + 1", Value::Int(2)),
        ("a == 1", Value::Bool(true)),
        ("'x' + name()", Value::String("xa.example.")),
        ("'ns0.example.'", Value::String("ns0.example.")),
        ("1", Value::Int(1)),
    ] {
        let expression =
            Expression::compile_with_variables(source, &[("a", ValueType::Int)]).unwrap();
        assert_eq!(
            expression
                .evaluate(&query, &metadata, &mut scratch)
                .unwrap(),
            expected,
            "{source}"
        );
    }
    assert!(Expression::compile("name() ==").is_err());
    assert!(Expression::compile("invalid expression").is_err());
    assert!(Expression::compile("undefined == 1").is_err());
    assert!(Expression::compile_with_variables("a + 'x'", &[("a", ValueType::Int)]).is_err());
    assert!(
        Expression::compile("incidr('notanip', '10.0.0.0/8')")
            .unwrap()
            .evaluate(&query, &metadata, &mut scratch)
            .is_err()
    );

    let wire = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x31\x32\x2d\x33\x34\x07example\x00\x00\x01\x00\x01";
    let message = Message::parse(wire).unwrap();
    let mut query = Query::new(
        &message,
        "10.240.0.1:1234".parse().unwrap(),
        "127.0.0.1:53".parse().unwrap(),
        Protocol::Udp,
    );
    query.matches = &["12-34.example.", "12", "34"];
    query.groups = &[("a", "12"), ("b", "34")];
    for (source, expected) in [
        ("group('a')", "12"),
        ("group(2)", "34"),
        ("group(0)", "12-34.example."),
        ("group('nosuchgroup') + group(9)", ""),
        ("group(\"a\") + group(1) + group(0)", "121212-34.example."),
    ] {
        assert_eq!(
            Expression::compile(source)
                .unwrap()
                .evaluate(&query, &metadata, &mut scratch)
                .unwrap(),
            Value::String(expected),
            "{source}"
        );
    }
    assert_eq!(
        Expression::compile("group('a') != ''")
            .unwrap()
            .evaluate(&query, &metadata, &mut scratch)
            .unwrap(),
        Value::Bool(true)
    );
}

#[test]
fn coredns_template_tests_cover_metadata_sections_and_runtime_errors() {
    // CoreDNS v1.15.0 plugin/template/template_test.go, TestHandler.
    let mut slots = [None; 2];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert("foo", "east"));
    assert!(metadata.insert("bar", "ns1"));
    let mut data = Data::new("ip-10-11-12-13.example.", &metadata);
    data.class = "IN";
    data.remote = "10.240.0.1";
    data.groups = &[("b", "11"), ("c", "12"), ("d", "13")];
    data.matches = &["example.", "capture"];
    for (source, expected) in [
        (
            "{{ .Name }} 60 IN A {{ .Remote }}",
            "ip-10-11-12-13.example. 60 IN A 10.240.0.1",
        ),
        (
            "{{ .Name }} 60 MX 10 {{ .Name }}",
            "ip-10-11-12-13.example. 60 MX 10 ip-10-11-12-13.example.",
        ),
        (
            "invalid. 60 {{ .Class }} SOA a.invalid. b.invalid. (1 60 60 60 60)",
            "invalid. 60 IN SOA a.invalid. b.invalid. (1 60 60 60 60)",
        ),
        (
            "{{ .Meta \"foo\" }}-{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}",
            "east-ip-10-11-12-13.example. 60 IN A 10.11.12.13",
        ),
        (
            "{{ .Meta \"bar\" }}.example. IN A 203.0.113.8",
            "ns1.example. IN A 203.0.113.8",
        ),
        (
            "example. IN NS {{ .Meta \"bar\" }}.example.com.",
            "example. IN NS ns1.example.com.",
        ),
        (
            "{{ .Meta \"foofoo\" }}{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}",
            "ip-10-11-12-13.example. 60 IN A 10.11.12.13",
        ),
        ("{{ .Name }}", "ip-10-11-12-13.example."),
    ] {
        let mut output = String::new();
        Template::compile(source)
            .unwrap()
            .render(&data, &mut output)
            .unwrap();
        assert_eq!(output, expected, "{source}");
    }
    for source in [
        "{{ .Name }} 60 IN TXT \"{{ index .Match 2 }}\"",
        "{{ .Name }} 60 IN TXT \"{{ parseInt \"gg\" 16 8 }}\"",
    ] {
        assert!(
            Template::compile(source)
                .unwrap()
                .render(&data, &mut String::new())
                .is_err(),
            "{source}"
        );
    }
}

#[test]
fn coredns_variable_templates_render_all_value_shapes() {
    // CoreDNS v1.15.0 plugin/template/var_test.go, TestVar.
    let mut slots = [];
    let metadata = Metadata::new(&mut slots);
    let mut data = Data::new("a.example.", &metadata);
    let variables = [
        ("ttl", Value::Int(60)),
        ("a", Value::Int(1)),
        ("b", Value::Int(2)),
        ("c", Value::Int(20)),
        ("missing", Value::String("")),
        ("n", Value::String("a.example.")),
        ("t", Value::String("A")),
        ("ip", Value::String("10.240.0.1")),
        ("region", Value::String("eu")),
        ("local", Value::Bool(true)),
        ("target", Value::String("ns0.example.")),
        ("v", Value::String("1")),
    ];
    data.variables = &variables;
    for (source, expected) in [
        (
            "{{ .Name }} {{ .Var.ttl }} IN A 10.0.0.1",
            "a.example. 60 IN A 10.0.0.1",
        ),
        (
            "{{ .Name }} 60 IN A 10.{{ .Var.a }}.{{ .Var.b }}.{{ .Var.c }}",
            "a.example. 60 IN A 10.1.2.20",
        ),
        (
            "{{ .Name }} 60 IN TXT \"empty={{ eq .Var.missing \"\" }}\"",
            "a.example. 60 IN TXT \"empty=true\"",
        ),
        (
            "{{ .Var.n }} 60 IN A {{ .Var.ip }}",
            "a.example. 60 IN A 10.240.0.1",
        ),
        (
            "{{ .Var.n }} 60 IN TXT \"{{ .Var.t }}\"",
            "a.example. 60 IN TXT \"A\"",
        ),
        (
            "{{ .Var.region }}.{{ .Name }} 60 IN A 10.0.0.1",
            "eu.a.example. 60 IN A 10.0.0.1",
        ),
        (
            "{{ .Name }} 60 IN A {{ if .Var.local }}10.0.0.1{{ else }}192.0.2.1{{ end }}",
            "a.example. 60 IN A 10.0.0.1",
        ),
        (
            "{{ .Var.target }} 60 IN A 10.0.0.2",
            "ns0.example. 60 IN A 10.0.0.2",
        ),
        (
            "example. 60 IN NS {{ .Var.target }}",
            "example. 60 IN NS ns0.example.",
        ),
        (
            "{{ .Name }} 60 IN A 10.0.0.{{ .Var.v }}",
            "a.example. 60 IN A 10.0.0.1",
        ),
    ] {
        let mut output = String::new();
        Template::compile(source)
            .unwrap()
            .render(&data, &mut output)
            .unwrap();
        assert_eq!(output, expected, "{source}");
    }
    let captures = [
        ("whole", Value::String("12-34.example.")),
        ("a", Value::String("12")),
        ("b", Value::String("34")),
    ];
    data.variables = &captures;
    let template =
        Template::compile("{{ .Var.whole }} 60 IN A 10.0.{{ .Var.a }}.{{ .Var.b }}").unwrap();
    let mut output = String::new();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "12-34.example. 60 IN A 10.0.12.34");
    data.variables = &[];
    let template = Template::compile("{{ .Name }} 60 IN TXT \"{{ len .Var }}\"").unwrap();
    output.clear();
    template.render(&data, &mut output).unwrap();
    assert_eq!(output, "a.example. 60 IN TXT \"0\"");
}

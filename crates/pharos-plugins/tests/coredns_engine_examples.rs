#![forbid(unsafe_code)]

use pharos_plugins::expression::{Expression, Query, Scratch, Value};
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

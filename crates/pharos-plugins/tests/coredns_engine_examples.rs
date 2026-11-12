#![forbid(unsafe_code)]

use pharos_plugins::expression::{Expression, Query, Scratch, Value};
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

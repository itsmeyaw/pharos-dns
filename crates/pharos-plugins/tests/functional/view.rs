#![cfg(feature = "plugin-view")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/view/setup_test.go.
#[test]
fn coredns_view_setup_cases() {
    for (directive, valid) in [
        ("view example {\n expr name() == 'example.com.'\n}", true),
        (
            "view example {\n expr incidr(client_ip(), '10.0.0.0/24')\n}",
            true,
        ),
        (
            "view example {\n expr name() == 'example.com.'\n expr name() == 'example2.com.'\n}",
            true,
        ),
        ("view", false),
        ("view example {\n expr invalid expression\n}", false),
        ("view x {\n foo bar\n}", false),
        ("view a { }\nview b { }", false),
    ] {
        let input = format!(".:53 {{\n{directive}\n}}");
        let blocks = parse("Corefile", &input).unwrap();
        assert_eq!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            valid,
            "{directive}"
        );
    }
}

// Derived from CoreDNS v1.15.0 plugin/view/view_test.go.
#[cfg(feature = "plugin-hosts")]
#[tokio::test]
async fn view_routes_first_matching_block_and_falls_back() {
    use pharos_plugins::servers;
    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
    use pharos_server::{Handler, Protocol};

    let text = ".:53 {\n view first {\n  expr name() == 'one.example.'\n }\n hosts {\n  192.0.2.1 one.example two.example\n }\n}\n.:53 {\n hosts {\n  192.0.2.2 one.example two.example\n }\n}";
    let blocks = parse("Corefile", text).unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    for (name, expected) in [
        ("one.example.", [192, 0, 2, 1]),
        ("two.example.", [192, 0, 2, 2]),
    ] {
        let name: Name = name.parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        // RFC 1035 §4.1.2: Encode QNAME, QTYPE, and QCLASS in the Question section.
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        server
            .handle(
                &wire,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await;
        // RFC 1035 §3.4.1: A RDATA is a 32-bit Internet address.
        assert_eq!(
            Message::parse(&response)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rdata,
            expected
        );
    }
}

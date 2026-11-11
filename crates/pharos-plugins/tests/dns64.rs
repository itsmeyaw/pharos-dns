#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-dns64", feature = "plugin-hosts"))]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Action, Handler, Protocol};
use std::net::Ipv6Addr;

// Derived from CoreDNS v1.15.0 plugin/dns64/dns64_test.go, TestTo6.
#[tokio::test]
async fn coredns_dns64_synthesizes_prefixes_through_self_lookup() {
    for (prefix, expected) in [
        ("64:ff9b::/96", "64:ff9b::4040:4040"),
        ("64:ff9b::/64", "64:ff9b::40:4040:4000:0"),
        ("64:ff9b::/56", "64:ff9b:0:40:40:4040::"),
        ("64::/32", "64:0:4040:4040::"),
    ] {
        let config = format!(
            ".:53 {{\n dns64 {prefix}\n hosts /nonexistent {{\n  64.64.64.64 example.org\n  ttl 60\n }}\n}}"
        );
        let blocks = parse("Corefile", &config).unwrap();
        let (mut listeners, _) =
            servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
        let (_, server) = listeners.drain().next().unwrap();
        let name: Name = "example.org.".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 42, 0x100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::AAAA,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    &wire,
                    "[::1]:1234".parse().unwrap(),
                    Protocol::Udp,
                    &mut response
                )
                .await,
            Action::Respond
        );
        let message = Message::parse(&response).unwrap();
        let answer = message.answers().next().expect(prefix);
        assert_eq!(answer.rtype, Type::AAAA, "{prefix}");
        assert_eq!(
            answer.rdata,
            expected.parse::<Ipv6Addr>().unwrap().octets(),
            "{prefix}"
        );
        assert_eq!(answer.ttl, 60);
    }
}

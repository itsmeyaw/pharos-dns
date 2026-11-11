#![forbid(unsafe_code)]
#![cfg(feature = "plugin-acl")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, EdnsOption, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct NextDrop;
impl Next for NextDrop {
    async fn run(self, _: &mut Context<'_>) -> Outcome {
        Outcome::Drop
    }
}

// Derived from CoreDNS v1.15.0 plugin/acl/acl_test.go.
#[tokio::test]
async fn coredns_acl_matches_ordered_policies_and_response_codes() {
    for (directive, client, typ, expected, ede) in [
        (
            "allow net 192.168.1.0/24\n block net 192.168.0.0/16",
            "192.168.1.2:53",
            Type::A,
            None,
            0,
        ),
        (
            "allow net 192.168.1.0/24\n block net 192.168.0.0/16",
            "192.168.2.2:53",
            Type::A,
            Some(Rcode::REFUSED),
            15,
        ),
        (
            "filter type AAAA net 2001:db8::/32",
            "[2001:db8::1]:53",
            Type::AAAA,
            Some(Rcode::NOERROR),
            17,
        ),
        ("block type AAAA", "127.0.0.1:53", Type::A, None, 0),
        ("drop", "127.0.0.1:53", Type::A, None, 0),
    ] {
        let text = format!(".:53 {{\n acl {{\n {directive}\n }}\n}}");
        let blocks = parse("Corefile", &text).unwrap();
        let chain = configure::<Chain>(&blocks, directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "example.org.".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), typ, Class::IN)
            .unwrap();
        let _ = builder.finish();
        let domain: Name = ".".parse().unwrap();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: client.parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let outcome = chain.acl.as_ref().unwrap().serve(&mut cx, NextDrop).await;
        if let Some(expected) = expected {
            assert_eq!(outcome, Outcome::Response, "{directive}");
            let msg = Message::parse(&response).unwrap();
            assert_eq!(msg.rcode(), expected);
            assert_eq!(
                msg.opt().unwrap().options().iter().next().unwrap(),
                EdnsOption::ExtendedError {
                    info_code: ede,
                    extra_text: &[]
                }
            );
        } else {
            assert_eq!(outcome, Outcome::Drop, "{directive}");
        }
    }
}

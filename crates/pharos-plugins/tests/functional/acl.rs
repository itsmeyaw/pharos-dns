#![forbid(unsafe_code)]
#![cfg(feature = "plugin-acl")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, EdnsOption, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct NextDrop;
impl Next for NextDrop {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Drop
    }
}

struct NextAllowed;
impl Next for NextAllowed {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(Rcode::NOERROR)
    }
}

// Derived from CoreDNS v1.15.0 plugin/acl/acl_test.go, TestACLServeDNS.
#[tokio::test]
async fn coredns_acl_serve_dns_cases() {
    // Each entry contains the Directive, Server Block domain, Query domain,
    // client, type, and expected action: 0=Next, 1=block, 2=filter, 3=drop.
    let cases = [
        // CoreDNS TestNormalize: host bits in a CIDR remain part of its subnet.
        (
            "acl example.org {\n block net 10.218.10.8/24\n}",
            ".",
            "www.example.org.",
            "10.218.10.9",
            Type::A,
            1,
        ),
        (
            "acl example.org {\n block type A net 192.168.0.0/16\n}",
            ".",
            "www.example.org.",
            "192.168.0.2",
            Type::A,
            1,
        ),
        (
            "acl example.org {\n block type A net 192.168.0.0/16\n}",
            ".",
            "www.example.org.",
            "192.167.0.2",
            Type::A,
            0,
        ),
        (
            "acl example.org {\n block type * net 192.168.0.0/16\n}",
            ".",
            "www.example.org.",
            "192.168.0.2",
            Type::AAAA,
            1,
        ),
        (
            "acl example.org {\n block type A\n}",
            ".",
            "www.example.org.",
            "10.1.0.2",
            Type::A,
            1,
        ),
        (
            "acl example.org {\n block type A\n}",
            ".",
            "www.example.org.",
            "10.1.0.2",
            Type::AAAA,
            0,
        ),
        (
            "acl example.org {\n block type A net 192.168.1.2\n}",
            ".",
            "www.example.org.",
            "192.168.1.2",
            Type::A,
            1,
        ),
        (
            "acl example.org {\n block type A net 192.168.1.2\n}",
            ".",
            "www.example.org.",
            "192.168.1.3",
            Type::A,
            0,
        ),
        (
            "acl example.org {\n filter type A net 192.168.0.0/16\n}",
            ".",
            "www.example.org.",
            "192.168.0.2",
            Type::A,
            2,
        ),
        (
            "acl example.org {\n filter type A net 192.168.0.0/16\n}",
            ".",
            "www.example.org.",
            "192.167.0.2",
            Type::A,
            0,
        ),
        (
            "acl example.org {\n allow net 192.168.0.0/16\n block\n}",
            ".",
            "www.example.org.",
            "192.168.0.2",
            Type::A,
            0,
        ),
        (
            "acl example.org {\n allow type * net 192.168.0.0/16\n block\n}",
            ".",
            "www.example.org.",
            "10.1.0.2",
            Type::A,
            1,
        ),
        (
            "acl example.org {\n drop net 192.168.0.0/16\n}",
            ".",
            "www.example.org.",
            "192.168.0.2",
            Type::A,
            3,
        ),
        (
            "acl example.org {\n block net 192.168.1.0/24\n drop net 192.168.0.0/16\n}",
            ".",
            "www.example.org.",
            "192.168.1.2",
            Type::A,
            1,
        ),
        (
            "acl example.org {\n drop net 192.168.0.0/16\n block net 192.168.1.0/24\n}",
            ".",
            "www.example.org.",
            "192.168.1.1",
            Type::A,
            3,
        ),
        (
            "acl example.org {\n drop type A\n allow net 192.168.0.0/16\n}",
            ".",
            "www.example.org.",
            "192.168.1.1",
            Type::A,
            3,
        ),
        (
            "acl example.org {\n drop type A\n allow net 192.168.0.0/16\n}",
            ".",
            "www.example.org.",
            "192.168.1.1",
            Type::AAAA,
            0,
        ),
        (
            "acl a.example.org {\n block type * net 192.168.1.0/24\n}",
            "example.org",
            "a.example.org.",
            "192.168.1.2",
            Type::A,
            1,
        ),
        (
            "acl a.example.org {\n block net 192.168.1.0/24\n}",
            "example.org",
            "www.example.org.",
            "192.168.1.2",
            Type::A,
            0,
        ),
        (
            "acl example.org {\n block net 192.168.1.0/24\n}",
            "example.org",
            "a.example.org.",
            "192.168.1.2",
            Type::A,
            1,
        ),
        (
            "acl {\n block net 192.168.1.0/24\n}",
            "example.org",
            "a.example.com.",
            "192.168.1.2",
            Type::A,
            0,
        ),
        (
            "acl a.example.org {\n block net 192.168.1.0/24\n}\n acl b.example.org {\n block type * net 192.168.2.0/24\n}",
            "example.org",
            "b.example.org.",
            "192.168.2.2",
            Type::A,
            1,
        ),
        (
            "acl a.example.org {\n block net 192.168.1.0/24\n}\n acl b.example.org {\n block net 192.168.2.0/24\n}",
            "example.org",
            "b.example.org.",
            "192.168.1.2",
            Type::A,
            0,
        ),
        (
            "acl example.org {\n block type A net 2001:db8:abcd:0012::0/64\n}",
            ".",
            "www.example.org.",
            "2001:db8:abcd:0012::1230",
            Type::A,
            1,
        ),
        (
            "acl example.org {\n block type A net 2001:db8:abcd:0012::0/64\n}",
            ".",
            "www.example.org.",
            "2001:db8:abcd:0013::0",
            Type::A,
            0,
        ),
        (
            "acl example.org {\n block type A\n}",
            ".",
            "www.example.org.",
            "2001:db8:85a3::8a2e:370:7334",
            Type::A,
            1,
        ),
        (
            "acl example.org {\n block type A net 2001:db8:85a3::8a2e:370:7334\n}",
            ".",
            "www.example.org.",
            "2001:db8:85a3::8a2e:370:7334",
            Type::A,
            1,
        ),
        (
            "acl example.org {\n block type A net 2001:db8:85a3::8a2e:370:7334\n}",
            ".",
            "www.example.org.",
            "2001:db8:85a3::8a2e:370:7335",
            Type::A,
            0,
        ),
        (
            "acl a.example.org {\n block type * net 2001:db8:abcd:0012::0/64\n}",
            "example.org",
            "a.example.org.",
            "2001:db8:abcd:12:2019::0",
            Type::A,
            1,
        ),
        (
            "acl a.example.org {\n block net 2001:db8:abcd:0012::0/64\n}",
            "example.org",
            "www.example.org.",
            "2001:db8:abcd:12:2019::0",
            Type::A,
            0,
        ),
        (
            "acl example.org {\n block type AAAA net 2001:db8:85a3::8a2e:370:7334\n}",
            "eth0",
            "www.example.org.",
            "2001:db8:85a3::8a2e:370:7334",
            Type::AAAA,
            1,
        ),
        (
            "acl example.org {\n drop net 2001:db8:85a3::8a2e:370:7334\n}",
            ".",
            "www.example.org.",
            "2001:db8:85a3::8a2e:370:7334",
            Type::AAAA,
            3,
        ),
        (
            "acl example.org {\n block net 2001:db8:abcd:12:8000::/66\n drop net 2001:db8:abcd:12::/64\n}",
            ".",
            "www.example.org.",
            "2001:db8:abcd:12:8000::1",
            Type::AAAA,
            1,
        ),
        (
            "acl example.org {\n drop net 2001:db8:abcd:12::/64\n block net 2001:db8:abcd:12:8000::/66\n}",
            ".",
            "www.example.org.",
            "2001:db8:abcd:12:8000::1",
            Type::AAAA,
            3,
        ),
        (
            "acl example.org {\n drop type A\n allow net 2001:db8:85a3::/64\n}",
            ".",
            "www.example.org.",
            "2001:db8:85a3::8a2e:370:7334",
            Type::A,
            3,
        ),
        (
            "acl example.org {\n drop type A\n allow net 2001:db8:85a3::/64\n}",
            ".",
            "www.example.org.",
            "2001:db8:85a3::8a2e:370:7334",
            Type::AAAA,
            0,
        ),
    ];
    for (directive, domain, name, client, typ, action) in cases {
        let text = format!("{domain}:53 {{\n{directive}\n}}");
        let blocks = parse("Corefile", &text).unwrap();
        let chain = configure::<Chain>(&blocks, directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = name.parse().unwrap();
        let domain: Name = if domain == "." {
            ".".to_owned()
        } else {
            format!("{domain}.")
        }
        .parse()
        .unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        builder
            .question(NameRef::parse(name.as_wire(), 0).unwrap(), typ, Class::IN)
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: std::net::SocketAddr::new(client.parse().unwrap(), 53),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let outcome = chain
            .acl
            .as_ref()
            .unwrap()
            .serve(&mut cx, NextAllowed)
            .await;
        match action {
            0 => assert_eq!(
                outcome,
                Outcome::Unanswered(Rcode::NOERROR),
                "{directive} {client}"
            ),
            3 => assert_eq!(outcome, Outcome::Drop, "{directive} {client}"),
            _ => {
                assert_eq!(outcome, Outcome::Response, "{directive} {client}");
                let msg = Message::parse(&response).unwrap();
                assert_eq!(
                    msg.rcode(),
                    if action == 1 {
                        Rcode::REFUSED
                    } else {
                        Rcode::NOERROR
                    }
                );
                assert_eq!(
                    msg.opt().unwrap().options().iter().next().unwrap(),
                    EdnsOption::ExtendedError {
                        info_code: if action == 1 { 15 } else { 17 },
                        extra_text: &[]
                    }
                );
            }
        }
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
        (
            "block net * net 192.168.1.0/24",
            "127.0.0.1:53",
            Type::A,
            Some(Rcode::REFUSED),
            15,
        ),
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

#![forbid(unsafe_code)]
#![cfg(feature = "plugin-rewrite")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct Echo;
impl Next for Echo {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let query = cx.query;
        let q = query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, query.id(), 0x8180).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        builder
            .record(
                Section::Answer,
                q.name,
                Type::A,
                Class::IN,
                5,
                &[10, 0, 0, 1],
            )
            .unwrap();
        if let Some(opt) = query.opt() {
            builder
                .record(
                    Section::Additional,
                    NameRef::parse(&[0], 0).unwrap(),
                    Type::OPT,
                    Class(opt.udp_payload_size()),
                    u32::from(opt.flags()),
                    opt.options().as_bytes(),
                )
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestEdns0MultiRule.
#[tokio::test]
async fn coredns_edns_multiple_rules_rows() {
    const EMPTY: &[u8] = b"";
    const LOCAL: &[u8] = b"\xff\xee\0\x06foobar";
    const REPLACED: &[u8] = b"\xff\xee\0\x06abcdef";
    const SET: &[u8] = b"\xff\xee\0\x06fedcba";
    const QTYPE: &[u8] = b"\xff\xee\0\x02\0\x01";
    const QNAME: &[u8] = b"\xff\xee\0\x0cexample.com.";
    const NSID: &[u8] = b"\0\x03\0\0";
    const LOCAL_NSID: &[u8] = b"\xff\xee\0\x06foobar\0\x03\0\0";
    const SUBNET_ZERO: &[u8] = b"\0\x08\0\x04\0\x01\0\0";
    const SUBNET_FULL: &[u8] = b"\0\x08\0\x08\0\x01\x20\0\x0a\xf0\0\x01";
    for (first, second, original, expected) in [
        (
            "local replace 0xffee abcdef",
            "local set 0xffee fedcba",
            EMPTY,
            SET,
        ),
        (
            "local replace 0xffee abcdef",
            "local set 0xffee fedcba",
            LOCAL,
            REPLACED,
        ),
        (
            "local replace 0xffee abcdef revert",
            "local set 0xffee fedcba revert",
            EMPTY,
            EMPTY,
        ),
        (
            "local replace 0xffee abcdef revert",
            "local set 0xffee fedcba revert",
            LOCAL,
            LOCAL,
        ),
        (
            "local replace 0xffee {qname}",
            "local set 0xffee {qtype}",
            EMPTY,
            QTYPE,
        ),
        (
            "local replace 0xffee {qname}",
            "local set 0xffee {qtype}",
            LOCAL,
            QNAME,
        ),
        (
            "local replace 0xffee {qname} revert",
            "local set 0xffee {qtype} revert",
            EMPTY,
            EMPTY,
        ),
        (
            "local replace 0xffee {qname} revert",
            "local set 0xffee {qtype} revert",
            LOCAL,
            LOCAL,
        ),
        ("nsid replace", "nsid set", EMPTY, NSID),
        ("nsid replace", "nsid set", LOCAL, LOCAL_NSID),
        ("nsid replace", "nsid set", NSID, NSID),
        ("nsid replace revert", "nsid set revert", EMPTY, EMPTY),
        ("nsid replace revert", "nsid set revert", LOCAL, LOCAL),
        ("nsid replace revert", "nsid set revert", NSID, NSID),
        (
            "subnet replace 32 56",
            "subnet set 0 56",
            EMPTY,
            SUBNET_ZERO,
        ),
        (
            "subnet replace 32 56",
            "subnet set 0 56",
            SUBNET_ZERO,
            SUBNET_FULL,
        ),
        (
            "subnet replace 32 56 revert",
            "subnet set 0 56 revert",
            EMPTY,
            EMPTY,
        ),
        (
            "subnet replace 32 56 revert",
            "subnet set 0 56 revert",
            SUBNET_ZERO,
            SUBNET_ZERO,
        ),
    ] {
        let config =
            format!(".:53 {{\n rewrite stop edns0 {first}\n rewrite stop edns0 {second}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives())
            .unwrap()
            .remove(0)
            .config;
        let name: Name = "example.com.".parse().unwrap();
        let root: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
            )
            .unwrap();
        builder
            .record(
                Section::Additional,
                NameRef::parse(root.as_wire(), 0).unwrap(),
                Type::OPT,
                Class(4096),
                0,
                original,
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "10.240.0.1:40212".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain.rewrite.as_ref().unwrap().serve(&mut cx, Echo).await,
            Outcome::Response,
            "{first}; {second}"
        );
        assert_eq!(
            Message::parse(cx.response)
                .unwrap()
                .opt()
                .unwrap()
                .options()
                .as_bytes(),
            expected,
            "{first}; {second}; {original:?}"
        );
    }
}

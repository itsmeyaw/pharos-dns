#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-loadbalance", feature = "plugin-hosts"))]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Phase, Plugin, Protocol, Transport};

#[tokio::test]
async fn round_robin_shuffles_hosts_answers() {
    let text = ".:53 {\n loadbalance\n hosts /nonexistent {\n 192.0.2.1 example.org\n 192.0.2.2 example.org\n 192.0.2.3 example.org\n reload 0\n }\n}";
    let blocks = parse("Corefile", text).unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    let name: Name = "example.org.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
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
    let mut first = std::collections::BTreeSet::new();
    for _ in 0..100 {
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
        let message = Message::parse(&response).unwrap();
        let mut addresses: Vec<_> = message.answers().map(|rr| rr.rdata.to_vec()).collect();
        assert_eq!(addresses.len(), 3);
        first.insert(addresses[0].clone());
        addresses.sort();
        assert_eq!(
            addresses,
            [vec![192, 0, 2, 1], vec![192, 0, 2, 2], vec![192, 0, 2, 3]]
        );
    }
    assert!(first.len() > 1, "the first address never changed");
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

struct Reply<'a>(&'a [u8]);

impl Next for Reply<'_> {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        cx.response.clear();
        cx.response.extend_from_slice(self.0);
        Outcome::Response
    }
}

#[tokio::test]
async fn weighted_prefer_reorders_non_address_queries() {
    let blocks = parse(
        "Corefile",
        ".:53 {\n loadbalance weighted weights {\n } {\n prefer 192.0.2.0/24\n }\n}",
    )
    .unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 2];
    wire.extend_from_slice(b"\x07example\x03org\0\0\x10\0\x01");
    for (typ, data) in [
        (16, &[1, b'x'][..]),
        (15, &[0, 10, 0xc0, 12][..]),
        (5, &[0xc0, 12][..]),
        (1, &[10, 0, 0, 1][..]),
        (1, &[192, 0, 2, 1][..]),
    ] {
        wire.extend_from_slice(&[0xc0, 12, 0, typ, 0, 1, 0, 0, 0, 30, 0, data.len() as u8]);
        wire.extend_from_slice(data);
    }
    let root: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .loadbalance
            .as_ref()
            .unwrap()
            .serve(&mut cx, Reply(&wire))
            .await,
        Outcome::Response
    );
    let message = Message::parse(&response).unwrap();
    assert_eq!(
        message.answers().map(|rr| rr.rtype).collect::<Vec<_>>(),
        [Type::CNAME, Type::MX, Type::TXT]
    );
    assert_eq!(message.additionals().next().unwrap().rdata, [192, 0, 2, 1]);
}

#[tokio::test]
async fn prefer_ipv4_subnet_matches_ipv4_mapped_aaaa() {
    let blocks = parse(
        "Corefile",
        ".:53 {\n loadbalance {\n prefer 192.0.2.0/24\n }\n}",
    )
    .unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
    wire.extend_from_slice(b"\x07example\x03org\0\0\x1c\0\x01");
    for address in ["::1", "::ffff:192.0.2.1"] {
        wire.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16]);
        wire.extend_from_slice(&address.parse::<std::net::Ipv6Addr>().unwrap().octets());
    }
    let root: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    for _ in 0..50 {
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .loadbalance
                .as_ref()
                .unwrap()
                .serve(&mut cx, Reply(&wire))
                .await,
            Outcome::Response
        );
        let message = Message::parse(&response).unwrap();
        assert_eq!(
            message.answers().next().unwrap().rdata,
            "::ffff:192.0.2.1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
    }
}

#[tokio::test]
async fn coredns_partition_and_transfer_bypass() {
    let blocks = parse("Corefile", ".:53 {\n loadbalance\n}").unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 4, 0, 2, 0, 2];
    wire.extend_from_slice(b"\x07example\x03org\0\0\x01\0\x01");
    fn rr(wire: &mut Vec<u8>, typ: u8, data: &[u8]) {
        wire.extend_from_slice(&[0xc0, 12, 0, typ, 0, 1, 0, 0, 0, 30, 0, data.len() as u8]);
        wire.extend_from_slice(data);
    }
    rr(&mut wire, 15, &[0, 10, 0xc0, 12]);
    rr(&mut wire, 1, &[10, 0, 0, 1]);
    rr(&mut wire, 5, &[0xc0, 12]);
    rr(&mut wire, 1, &[10, 0, 0, 2]);
    rr(&mut wire, 1, &[10, 0, 0, 3]);
    rr(&mut wire, 1, &[10, 0, 0, 4]);
    rr(&mut wire, 15, &[0, 20, 0xc0, 12]);
    rr(&mut wire, 5, &[0xc0, 12]);
    let root: Name = ".".parse().unwrap();
    for transfer in [false, true] {
        let mut input = wire.clone();
        if transfer {
            input[26] = 252;
        }
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&input).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .loadbalance
                .as_ref()
                .unwrap()
                .serve(&mut cx, Reply(&input))
                .await,
            Outcome::Response
        );
        if transfer {
            assert_eq!(response, input);
        } else {
            let response = Message::parse(&response).unwrap();
            assert_eq!(
                response.answers().map(|r| r.rtype).collect::<Vec<_>>(),
                [Type::CNAME, Type::A, Type::A, Type::MX]
            );
            assert_eq!(
                response.additionals().map(|r| r.rtype).collect::<Vec<_>>(),
                [Type::CNAME, Type::MX]
            );
        }
    }
}

#[tokio::test]
async fn compressed_names_pointing_into_moved_records_are_not_shuffled() {
    let blocks = parse("Corefile", ".:53 {\n loadbalance\n}").unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
    wire.extend_from_slice(b"\x07example\x03org\0\0\x0f\0\x01");
    wire.extend_from_slice(b"\xc0\x0c\0\x0f\0\x01\0\0\0\x1e\0\x14\0\x0a");
    let exchange_offset = wire.len();
    wire.extend_from_slice(b"\x04mail\x07example\x03org\0");
    wire.extend_from_slice(b"\xc0\x0c\0\x0f\0\x01\0\0\0\x1e\0\x04\0\x14");
    wire.extend_from_slice(&[0xc0, exchange_offset as u8]);
    let message = Message::parse(&wire).unwrap();
    assert!(message.answers().all(|rr| rr.data().is_ok()));
    let root: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut unchanged = 0;
    for _ in 0..100 {
        let mut slots = [];
        let mut cx = Context {
            query: message,
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &root,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .loadbalance
                .as_ref()
                .unwrap()
                .serve(&mut cx, Reply(&wire))
                .await,
            Outcome::Response
        );
        unchanged += usize::from(response == wire);
    }
    assert_eq!(unchanged, 100);
}

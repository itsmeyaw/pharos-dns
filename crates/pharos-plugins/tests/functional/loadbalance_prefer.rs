#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-loadbalance", feature = "plugin-hosts"))]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Context, Metadata, Outcome, Phase, Protocol, Transport};

fn config(
    directive: &str,
) -> Result<Vec<pharos_corefile::BlockContext<Chain>>, pharos_corefile::Error> {
    let text = format!(
        ".:53 {{\n {directive}\n hosts /nonexistent {{\n 10.9.30.1 example.org\n 10.9.20.1 example.org\n 192.0.2.1 example.org\n 2001:db8::1 example.org\n 2001:db8:abcd::1 example.org\n fd00::1 example.org\n reload 0\n }}\n}}"
    );
    let blocks = parse("Corefile", &text)?;
    configure::<Chain>(&blocks, directives())
}

#[test]
fn prefer_setup_accepts_cidrs_and_rejects_invalid_networks() {
    for directive in [
        "loadbalance {\n prefer\n}",
        "loadbalance round_robin {\n prefer 10.9.20.0/24 2001:db8::/32\n prefer 10.9.30.1/24\n}",
        "loadbalance weighted weights {\n } {\n prefer 10.9.20.0/24\n}",
    ] {
        assert!(config(directive).is_ok(), "{directive}");
    }
    for directive in [
        "loadbalance {\n prefer 10.9.20.1\n}",
        "loadbalance {\n prefer 10.9.20.0/33\n}",
        "loadbalance {\n prefer 10.9.20.0/+24\n}",
        "loadbalance weighted weights {\n prefer 10.9.20.0/24\n}",
    ] {
        assert!(config(directive).is_err(), "{directive}");
    }
}

#[tokio::test]
async fn preferred_subnets_follow_configured_priority() {
    let chain = config(
        "loadbalance {\n prefer 10.9.20.0/24 10.9.30.0/24 2001:db8:abcd::/48 2001:db8::/32\n}",
    )
    .unwrap()
    .remove(0)
    .config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    let name: Name = "example.org.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x0100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    for _ in 0..20 {
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
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
        let addresses: Vec<_> = message.answers().map(|rr| rr.rdata.to_vec()).collect();
        assert_eq!(
            addresses,
            [vec![10, 9, 20, 1], vec![10, 9, 30, 1], vec![192, 0, 2, 1]]
        );
    }
    query.clear();
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x0100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::AAAA,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let expected: Vec<Vec<u8>> = ["2001:db8:abcd::1", "2001:db8::1", "fd00::1"]
        .into_iter()
        .map(|s| s.parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec())
        .collect();
    for _ in 0..20 {
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
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
        assert_eq!(
            message
                .answers()
                .map(|rr| rr.rdata.to_vec())
                .collect::<Vec<_>>(),
            expected
        );
    }
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

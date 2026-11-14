#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use super::*;
use pharos_corefile::{configure, parse};
use pharos_proto::{Message, Rdata};
use pharos_server::{Metadata, Protocol, Transport};

fn configured() -> crate::Chain {
    let blocks = parse("Corefile", ".:53 {\n kubernetes interwebs.test\n}").unwrap();
    configure::<crate::Chain>(&blocks, crate::directives())
        .unwrap()
        .remove(0)
        .config
}

async fn query(chain: &crate::Chain, name: &str, kind: Type) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
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
    response
}

// CoreDNS kubernetes_test.go TestServicesAuthority injects localIPs directly.
#[tokio::test]
async fn authority_rows_use_the_injected_local_addresses() {
    for (local, kind, expected) in [
        ("1.2.3.4", Type::A, Some("1.2.3.4")),
        ("1.2.3.4", Type::AAAA, None),
        ("1:2::3:4", Type::A, None),
        ("1:2::3:4", Type::AAAA, Some("1:2::3:4")),
    ] {
        let mut chain = configured();
        chain.kubernetes.as_mut().unwrap().local_ips = vec![local.parse().unwrap()];
        let wire = query(&chain, "ns.dns.interwebs.test.", kind).await;
        let message = Message::parse(&wire).unwrap();
        assert_eq!(message.rcode(), Rcode::NOERROR);
        let answer = message.answers().next().map(|rr| match rr.data().unwrap() {
            Rdata::A(ip) => ip.to_string(),
            Rdata::Aaaa(ip) => ip.to_string(),
            other => panic!("unexpected address {other:?}"),
        });
        assert_eq!(answer.as_deref(), expected, "{local} {kind}");
        assert_eq!(message.answer_count(), u16::from(expected.is_some()));
    }
    let chain = configured();
    let plugin = chain.kubernetes.as_ref().unwrap();
    let zone: Name = "interwebs.test.".parse().unwrap();
    let zone = NameRef::parse(zone.as_wire(), 0).unwrap();
    let mut results = Vec::new();
    visit_ns(
        &Index::default(),
        &["1.2.3.4".parse().unwrap(), "1:2::3:4".parse().unwrap()],
        zone,
        &plugin.config,
        |name, ip| results.push((name.to_string(), ip.to_string())),
    );
    assert_eq!(
        results,
        [
            ("ns.dns.interwebs.test.".to_owned(), "1.2.3.4".to_owned()),
            ("ns.dns.interwebs.test.".to_owned(), "1:2::3:4".to_owned()),
        ]
    );
}

// CoreDNS kubernetes_apex_test.go TestServeDNSApex row 3 injects loopback.
#[tokio::test]
async fn apex_ns_with_injected_loopback_matches_coredns() {
    let mut chain = configured();
    chain.kubernetes.as_mut().unwrap().local_ips = vec!["127.0.0.1".parse().unwrap()];
    let wire = query(&chain, "interwebs.test.", Type::NS).await;
    let message = Message::parse(&wire).unwrap();
    assert_eq!(
        (
            message.rcode(),
            message.answer_count(),
            message.additional_count()
        ),
        (Rcode::NOERROR, 1, 1)
    );
    assert!(
        matches!(message.answers().next().unwrap().data().unwrap(), Rdata::Ns(name) if name.to_string() == "ns.dns.interwebs.test.")
    );
    // RFC 1034 §4.3.2: Include available NS target addresses as glue in the Additional section.
    assert!(
        matches!(message.additionals().next().unwrap().data().unwrap(), Rdata::A(ip) if ip.octets() == [127, 0, 0, 1])
    );
}

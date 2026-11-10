#![forbid(unsafe_code)]

use pharos_proto::{Message, Name};
use pharos_server::{ListenerKey, Protocol, Router, Transport};

fn key(port: u16) -> ListenerKey {
    ListenerKey {
        transport: Transport::Dns,
        address: ([127, 0, 0, 1], port).into(),
    }
}

fn query(name: &str, qtype: u16) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    wire.extend_from_slice(name.as_wire());
    wire.extend_from_slice(&qtype.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire
}

fn lookup<'a>(
    router: &'a Router<&'static str>,
    key: &ListenerKey,
    name: &str,
    qtype: u16,
) -> Option<&'a str> {
    let wire = query(name, qtype);
    router
        .route(
            key,
            Message::parse(&wire).unwrap(),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
        )
        .map(|block| *block.chain().unwrap())
}

#[test]
fn routes_longest_domain_and_ds_parent_per_listener() {
    let mut router = Router::default();
    for (domain, chain) in [
        (".", "root"),
        ("example.org.", "parent"),
        ("child.example.org.", "child"),
    ] {
        router.add(key(53), domain.parse().unwrap(), Some(chain), vec![]);
    }
    router.add(
        key(54),
        "example.org.".parse().unwrap(),
        Some("other"),
        vec![],
    );
    assert_eq!(
        lookup(&router, &key(53), "WWW.CHILD.Example.Org.", 1),
        Some("child")
    );
    assert_eq!(
        lookup(&router, &key(53), "child.example.org.", 43),
        Some("parent")
    );
    assert_eq!(lookup(&router, &key(53), "unknown.org.", 1), Some("root"));
    assert_eq!(
        lookup(&router, &key(53), "notexample.org.", 1),
        Some("root")
    );
    assert_eq!(lookup(&router, &key(54), "example.org.", 1), Some("other"));
    assert_eq!(lookup(&router, &key(54), "unknown.org.", 1), None);
}

#[test]
fn views_preserve_block_order_and_empty_domains_refuse() {
    fn reject(_: &Message<'_>, _: std::net::SocketAddr, _: Protocol) -> bool {
        false
    }
    let mut router = Router::default();
    router.add(
        key(53),
        "example.org.".parse().unwrap(),
        Some("hidden"),
        vec![reject],
    );
    router.add(
        key(53),
        "example.org.".parse().unwrap(),
        Some("visible"),
        vec![],
    );
    router.add(key(53), ".".parse().unwrap(), Some("root"), vec![]);
    assert_eq!(
        lookup(&router, &key(53), "example.org.", 1),
        Some("visible")
    );
    router.add(
        key(53),
        "empty.example.org.".parse().unwrap(),
        None,
        vec![reject],
    );
    assert_eq!(lookup(&router, &key(53), "empty.example.org.", 1), None);
    assert_eq!(
        lookup(&router, &key(53), "example.org.", 43),
        Some("visible")
    );
}

#[test]
fn ds_search_follows_coredns_to_the_last_matching_non_root_domain() {
    let mut router = Router::default();
    for (domain, chain) in [
        (".", "root"),
        ("org.", "grandparent"),
        ("example.org.", "parent"),
        ("child.example.org.", "child"),
    ] {
        router.add(key(53), domain.parse().unwrap(), Some(chain), vec![]);
    }
    assert_eq!(
        lookup(&router, &key(53), "child.example.org.", 43),
        Some("grandparent")
    );
    assert_eq!(
        lookup(&router, &key(53), "www.child.example.org.", 43),
        Some("grandparent")
    );
}

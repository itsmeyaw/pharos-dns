#![cfg(feature = "plugin-view")]

use pharos_plugins::{expression::Expression, view::View};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Protocol, Transport};

fn with_context(test: impl FnOnce(&Context<'_, '_>)) {
    let wire =
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 4];
    let cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    test(&cx);
}

// Derived from CoreDNS v1.15.0 plugin/view/view_test.go TestFilter.
#[test]
fn coredns_filter_accepts_only_all_true_results() {
    with_context(|cx| {
        for (rules, expected) in [
            (vec![], true),
            (vec!["name() == 'example.com.'"], true),
            (vec!["name() == 'notexample.com.'"], false),
            (vec!["1"], false),
            (vec!["incidr('invalid', '1.2.3.0/24')"], false),
            (vec!["true", "false"], false),
        ] {
            let view = View {
                name: "test".into(),
                expressions: rules
                    .iter()
                    .map(|s| Expression::compile(s).unwrap())
                    .collect(),
            };
            assert_eq!(view.name.as_ref(), "test");
            assert_eq!(view.matches(cx), expected, "{rules:?}");
        }
    });
}

#[test]
fn scratch_exhaustion_fails_closed() {
    with_context(|cx| {
        for (len, expected) in [(65_535, true), (65_536, false)] {
            let replacement = "x".repeat(len);
            let source = format!("replace('x', 'x', '{replacement}') != 'x'");
            let view = View {
                name: "large".into(),
                expressions: vec![Expression::compile(&source).unwrap()],
            };
            assert_eq!(view.matches(cx), expected, "{len}");
        }
    });
}

// Derived from CoreDNS v1.15.0 plugin/view/setup_test.go TestServeDNS_DelegatesToNext.
#[test]
fn coredns_view_delegates_to_next() {
    use pharos_server::{Next, Outcome, Plugin};
    use std::{
        future::Future,
        task::{Context as TaskContext, Poll, Waker},
    };

    struct NextPlugin;
    impl Next for NextPlugin {
        async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
            Outcome::Unanswered(pharos_proto::Rcode::REFUSED)
        }
    }
    let wire =
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let view = View {
        name: "test".into(),
        expressions: vec![],
    };
    let future = view.serve(&mut cx, NextPlugin);
    let mut future = std::pin::pin!(future);
    assert_eq!(
        future
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop())),
        Poll::Ready(Outcome::Unanswered(pharos_proto::Rcode::REFUSED))
    );
}

#[test]
fn readme_cidr_filters_ipv4_and_ipv6_clients() {
    let wire =
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let domain: Name = ".".parse().unwrap();
    for (address, cidr, expected) in [
        ("127.0.0.1:1234", "127.0.0.0/24", true),
        ("192.168.1.2:1234", "192.168.0.0/16", true),
        ("[2001:db8::1]:1234", "2001:db8::/32", true),
        ("203.0.113.1:1234", "127.0.0.0/24", false),
    ] {
        let expression = Expression::compile(&format!("incidr(client_ip(), '{cidr}')")).unwrap();
        let view = View {
            name: "cidr".into(),
            expressions: vec![expression],
        };
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let cx = Context {
            query: Message::parse(wire).unwrap(),
            client: address.parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(view.matches(&cx), expected, "{address} in {cidr}");
    }
}

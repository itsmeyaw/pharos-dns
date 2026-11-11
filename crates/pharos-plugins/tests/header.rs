#![forbid(unsafe_code)]
#![cfg(feature = "plugin-header")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name, Rcode};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

fn configured(text: &str) -> Result<Chain, String> {
    let blocks =
        parse("Corefile", &format!(".:53 {{\n{text}\n}}")).map_err(|error| error.to_string())?;
    Ok(configure::<Chain>(&blocks, directives())
        .map_err(|error| error.to_string())?
        .remove(0)
        .config)
}

#[test]
fn coredns_setup_cases() {
    for directive in [
        "header {\n query set rd\n}",
        "header {\n response set aa\n}",
        "header {\n response set ra aa\n query clear rd\n}",
        "header ignored {\n QuErY SeT RD aa\n ReSpOnSe ClEaR RA\n}",
        "header {}\nheader {\n query set rd\n}",
        "header {\n query set rd\n}\nheader {\n query foo rd\n}",
    ] {
        assert!(configured(directive).is_ok(), "{directive}");
    }
    for directive in [
        "header",
        "header ignored",
        "header {}",
        "header {\n foo\n}",
        "header {\n response set\n}",
        "header {\n query foo\n}",
        "header {\n query foo rd\n}",
        "header {\n query set ad\n}",
    ] {
        assert!(configured(directive).is_err(), "{directive}");
    }
}

struct Inspect {
    expected: u16,
    outcome: Outcome,
}

impl Next for Inspect {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        assert_eq!(cx.query.flags(), self.expected);
        let mut wire = Vec::with_capacity(512);
        cx.query.copy_wire(&mut wire);
        assert_eq!(Message::parse(&wire).unwrap().flags(), self.expected);
        cx.response.extend_from_slice(&wire);
        self.outcome
    }
}

#[tokio::test]
async fn coredns_query_and_response_rules_and_precedence() {
    for (selector, initial, action, flag, expected) in [
        ("response", 0_u16, "set", "ra", 0x80),
        ("response", 0x80, "clear", "ra", 0),
        ("response", 0, "set", "rd", 0x100),
        ("response", 0, "set", "aa", 0x400),
        ("query", 0, "set", "ra", 0x80),
        ("query", 0, "set", "rd", 0x100),
        ("query", 0x100, "clear", "rd", 0),
        ("query", 0, "set", "aa", 0x400),
    ] {
        let directive = format!("header {{\n {selector} {action} {flag}\n}}");
        let chain = configured(&directive).unwrap();
        let mut wire = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
        wire[2..4].copy_from_slice(&initial.to_be_bytes());
        let domain: Name = ".".parse().unwrap();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let query_expected = if selector == "query" {
            expected
        } else {
            initial
        };
        assert_eq!(
            chain
                .header
                .as_ref()
                .unwrap()
                .serve(
                    &mut cx,
                    Inspect {
                        expected: query_expected,
                        outcome: Outcome::Response,
                    }
                )
                .await,
            Outcome::Response
        );
        assert_eq!(
            Message::parse(cx.response).unwrap().flags(),
            expected,
            "{directive}"
        );
    }
}

#[tokio::test]
async fn rules_are_ordered_and_non_response_outcomes_are_preserved() {
    let chain = configured("header {\n query set aa ra rd\n query clear aa rd\n response set aa rd\n response clear rd\n}").unwrap();
    let wire = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    let domain: Name = ".".parse().unwrap();
    for outcome in [
        Outcome::Response,
        Outcome::Drop,
        Outcome::Unanswered(Rcode::REFUSED),
        Outcome::Error(pharos_server::Error::NoNextPlugin),
    ] {
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .header
                .as_ref()
                .unwrap()
                .serve(
                    &mut cx,
                    Inspect {
                        expected: 0x80,
                        outcome
                    }
                )
                .await,
            outcome
        );
        assert_eq!(
            Message::parse(cx.response).unwrap().flags(),
            if outcome == Outcome::Response {
                0x480
            } else {
                0x80
            }
        );
    }
}

#[cfg(feature = "plugin-forward")]
#[tokio::test]
async fn query_rules_reach_forward_upstream() {
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let chain = configured(&format!(
        "header {{\n query clear rd\n query set aa ra\n}}\nforward . {}",
        upstream.local_addr().unwrap()
    ))
    .unwrap();
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = upstream.recv_from(&mut wire).await.unwrap();
        assert_eq!(Message::parse(&wire[..len]).unwrap().flags(), 0x480);
        wire[2] |= 0x80;
        upstream.send_to(&wire[..len], peer).await.unwrap();
    });
    let wire = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    task.await.unwrap();
}

#[cfg(feature = "plugin-forward")]
#[tokio::test]
async fn forwarding_rejects_header_compression_even_when_ad_is_set() {
    let chain = configured("header {\n query set rd\n}\nforward . 127.0.0.1:5300").unwrap();
    let wire = [0, 0, 0, 0x20, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 1, 0, 1];
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain.serve(&mut cx).await,
        Outcome::Unanswered(Rcode::FORMERR)
    );
}

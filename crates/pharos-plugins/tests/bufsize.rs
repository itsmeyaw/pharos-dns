#![forbid(unsafe_code)]
#![cfg(feature = "plugin-bufsize")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name, Rcode};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

fn configured(text: &str) -> Result<Chain, String> {
    let source = format!(".:53 {{\n{text}\n}}");
    let blocks = parse("Corefile", &source).map_err(|e| e.to_string())?;
    let mut blocks = configure::<Chain>(&blocks, directives()).map_err(|e| e.to_string())?;
    Ok(blocks.remove(0).config)
}

#[test]
fn coredns_setup_and_boundaries() {
    for directive in [
        "bufsize",
        "bufsize \"1220\"",
        "bufsize 512",
        "bufsize 4096",
        "bufsize +1024",
    ] {
        assert!(configured(directive).is_ok(), "{directive}");
    }
    for directive in [
        "bufsize\nbufsize 1200",
        "bufsize {\n foo\n}",
        "bufsize {\n}",
    ] {
        assert!(configured(directive).is_ok(), "{directive}");
    }
    for directive in [
        "bufsize 5000",
        "bufsize \"512 512\"",
        "bufsize 511",
        "bufsize abc123",
        "bufsize 1024 1025",
    ] {
        assert!(configured(directive).is_err(), "{directive}");
    }
}

#[cfg(feature = "plugin-whoami")]
#[tokio::test]
async fn listener_uses_clamped_opt_for_udp_and_tcp_responses() {
    use pharos_plugins::servers;
    use pharos_server::{Action, Handler};

    let blocks = parse("Corefile", ".:53 {\n bufsize\n whoami\n}").unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    for protocol in [Protocol::Udp, Protocol::Tcp] {
        for (size, expected) in [(4096_u16, 1232), (1024, 1024)] {
            let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 41];
            wire.extend_from_slice(&size.to_be_bytes());
            wire.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            let mut response = Vec::with_capacity(65535);
            assert_eq!(
                server
                    .handle(
                        &wire,
                        "127.0.0.1:1234".parse().unwrap(),
                        protocol,
                        &mut response
                    )
                    .await,
                Action::Respond
            );
            assert_eq!(
                Message::parse(&response)
                    .unwrap()
                    .opt()
                    .unwrap()
                    .udp_payload_size(),
                expected
            );
        }
    }
}

#[cfg(feature = "plugin-hosts")]
#[tokio::test]
async fn clamped_udp_response_truncates_but_tcp_does_not() {
    use pharos_plugins::servers;
    use pharos_server::{Action, Handler};

    let mut source = String::from(".:53 {\n bufsize 512\n hosts /nonexistent {\n");
    for n in 1..=80 {
        source.push_str(&format!(" 192.0.2.{n} large.example\n"));
    }
    source.push_str(" }\n}");
    let blocks = parse("Corefile", &source).unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\x01\x05large\x07example\0\0\x01\0\x01\0\0\x29\x10\0\0\0\0\0\0\0";
    for protocol in [Protocol::Udp, Protocol::Tcp] {
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    wire,
                    "127.0.0.1:1234".parse().unwrap(),
                    protocol,
                    &mut response
                )
                .await,
            Action::Respond
        );
        let message = Message::parse(&response).unwrap();
        assert_eq!(message.opt().unwrap().udp_payload_size(), 512);
        assert_eq!(message.tc(), protocol == Protocol::Udp);
        assert_eq!(response.len() <= 512, protocol == Protocol::Udp);
    }
}

#[cfg(feature = "plugin-forward")]
#[tokio::test]
async fn forward_sends_clamped_wire_query_to_upstream() {
    use tokio::net::UdpSocket;

    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let chain = configured(&format!(
        "bufsize 1100\nforward . {}",
        upstream.local_addr().unwrap()
    ))
    .unwrap();
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = upstream.recv_from(&mut wire).await.unwrap();
        assert_eq!(
            Message::parse(&wire[..len])
                .unwrap()
                .opt()
                .unwrap()
                .udp_payload_size(),
            1100
        );
        wire[2] |= 0x80;
        upstream.send_to(&wire[..len], peer).await.unwrap();
    });
    let wire = [
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0,
    ];
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:53".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 4096,
    };
    assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    task.await.unwrap();
}

struct Inspect {
    expected: Option<u16>,
    max_response_size: usize,
    outcome: Outcome,
}

impl Next for Inspect {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        assert_eq!(cx.query.opt().map(|o| o.udp_payload_size()), self.expected);
        assert_eq!(cx.max_response_size, self.max_response_size);
        let mut wire = Vec::new();
        cx.query.copy_wire(&mut wire);
        assert_eq!(
            Message::parse(&wire)
                .unwrap()
                .opt()
                .map(|o| o.udp_payload_size()),
            self.expected
        );
        self.outcome
    }
}

#[tokio::test]
async fn coredns_clamps_only_larger_opt_and_preserves_outcome() {
    let chain = configured("bufsize 1024").unwrap();
    for (protocol, requested, expected, outcome) in [
        (Protocol::Udp, Some(1152_u16), Some(1024), Outcome::Response),
        (Protocol::Tcp, Some(1152), Some(1024), Outcome::Response),
        (Protocol::Udp, Some(896), Some(896), Outcome::Drop),
        (Protocol::Udp, Some(1), Some(1), Outcome::Drop),
        (
            Protocol::Udp,
            Some(1024),
            Some(1024),
            Outcome::Unanswered(Rcode::REFUSED),
        ),
        (
            Protocol::Udp,
            None,
            None,
            Outcome::Error(pharos_server::Error::NoNextPlugin),
        ),
    ] {
        let mut wire = vec![
            0,
            1,
            1,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            u8::from(requested.is_some()),
            0,
            0,
            1,
            0,
            1,
        ];
        if let Some(size) = requested {
            wire.extend_from_slice(&[0, 0, 41]);
            wire.extend_from_slice(&size.to_be_bytes());
            wire.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
        let domain: Name = ".".parse().unwrap();
        let mut response = Vec::with_capacity(4096);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:53".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: if protocol == Protocol::Udp {
                usize::from(requested.unwrap_or(512).max(512))
            } else {
                usize::from(u16::MAX)
            },
        };
        let max_response_size = if protocol == Protocol::Udp {
            usize::from(expected.unwrap_or(512).max(512))
        } else {
            usize::from(u16::MAX)
        };
        assert_eq!(
            chain
                .bufsize
                .as_ref()
                .unwrap()
                .serve(
                    &mut cx,
                    Inspect {
                        expected,
                        max_response_size,
                        outcome
                    }
                )
                .await,
            outcome
        );
    }
}

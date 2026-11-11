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
    for directive in ["bufsize", "bufsize \"1220\"", "bufsize 512", "bufsize 4096", "bufsize +1024"] {
        assert!(configured(directive).is_ok(), "{directive}");
    }
    for directive in ["bufsize 5000", "bufsize \"512 512\"", "bufsize 511", "bufsize abc123", "bufsize 1024 1025"] {
        assert!(configured(directive).is_err(), "{directive}");
    }
}

struct Inspect {
    expected: Option<u16>,
    outcome: Outcome,
}

impl Next for Inspect {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        assert_eq!(cx.query.opt().map(|o| o.udp_payload_size()), self.expected);
        assert_eq!(Message::parse(cx.query.as_wire()).unwrap().opt().map(|o| o.udp_payload_size()), self.expected);
        self.outcome
    }
}

#[tokio::test]
async fn coredns_clamps_only_larger_opt_and_preserves_outcome() {
    let chain = configured("bufsize 1024").unwrap();
    for (requested, expected, outcome) in [
        (Some(1152_u16), Some(1024), Outcome::Response),
        (Some(896), Some(896), Outcome::Drop),
        (Some(1024), Some(1024), Outcome::Unanswered(Rcode::REFUSED)),
        (None, None, Outcome::Error(pharos_server::Error::NoNextPlugin)),
    ] {
        let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, u8::from(requested.is_some()), 0, 0, 1, 0, 1];
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
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 4096,
        };
        assert_eq!(chain.bufsize.as_ref().unwrap().serve(&mut cx, Inspect { expected, outcome }).await, outcome);
    }
}

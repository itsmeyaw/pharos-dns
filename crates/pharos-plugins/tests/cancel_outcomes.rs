#![forbid(unsafe_code)]
#![cfg(feature = "plugin-cancel")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name, Rcode};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};
use std::sync::atomic::{AtomicBool, Ordering};

struct Pending<'a>(&'a AtomicBool);
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
impl Next for Pending<'_> {
    async fn run(self, _: &mut Context<'_>) -> Outcome {
        std::future::pending().await
    }
}

struct Immediate;
impl Next for Immediate {
    async fn run(self, _: &mut Context<'_>) -> Outcome {
        Outcome::Unanswered(Rcode::REFUSED)
    }
}

#[tokio::test]
async fn deadline_drops_next_and_fast_outcome_is_preserved() {
    let blocks = parse("Corefile", ".:53 {\n cancel 1ms\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let cancel = configured[0].config.cancel.as_ref().unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&[0; 12]).unwrap(),
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
        cancel.serve(&mut cx, Immediate).await,
        Outcome::Unanswered(Rcode::REFUSED)
    );
    let dropped = AtomicBool::new(false);
    assert_eq!(
        cancel.serve(&mut cx, Pending(&dropped)).await,
        Outcome::Drop
    );
    assert!(dropped.load(Ordering::SeqCst));
}

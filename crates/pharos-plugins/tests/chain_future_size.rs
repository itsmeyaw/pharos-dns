#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use pharos_plugins::Chain;
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Protocol, Transport};

#[test]
fn chain_future_fits_size_budget() {
    let chain = Chain::default();
    let domain: Name = ".".parse().unwrap();
    let wire = [0u8; 12];
    let mut response = Vec::new();
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
    let future = chain.serve(&mut cx);
    // Tripwire for inline buffers / per-query memory blowups (TCP path boxes this future per pipelined query, crates/pharos-server/src/tcp.rs), not a stack budget; measures 18,648 B aarch64, 19,392 B x86_64 (debug).
    assert!(
        std::mem::size_of_val(&future) <= 32 * 1024,
        "Chain future: {} bytes",
        std::mem::size_of_val(&future)
    );
}

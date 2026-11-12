#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use pharos_plugins::Chain;
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Protocol, Transport};

#[test]
fn chain_future_fits_stack_budget() {
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
    // Default features measure 17,224 bytes on aarch64; allow headroom up to 20,000.
    assert!(
        std::mem::size_of_val(&future) <= 20_000,
        "Chain future: {} bytes",
        std::mem::size_of_val(&future)
    );
}

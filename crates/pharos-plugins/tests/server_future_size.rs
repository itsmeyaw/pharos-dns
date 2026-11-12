#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use std::sync::Arc;

use pharos_plugins::Chain;
use pharos_server::{Handler, ListenerKey, Protocol, Router, Server, Transport};

#[test]
fn handle_shared_future_fits_stack_budget() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        key,
        ".".parse().unwrap(),
        Some(Arc::new(Chain::default())),
        vec![],
    );
    let server = Arc::new(Server::new(router, key));
    // Never polled: only the future's type size matters, not what the Query hits.
    let wire = [0_u8; 12];
    let mut response = Vec::new();
    let future = Handler::handle_shared(
        &server,
        &wire,
        "127.0.0.1:1234".parse().unwrap(),
        Protocol::Tcp,
        &mut response,
    );
    // Default features measure 20,808 bytes on aarch64; allow about 10% headroom.
    assert!(
        std::mem::size_of_val(&future) <= 23_000,
        "Server future: {} bytes",
        std::mem::size_of_val(&future)
    );
}

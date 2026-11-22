#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use std::sync::Arc;

use pharos_plugins::Chain;
use pharos_server::{Handler, ListenerKey, Protocol, Router, Server, Transport};

#[test]
fn handle_shared_future_fits_size_budget() {
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
    // Tripwire for inline buffers / per-query memory blowups (TCP path boxes this future per pipelined query, crates/pharos-server/src/tcp.rs), not a stack budget; measured 20,808 B aarch64, 23,024 B x86_64 (debug) before the azure Plugin; with it, after slimming its serve future, the x86_64 debug future is 33,224 B, so the budget is 36 KiB (about 10% headroom) rather than 32 KiB.
    assert!(
        std::mem::size_of_val(&future) <= 36 * 1024,
        "Server future: {} bytes",
        std::mem::size_of_val(&future)
    );
}

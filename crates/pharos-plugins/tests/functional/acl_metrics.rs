#![forbid(unsafe_code)]
#![cfg(feature = "plugin-acl")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::{Action, Handler, Protocol};

#[tokio::test]
async fn acl_counts_blocked_requests_by_server_and_domain() {
    let blocks = parse("Corefile", ".:0 {\n acl {\n  block\n }\n}").unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let query = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(
                query,
                "127.0.0.1:1000".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
        Action::Respond
    );
    let mut text = String::new();
    server.metrics().encode(&mut text);
    assert!(
        text.contains(
            "pharos_acl_blocked_requests_total{server=\"dns://:0\",view=\"\",zone=\".\"} 1"
        ),
        "{text}"
    );
}

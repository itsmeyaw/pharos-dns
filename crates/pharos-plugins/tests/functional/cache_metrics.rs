#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-cache", feature = "plugin-whoami"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::{Action, Handler, Protocol};

#[tokio::test]
async fn cache_counts_routed_requests_and_hits() {
    let blocks = parse("Corefile", ".:0 {\n cache\n whoami\n}").unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let query = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let peer = "127.0.0.1:1000".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    for _ in 0..2 {
        assert_eq!(
            server
                .handle(query, peer, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
    }
    let mut text = String::new();
    server.metrics().encode(&mut text);
    for line in [
        "pharos_cache_requests_total{server=\"dns://:0\",view=\"\",zones=\".\"} 2",
        "pharos_cache_hits_total{server=\"dns://:0\",type=\"success\",view=\"\",zones=\".\"} 1",
        "pharos_cache_misses_total{server=\"dns://:0\",view=\"\",zones=\".\"} 1",
        "pharos_cache_entries{server=\"dns://:0\",type=\"success\",view=\"\",zones=\".\"} 1",
    ] {
        assert!(text.contains(line), "missing {line} in {text}");
    }
}

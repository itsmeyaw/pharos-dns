#![cfg(all(feature = "plugin-dnssec", feature = "plugin-whoami"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers_with_registry};
use pharos_server::{Action, Handler, Protocol, metrics::Registry};

#[tokio::test]
async fn signature_cache_metrics_report_miss_and_hit() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl:53 {{\n dnssec {{\n key file {base}\n }}\n whoami\n}}");
    let registry = Registry::default();
    let (mut servers, _) = servers_with_registry(
        configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap(),
        registry.clone(),
    )
    .unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\x01\x03www\x04miek\x02nl\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\x80\0\0\0";
    let peer = "127.0.0.1:1001".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    for _ in 0..2 {
        assert_eq!(
            server
                .handle(query, peer, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
    }
    let mut output = String::new();
    registry.encode(&mut output);
    assert!(
        output.contains("pharos_dnssec_cache_entries{server=\"dns://:53\",type=\"signature\"} 2"),
        "{output}"
    );
    assert!(
        output.contains("pharos_dnssec_cache_hits_total{server=\"dns://:53\"} 2"),
        "{output}"
    );
    assert!(
        output.contains("pharos_dnssec_cache_misses_total{server=\"dns://:53\"} 2"),
        "{output}"
    );
}

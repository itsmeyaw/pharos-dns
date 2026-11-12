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
    // CoreDNS plugin/pkg/cache: zero and negative capacities still cache signatures.
    for capacity in ["", "cache_capacity 0", "cache_capacity -1"] {
        let text =
            format!("miek.nl:53 {{\n dnssec {{\n key file {base}\n {capacity}\n }}\n whoami\n}}");
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
            output
                .contains("pharos_dnssec_cache_entries{server=\"dns://:53\",type=\"signature\"} 2"),
            "{capacity}: {output}"
        );
        assert!(
            output.contains("pharos_dnssec_cache_hits_total{server=\"dns://:53\"} 2"),
            "{capacity}: {output}"
        );
        assert!(
            output.contains("pharos_dnssec_cache_misses_total{server=\"dns://:53\"} 2"),
            "{capacity}: {output}"
        );
    }
}

// CoreDNS plugin/dnssec TestCacheEmptySigsNotCached: keyless RRsets miss every time.
#[tokio::test]
async fn keyless_rrsets_never_produce_cache_hits_or_entries() {
    let text = "miek.nl:53 {\n dnssec\n whoami\n}";
    let registry = Registry::default();
    let (mut servers, _) = servers_with_registry(
        configure::<Chain>(&parse("Corefile", text).unwrap(), directives()).unwrap(),
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
    for expected in [
        "pharos_dnssec_cache_entries{server=\"dns://:53\",type=\"signature\"} 0",
        "pharos_dnssec_cache_hits_total{server=\"dns://:53\"} 0",
        "pharos_dnssec_cache_misses_total{server=\"dns://:53\"} 4",
    ] {
        assert!(output.contains(expected), "{output}");
    }
}

#![cfg(all(
    feature = "plugin-view",
    feature = "plugin-hosts",
    feature = "plugin-metadata"
))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::Message;
use pharos_server::{Handler, Protocol};

const QUERY: &[u8] =
    b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

#[tokio::test]
async fn metadata_view_name_is_available_before_filtering() {
    let text = ".:53 {\n metadata\n view local {\n  expr metadata('view/name') == 'local'\n }\n hosts {\n  192.0.2.1 example.com\n }\n}\n.:53 {\n hosts {\n  192.0.2.2 example.com\n }\n}";
    let blocks = parse("Corefile", text).unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    let mut response = Vec::with_capacity(512);
    server
        .handle(
            QUERY,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 1]
    );
}

#[tokio::test]
async fn long_view_name_metadata_is_not_truncated() {
    let name = "v".repeat(2048);
    let text = format!(
        ".:53 {{\n metadata\n view {name} {{\n  expr metadata('view/name') == '{name}'\n }}\n hosts {{\n  192.0.2.1 example.com\n }}\n}}\n.:53 {{\n hosts {{\n  192.0.2.2 example.com\n }}\n}}"
    );
    let blocks = parse("Corefile", &text).unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    let mut response = Vec::with_capacity(512);
    server
        .handle(
            QUERY,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 1]
    );
}

#[tokio::test]
async fn empty_view_name_still_filters() {
    let text = ".:53 {\n view \"\" {\n  expr false\n }\n hosts {\n  192.0.2.1 example.com\n }\n}\n.:53 {\n hosts {\n  192.0.2.2 example.com\n }\n}";
    let blocks = parse("Corefile", text).unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    let mut response = Vec::with_capacity(512);
    server
        .handle(
            QUERY,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 2]
    );
}

#[tokio::test]
async fn rejected_candidate_metadata_reaches_next_candidate_without_collector() {
    let text = ".:53 {\n metadata\n view first {\n  expr false\n }\n hosts {\n  192.0.2.1 example.com\n }\n}\n.:53 {\n view second {\n  expr metadata('view/name') == 'first'\n }\n hosts {\n  192.0.2.2 example.com\n }\n}\n.:53 {\n hosts {\n  192.0.2.3 example.com\n }\n}";
    let blocks = parse("Corefile", text).unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    let mut response = Vec::with_capacity(512);
    server
        .handle(
            QUERY,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 2]
    );
}

#[tokio::test]
async fn metadata_domain_excludes_view_provider() {
    let text = ".:53 {\n metadata other.test\n view first {\n  expr metadata('view/name') == 'first'\n }\n hosts {\n  192.0.2.1 example.com\n }\n}\n.:53 {\n hosts {\n  192.0.2.2 example.com\n }\n}";
    let blocks = parse("Corefile", text).unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    let mut response = Vec::with_capacity(512);
    server
        .handle(
            QUERY,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 2]
    );
}

#[cfg(feature = "plugin-prometheus")]
#[tokio::test]
async fn request_and_response_metrics_carry_view_name() {
    let text = ".:53 {\n prometheus 127.0.0.1:0\n view local {\n  expr true\n }\n hosts {\n  192.0.2.1 example.com\n }\n}";
    let blocks = parse("Corefile", text).unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    let mut response = Vec::with_capacity(512);
    server
        .handle(
            QUERY,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    let mut metrics = String::new();
    server.metrics().encode(&mut metrics);
    assert!(
        metrics
            .lines()
            .any(|line| line.starts_with("pharos_dns_requests_total{")
                && line.contains("view=\"local\"")
                && line.ends_with(" 1")),
        "{metrics}"
    );
    assert!(
        metrics
            .lines()
            .any(|line| line.starts_with("pharos_dns_responses_total{")
                && line.contains("view=\"local\"")
                && line.ends_with(" 1")),
        "{metrics}"
    );
}

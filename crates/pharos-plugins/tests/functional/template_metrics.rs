#![cfg(feature = "plugin-template")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::{Action, Handler, Protocol};

async fn metric_for(option: &str) -> String {
    let corefile = format!(".:0 {{\n template IN A {{\n  {option}\n }}\n}}");
    let blocks = parse("Corefile", &corefile).unwrap();
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
                &mut response,
            )
            .await,
        Action::Respond
    );
    let mut text = String::new();
    server.metrics().encode(&mut text);
    text
}

#[tokio::test]
async fn template_counts_matches() {
    let text = metric_for("rcode NXDOMAIN").await;
    assert!(text.contains("pharos_template_matches_total{"), "{text}");
    assert!(text.contains("class=\"IN\""), "{text}");
    assert!(text.contains("type=\"A\""), "{text}");
}

#[tokio::test]
async fn template_counts_render_failures() {
    let text = metric_for("answer \"{{ .Missing }}\"").await;
    assert!(
        text.contains("pharos_template_template_failures_total{"),
        "{text}"
    );
    assert!(text.contains("section=\"answer\""), "{text}");
}

#[tokio::test]
async fn template_counts_invalid_record_failures() {
    let text = metric_for("answer \"invalid record\"").await;
    assert!(
        text.contains("pharos_template_rr_failures_total{"),
        "{text}"
    );
    assert!(text.contains("section=\"answer\""), "{text}");
}

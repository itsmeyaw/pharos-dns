#![cfg(feature = "plugin-template")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::{Action, Handler, Protocol};

async fn metric_for(option: &str) -> String {
    metric_for_query("IN A", option, 1, 1).await
}

async fn metric_for_query(header: &str, option: &str, qtype: u8, qclass: u8) -> String {
    let chaos = if qclass == 1 { "" } else { " chaos\n" };
    let corefile = format!(".:0 {{\n{chaos} template {header} {{\n  {option}\n }}\n}}");
    metric_for_corefile(&corefile, qtype, qclass).await
}

async fn metric_for_corefile(corefile: &str, qtype: u8, qclass: u8) -> String {
    let blocks = parse("Corefile", corefile).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let query = [
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'x', 0, 0, qtype, 0, qclass,
    ];
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(
                &query,
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
#[cfg(feature = "plugin-chaos")]
async fn wildcard_template_metrics_use_question_class_and_type() {
    let text = metric_for_query("ANY ANY", "rcode NXDOMAIN", 16, 3).await;
    let line = text
        .lines()
        .find(|line| line.starts_with("pharos_template_matches_total{"))
        .expect(&text);
    assert!(line.contains("class=\"CH\""), "{line}");
    assert!(line.contains("type=\"TXT\""), "{line}");
    assert!(line.ends_with(" 1"), "{line}");
}

fn counter<'a>(text: &'a str, name: &str) -> &'a str {
    let line = text
        .lines()
        .find(|line| line.starts_with(name))
        .unwrap_or_else(|| panic!("missing {name}: {text}"));
    for label in [
        "server=\"dns://:0\"",
        "zone=\".\"",
        "view=\"\"",
        "class=\"IN\"",
        "type=\"A\"",
    ] {
        assert!(line.contains(label), "{line}");
    }
    assert!(line.ends_with(" 1"), "{line}");
    line
}

#[tokio::test]
#[cfg(feature = "plugin-view")]
async fn template_metrics_use_routed_view() {
    let corefile =
        ".:0 {\n view blue {\n  expr true\n }\n template IN A {\n  rcode NXDOMAIN\n }\n}";
    let text = metric_for_corefile(corefile, 1, 1).await;
    let line = text
        .lines()
        .find(|line| line.starts_with("pharos_template_matches_total{"))
        .expect(&text);
    assert!(line.contains("view=\"blue\""), "{line}");
    assert!(line.ends_with(" 1"), "{line}");
}

#[tokio::test]
async fn template_counts_matches() {
    let text = metric_for("rcode NXDOMAIN").await;
    counter(&text, "pharos_template_matches_total{");
}

#[tokio::test]
async fn template_counts_render_failures() {
    let text = metric_for("answer \"{{ .Missing }}\"").await;
    let line = counter(&text, "pharos_template_template_failures_total{");
    assert!(line.contains("section=\"answer\""), "{line}");
    assert!(line.contains("template=\""), "{line}");
}

#[tokio::test]
async fn template_counts_invalid_record_failures() {
    let text = metric_for("answer \"invalid record\"").await;
    let line = counter(&text, "pharos_template_rr_failures_total{");
    assert!(line.contains("section=\"answer\""), "{line}");
    assert!(line.contains("template=\""), "{line}");
}

#![cfg(all(
    feature = "plugin-view",
    feature = "plugin-acl",
    feature = "plugin-cache",
    feature = "plugin-whoami"
))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Name, Type};
use pharos_server::{Handler, Protocol};

fn query(name: &str, kind: Type) -> Vec<u8> {
    let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    wire.extend_from_slice(name.parse::<Name>().unwrap().as_wire());
    wire.extend_from_slice(&kind.0.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire
}

async fn metrics(corefile: &str, name: &str, kind: Type) -> String {
    let blocks = parse("Corefile", corefile).unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = servers.values().next().unwrap();
    server
        .handle(
            &query(name, kind),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut Vec::with_capacity(512),
        )
        .await;
    let mut output = String::new();
    server.metrics().encode(&mut output);
    output
}

#[tokio::test]
async fn acl_uses_routed_view_without_metadata_plugin() {
    let output = metrics(
        ".:53 {\n view blue {\n  expr true\n }\n acl {\n  filter\n }\n}",
        "example.org.",
        Type::A,
    )
    .await;
    assert!(
        output.contains(
            "pharos_acl_filtered_requests_total{server=\"dns://:53\",view=\"blue\",zone=\".\"} 1"
        ),
        "{output}"
    );
}

#[tokio::test]
async fn cache_uses_its_static_view() {
    let output = metrics(
        ".:53 {\n view blue {\n  expr true\n }\n cache\n whoami\n}",
        "example.org.",
        Type::A,
    )
    .await;
    assert!(
        output.contains(
            "pharos_cache_requests_total{server=\"dns://:53\",view=\"blue\",zones=\".\"} 1"
        ),
        "{output}"
    );
}

#[tokio::test]
async fn ds_acl_inherits_child_view_but_cache_keeps_parent_view() {
    let output = metrics("example.org:53 {\n view child {\n  expr true\n }\n whoami\n}\norg:53 {\n cache\n acl {\n  filter\n }\n}", "example.org.", Type::DS).await;
    assert!(output.contains("pharos_acl_filtered_requests_total{server=\"dns://:53\",view=\"child\",zone=\"org.\"} 1"), "{output}");
    let cache = metrics("example.org:53 {\n view child {\n  expr true\n }\n whoami\n}\norg:53 {\n cache\n whoami\n}", "example.org.", Type::DS).await;
    assert!(
        cache.contains(
            "pharos_cache_requests_total{server=\"dns://:53\",view=\"\",zones=\"org.\"} 1"
        ),
        "{cache}"
    );
}

#[tokio::test]
async fn acl_view_labels_cover_allowed_blocked_and_dropped() {
    for (policy, action) in [
        ("allow", "allowed"),
        ("block", "blocked"),
        ("drop", "dropped"),
    ] {
        let text = format!(
            ".:53 {{\n view blue {{\n  expr true\n }}\n acl {{\n  {policy}\n }}\n whoami\n}}"
        );
        let output = metrics(&text, "example.org.", Type::A).await;
        let labels = if action == "allowed" {
            "server=\"dns://:53\",view=\"blue\""
        } else {
            "server=\"dns://:53\",view=\"blue\",zone=\".\""
        };
        assert!(
            output.contains(&format!("pharos_acl_{action}_requests_total{{{labels}}} 1")),
            "{output}"
        );
    }
}

#[tokio::test]
async fn ds_rejected_child_does_not_inherit_and_named_parent_overrides() {
    for (child_match, parent_view, expected) in [
        ("false", "", ""),
        ("true", "view parent {\n  expr true\n }", "parent"),
    ] {
        let text = format!(
            "example.org:53 {{\n view child {{\n  expr {child_match}\n }}\n whoami\n}}\norg:53 {{\n {parent_view}\n acl {{\n  filter\n }}\n}}"
        );
        let output = metrics(&text, "example.org.", Type::DS).await;
        assert!(output.contains(&format!("pharos_acl_filtered_requests_total{{server=\"dns://:53\",view=\"{expected}\",zone=\"org.\"}} 1")), "{output}");
    }
}

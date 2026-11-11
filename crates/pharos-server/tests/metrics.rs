#![forbid(unsafe_code)]

use pharos_server::metrics::Registry;

#[test]
fn migration_table_matches_all_registry_metric_families() {
    use std::collections::BTreeSet;
    let registry = Registry::new("v", "rev", "rustc");
    let block = registry.block("dns://:53", ".", "");
    block.plugin_enabled("whoami");
    block
        .plugin("whoami")
        .record(1, false, false, true, 30, 60, 0, 0.001);
    for transport in ["https", "https3", "quic"] {
        registry
            .transport_status(transport, "server", "200")
            .increment();
    }
    registry.cache("dns://:53", ".", "");
    registry.hosts("hosts").update(2, 123.0);
    let proxy = registry.proxy("forward", "192.0.2.1:53");
    proxy.request_duration("NOERROR").observe(0.001);
    proxy.connection_cache("udp").hit();
    proxy.connection_cache("udp").miss();
    proxy.healthcheck_failure();
    registry.forward();
    registry.enable_health_metrics();
    registry.observe_health(0.001, true);
    registry.reload_failed();
    registry.reload_version("abc".into());
    let kubernetes = registry.kubernetes();
    let request = kubernetes.request("GET", "api:6443");
    request.observe(0.02, "200");
    request.rate_limiter(0.003);
    kubernetes.programming_duration("cluster_ip", 0.002);
    let mut text = String::new();
    registry.encode(&mut text);
    let actual: BTreeSet<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    let documented: BTreeSet<_> = include_str!("../../../MIGRATION.md")
        .lines()
        .filter_map(|line| line.strip_prefix("| `pharos_"))
        .filter_map(|line| line.split_once('`').map(|(name, _)| name))
        .map(|name| format!("pharos_{name}"))
        .collect();
    assert_eq!(actual, documented.iter().map(String::as_str).collect());
}

#[test]
fn reload_counter_and_current_hash_are_preserved() {
    let registry = Registry::default();
    registry.reload_version("old".into());
    registry.reload_failed();
    registry.reload_version("new".into());
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(text.contains("pharos_reload_failed_total 1\n"));
    assert!(text.contains("pharos_reload_version_info{hash=\"sha512\",value=\"new\"} 1\n"));
    assert!(!text.contains("value=\"old\""));
}

#[test]
fn fixed_registry_matches_go_client_golden() {
    let registry = Registry::new("1\"\\\n", "rev", "rustc");
    registry
        .block("dns://:53", "example.\n", "")
        .record(1, false, false, true, 100, 200, 0, 0.001);
    let mut text = String::new();
    registry.encode(&mut text);
    assert_eq!(text, include_str!("fixtures/metrics.prom"));
}

#[test]
fn empty_registry_exposes_build_info_and_panics_only() {
    let registry = Registry::new("1\"\\\n", "rev", "rustc");
    let mut text = String::new();
    registry.encode(&mut text);
    assert_eq!(
        text,
        concat!(
            "# HELP pharos_build_info A metric with a constant '1' value labeled by version, revision, and rustc from which Pharos was built.\n",
            "# TYPE pharos_build_info gauge\n",
            "pharos_build_info{revision=\"rev\",rustc=\"rustc\",version=\"1\\\"\\\\\\n\"} 1\n",
            "# HELP pharos_panics_total A metrics that counts the number of panics.\n",
            "# TYPE pharos_panics_total counter\n",
            "pharos_panics_total 0\n",
        )
    );
}

#[test]
fn observed_metrics_have_coredns_labels_buckets_and_float_format() {
    let registry = Registry::new("v", "r", "rust");
    let block = registry.block("dns://:53", "example.\n", "");
    block.plugin_enabled("file");
    block
        .plugin("file")
        .record(1, false, false, true, 100, 200, 0, 0.001);
    block.record(65400, true, true, false, 65536, 1_000_000, 3, 1_000_000.0);
    let mut text = String::new();
    registry.encode(&mut text);

    for expected in [
        "pharos_dns_requests_total{family=\"1\",proto=\"udp\",server=\"dns://:53\",type=\"A\",view=\"\",zone=\"example.\\n\"} 1\n",
        "pharos_dns_requests_total{family=\"2\",proto=\"tcp\",server=\"dns://:53\",type=\"other\",view=\"\",zone=\"example.\\n\"} 1\n",
        "pharos_dns_responses_total{plugin=\"file\",rcode=\"NOERROR\",server=\"dns://:53\",view=\"\",zone=\"example.\\n\"} 1\n",
        "pharos_dns_do_requests_total{server=\"dns://:53\",view=\"\",zone=\"example.\\n\"} 1\n",
        "pharos_plugin_enabled{name=\"file\",server=\"dns://:53\",view=\"\",zone=\"example.\\n\"} 1\n",
        "pharos_dns_request_duration_seconds_bucket{server=\"dns://:53\",view=\"\",zone=\"example.\\n\",le=\"0.001\"} 1\n",
        "pharos_dns_request_duration_seconds_bucket{server=\"dns://:53\",view=\"\",zone=\"example.\\n\",le=\"+Inf\"} 2\n",
        "pharos_dns_request_duration_seconds_sum{server=\"dns://:53\",view=\"\",zone=\"example.\\n\"} 1.000000001e+06\n",
        "pharos_dns_response_size_bytes_sum{proto=\"tcp\",server=\"dns://:53\",view=\"\",zone=\"example.\\n\"} 1e+06\n",
    ] {
        assert!(text.contains(expected), "missing {expected:?}\n{text}");
    }
}

#[test]
fn handles_share_series_and_only_emit_observed_labels() {
    let registry = Registry::new("v", "r", "rust");
    let first = registry.block("s", ".", "");
    let second = registry.clone().block("s", ".", "");
    first.record(28, true, false, false, 10, 20, 2, 0.0);
    second.record(28, true, false, false, 10, 20, 2, 0.0);
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(text.contains("pharos_dns_requests_total{family=\"1\",proto=\"tcp\",server=\"s\",type=\"AAAA\",view=\"\",zone=\".\"} 2\n"));
    assert!(!text.contains("pharos_dns_do_requests_total"));
    assert!(!text.contains("proto=\"udp\""));
}

#[test]
fn transport_status_vectors() {
    let registry = Registry::new("v", "r", "rust");
    registry
        .transport_status("https3", "server", "200")
        .increment();
    registry
        .transport_status("https", "server", "500")
        .increment();
    registry.transport_status("quic", "server", "0").increment();
    let mut out = String::from("prefix\n");
    registry.encode(&mut out);
    assert!(out.starts_with("prefix\n"));
    assert!(
        out.contains("pharos_dns_https3_responses_total{server=\"server\",status=\"200\"} 1\n")
    );
    assert!(out.contains("pharos_dns_https_responses_total{server=\"server\",status=\"500\"} 1\n"));
    assert!(out.contains("pharos_dns_quic_responses_total{server=\"server\",status=\"0\"} 1\n"));
    assert!(
        out.find("# HELP pharos_dns_https3_").unwrap()
            < out.find("# HELP pharos_dns_https_").unwrap()
    );
}

#[test]
fn duration_histogram_golden() {
    let registry = Registry::new("v", "r", "rust");
    registry
        .block("s", ".", "")
        .record(1, false, false, false, 100, 100, 0, 0.001);
    let mut text = String::new();
    registry.encode(&mut text);
    let start = text
        .find("# HELP pharos_dns_request_duration_seconds ")
        .unwrap();
    let end = text[start..]
        .find("# HELP pharos_dns_request_size_bytes ")
        .unwrap()
        + start;
    assert_eq!(
        &text[start..end],
        concat!(
            "# HELP pharos_dns_request_duration_seconds Histogram of the time (in seconds) each request took per zone.\n",
            "# TYPE pharos_dns_request_duration_seconds histogram\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"0.00025\"} 0\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"0.0005\"} 0\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"0.001\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"0.002\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"0.004\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"0.008\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"0.016\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"0.032\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"0.064\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"0.128\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"0.256\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"0.512\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"1.024\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"2.048\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"4.096\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"8.192\"} 1\n",
            "pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"+Inf\"} 1\n",
            "pharos_dns_request_duration_seconds_sum{server=\"s\",view=\"\",zone=\".\"} 0.001\n",
            "pharos_dns_request_duration_seconds_count{server=\"s\",view=\"\",zone=\".\"} 1\n",
        )
    );
}

#[test]
fn response_codes_match_coredns_and_unknown_values_are_preserved() {
    let registry = Registry::new("v", "r", "rust");
    let block = registry.block("s", ".", "");
    for code in [11, 16, 4095] {
        block.record(1, false, false, false, 0, 0, code, 0.0);
    }
    let mut text = String::new();
    registry.encode(&mut text);
    for code in ["DSOTYPENI", "BADSIG", "RCODE4095"] {
        assert!(text.contains(&format!("rcode=\"{code}\"")));
    }
}

#[test]
fn series_sort_by_label_values_across_server_blocks() {
    let registry = Registry::new("v", "r", "rust");
    registry
        .block("s", "a", "z")
        .plugin("z")
        .record(28, false, false, false, 10, 20, 3, 0.0);
    registry
        .block("s", "z", "a")
        .plugin("a")
        .record(1, false, false, false, 10, 20, 0, 0.0);
    let mut text = String::new();
    registry.encode(&mut text);
    let request_a = text.find("type=\"A\"").unwrap();
    let request_aaaa = text.find("type=\"AAAA\"").unwrap();
    assert!(request_a < request_aaaa);
    let plugin_a = text.find("plugin=\"a\"").unwrap();
    let plugin_z = text.find("plugin=\"z\"").unwrap();
    assert!(plugin_a < plugin_z);
    let duration = &text[text
        .find("# HELP pharos_dns_request_duration_seconds")
        .unwrap()..];
    assert!(duration.find("view=\"a\"").unwrap() < duration.find("view=\"z\"").unwrap());
}

#[test]
fn concurrent_recording_preserves_counts() {
    let registry = Registry::new("v", "r", "rust");
    let plugin = registry.block("s", ".", "").plugin("file");
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let plugin = plugin.clone();
            scope.spawn(move || {
                for _ in 0..1000 {
                    plugin.record(1, false, false, true, 100, 200, 0, 0.5);
                }
            });
        }
    });
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(
        text.contains("pharos_dns_do_requests_total{server=\"s\",view=\"\",zone=\".\"} 4000\n")
    );
    assert!(text.contains(
        "pharos_dns_request_duration_seconds_sum{server=\"s\",view=\"\",zone=\".\"} 2000\n"
    ));
    assert!(text.contains(
        "pharos_dns_request_duration_seconds_count{server=\"s\",view=\"\",zone=\".\"} 4000\n"
    ));
}

#[test]
fn histogram_large_counts_use_go_float_format() {
    let registry = Registry::new("v", "r", "rust");
    let block = registry.block("s", ".", "");
    for _ in 0..1_000_000 {
        block.record(1, false, false, false, 1, 1, 0, 0.0);
    }
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(text.contains(
        "pharos_dns_request_duration_seconds_count{server=\"s\",view=\"\",zone=\".\"} 1e+06\n"
    ));
    assert!(text.contains("pharos_dns_request_duration_seconds_bucket{server=\"s\",view=\"\",zone=\".\",le=\"+Inf\"} 1e+06\n"));
}

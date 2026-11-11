#![forbid(unsafe_code)]

use pharos_server::metrics::Registry;

#[test]
fn shed_counters_report_both_reasons() {
    let registry = Registry::new("v", "r", "rust");
    let metrics = registry.shed("dns://:53");
    metrics.query_drop();
    metrics.response_drop();
    metrics.response_drop();
    let mut output = String::new();
    registry.encode(&mut output);
    assert!(
        output.contains("pharos_shed_dropped_total{reason=\"query\",server=\"dns://:53\"} 1"),
        "{output}"
    );
    assert!(
        output.contains("pharos_shed_dropped_total{reason=\"response\",server=\"dns://:53\"} 2"),
        "{output}"
    );
}

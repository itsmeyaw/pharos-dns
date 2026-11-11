#![forbid(unsafe_code)]

use pharos_server::metrics::Registry;
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn cache_metrics_are_shared_escaped_and_allocation_free() {
    let registry = Registry::new("v", "r", "rust");
    let cache = registry.cache("dns://:53", "example.\n", "a\"b");
    let same = registry.cache("dns://:53", "example.\n", "a\"b").clone();
    let before = GLOBAL.stats();
    cache.request();
    same.request();
    cache.hit(false);
    cache.hit(true);
    cache.miss();
    cache.prefetch();
    cache.drop_response();
    cache.served_stale();
    cache.evict(false);
    cache.evict(true);
    cache.entries(false, 1_000_000);
    cache.entries(true, 5);
    cache.entries(true, 0);
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);

    let mut out = String::new();
    registry.encode(&mut out);
    for expected in [
        "# HELP pharos_cache_entries The number of elements in the cache.",
        "# TYPE pharos_cache_entries gauge",
        "# HELP pharos_cache_requests_total The count of cache requests.",
        "# HELP pharos_cache_hits_total The count of cache hits.",
        "# HELP pharos_cache_misses_total The count of cache misses. Deprecated, derive misses from cache hits/requests counters.",
        "# HELP pharos_cache_prefetch_total The number of times the cache has prefetched a cached item.",
        "# HELP pharos_cache_drops_total The number responses that are not cached, because the reply is malformed.",
        "# HELP pharos_cache_served_stale_total The number of requests served from stale cache entries.",
        "# HELP pharos_cache_evictions_total The count of cache evictions.",
        "# TYPE pharos_cache_hits_total counter",
        "pharos_cache_entries{server=\"dns://:53\",type=\"success\",view=\"a\\\"b\",zones=\"example.\\n\"} 1e+06",
        "pharos_cache_entries{server=\"dns://:53\",type=\"denial\",view=\"a\\\"b\",zones=\"example.\\n\"} 0",
        "pharos_cache_hits_total{server=\"dns://:53\",type=\"success\",view=\"a\\\"b\",zones=\"example.\\n\"} 1",
        "pharos_cache_hits_total{server=\"dns://:53\",type=\"denial\",view=\"a\\\"b\",zones=\"example.\\n\"} 1",
        "pharos_cache_evictions_total{server=\"dns://:53\",type=\"success\",view=\"a\\\"b\",zones=\"example.\\n\"} 1",
        "pharos_cache_evictions_total{server=\"dns://:53\",type=\"denial\",view=\"a\\\"b\",zones=\"example.\\n\"} 1",
        "pharos_cache_requests_total{server=\"dns://:53\",view=\"a\\\"b\",zones=\"example.\\n\"} 2",
        "pharos_cache_misses_total{server=\"dns://:53\",view=\"a\\\"b\",zones=\"example.\\n\"} 1",
        "pharos_cache_prefetch_total{server=\"dns://:53\",view=\"a\\\"b\",zones=\"example.\\n\"} 1",
        "pharos_cache_drops_total{server=\"dns://:53\",view=\"a\\\"b\",zones=\"example.\\n\"} 1",
        "pharos_cache_served_stale_total{server=\"dns://:53\",view=\"a\\\"b\",zones=\"example.\\n\"} 1",
    ] {
        assert!(
            out.lines().any(|line| line == expected),
            "missing {expected}\n{out}"
        );
    }
    cache_series_require_configuration_and_are_isolated_by_labels();
    concurrent_cache_recording_preserves_counts();
}

fn concurrent_cache_recording_preserves_counts() {
    let registry = Registry::new("v", "r", "rust");
    let cache = registry.cache("s", ".", "");
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let cache = cache.clone();
            scope.spawn(move || {
                for _ in 0..1000 {
                    cache.request();
                    cache.hit(true);
                }
            });
        }
    });
    let mut out = String::new();
    registry.encode(&mut out);
    assert!(out.contains("pharos_cache_requests_total{server=\"s\",view=\"\",zones=\".\"} 4000\n"));
    assert!(out.contains(
        "pharos_cache_hits_total{server=\"s\",type=\"denial\",view=\"\",zones=\".\"} 4000\n"
    ));
}

fn cache_series_require_configuration_and_are_isolated_by_labels() {
    let registry = Registry::new("v", "r", "rust");
    let mut out = String::new();
    registry.encode(&mut out);
    assert!(!out.contains("pharos_cache_"));

    registry.cache("s", ".", "one").request();
    registry.cache("s", ".", "two").request();
    registry.cache("s", "other.", "one").request();
    out.clear();
    registry.encode(&mut out);
    for labels in [
        "server=\"s\",view=\"one\",zones=\".\"",
        "server=\"s\",view=\"two\",zones=\".\"",
        "server=\"s\",view=\"one\",zones=\"other.\"",
    ] {
        assert!(out.contains(&format!("pharos_cache_requests_total{{{labels}}} 1\n")));
    }
}

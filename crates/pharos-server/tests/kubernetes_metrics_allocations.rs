#![forbid(unsafe_code)]

use pharos_server::metrics::Registry;
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn warm_kubernetes_metric_recording_does_not_allocate() {
    let registry = Registry::new("v", "r", "rust");
    let metrics = registry.kubernetes();
    metrics.request("GET", "api:6443").observe(0.1, "200");
    metrics.programming_duration("cluster_ip", 0.1);
    let before = GLOBAL.stats();
    for _ in 0..10 {
        let request = metrics.request("GET", "api:6443");
        request.observe(0.1, "200");
        request.rate_limiter(0.01);
        metrics.programming_duration("cluster_ip", 0.1);
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
}

#![forbid(unsafe_code)]

use pharos_server::metrics::Registry;
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn proxy_recording_never_allocates() {
    let registry = Registry::new("v", "r", "rust");
    let proxy = registry.proxy("forward", "192.0.2.1:53");
    let duration = proxy.request_duration("NOERROR");
    let udp = proxy.connection_cache("udp");
    let before = GLOBAL.stats();
    for _ in 0..10 {
        duration.observe(0.01);
        udp.hit();
        udp.miss();
        proxy.healthcheck_failure();
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
}

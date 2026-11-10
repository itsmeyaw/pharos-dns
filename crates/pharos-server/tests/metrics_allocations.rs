#![forbid(unsafe_code)]

use pharos_server::metrics::Registry;
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn recording_first_and_subsequent_queries_never_allocates() {
    let registry = Registry::new("v", "r", "rust");
    let block = registry.block("s", ".", "");
    let plugin = block.plugin("file");
    let before = GLOBAL.stats();
    for qtype in [1, 28, 65000] {
        for rcode in [0, 3, 42] {
            block.record(qtype, true, true, true, 128, 256, rcode, 0.01);
            plugin.record(qtype, true, true, true, 128, 256, rcode, 0.01);
        }
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
}

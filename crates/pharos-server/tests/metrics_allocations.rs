#![forbid(unsafe_code)]

use pharos_server::metrics::Registry;
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::alloc::System;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

// Keep this binary to one test: the allocator counts every thread in the process.
#[test]
fn common_codes_and_warmed_extended_codes_do_not_allocate() {
    let registry = Registry::new("v", "r", "rust");
    let before_zone = GLOBAL.stats();
    let block = registry.block("dns://:53", "example.org.", "");
    for name in ["auto", "prometheus", "p1", "p2", "p3", "p4", "p5"] {
        let _ = block.plugin(name);
    }
    let after_zone = GLOBAL.stats();
    let retained = (after_zone.bytes_allocated - before_zone.bytes_allocated)
        - (after_zone.bytes_deallocated - before_zone.bytes_deallocated);
    // Seven Plugin series, one default series, requests, histograms and registry metadata.
    assert!(retained < 6_000, "retained bytes: {retained}");
    println!("seven-plugin Zone metrics retain {retained} bytes");
    let plugin = block.plugin("file");
    let before = GLOBAL.stats();
    for qtype in [1, 28, 65000] {
        for rcode in 0..=23 {
            block.record(qtype, true, true, true, 128, 256, rcode, 0.01);
            plugin.record(qtype, true, true, true, 128, 256, rcode, 0.01);
        }
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);

    block.record(1, true, true, true, 128, 256, 42, 0.01);
    plugin.record(1, true, true, true, 128, 256, 42, 0.01);
    let initialized = GLOBAL.stats();
    assert_eq!(initialized.allocations - after.allocations, 2);
    assert_eq!(initialized.reallocations - after.reallocations, 0);
    for rcode in [24, 42, 4095] {
        block.record(1, true, true, true, 128, 256, rcode, 0.01);
        plugin.record(1, true, true, true, 128, 256, rcode, 0.01);
    }
    let warmed = GLOBAL.stats();
    assert_eq!(warmed.allocations - initialized.allocations, 0);
    assert_eq!(warmed.reallocations - initialized.reallocations, 0);
}

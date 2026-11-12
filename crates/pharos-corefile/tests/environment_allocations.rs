#![forbid(unsafe_code)]

use pharos_corefile::parse_with_env;
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::{
    alloc::System,
    sync::atomic::{AtomicUsize, Ordering},
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn environment_expansion_does_not_retain_each_intermediate_copy() {
    let input = format!("{{$0}}{}", "a".repeat(65536));
    let baseline = GLOBAL.stats();
    let baseline_live = baseline.bytes_allocated - baseline.bytes_deallocated;
    let peak = AtomicUsize::new(0);
    let blocks = parse_with_env("Corefile", &input, |name| {
        let stats = GLOBAL.stats();
        peak.fetch_max(
            stats.bytes_allocated - stats.bytes_deallocated - baseline_live,
            Ordering::Relaxed,
        );
        let index: usize = name.parse().unwrap();
        Some(if index == 119 {
            "x".into()
        } else {
            format!("{{${}}}", index + 1)
        })
    })
    .unwrap();
    assert!(blocks[0].keys()[0].starts_with('x'));
    assert!(
        peak.load(Ordering::Relaxed) < 2_000_000,
        "intermediate copies were retained"
    );
}

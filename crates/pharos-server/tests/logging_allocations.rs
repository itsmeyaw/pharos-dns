#![forbid(unsafe_code)]

use pharos_server::logging::{LogFormat, format_line};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::{alloc::System, time::UNIX_EPOCH};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn text_log_allocates_only_the_output_line() {
    let region = Region::new(GLOBAL);
    let line = format_line(LogFormat::Text, UNIX_EPOCH, "INFO", "log", "message");
    let stats = region.change();
    assert_eq!(line, "1970-01-01T00:00:00Z INFO log: message\n");
    assert_eq!((stats.allocations, stats.reallocations), (1, 0));
}

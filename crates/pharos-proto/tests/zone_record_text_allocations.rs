#![forbid(unsafe_code)]

use std::alloc::System;

use pharos_proto::{Name, zone::parse_record_text};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

// One test in its own process prevents unrelated test threads from contaminating counts.
#[test]
fn single_record_text_parse_does_not_allocate() {
    let origin: Name = "example.".parse().unwrap();
    let mut buffer = vec![0; 4096];
    let texts = [
        "www 60 IN A 192.0.2.1",
        "www.example. 60 IN AAAA 2001:db8::1",
        "www 60 IN CNAME target",
        "www 60 IN MX 10 mail",
        "example. 60 IN SOA ns hostmaster 1 2h 3m 4w 5",
        "_sip._tcp 60 IN SRV 1 2 5060 sip",
        "www 60 IN TXT \"v=spf1 include:example.net ~all\" more",
    ];
    let region = Region::new(GLOBAL);
    for text in texts {
        let record = parse_record_text(text, &origin, Some(3600), &mut buffer).unwrap();
        std::hint::black_box(&record);
    }
    let stats = region.change();
    assert_eq!(
        (
            stats.allocations,
            stats.reallocations,
            stats.bytes_allocated
        ),
        (0, 0, 0),
        "{stats:?}"
    );
}

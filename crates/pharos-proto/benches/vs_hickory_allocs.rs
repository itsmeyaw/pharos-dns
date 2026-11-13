mod common_hickory;
use common_hickory::*;
use hickory_proto::op::Message as HMessage;
use pharos_proto::Message;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::alloc::System;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn measure(label: &str, mut f: impl FnMut()) {
    f(); // warm
    let region = Region::new(GLOBAL);
    f();
    let s = region.change();
    println!(
        "{label:32} allocs={:3} bytes={:5}",
        s.allocations, s.bytes_allocated
    );
}

fn main() {
    let response = pharos_response();
    let hname = hickory_name();
    measure("pharos parse_query", || {
        std::hint::black_box(Message::parse(QUERY).unwrap());
    });
    measure("hickory parse_query", || {
        std::hint::black_box(HMessage::from_vec(QUERY).unwrap());
    });
    measure("pharos parse_response", || {
        let m = Message::parse(&response).unwrap();
        std::hint::black_box(m.answers().count());
    });
    measure("hickory parse_response", || {
        std::hint::black_box(HMessage::from_vec(&response).unwrap());
    });
    measure("hickory build+encode", || {
        std::hint::black_box(hickory_response(&hname).to_vec().unwrap());
    });
}

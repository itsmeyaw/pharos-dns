#![forbid(unsafe_code)]

use pharos_proto::{TsigAlgorithm, TsigKey, TsigStream};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::alloc::System;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn reused_stream_output_needs_no_rust_allocations() {
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let request_mac = [42; 32];
    let mut signer = TsigStream::new(&key, &request_mac);
    let mut verifier = TsigStream::new(&key, &request_mac);
    let mut wire = Vec::with_capacity(512);
    let region = Region::new(GLOBAL);
    for _ in 0..3 {
        wire.clear();
        wire.extend_from_slice(&[0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        signer.sign(&mut wire, 1000, 300).unwrap();
        verifier.verify(&wire, 1000, 0).unwrap();
    }
    verifier.finish().unwrap();
    assert_eq!(region.change().allocations, 0);
}

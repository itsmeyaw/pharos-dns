#![forbid(unsafe_code)]
#![recursion_limit = "512"]

//! Signed cache-miss latency and Rust-heap allocations per DNSSEC algorithm (#106).
//!
//! Usage: `cargo bench -p pharos-plugins --bench dnssec -- <label>=<key base path>...`
//! where `<base>.key` and `<base>.private` are BIND key files for `miek.nl`.

use std::{
    alloc::System,
    future::Future,
    hint::black_box,
    task::{Context, Poll, Waker},
    time::Instant,
};

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn run(future: impl Future<Output = Action>) -> Action {
    match std::pin::pin!(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("dnssec handler must be ready immediately"),
    }
}

// RFC 6891 §6.1.3 and RFC 4035 §3.2.1: EDNS0 OPT with DO set requests signatures.
fn query(i: usize) -> Vec<u8> {
    let label = format!("w{i}");
    let mut wire = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\x01".to_vec();
    wire.push(label.len() as u8);
    wire.extend_from_slice(label.as_bytes());
    wire.extend_from_slice(b"\x04miek\x02nl\0\0\x01\0\x01");
    wire.extend_from_slice(b"\0\0\x29\x04\xd0\0\0\x80\0\0\0");
    wire
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    sorted[(((sorted.len() - 1) as f64) * p).round() as usize]
}

fn summarize(times: &mut [u64]) -> String {
    times.sort_unstable();
    let mean = times.iter().sum::<u64>() / times.len() as u64;
    format!(
        "p50={}ns p99={}ns p99.9={}ns mean={}ns",
        percentile(times, 0.5),
        percentile(times, 0.99),
        percentile(times, 0.999),
        mean
    )
}

fn main() {
    let n: usize = std::env::var("PHAROS_BENCH_N")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(20_000);
    for arg in std::env::args().skip(1).filter(|arg| arg.contains('=')) {
        let (label, base) = arg.split_once('=').unwrap();
        let text = format!("miek.nl:0 {{\n dnssec {{\n key file {base}\n }}\n whoami\n}}");
        let (mut servers, _) =
            servers(configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap())
                .unwrap();
        let (_, server) = servers.drain().next().unwrap();
        let peer = "127.0.0.1:1001".parse().unwrap();
        let mut response = Vec::with_capacity(65535);
        let handle = |query: &[u8], response: &mut Vec<u8>| {
            run(server.handle(black_box(query), peer, Protocol::Udp, response))
        };

        // Queries are built up front so allocation counts cover only the handler.
        let queries: Vec<_> = (0..n + 2_000).map(query).collect();
        for q in &queries[..2_000] {
            handle(q, &mut response);
        }
        let mut miss = Vec::with_capacity(n);
        let (mut allocations, mut bytes) = (0, 0);
        for q in &queries[2_000..] {
            let before = GLOBAL.stats();
            let start = Instant::now();
            assert_eq!(handle(q, &mut response), Action::Respond);
            miss.push(start.elapsed().as_nanos() as u64);
            let after = GLOBAL.stats();
            allocations += after.allocations - before.allocations;
            bytes += after.bytes_allocated - before.bytes_allocated;
        }
        handle(&queries[2_000], &mut response);
        let message = pharos_proto::Message::parse(&response).unwrap();
        let rrsigs = message
            .answers()
            .chain(message.authorities())
            .chain(message.additionals())
            .filter(|rr| rr.rtype == pharos_proto::Type::RRSIG)
            .count();
        println!(
            "{label} miss  {} allocs/miss={:.1} bytes/miss={} rrsigs={rrsigs}",
            summarize(&mut miss),
            allocations as f64 / n as f64,
            bytes / n
        );

        // Cache hit on the most recent query (not evicted).
        let last = queries.last().unwrap();
        let mut hit = Vec::with_capacity(n);
        let before = GLOBAL.stats();
        for _ in 0..n {
            let start = Instant::now();
            handle(last, &mut response);
            hit.push(start.elapsed().as_nanos() as u64);
        }
        let after = GLOBAL.stats();
        println!(
            "{label} hit   {} allocs/hit={}",
            summarize(&mut hit),
            (after.allocations - before.allocations) / n
        );

        // Raw signer cost for one signature, to separate crypto from plugin overhead.
        let key = pharos_dnssec::keys::KeyPair::from_files(
            format!("{base}.key"),
            format!("{base}.private"),
        )
        .unwrap();
        let der = key.private.to_pkcs8_der().unwrap();
        let signer =
            pharos_dnssec::sign::SigningKey::from_pkcs8(key.public.algorithm, &der).unwrap();
        let mut signature = [0; 512];
        let mut sign = Vec::with_capacity(n);
        let before = GLOBAL.stats();
        for _ in 0..n {
            let start = Instant::now();
            black_box(signer.sign_into(black_box(b"canonical RRSIG data"), &mut signature))
                .unwrap();
            sign.push(start.elapsed().as_nanos() as u64);
        }
        let after = GLOBAL.stats();
        println!(
            "{label} sign  {} allocs/sign={}",
            summarize(&mut sign),
            (after.allocations - before.allocations) / n
        );
    }
}

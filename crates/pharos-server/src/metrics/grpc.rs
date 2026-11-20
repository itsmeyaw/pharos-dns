use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use super::{
    Histogram, ResponseCounters, SortedSamples, TIME_BUCKETS, encode_histogram, header, rcode,
};

// CoreDNS v1.15.0 plugin/grpc/metrics.go: `requests_total`, `responses_total` and `request_duration_seconds` are labelled by `to`.
#[derive(Default)]
pub(super) struct GrpcRegistry(Mutex<BTreeMap<String, Arc<Upstream>>>);

struct Upstream {
    requests: AtomicU64,
    responses: ResponseCounters,
    duration: Histogram,
}

/// Counters of one gRPC Upstream with its `to` label resolved at setup.
#[derive(Clone)]
pub struct GrpcMetrics(Arc<Upstream>);

impl GrpcRegistry {
    // CoreDNS v1.15.0 plugin/grpc/proxy.go query: series are keyed by the Upstream's address text.
    pub(super) fn resolve(&self, to: &str) -> GrpcMetrics {
        GrpcMetrics(Arc::clone(
            self.0.lock().unwrap().entry(to.into()).or_insert_with(|| {
                Arc::new(Upstream {
                    requests: AtomicU64::new(0),
                    responses: ResponseCounters::default(),
                    duration: Histogram::new(TIME_BUCKETS),
                })
            }),
        ))
    }

    pub(super) fn encode(&self, out: &mut String) {
        let upstreams = self.0.lock().unwrap();
        let mut sorted = SortedSamples::default();
        for (to, upstream) in upstreams.iter() {
            let n = upstream.requests.load(Ordering::Relaxed);
            if n != 0 {
                // CoreDNS v1.15.0 plugin/grpc/metrics.go RequestCount: `to` is the only label.
                sorted.sample("grpc_requests_total", &[("to", to)], n);
            }
        }
        if !sorted.0.is_empty() {
            // CoreDNS v1.15.0 plugin/grpc/metrics.go RequestCount: Help text.
            header(
                out,
                "grpc_requests_total",
                "Counter of requests made per upstream.",
                "counter",
            );
            sorted.write(out);
        }
        let mut sorted = SortedSamples::default();
        for (to, upstream) in upstreams.iter() {
            for (code, counter) in upstream.responses.iter() {
                let n = counter.load(Ordering::Relaxed);
                if n != 0 {
                    // CoreDNS v1.15.0 plugin/grpc/proxy.go: the RCODE label is its mnemonic.
                    let label = rcode(code as u16);
                    sorted.sample("grpc_responses_total", &[("rcode", &label), ("to", to)], n);
                }
            }
        }
        if !sorted.0.is_empty() {
            // CoreDNS v1.15.0 plugin/grpc/metrics.go RcodeCount: Help text repeats RequestCount's.
            header(
                out,
                "grpc_responses_total",
                "Counter of requests made per upstream.",
                "counter",
            );
            sorted.write(out);
        }
        let mut sorted = SortedSamples::default();
        for (to, upstream) in upstreams.iter() {
            if upstream.duration.count() != 0 {
                // CoreDNS v1.15.0 plugin/grpc/metrics.go RequestDuration: buckets are `plugin.TimeBuckets`.
                let values = [("to", to.as_str())];
                let mut text = String::new();
                encode_histogram(
                    &mut text,
                    "grpc_request_duration_seconds",
                    &values,
                    TIME_BUCKETS,
                    &upstream.duration,
                );
                sorted.insert(&values, text);
            }
        }
        if !sorted.0.is_empty() {
            // CoreDNS v1.15.0 plugin/grpc/metrics.go RequestDuration: Help text.
            header(
                out,
                "grpc_request_duration_seconds",
                "Histogram of the time each request took.",
                "histogram",
            );
            sorted.write(out);
        }
    }
}

impl GrpcMetrics {
    /// Record one successful call that answered with `rcode` after `seconds`.
    // CoreDNS v1.15.0 plugin/grpc/proxy.go query: the three series are updated together after a reply unpacks.
    pub fn observe(&self, rcode: u16, seconds: f64) {
        self.0.requests.fetch_add(1, Ordering::Relaxed);
        self.0.responses.increment(rcode);
        self.0.duration.observe(TIME_BUCKETS, seconds);
    }
}

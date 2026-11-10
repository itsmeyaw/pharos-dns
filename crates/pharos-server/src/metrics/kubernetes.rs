use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use super::{Histogram, encode_histogram, header, sample};

const REST: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
const PROGRAMMING: &[f64] = &[
    0.001, 0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128, 0.256, 0.512, 1.024, 2.048, 4.096,
    8.192, 16.384, 32.768, 65.536, 131.072, 262.144, 524.288,
];

#[derive(Default)]
struct Metrics {
    requests: Mutex<BTreeMap<(String, String), Arc<Request>>>,
    programming: Mutex<BTreeMap<String, Arc<Histogram>>>,
}

struct Request {
    duration: Histogram,
    limiter: Histogram,
    codes: Mutex<BTreeMap<String, Arc<AtomicU64>>>,
}

#[derive(Clone, Default)]
pub struct KubernetesMetrics(Arc<Metrics>);

#[derive(Clone)]
pub struct KubernetesRequestMetrics(Arc<Request>);

impl KubernetesMetrics {
    pub fn request(&self, verb: &str, host: &str) -> KubernetesRequestMetrics {
        let mut requests = self.0.requests.lock().unwrap();
        KubernetesRequestMetrics(
            requests
                .entry((verb.into(), host.into()))
                .or_insert_with(|| {
                    Arc::new(Request {
                        duration: Histogram::new(REST),
                        limiter: Histogram::new(REST),
                        codes: Mutex::new(BTreeMap::new()),
                    })
                })
                .clone(),
        )
    }

    pub fn programming_duration(&self, kind: &str, seconds: f64) {
        let histogram = self
            .0
            .programming
            .lock()
            .unwrap()
            .entry(kind.into())
            .or_insert_with(|| Arc::new(Histogram::new(PROGRAMMING)))
            .clone();
        histogram.observe(PROGRAMMING, seconds);
    }

    pub(super) fn encode(&self, out: &mut String) {
        let requests = self.0.requests.lock().unwrap();
        for (name, help, is_limiter) in [
            (
                "kubernetes_rest_client_request_duration_seconds",
                "Request latency in seconds. Broken down by verb and host.",
                false,
            ),
            (
                "kubernetes_rest_client_rate_limiter_duration_seconds",
                "Client side rate limiter latency in seconds. Broken down by verb and host.",
                true,
            ),
        ] {
            if requests.values().any(|request| {
                if is_limiter {
                    request.limiter.count() > 0
                } else {
                    request.duration.count() > 0
                }
            }) {
                header(out, name, help, "histogram");
                for ((verb, host), request) in requests.iter() {
                    let histogram = if is_limiter {
                        &request.limiter
                    } else {
                        &request.duration
                    };
                    if histogram.count() > 0 {
                        encode_histogram(
                            out,
                            name,
                            &[("host", host), ("verb", verb)],
                            REST,
                            histogram,
                        );
                    }
                }
            }
        }
        if requests
            .values()
            .any(|request| !request.codes.lock().unwrap().is_empty())
        {
            let name = "kubernetes_rest_client_requests_total";
            header(
                out,
                name,
                "Number of HTTP requests, partitioned by status code, method, and host.",
                "counter",
            );
            for ((verb, host), request) in requests.iter() {
                for (code, count) in request.codes.lock().unwrap().iter() {
                    sample(
                        out,
                        name,
                        &[("code", code), ("host", host), ("method", verb)],
                        count.load(Ordering::Relaxed),
                    );
                }
            }
        }
        let programming = self.0.programming.lock().unwrap();
        if !programming.is_empty() {
            let name = "kubernetes_dns_programming_duration_seconds";
            header(
                out,
                name,
                "Histogram of the time (in seconds) it took to program a dns instance.",
                "histogram",
            );
            for (kind, histogram) in programming.iter() {
                encode_histogram(out, name, &[("service_kind", kind)], PROGRAMMING, histogram);
            }
        }
    }
}

impl KubernetesRequestMetrics {
    pub fn observe(&self, seconds: f64, code: &str) {
        self.0.duration.observe(REST, seconds);
        self.0
            .codes
            .lock()
            .unwrap()
            .entry(code.into())
            .or_default()
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn rate_limiter(&self, seconds: f64) {
        self.0.limiter.observe(REST, seconds);
    }
}

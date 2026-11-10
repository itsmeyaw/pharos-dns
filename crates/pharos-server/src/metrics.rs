//! The custom encoder matches Go floats, which `prometheus` 0.14 does not.

use std::{
    collections::BTreeMap,
    fmt::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

const TYPES: &[(u16, &str)] = &[
    (1, "A"),
    (28, "AAAA"),
    (5, "CNAME"),
    (48, "DNSKEY"),
    (43, "DS"),
    (15, "MX"),
    (50, "NSEC3"),
    (47, "NSEC"),
    (2, "NS"),
    (12, "PTR"),
    (46, "RRSIG"),
    (6, "SOA"),
    (33, "SRV"),
    (16, "TXT"),
    (65, "HTTPS"),
    (64, "SVCB"),
    (251, "IXFR"),
    (252, "AXFR"),
    (255, "ANY"),
];
const RESPONSE_CODES: usize = 4096;
pub const WRITER_METADATA: &str = "prometheus/writer";
const TIME_BUCKETS: &[f64] = &[
    0.00025, 0.0005, 0.001, 0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.128, 0.256, 0.512, 1.024,
    2.048, 4.096, 8.192,
];
const HEALTH_BUCKETS: &[f64] = &[0.00025, 0.0025, 0.025, 0.25, 2.5];
const SIZE_BUCKETS: &[f64] = &[
    0., 100., 200., 300., 400., 511., 1023., 2047., 4095., 8291., 16000., 32000., 48000., 64000.,
];

type Key = (String, String, String);
type StatusKey = (String, String, String);

#[derive(Clone)]
pub struct Registry(Arc<RegistryInner>);

struct RegistryInner {
    version: String,
    revision: String,
    rustc: String,
    blocks: Mutex<BTreeMap<Key, Arc<Block>>>,
    statuses: Mutex<BTreeMap<StatusKey, Arc<AtomicU64>>>,
    process: AtomicBool,
    health_enabled: AtomicBool,
    health_duration: Histogram,
    health_failures: AtomicU64,
}

#[derive(Clone)]
pub struct BlockMetrics(Arc<Block>);

#[derive(Clone)]
pub struct TransportStatus(Arc<AtomicU64>);

impl TransportStatus {
    pub fn increment(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct PluginMetrics {
    block: Arc<Block>,
    responses: Arc<Vec<AtomicU64>>,
}

struct Block {
    server: String,
    zone: String,
    view: String,
    requests: Vec<AtomicU64>,
    do_requests: AtomicU64,
    duration: Histogram,
    request_size: [Histogram; 2],
    response_size: [Histogram; 2],
    default_responses: Arc<Vec<AtomicU64>>,
    plugins: Mutex<BTreeMap<String, Arc<Vec<AtomicU64>>>>,
    enabled: Mutex<BTreeMap<String, bool>>,
}

struct Histogram {
    buckets: Vec<AtomicU64>,
    sum: AtomicU64,
}

impl Histogram {
    fn new(bounds: &[f64]) -> Self {
        Self {
            buckets: counters(bounds.len() + 1),
            sum: AtomicU64::new(0),
        }
    }

    fn observe(&self, bounds: &[f64], value: f64) {
        let index = bounds
            .iter()
            .position(|bound| value <= *bound)
            .unwrap_or(bounds.len());
        let mut bits = self.sum.load(Ordering::Relaxed);
        loop {
            let next = (f64::from_bits(bits) + value).to_bits();
            match self
                .sum
                .compare_exchange_weak(bits, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(actual) => bits = actual,
            }
        }
        self.buckets[index].fetch_add(1, Ordering::Relaxed);
    }

    fn count(&self) -> u64 {
        // shortcut: scrape snapshots can race observations until histogram snapshots are synchronized.
        self.buckets.iter().map(|n| n.load(Ordering::Relaxed)).sum()
    }
}

fn counters(count: usize) -> Vec<AtomicU64> {
    (0..count).map(|_| AtomicU64::new(0)).collect()
}

impl Registry {
    pub fn new(version: &str, revision: &str, rustc: &str) -> Self {
        Self(Arc::new(RegistryInner {
            version: version.into(),
            revision: revision.into(),
            rustc: rustc.into(),
            blocks: Mutex::new(BTreeMap::new()),
            statuses: Mutex::new(BTreeMap::new()),
            process: AtomicBool::new(false),
            health_enabled: AtomicBool::new(false),
            health_duration: Histogram::new(HEALTH_BUCKETS),
            health_failures: AtomicU64::new(0),
        }))
    }

    pub fn block(&self, server: &str, zone: &str, view: &str) -> BlockMetrics {
        let key = (server.to_owned(), zone.to_owned(), view.to_owned());
        let mut blocks = self.0.blocks.lock().unwrap();
        BlockMetrics(Arc::clone(blocks.entry(key).or_insert_with(|| {
            let default_responses = Arc::new(counters(RESPONSE_CODES));
            let mut plugins = BTreeMap::new();
            plugins.insert(String::new(), Arc::clone(&default_responses));
            Arc::new(Block {
                server: server.into(),
                zone: zone.into(),
                view: view.into(),
                requests: counters((TYPES.len() + 1) * 4),
                do_requests: AtomicU64::new(0),
                duration: Histogram::new(TIME_BUCKETS),
                request_size: std::array::from_fn(|_| Histogram::new(SIZE_BUCKETS)),
                response_size: std::array::from_fn(|_| Histogram::new(SIZE_BUCKETS)),
                default_responses,
                plugins: Mutex::new(plugins),
                enabled: Mutex::new(BTreeMap::new()),
            })
        })))
    }

    /// Include process metrics from the operating system at scrape time.
    pub fn enable_process_metrics(&self) {
        self.0.process.store(true, Ordering::Relaxed);
    }

    pub fn enable_health_metrics(&self) {
        self.0.health_enabled.store(true, Ordering::Relaxed);
    }

    pub fn observe_health(&self, seconds: f64, failed: bool) {
        self.0.health_duration.observe(HEALTH_BUCKETS, seconds);
        if failed {
            self.0.health_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Resolve a transport status vector ("https", "https3", or "quic").
    pub fn transport_status(&self, transport: &str, server: &str, status: &str) -> TransportStatus {
        assert!(matches!(transport, "https" | "https3" | "quic"));
        let counter = self
            .0
            .statuses
            .lock()
            .unwrap()
            .entry((transport.into(), server.into(), status.into()))
            .or_default()
            .clone();
        TransportStatus(counter)
    }

    /// Append text to `out`; callers can append process metrics to the same buffer.
    pub fn encode(&self, out: &mut String) {
        if self.0.health_enabled.load(Ordering::Relaxed) {
            let name = "health_request_duration_seconds";
            header(
                out,
                name,
                "Histogram of the time (in seconds) each request took.",
                "histogram",
            );
            let histogram = &self.0.health_duration;
            let mut count = 0;
            for (index, bucket) in histogram.buckets.iter().enumerate() {
                count += bucket.load(Ordering::Relaxed);
                let bound = HEALTH_BUCKETS
                    .get(index)
                    .map_or_else(|| "+Inf".into(), |v| float(*v));
                writeln!(out, "pharos_{name}_bucket{{le=\"{bound}\"}} {count}").unwrap();
            }
            writeln!(
                out,
                "pharos_{name}_sum {}",
                float(f64::from_bits(histogram.sum.load(Ordering::Relaxed)))
            )
            .unwrap();
            writeln!(out, "pharos_{name}_count {count}").unwrap();
            header(
                out,
                "health_request_failures_total",
                "The number of times the health check failed.",
                "counter",
            );
            writeln!(
                out,
                "pharos_health_request_failures_total {}",
                self.0.health_failures.load(Ordering::Relaxed)
            )
            .unwrap();
        }
        header(
            out,
            "build_info",
            "A metric with a constant '1' value labeled by version, revision, and rustc from which Pharos was built.",
            "gauge",
        );
        out.push_str("pharos_build_info{");
        labels(
            out,
            &[
                ("revision", &self.0.revision),
                ("rustc", &self.0.rustc),
                ("version", &self.0.version),
            ],
        );
        out.push_str("} 1\n");

        let blocks = self.0.blocks.lock().unwrap();
        let status = self.0.statuses.lock().unwrap();
        if blocks
            .values()
            .any(|b| b.do_requests.load(Ordering::Relaxed) != 0)
        {
            header(
                out,
                "dns_do_requests_total",
                "Counter of DNS requests with DO bit set per zone.",
                "counter",
            );
            let mut sorted = SortedSamples::default();
            for b in blocks.values() {
                let n = b.do_requests.load(Ordering::Relaxed);
                if n != 0 {
                    sorted.sample("dns_do_requests_total", &b.labels(), n);
                }
            }
            sorted.write(out);
        }
        for (transport, help) in [
            (
                "https3",
                "Counter of DoH3 responses per server and http status code.",
            ),
            (
                "https",
                "Counter of DoH responses per server and http status code.",
            ),
            (
                "quic",
                "Counter of DoQ responses per server and QUIC application code.",
            ),
        ] {
            if status.keys().any(|(kind, _, _)| kind == transport) {
                let name = format!("dns_{transport}_responses_total");
                header(out, &name, help, "counter");
                for ((kind, server, code), n) in
                    status.iter().filter(|((kind, _, _), _)| kind == transport)
                {
                    let _ = kind;
                    sample(
                        out,
                        &name,
                        &[("server", server), ("status", code)],
                        n.load(Ordering::Relaxed),
                    );
                }
            }
        }
        histogram_family(
            out,
            &blocks,
            "dns_request_duration_seconds",
            "Histogram of the time (in seconds) each request took per zone.",
            TIME_BUCKETS,
            |b| vec![(None, &b.duration)],
        );
        histogram_family(
            out,
            &blocks,
            "dns_request_size_bytes",
            "Size of the EDNS0 UDP buffer in bytes (64K for TCP) per zone and protocol.",
            SIZE_BUCKETS,
            |b| {
                vec![
                    (Some("tcp"), &b.request_size[1]),
                    (Some("udp"), &b.request_size[0]),
                ]
            },
        );
        if blocks
            .values()
            .any(|b| b.requests.iter().any(|n| n.load(Ordering::Relaxed) != 0))
        {
            header(
                out,
                "dns_requests_total",
                "Counter of DNS requests made per zone, protocol and family.",
                "counter",
            );
            let mut sorted = SortedSamples::default();
            for b in blocks.values() {
                for family in 0..2 {
                    for proto in 0..2 {
                        for typ in 0..=TYPES.len() {
                            let n = b.requests[(family * 2 + proto) * (TYPES.len() + 1) + typ]
                                .load(Ordering::Relaxed);
                            if n == 0 {
                                continue;
                            }
                            let ty = TYPES.get(typ).map_or("other", |(_, name)| *name);
                            sorted.sample(
                                "dns_requests_total",
                                &[
                                    ("family", if family == 0 { "1" } else { "2" }),
                                    ("proto", if proto == 0 { "udp" } else { "tcp" }),
                                    ("server", &b.server),
                                    ("type", ty),
                                    ("view", &b.view),
                                    ("zone", &b.zone),
                                ],
                                n,
                            );
                        }
                    }
                }
            }
            sorted.write(out);
        }
        histogram_family(
            out,
            &blocks,
            "dns_response_size_bytes",
            "Size of the returned response in bytes.",
            SIZE_BUCKETS,
            |b| {
                vec![
                    (Some("tcp"), &b.response_size[1]),
                    (Some("udp"), &b.response_size[0]),
                ]
            },
        );
        if blocks.values().any(|b| {
            b.plugins
                .lock()
                .unwrap()
                .values()
                .any(|v| v.iter().any(|n| n.load(Ordering::Relaxed) != 0))
        }) {
            header(
                out,
                "dns_responses_total",
                "Counter of response status codes.",
                "counter",
            );
            let mut sorted = SortedSamples::default();
            for b in blocks.values() {
                for (plugin, counts) in b.plugins.lock().unwrap().iter() {
                    for (code, counter) in counts.iter().enumerate() {
                        let n = counter.load(Ordering::Relaxed);
                        if n != 0 {
                            let rcode = rcode(code as u16);
                            sorted.sample(
                                "dns_responses_total",
                                &[
                                    ("plugin", plugin),
                                    ("rcode", &rcode),
                                    ("server", &b.server),
                                    ("view", &b.view),
                                    ("zone", &b.zone),
                                ],
                                n,
                            );
                        }
                    }
                }
            }
            sorted.write(out);
        }
        header(
            out,
            "panics_total",
            "A metrics that counts the number of panics.",
            "counter",
        );
        writeln!(
            out,
            "pharos_panics_total {}",
            float(crate::panics_total() as f64)
        )
        .unwrap();
        if blocks
            .values()
            .any(|b| !b.enabled.lock().unwrap().is_empty())
        {
            header(
                out,
                "plugin_enabled",
                "A metric that indicates whether a plugin is enabled on per server and zone basis.",
                "gauge",
            );
            let mut sorted = SortedSamples::default();
            for b in blocks.values() {
                for (name, enabled) in b.enabled.lock().unwrap().iter() {
                    sorted.sample(
                        "plugin_enabled",
                        &[
                            ("name", name),
                            ("server", &b.server),
                            ("view", &b.view),
                            ("zone", &b.zone),
                        ],
                        u64::from(*enabled),
                    );
                }
            }
            sorted.write(out);
        }
        if self.0.process.load(Ordering::Relaxed) {
            crate::process_metrics::encode_process(out);
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        let registry = Self::new(
            env!("CARGO_PKG_VERSION"),
            env!("PHAROS_REVISION"),
            env!("PHAROS_RUSTC"),
        );
        registry.enable_process_metrics();
        registry
    }
}

impl Block {
    fn labels(&self) -> [(&str, &str); 3] {
        [
            ("server", &self.server),
            ("view", &self.view),
            ("zone", &self.zone),
        ]
    }
}

impl BlockMetrics {
    pub fn plugin(&self, name: &str) -> PluginMetrics {
        let mut plugins = self.0.plugins.lock().unwrap();
        let responses = Arc::clone(
            plugins
                .entry(name.into())
                .or_insert_with(|| Arc::new(counters(RESPONSE_CODES))),
        );
        PluginMetrics {
            block: Arc::clone(&self.0),
            responses,
        }
    }

    pub fn plugin_enabled(&self, name: &str) {
        self.0.enabled.lock().unwrap().insert(name.into(), true);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        qtype: u16,
        tcp: bool,
        ipv6: bool,
        dnssec_ok: bool,
        request_bytes: usize,
        response_bytes: usize,
        rcode: u16,
        duration: f64,
    ) {
        // The default series is resolved when the Server Block is created, not here.
        record(
            &self.0,
            &self.0.default_responses,
            qtype,
            tcp,
            ipv6,
            dnssec_ok,
            request_bytes,
            response_bytes,
            rcode,
            duration,
        );
    }
}

impl PluginMetrics {
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        qtype: u16,
        tcp: bool,
        ipv6: bool,
        dnssec_ok: bool,
        request_bytes: usize,
        response_bytes: usize,
        rcode: u16,
        duration: f64,
    ) {
        record(
            &self.block,
            &self.responses,
            qtype,
            tcp,
            ipv6,
            dnssec_ok,
            request_bytes,
            response_bytes,
            rcode,
            duration,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn record(
    block: &Block,
    responses: &[AtomicU64],
    qtype: u16,
    tcp: bool,
    ipv6: bool,
    dnssec_ok: bool,
    request_bytes: usize,
    response_bytes: usize,
    rcode: u16,
    duration: f64,
) {
    assert!(
        usize::from(rcode) < RESPONSE_CODES,
        "DNS RCODE must fit in 12 bits"
    );
    let typ = TYPES
        .iter()
        .position(|(code, _)| *code == qtype)
        .unwrap_or(TYPES.len());
    let proto = usize::from(tcp);
    block.requests[(usize::from(ipv6) * 2 + proto) * (TYPES.len() + 1) + typ]
        .fetch_add(1, Ordering::Relaxed);
    if dnssec_ok {
        block.do_requests.fetch_add(1, Ordering::Relaxed);
    }
    block.duration.observe(TIME_BUCKETS, duration);
    block.request_size[proto].observe(SIZE_BUCKETS, request_bytes as f64);
    block.response_size[proto].observe(SIZE_BUCKETS, response_bytes as f64);
    responses[usize::from(rcode)].fetch_add(1, Ordering::Relaxed);
}

fn header(out: &mut String, name: &str, help: &str, kind: &str) {
    writeln!(
        out,
        "# HELP pharos_{name} {help}\n# TYPE pharos_{name} {kind}"
    )
    .unwrap();
}

fn labels(out: &mut String, values: &[(&str, &str)]) {
    for (index, (name, value)) in values.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        write!(out, "{name}=\"").unwrap();
        for c in value.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                _ => out.push(c),
            }
        }
        out.push('"');
    }
}

fn sample(out: &mut String, name: &str, values: &[(&str, &str)], n: u64) {
    write!(out, "pharos_{name}{{").unwrap();
    labels(out, values);
    writeln!(out, "}} {}", float(n as f64)).unwrap();
}

#[derive(Default)]
struct SortedSamples(Vec<(Vec<String>, String)>);

impl SortedSamples {
    fn insert(&mut self, values: &[(&str, &str)], text: String) {
        self.0.push((
            values.iter().map(|(_, value)| (*value).into()).collect(),
            text,
        ));
    }

    fn sample(&mut self, name: &str, values: &[(&str, &str)], n: u64) {
        let mut text = String::new();
        sample(&mut text, name, values, n);
        self.insert(values, text);
    }

    fn write(mut self, out: &mut String) {
        self.0.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for (_, text) in self.0 {
            out.push_str(&text);
        }
    }
}

pub(crate) fn float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value == f64::INFINITY {
        return "+Inf".into();
    }
    if value == f64::NEG_INFINITY {
        return "-Inf".into();
    }
    if value != 0. && (value.abs() < 0.0001 || value.abs() >= 1_000_000.) {
        let text = format!("{value:e}");
        let (mantissa, exp) = text.split_once('e').unwrap();
        let exponent: i32 = exp.parse().unwrap();
        return format!(
            "{mantissa}e{}{abs:02}",
            if exponent < 0 { '-' } else { '+' },
            abs = exponent.abs()
        );
    }
    value.to_string()
}

fn histogram_family<'a>(
    out: &mut String,
    blocks: &'a BTreeMap<Key, Arc<Block>>,
    name: &str,
    help: &str,
    bounds: &[f64],
    get: impl Fn(&'a Block) -> Vec<(Option<&'static str>, &'a Histogram)>,
) {
    if !blocks
        .values()
        .any(|b| get(b).iter().any(|(_, h)| h.count() != 0))
    {
        return;
    }
    header(out, name, help, "histogram");
    let mut sorted = SortedSamples::default();
    for b in blocks.values() {
        for (proto, histogram) in get(b) {
            if histogram.count() == 0 {
                continue;
            }
            let mut values = Vec::new();
            if let Some(proto) = proto {
                values.push(("proto", proto));
            }
            values.extend(b.labels());
            let mut text = String::new();
            let out = &mut text;
            let mut count = 0;
            for (i, bucket) in histogram.buckets.iter().enumerate() {
                count += bucket.load(Ordering::Relaxed);
                write!(out, "pharos_{name}_bucket{{").unwrap();
                labels(out, &values);
                let bound = bounds
                    .get(i)
                    .map_or_else(|| "+Inf".into(), |value| float(*value));
                writeln!(out, ",le=\"{bound}\"}} {}", float(count as f64)).unwrap();
            }
            write!(out, "pharos_{name}_sum{{").unwrap();
            labels(out, &values);
            writeln!(
                out,
                "}} {}",
                float(f64::from_bits(histogram.sum.load(Ordering::Relaxed)))
            )
            .unwrap();
            write!(out, "pharos_{name}_count{{").unwrap();
            labels(out, &values);
            writeln!(out, "}} {}", float(count as f64)).unwrap();
            sorted.insert(&values, text);
        }
    }
    sorted.write(out);
}

fn rcode(code: u16) -> String {
    match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        11 => "DSOTYPENI",
        16 => "BADSIG",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => return format!("RCODE{code}"),
    }
    .into()
}

#[cfg(test)]
mod tests {
    #[test]
    fn go_float_formatting() {
        for (value, expected) in [
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (999999., "999999"),
            (1_000_000., "1e+06"),
            (-0.0, "-0"),
            (f64::INFINITY, "+Inf"),
            (f64::NEG_INFINITY, "-Inf"),
            (f64::NAN, "NaN"),
        ] {
            assert_eq!(super::float(value), expected);
        }
    }
}

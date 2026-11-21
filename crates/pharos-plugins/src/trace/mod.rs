//! Sampled Query tracing exported to a Zipkin collector.

mod export;
mod queue;
pub(crate) mod setup;
mod span;
#[cfg(test)]
mod tests;
mod zipkin;

use std::{
    fmt, io,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwapOption;
use pharos_corefile::{Cursor, Error};
use pharos_server::{
    Context, Lifecycle, Next, Outcome, Phase, Plugin,
    metrics::{Registry, TraceMetrics},
};

use self::{
    export::Tracer,
    span::{SpanRecord, hex_id, unix_micros},
};

// CoreDNS v1.15.0 plugin/trace/setup.go supportedProviders: the default endpoint of each type.
const ZIPKIN_ENDPOINT: &str = "localhost:9411";
const DATADOG_ENDPOINT: &str = "localhost:8126";
// CoreDNS v1.15.0 plugin/trace/trace.go metaTraceIdKey.
const TRACE_ID_METADATA: &str = "trace/traceid";
// CoreDNS v1.15.0 plugin/trace/setup.go defServiceName.
const DEFAULT_SERVICE: &str = "coredns";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EndpointType {
    Zipkin,
    Datadog,
}

/// Parsed `trace` Directive; zero sizes and interval mean the exporter default.
#[derive(Debug)]
pub(crate) struct Config {
    pub endpoint_type: EndpointType,
    pub endpoint: String,
    pub service_endpoint: String,
    pub service_name: String,
    pub client_server: bool,
    pub every: u64,
    pub datadog_analytics_rate: f64,
    pub zipkin_max_backlog_size: i64,
    pub zipkin_max_batch_size: i64,
    pub zipkin_max_batch_interval: Duration,
}

struct Shared {
    config: Config,
    count: AtomicU64,
    ids: AtomicU64,
    tracer: ArcSwapOption<Tracer>,
    metrics: OnceLock<TraceMetrics>,
}

/// The `trace` Plugin: it samples Queries and exports them as spans.
pub struct Trace {
    shared: Arc<Shared>,
}

impl fmt::Debug for Trace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Trace")
            .field("config", &self.shared.config)
            .finish_non_exhaustive()
    }
}

impl Shared {
    // zipkin-go StartSpan draws IDs from a PRNG; a seeded SplitMix64 stream avoids a syscall per sampled Query.
    fn next_id(&self) -> u64 {
        const GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut z = self
            .ids
            .fetch_add(GAMMA, Ordering::Relaxed)
            .wrapping_add(GAMMA);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        // Zipkin v2 API spec: an ID of zero is not valid.
        (z ^ (z >> 31)).max(1)
    }

    // CoreDNS v1.15.0 plugin/trace/trace.go ServeDNS: every Nth Query is traced and `every 0` traces none.
    fn sampled(&self) -> bool {
        self.config.every != 0
            && self
                .count
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1)
                .is_multiple_of(self.config.every)
    }

    // CoreDNS v1.15.0 plugin/trace/trace.go OnStartup: the tracer is built once, here after a Reload failed it is built again.
    async fn start(&self) -> io::Result<()> {
        if self.tracer.load().is_some() {
            return Ok(());
        }
        let metrics = self.metrics.get().cloned().unwrap_or_default();
        let tracer = Tracer::start(&self.config, metrics).await?;
        self.tracer.store(Some(Arc::new(tracer)));
        Ok(())
    }

    async fn stop(&self) {
        if let Some(tracer) = self.tracer.swap(None) {
            tracer.stop().await;
        }
    }
}

impl Trace {
    pub(crate) fn new(config: Config) -> Self {
        let mut seed = [0; 8];
        // getrandom failing leaves a fixed seed: IDs stay valid, only less unpredictable.
        let _ = getrandom::getrandom(&mut seed);
        Self {
            shared: Arc::new(Shared {
                config,
                count: AtomicU64::new(0),
                ids: AtomicU64::new(u64::from_le_bytes(seed)),
                tracer: ArcSwapOption::empty(),
                metrics: OnceLock::new(),
            }),
        }
    }

    /// Record span counters in the process-wide registry.
    pub(crate) fn set_metrics(&self, registry: &Registry) {
        let _ = self.shared.metrics.set(registry.trace());
    }

    /// Start the exporter with the Server, flush it on Restart and Shutdown, and restore it if a Reload fails.
    pub(crate) fn register_hooks(&self, lifecycle: &mut Lifecycle) {
        let shared = Arc::clone(&self.shared);
        let start = move || {
            let shared = Arc::clone(&shared);
            async move { shared.start().await }
        };
        lifecycle.register(Phase::Startup, start.clone());
        lifecycle.register(Phase::RestartFailed, start);
        let shared = Arc::clone(&self.shared);
        let stop = move || {
            let shared = Arc::clone(&shared);
            async move {
                shared.stop().await;
                Ok(())
            }
        };
        lifecycle.register(Phase::Restart, stop.clone());
        lifecycle.register(Phase::Shutdown, stop);
    }
}

impl Plugin for Trace {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let shared = &*self.shared;
        if !shared.sampled() || shared.tracer.load().is_none() {
            return next.run(cx).await;
        }
        let id = shared.next_id();
        // CoreDNS v1.15.0 plugin/trace/trace.go: metadata `trace/traceid` is the trace ID of the Query.
        if cx.metadata.enabled() {
            let mut hex = [0; 16];
            cx.metadata
                .insert_copied(TRACE_ID_METADATA, hex_id(id, &mut hex));
        }
        let (start, started) = (Instant::now(), unix_micros());
        let outcome = next.run(cx).await;
        let span = SpanRecord::capture(id, started, start.elapsed(), cx, &outcome);
        if let Some(tracer) = &*shared.tracer.load() {
            tracer.record(span);
        }
        outcome
    }
}

// CoreDNS v1.15.0 plugin/trace/setup.go normalizeEndpoint: only known types, and a bare Zipkin host becomes a collector URL.
fn normalize_endpoint(
    endpoint_type: &str,
    endpoint: &str,
) -> Result<(EndpointType, String), String> {
    let (kind, default) = match endpoint_type {
        "zipkin" => (EndpointType::Zipkin, ZIPKIN_ENDPOINT),
        "datadog" => (EndpointType::Datadog, DATADOG_ENDPOINT),
        _ => {
            return Err(format!(
                "tracing endpoint type '{endpoint_type}' is not supported"
            ));
        }
    };
    let endpoint = if endpoint.is_empty() {
        default
    } else {
        endpoint
    };
    let lower = endpoint.to_ascii_lowercase();
    if kind == EndpointType::Zipkin
        && !lower.starts_with("http://")
        && !lower.starts_with("https://")
    {
        return Ok((kind, format!("http://{endpoint}/api/v2/spans")));
    }
    Ok((kind, endpoint.to_owned()))
}

// Go strconv.ParseBool: exactly these spellings.
fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

// Go net.JoinHostPort brackets a host that contains a colon.
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) fn parse(
    cursor: &mut Cursor<'_>,
    listen_hosts: &[String],
    port: &str,
) -> Result<Config, Error> {
    let mut config = Config {
        endpoint_type: EndpointType::Zipkin,
        endpoint: String::new(),
        service_endpoint: String::new(),
        service_name: DEFAULT_SERVICE.to_owned(),
        client_server: false,
        every: 1,
        datadog_analytics_rate: 0.0,
        zipkin_max_backlog_size: 0,
        zipkin_max_batch_size: 0,
        zipkin_max_batch_interval: Duration::ZERO,
    };
    if let Some(host) = listen_hosts.first().filter(|host| !host.is_empty()) {
        config.service_endpoint = join_host_port(host, port);
    }
    while cursor.next() {
        let args = cursor.remaining_args();
        let lowered;
        let (endpoint_type, endpoint) = match args.as_slice() {
            [] => ("zipkin", ""),
            [endpoint] => ("zipkin", endpoint.as_str()),
            [endpoint_type, endpoint] => {
                lowered = endpoint_type.to_lowercase();
                (lowered.as_str(), endpoint.as_str())
            }
            _ => return Err(cursor.arg_err()),
        };
        (config.endpoint_type, config.endpoint) =
            normalize_endpoint(endpoint_type, endpoint).map_err(|message| cursor.error(message))?;
        while cursor.next_block() {
            let property = cursor.val().to_owned();
            let args = cursor.remaining_args();
            match property.as_str() {
                "every" => {
                    let [value] = args.as_slice() else {
                        return Err(cursor.arg_err());
                    };
                    // Go strconv.ParseUint rejects a sign, which Rust's parser accepts.
                    config.every = value
                        .parse::<u64>()
                        .ok()
                        .filter(|_| !value.starts_with('+'))
                        .ok_or_else(|| cursor.error(format!("invalid syntax: '{value}'")))?;
                }
                "service" => {
                    let [value] = args.as_slice() else {
                        return Err(cursor.arg_err());
                    };
                    config.service_name.clone_from(value);
                }
                "client_server" => {
                    config.client_server = match args.as_slice() {
                        [] => true,
                        [value] => parse_bool(value)
                            .ok_or_else(|| cursor.error(format!("invalid syntax: '{value}'")))?,
                        _ => return Err(cursor.arg_err()),
                    };
                }
                "datadog_analytics_rate" => {
                    config.datadog_analytics_rate = match args.as_slice() {
                        [] => 0.0,
                        [value] => value
                            .parse::<f64>()
                            .map_err(|_| cursor.error(format!("invalid syntax: '{value}'")))?,
                        _ => return Err(cursor.arg_err()),
                    };
                    let rate = config.datadog_analytics_rate;
                    if !(0.0..=1.0).contains(&rate) && !rate.is_nan() {
                        return Err(cursor.error(format!(
                            "datadog analytics rate must be between 0 and 1, '{rate:.6}' is not supported"
                        )));
                    }
                }
                "zipkin_max_backlog_size" | "zipkin_max_batch_size" => {
                    let [value] = args.as_slice() else {
                        return Err(cursor.arg_err());
                    };
                    let size = value
                        .parse::<i64>()
                        .map_err(|_| cursor.error(format!("invalid syntax: '{value}'")))?;
                    if property == "zipkin_max_backlog_size" {
                        config.zipkin_max_backlog_size = size;
                    } else {
                        config.zipkin_max_batch_size = size;
                    }
                }
                "zipkin_max_batch_interval" => {
                    let [value] = args.as_slice() else {
                        return Err(cursor.arg_err());
                    };
                    config.zipkin_max_batch_interval = crate::health::parse_duration(value)
                        .ok_or_else(|| cursor.error(format!("invalid duration: '{value}'")))?;
                }
                _ => return Err(cursor.error(format!("unknown property '{property}'"))),
            }
        }
    }
    Ok(config)
}

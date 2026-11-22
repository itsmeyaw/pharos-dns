//! One `dnstap` Directive at run time: its queue, counters and background task.

use std::{
    cell::RefCell,
    fmt,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use pharos_server::{
    Context,
    metrics::{DnstapDrop, DnstapMetrics, Registry},
};
use tokio::{sync::watch, task::JoinHandle};

use super::{
    Config, Role,
    framestream::TCP_TIMEOUT,
    io, listener,
    msg::{Header, Message},
    queue::Queue,
};
use crate::log::format::Format;

// CoreDNS v1.15.0 plugin/dnstap/io.go queueSize: the queue holds `queue` times 10,000 messages.
const QUEUE_UNIT: usize = 10_000;

thread_local! {
    static EXTRA: RefCell<String> = const { RefCell::new(String::new()) };
}

/// The timings that CoreDNS v1.15.0 fixes in `io.go`, so tests can shorten them.
#[derive(Clone, Copy, Debug)]
pub(super) struct Timing {
    /// Dial, handshake and per-write limit (`tcpTimeout`).
    pub timeout: Duration,
    /// How often buffered frames are flushed (`flushTimeout`).
    pub flush: Duration,
    /// How often dropped messages are reported (`errorCheckInterval`).
    pub report: Duration,
    /// First wait before redialing after a failed dial; doubles up to `backoff_max`.
    pub backoff_min: Duration,
    pub backoff_max: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            // CoreDNS v1.15.0 plugin/dnstap/io.go: tcpTimeout, flushTimeout and errorCheckInterval.
            timeout: TCP_TIMEOUT,
            flush: Duration::from_secs(1),
            report: Duration::from_secs(10),
            // Pharos choice: redial quickly after a brief outage, but never hammer a down collector.
            backoff_min: Duration::from_millis(100),
            backoff_max: Duration::from_secs(10),
        }
    }
}

type Warn = Arc<dyn Fn(&str) + Send + Sync>;

enum Extra {
    None,
    /// Sent as configured: no placeholders.
    Literal(Vec<u8>),
    /// Placeholders expand per message when a Context is at hand; `raw` is sent otherwise.
    Format {
        format: Format,
        raw: Vec<u8>,
    },
}

struct Running {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

pub(super) struct Inner {
    pub(super) config: Config,
    pub(super) queue: Queue,
    pub(super) timing: Timing,
    extra: Extra,
    metrics: OnceLock<DnstapMetrics>,
    warn: Warn,
    // Messages dropped since the last report; CoreDNS v1.15.0 plugin/dnstap/io.go dio.dropped.
    dropped: AtomicU64,
    // Open sink connections: dialed (Dial) or accepted (Listen).
    sinks: AtomicUsize,
    running: Mutex<Option<Running>>,
}

/// A configured `dnstap` Directive: encodes messages onto its own queue for a background task to send.
/// Clones share the queue, so a Plugin that emits its own dnstap messages can hold one.
#[derive(Clone)]
pub struct Tap(pub(super) Arc<Inner>);

impl fmt::Debug for Tap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tap")
            .field("role", &self.0.config.role)
            .field("endpoint", &self.0.config.endpoint)
            .finish_non_exhaustive()
    }
}

impl Tap {
    pub(super) fn new(config: Config) -> Self {
        Self::with_options(
            config,
            Timing::default(),
            Arc::new(|text| pharos_server::logging::log("WARN", "dnstap", text)),
        )
    }

    pub(super) fn with_options(config: Config, timing: Timing, warn: Warn) -> Self {
        let capacity = config.queue as usize * QUEUE_UNIT;
        let extra = if config.extra.is_empty() {
            Extra::None
        } else if config.extra.contains('{') {
            Extra::Format {
                format: Format::compile(&config.extra),
                raw: config.extra.clone().into_bytes(),
            }
        } else {
            Extra::Literal(config.extra.clone().into_bytes())
        };
        Self(Arc::new(Inner {
            config,
            queue: Queue::new(capacity),
            timing,
            extra,
            metrics: OnceLock::new(),
            warn,
            dropped: AtomicU64::new(0),
            sinks: AtomicUsize::new(0),
            running: Mutex::new(None),
        }))
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.0.config
    }

    /// Whether messages should carry the raw DNS message (`full`).
    #[must_use]
    pub fn include_raw(&self) -> bool {
        self.0.config.full
    }

    pub(crate) fn set_metrics(&self, registry: &Registry) {
        let _ = self.0.metrics.set(registry.dnstap());
    }

    /// Encodes `message` onto the queue without blocking; `extra` is sent as configured.
    // CoreDNS v1.15.0 plugin/dnstap/handler.go TapMessage: no Context, so `extra` placeholders stay unexpanded.
    pub fn send(&self, message: &Message<'_>) {
        self.enqueue(message, None);
    }

    /// Like `send`, expanding `extra` placeholders from `cx`.
    // CoreDNS v1.15.0 plugin/dnstap/handler.go TapMessageWithMetadata: `extra` expands per message.
    pub fn send_with(&self, message: &Message<'_>, cx: &Context<'_, '_>) {
        self.enqueue(message, Some(cx));
    }

    fn enqueue(&self, message: &Message<'_>, cx: Option<&Context<'_, '_>>) {
        let inner = &*self.0;
        // CoreDNS v1.15.0 plugin/dnstap/listener.go Dnstap: with no sink connected a broadcast reaches nobody, so skip the encoding.
        if inner.config.role == Role::Listen && inner.sinks.load(Ordering::Relaxed) == 0 {
            return;
        }
        let Some(mut buffer) = inner.queue.acquire() else {
            self.count_drop(DnstapDrop::QueueFull, 1);
            return;
        };
        let encode = |extra: Option<&[u8]>, buffer: &mut Vec<u8>| {
            let header = Header {
                identity: &inner.config.identity,
                version: &inner.config.version,
                extra,
            };
            message.encode(&header, buffer);
        };
        match (&inner.extra, cx) {
            (Extra::None, _) => encode(None, &mut buffer),
            (Extra::Literal(extra), _) | (Extra::Format { raw: extra, .. }, None) => {
                encode(Some(extra), &mut buffer);
            }
            (Extra::Format { format, .. }, Some(cx)) => EXTRA.with_borrow_mut(|text| {
                text.clear();
                format.format_unrecorded(text, cx);
                encode(Some(text.as_bytes()), &mut buffer);
            }),
        }
        inner.queue.push(buffer);
        self.metric(DnstapMetrics::enqueued);
    }

    pub(super) fn metric(&self, update: impl FnOnce(&DnstapMetrics)) {
        if let Some(metrics) = self.0.metrics.get() {
            update(metrics);
        }
    }

    pub(super) fn count_drop(&self, reason: DnstapDrop, count: u64) {
        self.0.dropped.fetch_add(count, Ordering::Relaxed);
        self.metric(|metrics| metrics.dropped(reason, count));
    }

    /// Logs and resets the drop count.
    // CoreDNS v1.15.0 plugin/dnstap/io.go dio.serve: every errorCheckInterval, "Dropped dnstap messages: %d".
    pub(super) fn report_drops(&self) {
        let dropped = self.0.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            (self.0.warn)(&format!("Dropped dnstap messages: {dropped}"));
        }
    }

    pub(super) fn warn(&self, text: &str) {
        (self.0.warn)(text);
    }

    /// Records a sink connection coming or going.
    pub(super) fn sink_connected(&self) {
        self.0.sinks.fetch_add(1, Ordering::Relaxed);
        self.metric(DnstapMetrics::connected);
    }

    pub(super) fn sink_disconnected(&self) {
        self.0.sinks.fetch_sub(1, Ordering::Relaxed);
        self.metric(DnstapMetrics::disconnected);
    }

    /// Starts the background task unless it already runs: dial or accept per the Directive's role.
    // CoreDNS v1.15.0 plugin/dnstap/setup.go OnStartup: a failure to connect or listen is logged, never fatal.
    pub(crate) async fn start(&self) {
        if self.0.running.lock().unwrap().is_some() {
            return;
        }
        let (stop, stopped) = watch::channel(false);
        let tap = self.clone();
        let task = match self.0.config.role {
            Role::Dial => tokio::spawn(io::run(tap, stopped)),
            Role::Listen => match listener::bind(&self.0.config).await {
                Ok(bound) => tokio::spawn(listener::run(tap, bound, stopped)),
                Err(error) => {
                    pharos_server::logging::log(
                        "ERROR",
                        "dnstap",
                        &format!("Failed to start dnstap listener: {error}"),
                    );
                    return;
                }
            },
        };
        *self.0.running.lock().unwrap() = Some(Running { stop, task });
    }

    /// Asks the task to finish what is queued and close the sinks, and waits a bounded time for it.
    // CoreDNS v1.15.0 plugin/dnstap/setup.go OnRestart and OnFinalShutdown: close the connection or listener.
    pub(crate) async fn stop(&self) {
        let Some(Running { stop, task }) = self.0.running.lock().unwrap().take() else {
            return;
        };
        let _ = stop.send(true);
        // A close is STOP, then FINISH, each bounded by the timeout; allow for both and the final flush.
        let limit = self.0.timing.timeout * 3;
        let abort = task.abort_handle();
        if tokio::time::timeout(limit, task).await.is_err() {
            abort.abort();
        }
    }
}

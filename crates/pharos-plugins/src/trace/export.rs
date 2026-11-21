//! Background batcher and HTTP transport of finished spans.

use std::{
    collections::VecDeque,
    io,
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use pharos_server::{
    logging::log,
    metrics::TraceMetrics,
    tls::{ClientOptions, ServerName, TlsConnector, client_config},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    task::JoinHandle,
    time::{Instant, sleep_until, timeout},
};

use super::{
    Config, EndpointType, datadog,
    queue::Queue,
    span::SpanRecord,
    zipkin::{self, local_endpoint},
};

// zipkin-go reporter/http defaults: 100 spans per batch, 1 s interval, 1000 spans of backlog, 5 s request timeout.
const DEFAULT_BATCH_SIZE: usize = 100;
const DEFAULT_BATCH_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_BACKLOG: usize = 1000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// A collector URL split into what a connection and a request need.
#[derive(Debug, Eq, PartialEq)]
struct Target {
    tls: bool,
    host: String,
    port: u16,
    authority: String,
    path: String,
}

impl Target {
    // RFC 3986 §3: scheme, authority, path and query; RFC 9110 §7.1 makes the origin-form `path?query` the request target.
    fn parse(url: &str) -> Result<Self, String> {
        let lower = url.to_ascii_lowercase();
        let (tls, rest) = if lower.starts_with("http://") {
            (false, &url[7..])
        } else if lower.starts_with("https://") {
            (true, &url[8..])
        } else {
            return Err(format!("unsupported collector URL '{url}'"));
        };
        let rest = rest.split('#').next().unwrap_or_default();
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        if authority.contains('@') {
            // shortcut: no userinfo credentials in a collector URL, add Basic auth when a deployment needs it.
            return Err(format!("collector URL '{url}' must not carry credentials"));
        }
        // RFC 3986 §3.2.2: an IPv6 literal is bracketed, so a colon inside the brackets is not a port separator.
        let (host, port) = match authority.strip_prefix('[') {
            Some(inner) => {
                let (host, after) = inner
                    .split_once(']')
                    .ok_or_else(|| format!("invalid collector URL '{url}'"))?;
                (host, after.strip_prefix(':'))
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            },
        };
        if host.is_empty() {
            return Err(format!("collector URL '{url}' has no host"));
        }
        let port = match port {
            Some(port) => port
                .parse()
                .map_err(|_| format!("invalid port in collector URL '{url}'"))?,
            // RFC 9110 §4.2.1 and §4.2.2: http and https default to ports 80 and 443.
            None if tls => 443,
            None => 80,
        };
        let path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        Ok(Self {
            tls,
            host: host.to_owned(),
            port,
            authority: authority.to_owned(),
            path,
        })
    }
}

struct Transport {
    target: Target,
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

impl Transport {
    fn new(endpoint: &str) -> io::Result<Self> {
        let target = Target::parse(endpoint)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let tls = if target.tls {
            let name = ServerName::try_from(target.host.clone())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            let config = client_config(&ClientOptions::default())?;
            Some((TlsConnector::from(config), name))
        } else {
            None
        };
        Ok(Self { target, tls })
    }

    async fn send(&self, method: &str, headers: &str, body: &[u8]) -> io::Result<u16> {
        let tcp = TcpStream::connect((self.target.host.as_str(), self.target.port)).await?;
        tcp.set_nodelay(true)?;
        // RFC 9110 §9.3 and §8.3: the method, the exporter's headers (media type among them), then the body's length.
        let head = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.target.path,
            self.target.authority,
            body.len()
        );
        match &self.tls {
            Some((connector, name)) => {
                let mut stream = connector.connect(name.clone(), tcp).await?;
                exchange(&mut stream, &head, body).await
            }
            None => {
                let mut tcp = tcp;
                exchange(&mut tcp, &head, body).await
            }
        }
    }
}

// RFC 9112 §4: the status line carries the status code; the reply body is not needed.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    head: &str,
    body: &[u8],
) -> io::Result<u16> {
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    let mut buffer = [0; 256];
    let mut len = 0;
    loop {
        let read = stream.read(&mut buffer[len..]).await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        len += read;
        if let Some(end) = buffer[..len].windows(2).position(|pair| pair == b"\r\n") {
            let line = String::from_utf8_lossy(&buffer[..end]);
            return line
                .split(' ')
                .nth(1)
                .and_then(|code| code.parse().ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid status line"));
        }
        if len == buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "status line too long",
            ));
        }
    }
}

/// How a batch of spans becomes a request body.
enum Encoder {
    Zipkin {
        local_endpoint: Option<String>,
    },
    Datadog {
        service: String,
        analytics_rate: f64,
    },
}

impl Encoder {
    fn method(&self) -> &'static str {
        match self {
            // Zipkin v2 API spec: spans are POSTed to /api/v2/spans.
            Self::Zipkin { .. } => "POST",
            // dd-trace-go v2.10.1 transport.go send: traces are POSTed to /v0.4/traces (the agent also accepts PUT).
            Self::Datadog { .. } => "POST",
        }
    }

    /// The header lines of a request carrying `count` spans, each ended by CRLF.
    fn headers(&self, count: usize) -> String {
        match self {
            // Zipkin v2 API spec: the JSON encoding is application/json.
            // zipkin-go reporter/http sendBatch: `b3: 0` keeps a sidecar from tracing the report itself.
            Self::Zipkin { .. } => "b3: 0\r\nContent-Type: application/json\r\n".to_owned(),
            // dd-trace-go v2.10.1 transport.go datadogHeaders and send: the tracer identity, the trace count and top-level spans marked by the client.
            Self::Datadog { .. } => format!(
                "Content-Type: application/msgpack\r\nDatadog-Meta-Lang: rust\r\nDatadog-Meta-Lang-Interpreter: rustc-{}-{}\r\nDatadog-Meta-Tracer-Version: {}\r\nX-Datadog-Trace-Count: {count}\r\nDatadog-Client-Computed-Top-Level: t\r\n",
                std::env::consts::ARCH,
                std::env::consts::OS,
                env!("CARGO_PKG_VERSION"),
            ),
        }
    }

    fn encode(&self, spans: &VecDeque<SpanRecord>, out: &mut Vec<u8>) {
        match self {
            Self::Zipkin { local_endpoint } => {
                out.clear();
                let mut text = String::from_utf8(std::mem::take(out)).unwrap_or_default();
                zipkin::encode(spans, local_endpoint.as_deref(), &mut text);
                *out = text.into_bytes();
            }
            Self::Datadog {
                service,
                analytics_rate,
            } => {
                out.clear();
                datadog::encode(spans.iter(), service, *analytics_rate, out);
            }
        }
    }
}

// zipkin-go endpoint.go NewEndpoint: the service endpoint is `host:port`, a hostname is resolved, and the first IPv4 and IPv6 address are reported.
async fn resolve_local_endpoint(service: &str, host_port: &str) -> io::Result<Option<String>> {
    let invalid = |message: String| io::Error::new(io::ErrorKind::InvalidInput, message);
    if host_port.is_empty() || host_port == ":0" {
        return Ok(local_endpoint(service, None, None, 0));
    }
    let host_port = if host_port.contains(':') {
        host_port.to_owned()
    } else {
        format!("{host_port}:0")
    };
    let (host, port) = host_port
        .rsplit_once(':')
        .ok_or_else(|| invalid(format!("invalid service endpoint '{host_port}'")))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port
        .parse()
        .map_err(|_| invalid(format!("invalid port in service endpoint '{host_port}'")))?;
    let addresses: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::net::lookup_host((host, 0))
            .await
            .map_err(|error| io::Error::new(error.kind(), format!("host lookup failure: {error}")))?
            .map(|address| address.ip())
            .collect(),
    };
    let ipv4 = addresses.iter().copied().find(IpAddr::is_ipv4);
    let ipv6 = addresses.iter().copied().find(IpAddr::is_ipv6);
    Ok(local_endpoint(service, ipv4, ipv6, port))
}

/// A running exporter: spans enter the bounded queue and leave in batches.
pub(super) struct Tracer {
    queue: Arc<Queue>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Tracer {
    pub(super) async fn start(config: &Config, metrics: TraceMetrics) -> io::Result<Self> {
        let encoder = match config.endpoint_type {
            EndpointType::Zipkin => Encoder::Zipkin {
                local_endpoint: resolve_local_endpoint(
                    &config.service_name,
                    &config.service_endpoint,
                )
                .await
                .map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("build Zipkin endpoint error: {error}"),
                    )
                })?,
            },
            EndpointType::Datadog => Encoder::Datadog {
                service: config.service_name.clone(),
                analytics_rate: config.datadog_analytics_rate,
            },
        };
        let endpoint = match config.endpoint_type {
            EndpointType::Zipkin => config.endpoint.clone(),
            EndpointType::Datadog => datadog::traces_url(&config.endpoint),
        };
        let transport = Transport::new(&endpoint)?;
        // CoreDNS v1.15.0 plugin/trace/setup.go OnStartup: only the Zipkin reporter reads the zipkin_max_* settings.
        let (backlog_setting, batch_setting, interval_setting) = match config.endpoint_type {
            EndpointType::Zipkin => (
                config.zipkin_max_backlog_size,
                config.zipkin_max_batch_size,
                config.zipkin_max_batch_interval,
            ),
            EndpointType::Datadog => (0, 0, Duration::ZERO),
        };
        // zipkin-go reporter/http options: a zero or negative setting keeps the default.
        let positive = |value: i64, default: usize| {
            usize::try_from(value)
                .ok()
                .filter(|&n| n > 0)
                .unwrap_or(default)
        };
        let batch_size = positive(batch_setting, DEFAULT_BATCH_SIZE);
        let backlog = positive(backlog_setting, DEFAULT_BACKLOG);
        let interval = if interval_setting.is_zero() {
            DEFAULT_BATCH_INTERVAL
        } else {
            interval_setting
        };
        let queue = Arc::new(Queue::new(backlog, batch_size, metrics.clone()));
        let task = tokio::spawn(run(
            Arc::clone(&queue),
            encoder,
            transport,
            interval,
            batch_size,
            metrics,
        ));
        Ok(Self {
            queue,
            task: Mutex::new(Some(task)),
        })
    }

    /// A tracer whose spans stay in `queue` for a test to inspect.
    #[cfg(test)]
    pub(super) fn detached(queue: Arc<Queue>) -> Self {
        Self {
            queue,
            task: Mutex::new(None),
        }
    }

    pub(super) fn record(&self, span: SpanRecord) {
        self.queue.push(span);
    }

    /// Flush what is queued and end the task, giving a stuck collector one request timeout.
    pub(super) async fn stop(&self) {
        self.queue.close();
        let task = self
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(mut task) = task
            && timeout(REQUEST_TIMEOUT, &mut task).await.is_err()
        {
            task.abort();
        }
    }
}

async fn run(
    queue: Arc<Queue>,
    encoder: Encoder,
    transport: Transport,
    interval: Duration,
    batch_size: usize,
    metrics: TraceMetrics,
) {
    let mut spare = queue.spare();
    let mut body = Vec::new();
    let mut next = Instant::now() + interval;
    let mut failing = false;
    loop {
        tokio::select! {
            () = queue.wake.notified() => {}
            () = sleep_until(next) => {}
        }
        let closing = queue.is_closed();
        if closing || queue.len() >= batch_size || Instant::now() >= next {
            next = Instant::now() + interval;
            queue.swap(&mut spare);
            if !spare.is_empty() {
                let count = spare.len() as u64;
                encoder.encode(&spare, &mut body);
                // zipkin-go reporter/http sendBatch: the request is bounded by a timeout and a failed batch is not retried here.
                let result = timeout(
                    REQUEST_TIMEOUT,
                    transport.send(encoder.method(), &encoder.headers(spare.len()), &body),
                )
                .await;
                let failure = match result {
                    // RFC 9110 §15.3: 2xx means the collector accepted the spans.
                    Ok(Ok(status)) if (200..300).contains(&status) => None,
                    Ok(Ok(status)) => Some(format!("collector answered status {status}")),
                    Ok(Err(error)) => Some(format!("failed to send spans: {error}")),
                    Err(_) => Some("failed to send spans: timed out".to_owned()),
                };
                match failure {
                    None => {
                        metrics.exported(count);
                        failing = false;
                    }
                    Some(message) => {
                        metrics.dropped_export_failed(count);
                        // One line per outage rather than one per batch keeps a down collector from flooding the log.
                        if !std::mem::replace(&mut failing, true) {
                            log("ERROR", "trace", &message);
                        }
                    }
                }
                spare.clear();
            }
        }
        if closing {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Target;

    #[test]
    fn target_splits_scheme_authority_and_path() {
        let target = Target::parse("HTTP://collector:9411/Custom/Spans?Tenant=Blue#x").unwrap();
        assert!(!target.tls);
        assert_eq!(
            (target.host.as_str(), target.port, target.path.as_str()),
            ("collector", 9411, "/Custom/Spans?Tenant=Blue")
        );
        let target = Target::parse("httpS://[::1]/").unwrap();
        assert!(target.tls);
        assert_eq!((target.host.as_str(), target.port), ("::1", 443));
        assert_eq!(Target::parse("http://h?x=1").unwrap().path, "/?x=1");
        assert_eq!(Target::parse("http://h").unwrap().path, "/");
        for bad in [
            "ftp://h/",
            "http://",
            "http://h:port/",
            "http://u:p@h/",
            "h:9411",
        ] {
            assert!(Target::parse(bad).is_err(), "{bad}");
        }
    }
}

//! The task behind an outgoing `dnstap` Directive: dials the collector and writes queued payloads.
//!
//! Follows CoreDNS v1.15.0 `plugin/dnstap/io.go` `dio`: a bidirectional Frame Streams writer that
//! flushes every second, redials at once after a write error, and drops what it cannot send. Where
//! CoreDNS retries a lost connection on a fixed 10 s ticker, this redials with exponential backoff.

use std::{collections::VecDeque, io, net::SocketAddr, time::Duration};

use pharos_server::{
    metrics::DnstapDrop,
    tls::{ClientOptions, ServerName, TlsConnector, client_config, client_config_unverified},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpSocket, TcpStream, UnixStream, lookup_host},
    sync::watch,
    time::{Instant, MissedTickBehavior, interval, sleep_until, timeout},
};

use super::{
    Endpoint,
    framestream::{CONTENT_TYPE, Encoder},
    tap::Tap,
};

#[cfg(test)]
mod tests;

pub(super) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub(super) type Link = Encoder<Box<dyn Stream>>;

const MIB: u64 = 1024 * 1024;

// Doubles the wait after each failed dial, up to a ceiling; a successful dial starts it over.
struct Backoff {
    next: Duration,
    min: Duration,
    max: Duration,
}

impl Backoff {
    fn new(min: Duration, max: Duration) -> Self {
        Self {
            next: min,
            min,
            max,
        }
    }

    fn failed(&mut self) -> Duration {
        let wait = self.next;
        self.next = (self.next * 2).min(self.max);
        wait
    }

    fn reset(&mut self) {
        self.next = self.min;
    }
}

struct Writer {
    tap: Tap,
    tls: Option<TlsConnector>,
    link: Option<Link>,
    backoff: Backoff,
    retry_at: Instant,
    connected_before: bool,
    failure_logged: bool,
}

pub(super) async fn run(tap: Tap, mut stopped: watch::Receiver<bool>) {
    let timing = tap.0.timing;
    let mut writer = Writer {
        backoff: Backoff::new(timing.backoff_min, timing.backoff_max),
        tap,
        tls: None,
        link: None,
        retry_at: Instant::now(),
        connected_before: false,
        failure_logged: false,
    };
    let mut flush = interval(timing.flush);
    flush.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut report = interval(timing.report);
    report.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // The first tick of an interval is immediate; the first report and flush are due one period out.
    flush.tick().await;
    report.tick().await;
    let mut batch = VecDeque::new();
    loop {
        if writer.link.is_none() && Instant::now() >= writer.retry_at {
            tokio::select! {
                () = writer.connect() => {}
                _ = stopped.changed() => break,
            }
        }
        let retry_at = writer.retry_at;
        let queue = &writer.tap.0.queue;
        tokio::select! {
            biased;
            _ = stopped.changed() => break,
            () = queue.next_batch(&mut batch) => writer.write_batch(&mut batch).await,
            _ = flush.tick(), if writer.link.is_some() => writer.flush().await,
            _ = report.tick() => writer.tap.report_drops(),
            () = sleep_until(retry_at), if writer.link.is_none() => {}
        }
    }
    writer.finish().await;
}

impl Writer {
    async fn connect(&mut self) {
        match self.dial().await {
            Ok(link) => {
                self.link = Some(link);
                self.backoff.reset();
                self.failure_logged = false;
                self.tap.sink_connected();
                if self.connected_before {
                    self.tap.metric(|metrics| metrics.reconnect());
                }
                self.connected_before = true;
            }
            Err(error) => {
                self.tap.metric(|metrics| metrics.connect_failure());
                // CoreDNS v1.15.0 plugin/dnstap/setup.go: "No connection to dnstap endpoint"; logged once per outage, not on every retry.
                if !self.failure_logged {
                    self.failure_logged = true;
                    pharos_server::logging::log(
                        "ERROR",
                        "dnstap",
                        &format!("No connection to dnstap endpoint: {error}"),
                    );
                }
                self.retry_at = Instant::now() + self.backoff.failed();
            }
        }
    }

    fn disconnect(&mut self) {
        // Dropping the stream closes the socket; the collector sees a reset or EOF, as when CoreDNS closes the old encoder before redialing.
        if self.link.take().is_some() {
            self.tap.sink_disconnected();
        }
    }

    async fn write_batch(&mut self, batch: &mut VecDeque<Vec<u8>>) {
        let mut spent = Vec::with_capacity(batch.len());
        let mut written = 0;
        while let Some(payload) = batch.pop_front() {
            // CoreDNS v1.15.0 plugin/dnstap/io.go dio.serve: a write error redials at once.
            if self.link.is_none() && Instant::now() >= self.retry_at {
                self.connect().await;
            }
            match self.link.as_mut() {
                // CoreDNS v1.15.0 plugin/dnstap/io.go dio.write: errNoOutput counts as a drop.
                None => self.tap.count_drop(DnstapDrop::NoConnection, 1),
                Some(link) => match link.write_frame(&payload).await {
                    Ok(()) => written += 1,
                    Err(_) => {
                        self.tap.count_drop(DnstapDrop::WriteError, 1);
                        self.disconnect();
                        self.retry_at = Instant::now();
                    }
                },
            }
            spent.push(payload);
        }
        self.tap.0.queue.recycle(&mut spent);
        if written > 0 {
            self.tap.metric(|metrics| metrics.written(written));
        }
    }

    async fn flush(&mut self) {
        if let Some(link) = self.link.as_mut()
            && link.flush().await.is_err()
        {
            // The next write fails on the dead connection and redials.
            self.disconnect();
            self.retry_at = Instant::now();
        }
    }

    // CoreDNS v1.15.0 plugin/dnstap/io.go dio.serve: on quit, flush and close the encoder (STOP, then FINISH).
    async fn finish(&mut self) {
        let mut batch = VecDeque::new();
        if self.tap.0.queue.try_batch(&mut batch) {
            // No redial on the way out: only an open connection takes what is left.
            self.retry_at = Instant::now() + Duration::from_secs(3600);
            self.write_batch(&mut batch).await;
        }
        self.tap.report_drops();
        if let Some(mut link) = self.link.take() {
            let _ = link.flush().await;
            let _ = link.close().await;
            self.tap.sink_disconnected();
        }
    }

    async fn dial(&mut self) -> io::Result<Link> {
        let tap = self.tap.clone();
        let config = &tap.0.config;
        let limit = tap.0.timing.timeout;
        // CoreDNS v1.15.0 plugin/dnstap/io.go dial: `tcpTimeout` bounds the connect, and the TLS handshake with it.
        let stream: Box<dyn Stream> = match &config.endpoint {
            Endpoint::Unix(path) => Box::new(within(limit, UnixStream::connect(path)).await?),
            Endpoint::Tcp(address) => {
                Box::new(within(limit, connect_tcp(address, config.write_buffer)).await?)
            }
            Endpoint::Tls(address) => {
                let connector = self.tls_connector().await?;
                let name = server_name(address)?;
                let handshake = async {
                    let tcp = connect_tcp(address, config.write_buffer).await?;
                    connector.connect(name, tcp).await
                };
                Box::new(within(limit, handshake).await?)
            }
        };
        // Handshake and every later write carry their own `tcpTimeout`.
        Encoder::connect(stream, CONTENT_TYPE, limit).await
    }

    async fn tls_connector(&mut self) -> io::Result<TlsConnector> {
        if let Some(connector) = &self.tls {
            return Ok(connector.clone());
        }
        // CoreDNS v1.15.0 plugin/dnstap/io.go dial: `skipverify` sets `InsecureSkipVerify`; otherwise the system roots verify the collector.
        let skip = self.tap.0.config.skip_verify;
        let config = tokio::task::spawn_blocking(move || {
            if skip {
                client_config_unverified()
            } else {
                client_config(&ClientOptions::default())
            }
        })
        .await
        .map_err(io::Error::other)??;
        let connector = TlsConnector::from(config);
        self.tls = Some(connector.clone());
        Ok(connector)
    }
}

pub(super) async fn within<T>(
    limit: Duration,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    timeout(limit, operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dial timeout"))?
}

// CoreDNS v1.15.0 plugin/dnstap/io.go dial: `SetWriteBuffer` of `writebuffer` MiB on the TCP connection (Nagle stays on).
// A socket option set before `connect` also shapes the TCP window, which a later `SetWriteBuffer` cannot.
async fn connect_tcp(address: &str, write_buffer_mib: u32) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address resolved");
    for peer in lookup_host(address).await? {
        match connect_to(peer, write_buffer_mib).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last = error,
        }
    }
    Err(last)
}

async fn connect_to(peer: SocketAddr, write_buffer_mib: u32) -> io::Result<TcpStream> {
    let socket = if peer.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    set_send_buffer(&socket, write_buffer_mib);
    socket.connect(peer).await
}

fn set_send_buffer(socket: &TcpSocket, mib: u32) {
    // The Directive caps `writebuffer` at 1024 MiB, so the product fits in a u32; Go ignores a failing SetWriteBuffer too.
    if let Ok(bytes) = u32::try_from(u64::from(mib) * MIB) {
        let _ = socket.set_send_buffer_size(bytes);
    }
}

// Go crypto/tls Dial: the server name is the host of the address.
fn server_name(address: &str) -> io::Result<ServerName<'static>> {
    let host = address.rsplit_once(':').map_or(address, |(host, _)| host);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    ServerName::try_from(host.to_owned())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))
}

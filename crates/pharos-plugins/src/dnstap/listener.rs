//! `dnstap listen ENDPOINT`: accepts collectors that connect in and broadcasts every message to them.
//!
//! Follows CoreDNS v1.15.0 `plugin/dnstap/listener.go`: no buffering per collector, and a collector
//! whose write fails is closed alone. CoreDNS writes from the Query's own goroutine; here the Query
//! path only encodes onto the shared queue and this task writes, so a slow collector never delays a Query.

use std::{collections::VecDeque, io, time::Duration};

use pharos_server::{
    metrics::DnstapDrop,
    tls::{ClientAuth, ServerOptions, ServerTls, TlsAcceptor},
};
use tokio::{
    net::{TcpListener, TcpStream, UnixListener},
    sync::{mpsc, watch},
    task::JoinSet,
    time::{MissedTickBehavior, interval, sleep},
};

use super::{
    Config, Endpoint,
    framestream::{CONTENT_TYPE, Encoder},
    io::{Link, Stream, within},
    tap::Tap,
};

#[cfg(test)]
mod tests;

// CoreDNS v1.15.0 plugin/dnstap/listener.go acceptLoop: a brief pause after an accept error.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

pub(super) enum Bound {
    Unix(UnixListener, String),
    Tcp(TcpListener),
    Tls(TcpListener, TlsAcceptor),
}

enum Incoming {
    Stream(Box<dyn Stream>),
    Tls(TcpStream, TlsAcceptor),
}

/// Binds the listener of `config`, or `None` after a warning when a `tls://` endpoint lacks its `tls` files.
// CoreDNS v1.15.0 plugin/dnstap/listener.go listen.
pub(super) async fn bind(config: &Config) -> io::Result<Option<Bound>> {
    match &config.endpoint {
        Endpoint::Unix(path) => Ok(Some(Bound::Unix(UnixListener::bind(path)?, path.clone()))),
        Endpoint::Tcp(address) => Ok(Some(Bound::Tcp(listen(address).await?))),
        Endpoint::Tls(address) => {
            let Some(files) = &config.tls else {
                pharos_server::logging::log(
                    "WARN",
                    "dnstap",
                    "TLS listener requires cert and key files",
                );
                return Ok(None);
            };
            // CoreDNS v1.15.0 plugin/dnstap/listener.go listen: a CA file makes client certificates required and verified,
            // or verified only when presented under `skipverify`; without one no client certificate is asked for.
            let options = ServerOptions {
                cert: files.cert.clone().into(),
                key: files.key.clone().into(),
                ca: files.ca.clone().map(Into::into),
                client_auth: match (&files.ca, config.skip_verify) {
                    (None, _) => ClientAuth::NoCert,
                    (Some(_), true) => ClientAuth::VerifyIfGiven,
                    (Some(_), false) => ClientAuth::RequireAndVerify,
                },
                keylog: None,
            };
            let tls = tokio::task::spawn_blocking(move || ServerTls::load(&options))
                .await
                .map_err(io::Error::other)??;
            Ok(Some(Bound::Tls(listen(address).await?, tls.acceptor())))
        }
    }
}

// Go net.Listen accepts ":port" for every interface; Rust's resolver needs a host.
async fn listen(address: &str) -> io::Result<TcpListener> {
    match address.strip_prefix(':') {
        Some(port) => TcpListener::bind(format!("[::]:{port}")).await,
        None => TcpListener::bind(address).await,
    }
}

impl Bound {
    async fn accept(&self) -> io::Result<Incoming> {
        Ok(match self {
            Self::Unix(listener, _) => Incoming::Stream(Box::new(listener.accept().await?.0)),
            Self::Tcp(listener) => Incoming::Stream(Box::new(listener.accept().await?.0)),
            Self::Tls(listener, acceptor) => {
                Incoming::Tls(listener.accept().await?.0, acceptor.clone())
            }
        })
    }

    #[cfg(test)]
    pub(super) fn local_address(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::Tcp(listener) | Self::Tls(listener, _) => listener.local_addr().ok(),
            Self::Unix(..) => None,
        }
    }
}

pub(super) async fn run(tap: Tap, bound: Option<Bound>, mut stopped: watch::Receiver<bool>) {
    let Some(bound) = bound else { return };
    let timing = tap.0.timing;
    let (ready_tx, mut ready) = mpsc::channel::<Link>(16);
    let mut handshakes = JoinSet::new();
    let mut clients: Vec<Link> = Vec::new();
    let mut batch = VecDeque::new();
    let mut report = interval(timing.report);
    report.set_missed_tick_behavior(MissedTickBehavior::Delay);
    report.tick().await;
    loop {
        let queue = &tap.0.queue;
        tokio::select! {
            biased;
            _ = stopped.changed() => break,
            accepted = bound.accept() => match accepted {
                Ok(incoming) => {
                    // CoreDNS v1.15.0 plugin/dnstap/listener.go acceptLoop: the Frame Streams handshake gates a collector joining.
                    let ready_tx = ready_tx.clone();
                    handshakes.spawn(async move {
                        let handshake = async {
                            let stream: Box<dyn Stream> = match incoming {
                                Incoming::Stream(stream) => stream,
                                Incoming::Tls(tcp, acceptor) => Box::new(acceptor.accept(tcp).await?),
                            };
                            Encoder::connect(stream, CONTENT_TYPE, timing.timeout).await
                        };
                        // The handshake bounds each step by the timeout; this bounds the TLS accept before it.
                        match within(timing.timeout * 4, handshake).await {
                            Ok(link) => {
                                let _ = ready_tx.send(link).await;
                            }
                            Err(error) => pharos_server::logging::log(
                                "WARN",
                                "dnstap",
                                &format!("Error creating encoder for dnstap client: {error}"),
                            ),
                        }
                    });
                }
                Err(error) => {
                    tap.warn(&format!("Error accepting dnstap connection: {error}"));
                    sleep(ACCEPT_PAUSE).await;
                }
            },
            Some(link) = ready.recv() => {
                tap.sink_connected();
                clients.push(link);
            }
            Some(_) = handshakes.join_next() => {}
            () = queue.next_batch(&mut batch) => broadcast(&tap, &mut clients, &mut batch).await,
            _ = report.tick() => tap.report_drops(),
        }
    }
    handshakes.abort_all();
    if tap.0.queue.try_batch(&mut batch) {
        broadcast(&tap, &mut clients, &mut batch).await;
    }
    tap.report_drops();
    // CoreDNS v1.15.0 plugin/dnstap/listener.go close: flush and close each client's encoder.
    for link in clients {
        let _ = link.close().await;
        tap.sink_disconnected();
    }
    if let Bound::Unix(_, path) = &bound {
        // Go's UnixListener.Close unlinks the socket file; Tokio's does not.
        let _ = std::fs::remove_file(path);
    }
}

// CoreDNS v1.15.0 plugin/dnstap/listener.go Dnstap: write and flush to every client; a failure closes that client only.
async fn broadcast(tap: &Tap, clients: &mut Vec<Link>, batch: &mut VecDeque<Vec<u8>>) {
    let count = batch.len() as u64;
    if clients.is_empty() {
        tap.count_drop(DnstapDrop::NoConnection, count);
    }
    let mut index = 0;
    while index < clients.len() {
        let link = &mut clients[index];
        let result = async {
            for payload in batch.iter() {
                link.write_frame(payload).await?;
            }
            link.flush().await
        }
        .await;
        if result.is_ok() {
            tap.metric(|metrics| metrics.written(count));
            index += 1;
        } else {
            tap.count_drop(DnstapDrop::WriteError, count);
            drop(clients.swap_remove(index));
            tap.sink_disconnected();
        }
    }
    let mut spent: Vec<Vec<u8>> = batch.drain(..).collect();
    tap.0.queue.recycle(&mut spent);
}

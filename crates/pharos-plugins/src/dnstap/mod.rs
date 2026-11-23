//! dnstap Directive: logs Queries and Responses as dnstap messages.

pub mod framestream;
mod io;
mod listener;
pub mod msg;
mod queue;
pub(crate) mod setup;
mod tap;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod tests;

use std::{cell::RefCell, time::SystemTime};

use pharos_proto::Rcode;
use pharos_server::{Context, Lifecycle, Next, Outcome, Phase, Plugin, Protocol, write_error};
use tokio::task::JoinSet;

use self::msg::{Message, MessageType, SocketProtocol};
pub use self::tap::Tap;

/// Where a sink connects or listens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Endpoint {
    /// A Unix domain socket path.
    Unix(String),
    /// A TCP `host:port`.
    Tcp(String),
    /// A TLS-over-TCP `host:port`.
    Tls(String),
}

/// Whether a `dnstap` Directive dials a sink or accepts sinks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Pharos connects out to a collector.
    Dial,
    /// Collectors connect in (`dnstap listen ...`).
    Listen,
}

/// The `tls CERT KEY [CA]` files of a `listen` Directive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsFiles {
    pub cert: String,
    pub key: String,
    pub ca: Option<String>,
}

/// One parsed `dnstap` Directive. Plain data: parsing starts no IO.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub role: Role,
    pub endpoint: Endpoint,
    /// `full`: include the raw DNS message in each dnstap message.
    pub full: bool,
    /// Write buffer in MiB units per TCP connection.
    pub write_buffer: u32,
    /// Queue size in units of 10,000 messages.
    pub queue: u32,
    pub identity: Vec<u8>,
    pub version: Vec<u8>,
    /// The `extra` format, empty when unset.
    pub extra: String,
    pub skip_verify: bool,
    /// Set only for a `tls://` listener with a `tls` block line.
    pub tls: Option<TlsFiles>,
}

/// The `dnstap` Directives of one Server Block.
#[derive(Debug)]
pub struct Dnstap {
    taps: Vec<Tap>,
    any_full: bool,
}

thread_local! {
    // The header-only Response the Server will write for a Query that no Plugin answered.
    static DEFERRED: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

impl Dnstap {
    pub(crate) fn new(configs: Vec<Config>) -> Self {
        Self {
            any_full: configs.iter().any(|config| config.full),
            taps: configs.into_iter().map(Tap::new).collect(),
        }
    }

    /// The configured taps in Corefile order. Clones share the queue and the background task.
    ///
    /// A Plugin that emits its own dnstap messages (CoreDNS `forward` sends FORWARDER_QUERY and
    /// FORWARDER_RESPONSE) holds clones and calls `Tap::send`.
    #[must_use]
    pub fn taps(&self) -> &[Tap] {
        &self.taps
    }

    pub(crate) fn set_metrics(&self, registry: &pharos_server::metrics::Registry) {
        for tap in &self.taps {
            tap.set_metrics(registry);
        }
    }

    /// Dials or listens at Startup and closes at Restart and Shutdown, as CoreDNS OnStartup, OnRestart and OnFinalShutdown.
    pub(crate) fn register_hooks(&self, lifecycle: &mut Lifecycle) {
        let taps = self.taps.clone();
        let start = move || {
            let taps = taps.clone();
            async move {
                for tap in &taps {
                    tap.start().await;
                }
                Ok(())
            }
        };
        // A failed reload resumes the old configuration, whose Restart hook has already closed its taps.
        lifecycle.register(Phase::Startup, start.clone());
        lifecycle.register(Phase::RestartFailed, start);
        let taps = self.taps.clone();
        let stop = move || {
            let taps = taps.clone();
            async move {
                let mut stopping = JoinSet::new();
                for tap in taps {
                    stopping.spawn(async move { tap.stop().await });
                }
                while stopping.join_next().await.is_some() {}
                Ok(())
            }
        };
        lifecycle.register(Phase::Restart, stop.clone());
        lifecycle.register(Phase::Shutdown, stop);
    }

    fn tap_query(&self, cx: &Context<'_, '_>, query_time: SystemTime) {
        for tap in &self.taps {
            // CoreDNS v1.15.0 plugin/dnstap/handler.go tapQuery.
            let mut message = Message::new(MessageType::ClientQuery);
            message.set_query_time(query_time);
            message.set_query_address(cx.client, socket_protocol(cx.protocol));
            if tap.include_raw() {
                message.set_query_message(cx.query.as_wire());
            }
            tap.send_with(&message, cx);
        }
    }

    fn tap_response(&self, cx: &Context<'_, '_>, query_time: SystemTime, wire: &[u8]) {
        let response_time = SystemTime::now();
        for tap in &self.taps {
            // CoreDNS v1.15.0 plugin/dnstap/writer.go tapResponse: the client address and both times, no query message.
            let mut message = Message::new(MessageType::ClientResponse);
            message.set_query_time(query_time);
            message.set_response_time(response_time);
            message.set_query_address(cx.client, socket_protocol(cx.protocol));
            if tap.include_raw() {
                message.set_response_message(wire);
            }
            tap.send_with(&message, cx);
        }
    }

    // CoreDNS v1.15.0 plugin/dnstap/handler.go ServeDNS (#6532): an error Response written after the chain returns is tapped too.
    fn tap_deferred(&self, cx: &Context<'_, '_>, query_time: SystemTime, rcode: Rcode) {
        DEFERRED.with_borrow_mut(|wire| {
            if self.any_full {
                write_error(cx.query, wire, rcode);
            }
            self.tap_response(cx, query_time, wire);
        });
    }
}

// RFC 1035 §4.1.1: the SocketProtocol follows the transport the client used; CoreDNS maps net.UDPAddr and net.TCPAddr.
fn socket_protocol(protocol: Protocol) -> SocketProtocol {
    match protocol {
        Protocol::Udp => SocketProtocol::Udp,
        Protocol::Tcp => SocketProtocol::Tcp,
    }
}

impl Plugin for Dnstap {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let query_time = SystemTime::now();
        // CoreDNS v1.15.0 plugin/dnstap/handler.go ServeDNS: the query is tapped before the chain runs, so the messages stay in order.
        self.tap_query(cx, query_time);
        let outcome = next.run(cx).await;
        match &outcome {
            Outcome::Response => self.tap_response(cx, query_time, cx.response),
            Outcome::Error(_) => self.tap_deferred(cx, query_time, Rcode::SERVFAIL),
            // The Server answers these after the chain returns; any other code is dropped unanswered.
            Outcome::Unanswered(
                code @ (Rcode::SERVFAIL
                | Rcode::REFUSED
                | Rcode::FORMERR
                | Rcode::NOTIMP
                | Rcode::NOTAUTH),
            ) => self.tap_deferred(cx, query_time, *code),
            Outcome::Unanswered(_) | Outcome::Stream(_) | Outcome::Drop => {}
        }
        outcome
    }
}

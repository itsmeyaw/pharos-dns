use std::{future::Future, net::SocketAddr, sync::Arc, time::Instant};

use crate::{
    Action, Admission, Context, Error, Handler, ListenerKey, Metadata, Outcome, Protocol, Router,
    admit, finish_outcome,
    metrics::{BlockMetrics, Registry},
    response_limit,
};
use pharos_proto::Rcode;

/// Statically dispatched Plugin Chain supplied by the Plugin registry.
pub trait Chain: Send + Sync + 'static {
    fn serve(&self, context: &mut Context<'_>) -> impl Future<Output = Outcome> + Send;
    fn is_empty(&self) -> bool;
    fn visit_enabled(&self, _visit: &mut dyn FnMut(&'static str)) {}
    fn metrics_enabled(&self) -> bool {
        true
    }
    /// Whether contained Plugin panics should include a stacktrace.
    fn stacktrace(&self) -> bool {
        false
    }
}

impl<C: Chain> Chain for Arc<C> {
    fn serve(&self, context: &mut Context<'_>) -> impl Future<Output = Outcome> + Send {
        self.as_ref().serve(context)
    }
    fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
    fn visit_enabled(&self, visit: &mut dyn FnMut(&'static str)) {
        self.as_ref().visit_enabled(visit);
    }
    fn metrics_enabled(&self) -> bool {
        self.as_ref().metrics_enabled()
    }
    fn stacktrace(&self) -> bool {
        self.as_ref().stacktrace()
    }
}

/// One Listener's routing, admission and Plugin Chain execution.
pub struct Server<C> {
    pub router: Router<C>,
    pub key: ListenerKey,
    pub allow_non_in: bool,
    pub debug: bool,
    pub logger: fn(Error),
    metrics: Registry,
    dropped: Option<BlockMetrics>,
}

impl<C: Chain> Server<C> {
    pub fn new(router: Router<C>, key: ListenerKey) -> Self {
        let metrics = Registry::default();
        Self::with_registry(router, key, metrics)
    }

    pub fn with_registry(mut router: Router<C>, key: ListenerKey, metrics: Registry) -> Self {
        let scheme = match key.transport {
            crate::Transport::Dns => "dns",
            crate::Transport::Tls => "tls",
            crate::Transport::Quic => "quic",
            crate::Transport::Grpc => "grpc",
            crate::Transport::Https => "https",
            crate::Transport::Https3 => "https3",
        };
        let address = if key.address.ip().is_unspecified() {
            format!(":{}", key.address.port())
        } else {
            key.address.to_string()
        };
        let server = format!("{scheme}://{address}");
        router.prepare_metrics(&key, &metrics, &server);
        let dropped = router
            .metrics_enabled(&key)
            .then(|| metrics.block(&server, "dropped", ""));
        Self {
            router,
            key,
            allow_non_in: false,
            debug: false,
            logger: log_error,
            metrics,
            dropped,
        }
    }

    pub fn metrics(&self) -> &Registry {
        &self.metrics
    }
}

fn log_error(error: Error) {
    log_plugin_error("server", error);
}

fn log_plugin_error(plugin: &str, error: Error) {
    crate::logging::log("ERROR", plugin, &format!("Plugin error: {error}"));
}

impl<C: Chain> Handler for Server<C> {
    async fn handle(
        &self,
        wire: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        self.handle_with_depth(wire, peer, protocol, response, 0, self)
            .await
    }

    async fn handle_shared(
        self: &Arc<Self>,
        wire: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        self.handle_with_depth(wire, peer, protocol, response, 0, self)
            .await
    }
}

impl<C: Chain> crate::SelfLookupServer for Server<C> {
    fn lookup<'a>(
        &'a self,
        wire: &'a [u8],
        peer: SocketAddr,
        protocol: Protocol,
        depth: u8,
        response: &'a mut Vec<u8>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Action> + Send + 'a>> {
        // shortcut: static re-entry boxes a future, remove if recursive dispatch no longer needs it.
        Box::pin(self.handle_with_depth(wire, peer, protocol, response, depth, self))
    }
}

impl<C: Chain> crate::SelfLookupServer for Arc<Server<C>> {
    fn lookup<'a>(
        &'a self,
        wire: &'a [u8],
        peer: SocketAddr,
        protocol: Protocol,
        depth: u8,
        response: &'a mut Vec<u8>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Action> + Send + 'a>> {
        Box::pin(self.handle_with_depth(wire, peer, protocol, response, depth, self))
    }

    fn owned(&self) -> Option<Arc<dyn crate::OwnedSelfLookupServer>> {
        Some(Arc::clone(self) as Arc<dyn crate::OwnedSelfLookupServer>)
    }
}

impl<C: Chain> crate::OwnedSelfLookupServer for Server<C> {
    fn lookup<'a>(
        self: Arc<Self>,
        wire: &'a [u8],
        peer: SocketAddr,
        protocol: Protocol,
        depth: u8,
        response: &'a mut Vec<u8>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Action> + Send + 'a>> {
        Box::pin(async move {
            self.handle_with_depth(wire, peer, protocol, response, depth, &self)
                .await
        })
    }
}

impl<C: Chain> Server<C> {
    async fn handle_with_depth(
        &self,
        wire: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
        depth: u8,
        lookup_server: &dyn crate::SelfLookupServer,
    ) -> Action {
        let start = Instant::now();
        let query = match admit(wire, self.allow_non_in, response) {
            Admission::Query(query) => query,
            Admission::Respond => {
                if let Ok(query) = pharos_proto::Message::parse(wire) {
                    let rcode = pharos_proto::Message::parse(response)
                        .map_or(0, |message| message.rcode().0);
                    if rcode != Rcode::BADVERS.0
                        && let Some(dropped) = &self.dropped
                    {
                        dropped.record(
                            query.questions().next().map_or(0, |q| q.qtype.0),
                            protocol == Protocol::Tcp,
                            peer_is_ipv6(peer),
                            query.opt().is_some_and(|opt| opt.dnssec_ok()),
                            wire.len(),
                            response.len(),
                            rcode,
                            start.elapsed().as_secs_f64(),
                        );
                    }
                }
                return Action::Respond;
            }
            Admission::Drop => return Action::Drop,
        };
        let block = self.router.route(&self.key, query, peer, protocol);
        let chain_start = Instant::now();
        let mut producer = None;
        let mut error_plugin = None;
        let mut error_logged = false;
        let outcome = if let Some(block) = block {
            if let Some(chain) = block.chain() {
                let mut slots = [None; 18];
                slots[0] = Some((crate::metrics::WRITER_METADATA, ""));
                slots[1] = Some((crate::logging::PLUGIN_METADATA, ""));
                slots[2] = Some((crate::logging::ERROR_LOGGED_METADATA, ""));
                let mut metadata = Metadata::new(&mut slots);
                metadata.self_lookup = Some(crate::SelfLookupState {
                    server: lookup_server,
                    depth,
                });
                let mut context = Context {
                    query,
                    client: peer,
                    local: self.key.address,
                    transport: self.key.transport,
                    protocol,
                    domain: block.domain(),
                    metadata,
                    response,
                    max_response_size: response_limit(query, protocol),
                };
                let outcome = crate::panic::contain_panic_with_stacktrace(
                    chain.serve(&mut context),
                    self.debug,
                    chain.stacktrace(),
                )
                .await;
                producer = context
                    .metadata
                    .get(crate::metrics::WRITER_METADATA)
                    .and_then(|name| block.plugin_metrics(name));
                error_plugin = context
                    .metadata
                    .get(crate::logging::PLUGIN_METADATA)
                    .and_then(|name| block.plugin_name(name));
                error_logged =
                    context.metadata.get(crate::logging::ERROR_LOGGED_METADATA) == Some("true");
                outcome
            } else {
                Outcome::Unanswered(Rcode::REFUSED)
            }
        } else {
            Outcome::Unanswered(Rcode::REFUSED)
        };
        let recorded_size = if outcome == Outcome::Response {
            response.len()
        } else {
            0
        };
        let recorded_code = match outcome {
            Outcome::Response => {
                pharos_proto::Message::parse(response).map_or(0, |message| message.rcode().0)
            }
            Outcome::Unanswered(code) => code.0,
            Outcome::Error(_) => Rcode::SERVFAIL.0,
            Outcome::Drop | Outcome::Stream(_) => 0,
        };
        let duration = chain_start.elapsed().as_secs_f64();
        let default_logger = std::ptr::fn_addr_eq(self.logger, log_error as fn(Error));
        let mut first_error = true;
        let action = finish_outcome(query, protocol, outcome, response, |error| {
            let suppress = first_error
                && (error_logged || default_logger)
                && matches!(outcome, Outcome::Error(e) if e != Error::PluginPanic);
            first_error = false;
            if suppress {
                return;
            }
            if let Some(plugin) = error_plugin.filter(|_| default_logger) {
                log_plugin_error(plugin, error);
            } else {
                (self.logger)(error);
            }
        });
        let code = if (block.is_none() || outcome == Outcome::Error(Error::PluginPanic))
            && action == Action::Respond
        {
            pharos_proto::Message::parse(response).map_or(0, |message| message.rcode().0)
        } else {
            recorded_code
        };
        // shortcut: compressed Query lengths differ until decoded Message lengths are available.
        let qtype = query.questions().next().map_or(0, |q| q.qtype.0);
        let dnssec = query.opt().is_some_and(|opt| opt.dnssec_ok());
        let response_len = if (block.is_none() || outcome == Outcome::Error(Error::PluginPanic))
            && action == Action::Respond
        {
            response.len()
        } else {
            recorded_size
        };
        if let Some(producer) = producer {
            producer.record(
                qtype,
                protocol == Protocol::Tcp,
                peer_is_ipv6(peer),
                dnssec,
                wire.len(),
                response_len,
                code,
                duration,
            );
        } else {
            let metrics = if outcome == Outcome::Error(Error::PluginPanic) {
                self.dropped.as_ref()
            } else {
                block.map_or(self.dropped.as_ref(), |block| block.metrics())
            };
            if let Some(metrics) = metrics {
                metrics.record(
                    qtype,
                    protocol == Protocol::Tcp,
                    peer_is_ipv6(peer),
                    dnssec,
                    wire.len(),
                    response_len,
                    code,
                    duration,
                );
            }
        }
        action
    }
}

fn peer_is_ipv6(peer: SocketAddr) -> bool {
    match peer.ip() {
        std::net::IpAddr::V4(_) => false,
        std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().is_none(),
    }
}

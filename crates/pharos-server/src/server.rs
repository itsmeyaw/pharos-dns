use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use crate::{
    Action, Admission, Context, Error, Handler, ListenerKey, Metadata, Outcome, Protocol, Router,
    admit_with_update, finish_outcome_signed,
    metrics::{BlockMetrics, Registry},
    response_limit,
};
use pharos_proto::Rcode;

/// Statically dispatched Plugin Chain supplied by the Plugin registry.
pub trait Chain: Send + Sync + 'static {
    fn serve(&self, context: &mut Context<'_, '_>) -> impl Future<Output = Outcome> + Send;
    fn is_empty(&self) -> bool;
    /// Whether this Server Block accepts RFC 2136 UPDATE messages.
    fn accepts_update(&self) -> bool {
        false
    }
    /// Whether this Chain resets and collects Metadata before its filters.
    fn has_metadata_collector(&self) -> bool {
        false
    }
    /// Collect this candidate's Metadata after the server resets collected values.
    fn collect_metadata(&self, _context: &mut Context<'_, '_>) {}
    /// Evaluate the candidate's View after Metadata and legacy filters.
    fn matches_view(&self, _context: &Context<'_, '_>) -> bool {
        true
    }
    /// Whether this Chain has a View, including one with an empty name.
    fn has_view(&self) -> bool {
        false
    }
    /// Return the View name, or an empty string when absent.
    fn view_name(&self) -> &str {
        ""
    }
    /// Serve a routed Query. Override to preserve Metadata when `collected` is true.
    fn serve_routed(
        &self,
        context: &mut Context<'_, '_>,
        _collected: bool,
    ) -> impl Future<Output = Outcome> + Send {
        self.serve(context)
    }
    fn parallel_query(
        &self,
        _query: &pharos_proto::Message<'_>,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        None
    }
    fn visit_enabled(&self, _visit: &mut dyn FnMut(&'static str)) {}
    fn metrics_enabled(&self) -> bool {
        true
    }
    /// Return dynamically discovered metric Zone names, when configured.
    fn dynamic_metric_zones(&self) -> Option<&crate::metrics::DynamicZones> {
        None
    }
    fn shed_enabled(&self) -> bool {
        false
    }
    /// Whether contained Plugin panics should include a stacktrace.
    fn stacktrace(&self) -> bool {
        false
    }
}

impl<C: Chain> Chain for Arc<C> {
    fn serve(&self, context: &mut Context<'_, '_>) -> impl Future<Output = Outcome> + Send {
        self.as_ref().serve(context)
    }
    fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
    fn accepts_update(&self) -> bool {
        self.as_ref().accepts_update()
    }
    fn has_metadata_collector(&self) -> bool {
        self.as_ref().has_metadata_collector()
    }
    fn collect_metadata(&self, context: &mut Context<'_, '_>) {
        self.as_ref().collect_metadata(context);
    }
    fn matches_view(&self, context: &Context<'_, '_>) -> bool {
        self.as_ref().matches_view(context)
    }
    fn has_view(&self) -> bool {
        self.as_ref().has_view()
    }
    fn view_name(&self) -> &str {
        self.as_ref().view_name()
    }
    fn serve_routed(
        &self,
        context: &mut Context<'_, '_>,
        collected: bool,
    ) -> impl Future<Output = Outcome> + Send {
        self.as_ref().serve_routed(context, collected)
    }
    fn parallel_query(
        &self,
        query: &pharos_proto::Message<'_>,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        self.as_ref().parallel_query(query)
    }
    fn visit_enabled(&self, visit: &mut dyn FnMut(&'static str)) {
        self.as_ref().visit_enabled(visit);
    }
    fn metrics_enabled(&self) -> bool {
        self.as_ref().metrics_enabled()
    }
    fn dynamic_metric_zones(&self) -> Option<&crate::metrics::DynamicZones> {
        self.as_ref().dynamic_metric_zones()
    }
    fn shed_enabled(&self) -> bool {
        self.as_ref().shed_enabled()
    }
    fn stacktrace(&self) -> bool {
        self.as_ref().stacktrace()
    }
}

/// One Listener's routing, admission and Plugin Chain execution.
pub struct Server<C> {
    pub router: Arc<Router<C>>,
    pub key: ListenerKey,
    pub allow_non_in: bool,
    pub debug: bool,
    pub udp_workers: usize,
    pub tcp_options: crate::TcpOptions,
    pub logger: fn(Error),
    metrics: Registry,
    dropped: Option<BlockMetrics>,
    shed: Option<crate::metrics::ShedMetrics>,
    has_views: Arc<AtomicBool>,
    root: pharos_proto::Name,
}

impl<C: Chain> Server<C> {
    fn route_view<'s, 'm>(
        &'s self,
        query: pharos_proto::Message<'_>,
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
        metadata: &mut Metadata<'m>,
    ) -> (Option<&'s crate::ServerBlock<C>>, &'s str) {
        let mut view = "";
        let block = self.router.route_with::<true>(&self.key, query, |block| {
            let Some(chain) = block.chain() else {
                return false;
            };
            let mut context = Context {
                query,
                client: peer,
                local: self.key.address,
                transport: self.key.transport,
                protocol,
                domain: block.domain(),
                metadata: std::mem::replace(metadata, Metadata::new(&mut [])),
                response,
                max_response_size: response_limit(query, protocol),
            };
            if chain.has_metadata_collector() {
                context.metadata.clear_collected();
                chain.collect_metadata(&mut context);
            }
            let matches =
                block.matches_filters(&query, peer, protocol) && chain.matches_view(&context);
            if matches && !chain.view_name().is_empty() {
                // CoreDNS core/dnsserver/server.go: empty ViewName does not replace the prior match.
                view = chain.view_name();
            }
            *metadata = context.metadata;
            matches
        });
        (block, view)
    }

    fn route_for_dispatch(
        &self,
        query: pharos_proto::Message<'_>,
        peer: SocketAddr,
        protocol: Protocol,
    ) -> Option<&crate::ServerBlock<C>> {
        if !self.has_views.load(Ordering::Relaxed) {
            return self.router.route(&self.key, query, peer, protocol);
        }
        let mut slots = [None; 18];
        let mut metadata = Metadata::new(&mut slots);
        metadata.set_enabled(false);
        self.route_view(query, peer, protocol, &mut Vec::new(), &mut metadata)
            .0
    }

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
        let has_views = router.prepare_metrics(&key, &metrics, &server);
        let dropped = router
            .metrics_enabled(&key)
            .then(|| metrics.block(&server, "dropped", ""));
        let shed = router.shed_enabled(&key).then(|| metrics.shed(&server));
        Self {
            router: Arc::new(router),
            key,
            allow_non_in: false,
            debug: false,
            udp_workers: crate::quota::worker_count(),
            tcp_options: crate::TcpOptions::default(),
            logger: log_error,
            metrics,
            dropped,
            shed,
            has_views,
            root: ".".parse().expect("root Domain"),
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
    fn shed_metrics(&self) -> Option<crate::metrics::ShedMetrics> {
        self.shed.clone()
    }
    fn shed_query(&self, wire: &[u8], peer: SocketAddr) -> bool {
        // shortcut: admit writes its discarded error Response here, so a malformed, non-IN, or BADVERS Query allocates while the stack is full; pass a reused buffer if overload floods of such Queries matter.
        let mut response = Vec::new();
        let allow_update = wire.get(2).is_some_and(|flags| flags & 0x78 == 0x28)
            && self.router.accepts_update(&self.key);
        let Admission::Query(query) =
            admit_with_update(wire, self.allow_non_in, allow_update, &mut response)
        else {
            return false;
        };
        self.route_for_dispatch(query, peer, Protocol::Udp)
            .and_then(|block| block.chain())
            .is_some_and(Chain::shed_enabled)
    }
    fn tcp_options(&self) -> crate::TcpOptions {
        self.tcp_options
    }
    fn udp_workers(&self) -> usize {
        self.udp_workers
    }
    fn parallel_query(
        &self,
        wire: &[u8],
        peer: SocketAddr,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        let Ok(query) = pharos_proto::Message::parse(wire) else {
            return None;
        };
        // shortcut: only loop probes require parallel dispatch; extend for other self-queries.
        if query
            .questions()
            .next()
            .is_none_or(|question| question.qtype != pharos_proto::Type::HINFO)
        {
            return None;
        }
        self.route_for_dispatch(query, peer, Protocol::Udp)
            .and_then(|block| block.chain())
            .and_then(|chain| chain.parallel_query(&query))
    }
    // RFC 1034 §2.2: DNS query handling accepts transport-independent messages.
    async fn handle(
        &self,
        wire: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        self.handle_with_depth(wire, peer, protocol, response, (0, false, false), self)
            .await
    }

    async fn handle_shared(
        self: &Arc<Self>,
        wire: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        self.handle_with_depth(wire, peer, protocol, response, (0, false, false), self)
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
        flags: (bool, bool),
        response: &'a mut Vec<u8>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Action> + Send + 'a>> {
        // shortcut: static re-entry boxes a future, remove if recursive dispatch no longer needs it.
        Box::pin(self.handle_with_depth(
            wire,
            peer,
            protocol,
            response,
            (depth, flags.0, flags.1),
            self,
        ))
    }

    fn owned(&self) -> Option<Arc<dyn crate::OwnedSelfLookupServer>> {
        Some(Arc::new(Self {
            router: Arc::clone(&self.router),
            key: self.key,
            allow_non_in: self.allow_non_in,
            debug: self.debug,
            udp_workers: self.udp_workers,
            tcp_options: self.tcp_options,
            logger: self.logger,
            metrics: self.metrics.clone(),
            shed: self.shed.clone(),
            has_views: Arc::clone(&self.has_views),
            dropped: self.dropped.clone(),
            root: self.root.clone(),
        }))
    }
}

impl<C: Chain> crate::SelfLookupServer for Arc<Server<C>> {
    fn lookup<'a>(
        &'a self,
        wire: &'a [u8],
        peer: SocketAddr,
        protocol: Protocol,
        depth: u8,
        flags: (bool, bool),
        response: &'a mut Vec<u8>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Action> + Send + 'a>> {
        Box::pin(self.handle_with_depth(
            wire,
            peer,
            protocol,
            response,
            (depth, flags.0, flags.1),
            self,
        ))
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
        flags: (bool, bool),
        response: &'a mut Vec<u8>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Action> + Send + 'a>> {
        Box::pin(async move {
            self.handle_with_depth(
                wire,
                peer,
                protocol,
                response,
                (depth, flags.0, flags.1),
                &self,
            )
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
        lookup: (u8, bool, bool),
        lookup_server: &dyn crate::SelfLookupServer,
    ) -> Action {
        let start = Instant::now();
        let allow_update = wire.get(2).is_some_and(|flags| flags & 0x78 == 0x28)
            && self.router.accepts_update(&self.key);
        let mut query = match admit_with_update(wire, self.allow_non_in, allow_update, response) {
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
        // shortcut: no-View routing reads a flag and initializes Metadata early; specialize Listener dispatch to remove this cost.
        let has_views = self.has_views.load(Ordering::Relaxed);
        let mut slots = [None; 18];
        slots[0] = Some((crate::metrics::WRITER_METADATA, ""));
        slots[1] = Some((crate::logging::PLUGIN_METADATA, ""));
        slots[2] = Some((crate::logging::ERROR_LOGGED_METADATA, ""));
        // ADR 0005 (#92): finish the potentially unwinding call first so Metadata is built in place, not copied.
        let max_response_size = response_limit(query, protocol);
        let mut context = Context {
            query,
            client: peer,
            local: self.key.address,
            transport: self.key.transport,
            protocol,
            domain: &self.root,
            metadata: Metadata::new(&mut slots),
            response,
            max_response_size,
        };
        context.metadata.self_lookup = Some(crate::SelfLookupState {
            server: lookup_server,
            depth: lookup.0,
            siit: lookup.1,
            autopath: lookup.2,
        });
        let (block, view) = if has_views {
            context.metadata.set_enabled(false);
            self.route_view(
                query,
                peer,
                protocol,
                context.response,
                &mut context.metadata,
            )
        } else {
            (self.router.route(&self.key, query, peer, protocol), "")
        };
        let dynamic_metrics = block
            .and_then(|block| block.dynamic_metrics(view))
            .map(|metrics| metrics.snapshot());
        let chain_start = Instant::now();
        let mut producer = None;
        let mut metric_producer = None;
        let mut error_plugin = None;
        let mut error_logged = false;
        let mut tsig_signing = None;
        let outcome = if let Some(block) = block {
            if let Some(chain) = block.chain() {
                // RFC 2136 §3: Return NOTIMP when UPDATE is not implemented.
                if query.opcode() == pharos_proto::Opcode::UPDATE && !chain.accepts_update() {
                    Outcome::Unanswered(Rcode::NOTIMP)
                } else {
                    if has_views {
                        context.metadata.set_metric_view(view);
                    }
                    context.domain = block.domain();
                    let outcome = {
                        let future = std::pin::pin!(chain.serve_routed(&mut context, has_views));
                        crate::panic::contain_panic_with_stacktrace(
                            future,
                            self.debug,
                            chain.stacktrace(),
                        )
                        .await
                    };
                    if let Some(opt) = context.query.opt() {
                        query = query.with_udp_payload_limit(opt.udp_payload_size());
                    }
                    producer = context
                        .metadata
                        .get(crate::metrics::WRITER_METADATA)
                        .and_then(|name| block.plugin_metrics(name, view));
                    if dynamic_metrics.is_some() {
                        metric_producer = context
                            .metadata
                            .get(crate::metrics::WRITER_METADATA)
                            .and_then(|name| block.plugin_name(name));
                    }
                    error_plugin = context
                        .metadata
                        .get(crate::logging::PLUGIN_METADATA)
                        .and_then(|name| block.plugin_name(name));
                    error_logged =
                        context.metadata.get(crate::logging::ERROR_LOGGED_METADATA) == Some("true");
                    tsig_signing = context.metadata.take_tsig_signing();
                    outcome
                }
            } else {
                Outcome::Unanswered(Rcode::REFUSED)
            }
        } else {
            // RFC 1035 §4.1.1: REFUSED means the server declines the requested operation.
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
            // RFC 1035 §4.1.1: RCODE 2 reports a server processing problem.
            Outcome::Error(_) => Rcode::SERVFAIL.0,
            Outcome::Drop | Outcome::Stream(_) => 0,
        };
        let duration = chain_start.elapsed().as_secs_f64();
        let default_logger = std::ptr::fn_addr_eq(self.logger, log_error as fn(Error));
        let mut first_error = true;
        let plugin_panic = outcome == Outcome::Error(Error::PluginPanic);
        let plugin_error = matches!(outcome, Outcome::Error(e) if e != Error::PluginPanic);
        let action =
            finish_outcome_signed(query, protocol, outcome, response, tsig_signing, |error| {
                let suppress = first_error && (error_logged || default_logger) && plugin_error;
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
        let code = if (block.is_none() || plugin_panic) && action == Action::Respond {
            pharos_proto::Message::parse(response).map_or(0, |message| message.rcode().0)
        } else {
            recorded_code
        };
        // shortcut: compressed Query lengths differ until decoded Message lengths are available.
        let qtype = query.questions().next().map_or(0, |q| q.qtype.0);
        let dnssec = query.opt().is_some_and(|opt| opt.dnssec_ok());
        let response_len = if (block.is_none() || plugin_panic) && action == Action::Respond {
            response.len()
        } else {
            recorded_size
        };
        if let Some(dynamic) = dynamic_metrics.filter(|_| !plugin_panic || producer.is_some()) {
            dynamic.record(
                query.questions().next().map(|question| question.name),
                metric_producer,
                qtype,
                protocol == Protocol::Tcp,
                peer_is_ipv6(peer),
                dnssec,
                wire.len(),
                response_len,
                code,
                duration,
            );
        } else if let Some(producer) = producer {
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
            let metrics = if plugin_panic {
                self.dropped.as_ref()
            } else {
                block.map_or(self.dropped.as_ref(), |block| block.metrics(view))
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

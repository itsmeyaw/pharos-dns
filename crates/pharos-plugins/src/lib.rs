#![forbid(unsafe_code)]
#![recursion_limit = "512"]
//! Plugins are enabled by `plugin-<directive>` Cargo features (underscores in
//! Directive names become hyphens). Enabled but unimplemented Directives reject
//! configuration rather than silently accepting it.

use pharos_corefile::{BlockContext, Cursor, Directive, Error};
use pharos_server::{Lifecycle, ListenerKey, Router, Server, Transport};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
};

#[cfg(feature = "plugin-any")]
pub mod any;
#[cfg(feature = "plugin-bind")]
pub mod bind;
#[cfg(feature = "plugin-bufsize")]
pub mod bufsize;
#[cfg(feature = "plugin-cache")]
pub mod cache;
#[cfg(feature = "plugin-chaos")]
pub mod chaos;
#[cfg(feature = "plugin-errors")]
pub mod errors;
#[cfg(any(
    feature = "plugin-health",
    feature = "plugin-errors",
    feature = "plugin-reload",
    feature = "plugin-hosts",
    feature = "plugin-loadbalance",
    feature = "plugin-kubernetes"
))]
pub mod health;
#[cfg(feature = "plugin-hosts")]
pub mod hosts;
#[cfg(feature = "plugin-kubernetes")]
pub mod kubernetes;
#[cfg(feature = "plugin-loadbalance")]
pub mod loadbalance;
#[cfg(feature = "plugin-nsid")]
pub mod nsid;
pub mod proxy;

#[cfg(all(test, feature = "plugin-cache", feature = "plugin-hosts"))]
mod self_lookup_test;

#[cfg(feature = "plugin-forward")]
pub mod forward;

#[cfg(feature = "plugin-log")]
pub mod log;
#[cfg(feature = "plugin-log")]
pub mod log_format;
#[cfg(feature = "plugin-loop")]
pub mod r#loop;
#[cfg(feature = "plugin-prometheus")]
pub mod prometheus;
#[cfg(feature = "plugin-ready")]
pub mod ready;
#[cfg(feature = "plugin-reload")]
pub mod reload;
#[cfg(feature = "plugin-whoami")]
pub mod whoami;

include!(concat!(env!("OUT_DIR"), "/plugins.rs"));

#[cfg(any(
    feature = "plugin-health",
    feature = "plugin-prometheus",
    feature = "plugin-ready"
))]
fn valid_http_address(address: &str) -> bool {
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    if port.contains(['[', ']']) {
        return false;
    }
    if host.starts_with('[') {
        host.ends_with(']') && !host[1..host.len() - 1].contains(['[', ']'])
    } else {
        !host.contains([':', '[', ']'])
    }
}

/// Directive registry in Plugin Order.
#[must_use]
pub fn directives() -> &'static [Directive<'static, Chain>] {
    DIRECTIVES
}

/// CoreDNS-style alphabetically sorted plugin listing, including final blank line.
#[must_use]
pub const fn plugins_listing() -> &'static str {
    PLUGINS_LISTING
}

/// Configured DNS Servers keyed by Listener.
pub type Servers = HashMap<ListenerKey, Server<Arc<Chain>>>;

/// Group Server Blocks by Listener and collect their hooks in block order.
/// The caller runs Startup before serving and Shutdown before Listeners drain.
pub fn servers(blocks: Vec<BlockContext<Chain>>) -> io::Result<(Servers, Lifecycle)> {
    servers_with_registry(blocks, pharos_server::metrics::Registry::default())
}

/// Build servers using a process-wide metrics registry.
pub fn servers_with_registry(
    blocks: Vec<BlockContext<Chain>>,
    metrics: pharos_server::metrics::Registry,
) -> io::Result<(Servers, Lifecycle)> {
    let mut groups: HashMap<ListenerKey, (Router<Arc<Chain>>, Option<usize>)> = HashMap::new();
    let mut lifecycle = Lifecycle::default();
    #[cfg(feature = "plugin-forward")]
    let _ = metrics.forward();
    #[cfg(feature = "plugin-health")]
    metrics.enable_health_metrics();
    #[cfg(feature = "plugin-prometheus")]
    let mut exporters = std::collections::BTreeMap::new();
    #[cfg(feature = "plugin-ready")]
    let ready_state = Arc::new(ready::State::default());
    #[cfg(feature = "plugin-ready")]
    let mut ready_addresses = std::collections::BTreeSet::new();
    #[cfg(feature = "plugin-health")]
    let mut health_addresses: Vec<(String, std::time::Duration)> = Vec::new();
    #[cfg(feature = "plugin-ready")]
    {
        let state = Arc::clone(&ready_state);
        // This hook precedes all block shutdown hooks, including a future lameduck delay.
        lifecycle.register_sync(pharos_server::Phase::Shutdown, move || {
            state.begin_shutdown();
            Ok(())
        });
    }
    for block in blocks {
        #[cfg(any(feature = "plugin-forward", feature = "plugin-cache"))]
        let mut block = block;
        #[cfg(feature = "plugin-forward")]
        if let Some(forward) = &mut block.config.forward {
            forward.set_metrics(&metrics);
        }
        #[cfg(feature = "plugin-hosts")]
        if let Some(hosts) = &block.config.hosts {
            hosts.set_metrics(&metrics);
        }
        #[cfg(feature = "plugin-kubernetes")]
        if let Some(kubernetes) = &block.config.kubernetes {
            kubernetes.set_metrics(&metrics);
        }
        #[cfg(feature = "plugin-health")]
        if let Some(health) = &block.config.health
            && !health_addresses
                .iter()
                .any(|(address, _)| *address == health.address)
        {
            health_addresses.push((health.address.clone(), health.lameduck));
        }
        #[cfg(feature = "plugin-ready")]
        if let Some(ready) = &block.config.ready {
            ready_addresses.insert(ready.address.clone());
            ready_state.set_continuous(ready.continuous);
        }
        #[cfg(feature = "plugin-prometheus")]
        if let Some(prometheus) = &block.config.prometheus {
            if exporters
                .get(&prometheus.address)
                .is_some_and(|config| config != &prometheus.tls_config)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "conflicting prometheus TLS configuration",
                ));
            }
            exporters
                .entry(prometheus.address.clone())
                .or_insert_with(|| prometheus.tls_config.clone());
        }
        let keys = block.keys().to_vec();
        let addresses = block.listen_addresses.clone();
        let empty = pharos_server::Chain::is_empty(&block.config);
        lifecycle.extend(&block.config.lifecycle);
        let mut routes = Vec::new();
        for key in keys {
            if key.transport != "dns" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported Listener transport",
                ));
            }
            let port: u16 = key.port.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid Listener port")
            })?;
            let domain: pharos_proto::Name = key.domain.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid Listener Domain")
            })?;
            for address in &addresses {
                let socket = if address.is_empty() {
                    SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)
                } else if let Some((ip, interface)) = address.split_once('%') {
                    let ip: Ipv6Addr = ip.parse().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid Listener address")
                    })?;
                    // POSIX.1-2024 if_nametoindex: map an interface name to its index.
                    let scope = nix::net::if_::if_nametoindex(interface)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                    SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope))
                } else {
                    let ip: IpAddr = address.parse().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid Listener address")
                    })?;
                    let ip = match ip {
                        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
                        ip => ip,
                    };
                    SocketAddr::new(ip, port)
                };
                routes.push((
                    ListenerKey {
                        transport: Transport::Dns,
                        address: socket,
                    },
                    domain.clone(),
                ));
            }
        }
        #[cfg(feature = "plugin-loop")]
        if let Some(plugin) = &block.config.r#loop
            && let Some((listener, _)) = routes.first()
        {
            plugin.register(&mut lifecycle, listener.address);
        }
        #[cfg(feature = "plugin-cache")]
        if let Some(cache) = &mut block.config.cache {
            let listeners = routes.iter().map(|(key, _)| *key).collect::<Vec<_>>();
            cache.set_metrics(&metrics, &listeners);
        }
        #[cfg(feature = "plugin-multisocket")]
        let workers = block.config.multisocket.flatten();
        #[cfg(not(feature = "plugin-multisocket"))]
        let workers = None;
        let chain = Arc::new(block.config);
        #[cfg(feature = "plugin-cache")]
        if let Some(cache) = &chain.cache {
            cache.bind(&chain);
        }
        #[cfg(feature = "plugin-forward")]
        if chain.forward.is_some() {
            let chain = Arc::clone(&chain);
            lifecycle.register_sync(pharos_server::Phase::Shutdown, move || {
                if let Some(forward) = &chain.forward {
                    forward.stop();
                }
                Ok(())
            });
        }
        #[cfg(feature = "plugin-ready")]
        if chain.ready.is_some() {
            chain.collect_readiness(&ready_state);
        }
        for (listener, domain) in routes {
            groups
                .entry(listener)
                .or_insert_with(|| (Router::default(), workers))
                .0
                .add(
                    listener,
                    domain,
                    (!empty).then(|| Arc::clone(&chain)),
                    vec![],
                );
        }
    }
    let servers = groups
        .into_iter()
        .map(|(key, (router, workers))| {
            let mut server = Server::with_registry(router, key, metrics.clone());
            if let Some(workers) = workers {
                server.udp_workers = workers;
            }
            (key, server)
        })
        .collect();
    #[cfg(feature = "plugin-health")]
    for (address, lameduck) in health_addresses {
        let listener = Arc::new(std::sync::Mutex::new(
            None::<(
                pharos_server::http::Listener,
                pharos_server::http::HealthProbe,
            )>,
        ));
        let startup_listener = Arc::clone(&listener);
        let registry = metrics.clone();
        let start = move || {
            let address = address.clone();
            let listener = Arc::clone(&startup_listener);
            let registry = registry.clone();
            async move {
                if listener.lock().unwrap().is_some() {
                    return Ok(());
                }
                let server =
                    pharos_server::http::Listener::bind_with_methods(&address, |_, path| {
                        Some(if path == "/health" {
                            (200, "text/plain; charset=utf-8", "OK".into())
                        } else {
                            (
                                404,
                                "text/plain; charset=utf-8",
                                "404 page not found\n".into(),
                            )
                        })
                    })
                    .await?;
                let probe = pharos_server::http::HealthProbe::start(&address, registry);
                *listener.lock().unwrap() = Some((server, probe));
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Startup, start.clone());
        lifecycle.register(pharos_server::Phase::RestartFailed, start);
        let restart_listener = Arc::clone(&listener);
        lifecycle.register(pharos_server::Phase::Restart, move || {
            let server = restart_listener.lock().unwrap().take();
            async move {
                if let Some((server, probe)) = server {
                    drop(probe);
                    server.shutdown().await?;
                }
                Ok(())
            }
        });
        lifecycle.register(pharos_server::Phase::Shutdown, move || {
            let server = listener.lock().unwrap().take();
            async move {
                if let Some((server, probe)) = server {
                    tokio::time::sleep(lameduck).await;
                    drop(probe);
                    server.shutdown().await?;
                }
                Ok(())
            }
        });
    }
    #[cfg(feature = "plugin-ready")]
    for address in ready_addresses {
        let listener = Arc::new(std::sync::Mutex::new(None::<pharos_server::http::Listener>));
        let startup_listener = Arc::clone(&listener);
        let state = Arc::clone(&ready_state);
        let start = move || {
            let address = address.clone();
            let state = Arc::clone(&state);
            let listener = Arc::clone(&startup_listener);
            async move {
                if listener.lock().unwrap().is_some() {
                    return Ok(());
                }
                let server =
                    pharos_server::http::Listener::bind_with_status(&address, move |path| {
                        (path == "/ready").then(|| {
                            let (status, body) = state.response();
                            (status, "text/plain; charset=utf-8", body)
                        })
                    })
                    .await?;
                *listener.lock().unwrap() = Some(server);
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Startup, start.clone());
        lifecycle.register(pharos_server::Phase::RestartFailed, start);
        let stop = move || {
            let server = listener.lock().unwrap().take();
            async move {
                if let Some(server) = server {
                    server.shutdown().await?;
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Restart, stop.clone());
        lifecycle.register(pharos_server::Phase::Shutdown, stop);
    }
    #[cfg(feature = "plugin-prometheus")]
    for (address, tls_config) in exporters {
        let listener = Arc::new(std::sync::Mutex::new(None::<pharos_server::http::Listener>));
        let startup_listener = Arc::clone(&listener);
        let registry = metrics.clone();
        let start = move || {
            let address = address.clone();
            let tls_config = tls_config.clone();
            let registry = registry.clone();
            let listener = Arc::clone(&startup_listener);
            async move {
                if listener.lock().unwrap().is_some() {
                    return Ok(());
                }
                if tls_config.is_some() {
                    // shortcut: exporter-toolkit TLS and authentication require a compatible configuration implementation.
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "prometheus TLS configuration is not supported",
                    ));
                }
                let server = pharos_server::http::Listener::bind(&address, move |path| {
                    if path != "/metrics" {
                        return None;
                    }
                    let mut body = String::new();
                    registry.encode(&mut body);
                    Some(("text/plain; version=0.0.4; charset=utf-8", body))
                })
                .await?;
                *listener.lock().unwrap() = Some(server);
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Startup, start.clone());
        lifecycle.register(pharos_server::Phase::RestartFailed, start);
        let stop = move || {
            let server = listener.lock().unwrap().take();
            async move {
                if let Some(server) = server {
                    server.shutdown().await?;
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Restart, stop.clone());
        lifecycle.register(pharos_server::Phase::Shutdown, stop);
    }
    Ok((servers, lifecycle))
}

/// Placeholder for enabled but unimplemented Plugins, whose setup always fails.
#[derive(Debug)]
pub struct Unimplemented;

impl pharos_server::Plugin for Unimplemented {
    async fn serve<N: pharos_server::Next + Send>(
        &self,
        _cx: &mut pharos_server::Context<'_>,
        _next: N,
    ) -> pharos_server::Outcome {
        pharos_server::Outcome::Error(pharos_server::Error::NotImplemented)
    }
}

#[cfg(feature = "plugin-any")]
fn setup_any(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    cursor.next();
    if !cursor.remaining_args().is_empty() || cursor.next_block() {
        return Err(cursor.arg_err());
    }
    block.config.any = Some(any::Any);
    Ok(())
}

#[cfg(feature = "plugin-chaos")]
fn setup_chaos(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    block.config.chaos = Some(chaos::Chaos::parse(cursor)?);
    Ok(())
}

#[cfg(feature = "plugin-whoami")]
fn setup_whoami(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    cursor.next();
    if cursor.next_arg() {
        return Err(cursor.arg_err());
    }
    block.config.whoami = Some(whoami::Whoami);
    Ok(())
}

#[cfg(feature = "plugin-nsid")]
fn setup_nsid(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    block.config.nsid = Some(nsid::Nsid::parse(cursor)?);
    Ok(())
}

#[cfg(feature = "plugin-bufsize")]
fn setup_bufsize(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    block.config.bufsize = Some(bufsize::Bufsize::parse(cursor)?);
    Ok(())
}

#[cfg(feature = "plugin-loop")]
fn setup_loop(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    cursor.next();
    if cursor.next_arg() {
        return Err(cursor.arg_err());
    }
    let domain = block.keys().first().map_or(".", |key| key.domain.as_str());
    block.config.r#loop = Some(r#loop::Loop::new(domain));
    Ok(())
}

#[cfg(feature = "plugin-cache")]
fn setup_cache(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    let zones = block
        .keys()
        .iter()
        .map(|key| key.domain.clone())
        .collect::<Vec<_>>();
    block.config.cache = Some(cache::Cache::parse(cursor, &zones)?);
    Ok(())
}

#[cfg(feature = "plugin-log")]
fn setup_log(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    block.config.log = Some(log::parse(cursor)?);
    Ok(())
}

#[cfg(feature = "plugin-prometheus")]
fn setup_prometheus(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    block.config.prometheus = Some(prometheus::parse(cursor)?);
    Ok(())
}

#[cfg(feature = "plugin-ready")]
fn setup_ready(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    block.config.ready = Some(ready::parse(cursor)?);
    Ok(())
}

#[cfg(feature = "plugin-reload")]
fn setup_reload(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    block.config.reload = Some(reload::parse(cursor)?);
    Ok(())
}

#[cfg(feature = "plugin-bind")]
fn setup_bind(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    block.listen_addresses = bind::parse(cursor)?;
    block.config.bind = Some(());
    Ok(())
}

#[cfg(feature = "plugin-multisocket")]
fn setup_multisocket(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<Chain>,
) -> Result<(), Error> {
    cursor.next();
    let args = cursor.remaining_args();
    if args.len() > 1 || cursor.next() {
        return Err(cursor.arg_err());
    }
    let count = args
        .first()
        .map(|arg| {
            arg.parse::<usize>()
                .ok()
                .filter(|count| (1..=1024).contains(count))
                .ok_or_else(|| cursor.error("invalid socket count"))
        })
        .transpose()?;
    block.config.multisocket = Some(count);
    Ok(())
}

#[cfg(feature = "plugin-forward")]
fn setup_forward(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    block.config.forward = Some(forward::Forward::parse(cursor)?);
    Ok(())
}

#[cfg(feature = "plugin-health")]
fn setup_health(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    block.config.health = Some(health::parse(cursor)?);
    Ok(())
}

#[cfg(feature = "plugin-hosts")]
fn setup_hosts(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    let domains = block
        .keys()
        .iter()
        .map(|key| key.domain.as_str())
        .collect::<Vec<_>>();
    let hosts = hosts::Hosts::parse(cursor, &domains)?;
    hosts.register_hooks(&mut block.config.lifecycle);
    block.config.hosts = Some(hosts);
    Ok(())
}

#[cfg(feature = "plugin-loadbalance")]
fn setup_loadbalance(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<Chain>,
) -> Result<(), Error> {
    let plugin = loadbalance::LoadBalance::parse(cursor)?;
    plugin.register_hooks(&mut block.config.lifecycle);
    block.config.loadbalance = Some(plugin);
    Ok(())
}

#[cfg(feature = "plugin-errors")]
fn setup_errors(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    let plugin = errors::parse(cursor)?;
    plugin.register_shutdown(&mut block.config.lifecycle);
    block.config.errors = Some(plugin);
    Ok(())
}

#[allow(dead_code)]
fn setup_unimplemented(cursor: &mut Cursor<'_>, _: &mut BlockContext<Chain>) -> Result<(), Error> {
    cursor.next();
    Err(cursor.error(format!("{}: plugin is not implemented", cursor.val())))
}

#[cfg(feature = "plugin-kubernetes")]
fn setup_kubernetes(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    let domains = block
        .keys()
        .iter()
        .map(|key| key.domain.as_str())
        .collect::<Vec<_>>();
    let config = kubernetes::setup::parse(cursor, &domains)?;
    let plugin = kubernetes::Kubernetes::with_listen_addresses(config, &block.listen_addresses)
        .map_err(|error| cursor.error(error))?;
    plugin.register_hooks(&mut block.config.lifecycle);
    block.config.kubernetes = Some(plugin);
    Ok(())
}

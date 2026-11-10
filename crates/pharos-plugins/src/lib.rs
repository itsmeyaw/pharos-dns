#![forbid(unsafe_code)]
#![recursion_limit = "512"]
//! Plugins are enabled by `plugin-<directive>` Cargo features (underscores in
//! Directive names become hyphens). Log, prometheus and whoami are implemented; other enabled
//! Directives reject configuration rather than silently accepting it.

use pharos_corefile::{BlockContext, Cursor, Directive, Error};
use pharos_server::{Lifecycle, ListenerKey, Router, Server, Transport};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

#[cfg(feature = "plugin-health")]
pub mod health;
#[cfg(feature = "plugin-log")]
pub mod log;
#[cfg(feature = "plugin-log")]
pub mod log_format;
#[cfg(feature = "plugin-prometheus")]
pub mod prometheus;
#[cfg(feature = "plugin-ready")]
pub mod ready;
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
/// The caller runs Startup before serving and Shutdown after all Listeners drain.
pub fn servers(blocks: Vec<BlockContext<Chain>>) -> io::Result<(Servers, Lifecycle)> {
    let mut groups: HashMap<ListenerKey, Router<Arc<Chain>>> = HashMap::new();
    let mut lifecycle = Lifecycle::default();
    let metrics = pharos_server::metrics::Registry::default();
    #[cfg(feature = "plugin-prometheus")]
    let mut exporters = std::collections::BTreeMap::new();
    #[cfg(feature = "plugin-ready")]
    let ready_state = Arc::new(ready::State::default());
    #[cfg(feature = "plugin-ready")]
    let mut ready_addresses = std::collections::BTreeSet::new();
    #[cfg(feature = "plugin-health")]
    let mut health_addresses = std::collections::BTreeMap::new();
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
        #[cfg(feature = "plugin-health")]
        if let Some(health) = &block.config.health {
            health_addresses
                .entry(health.address.clone())
                .or_insert(health.lameduck);
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
        let chain = Arc::new(block.config);
        #[cfg(feature = "plugin-ready")]
        if chain.ready.is_some() {
            chain.collect_readiness(&ready_state);
        }
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
                let ip: IpAddr = if address.is_empty() {
                    Ipv4Addr::UNSPECIFIED.into()
                } else {
                    address.parse().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid Listener address")
                    })?
                };
                let listener = ListenerKey {
                    transport: Transport::Dns,
                    address: SocketAddr::new(ip, port),
                };
                groups.entry(listener).or_default().add(
                    listener,
                    domain.clone(),
                    (!empty).then(|| Arc::clone(&chain)),
                    vec![],
                );
            }
        }
    }
    let servers = groups
        .into_iter()
        .map(|(key, router)| (key, Server::with_registry(router, key, metrics.clone())))
        .collect();
    #[cfg(feature = "plugin-health")]
    for (address, lameduck) in health_addresses {
        let listener = Arc::new(std::sync::Mutex::new(None::<pharos_server::http::Listener>));
        let startup_listener = Arc::clone(&listener);
        lifecycle.register(pharos_server::Phase::Startup, move || {
            let address = address.clone();
            let listener = Arc::clone(&startup_listener);
            async move {
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
                *listener.lock().unwrap() = Some(server);
                Ok(())
            }
        });
        lifecycle.register(pharos_server::Phase::Shutdown, move || {
            let server = listener.lock().unwrap().take();
            async move {
                if let Some(server) = server {
                    tokio::time::sleep(lameduck).await;
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
        lifecycle.register(pharos_server::Phase::Startup, move || {
            let address = address.clone();
            let state = Arc::clone(&state);
            let listener = Arc::clone(&startup_listener);
            async move {
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
        });
        lifecycle.register(pharos_server::Phase::Shutdown, move || {
            let server = listener.lock().unwrap().take();
            async move {
                if let Some(server) = server {
                    server.shutdown().await?;
                }
                Ok(())
            }
        });
    }
    #[cfg(feature = "plugin-prometheus")]
    for (address, tls_config) in exporters {
        let listener = Arc::new(std::sync::Mutex::new(None::<pharos_server::http::Listener>));
        let startup_listener = Arc::clone(&listener);
        let registry = metrics.clone();
        lifecycle.register(pharos_server::Phase::Startup, move || {
            let address = address.clone();
            let tls_config = tls_config.clone();
            let registry = registry.clone();
            let listener = Arc::clone(&startup_listener);
            async move {
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
        });
        lifecycle.register(pharos_server::Phase::Shutdown, move || {
            let server = listener.lock().unwrap().take();
            async move {
                if let Some(server) = server {
                    server.shutdown().await?;
                }
                Ok(())
            }
        });
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

#[cfg(feature = "plugin-whoami")]
fn setup_whoami(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    cursor.next();
    if cursor.next_arg() {
        return Err(cursor.arg_err());
    }
    block.config.whoami = Some(whoami::Whoami);
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

#[cfg(feature = "plugin-health")]
fn setup_health(cursor: &mut Cursor<'_>, block: &mut BlockContext<Chain>) -> Result<(), Error> {
    block.config.health = Some(health::parse(cursor)?);
    Ok(())
}

#[allow(dead_code)]
fn setup_unimplemented(cursor: &mut Cursor<'_>, _: &mut BlockContext<Chain>) -> Result<(), Error> {
    cursor.next();
    Err(cursor.error(format!("{}: plugin is not implemented", cursor.val())))
}

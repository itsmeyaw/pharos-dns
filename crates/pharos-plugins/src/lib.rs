#![forbid(unsafe_code)]
#![recursion_limit = "512"]
//! Plugins are enabled by `plugin-<directive>` Cargo features (underscores in
//! Directive names become hyphens). Log and whoami are implemented; other enabled
//! Directives reject configuration rather than silently accepting it.

use pharos_corefile::{BlockContext, Cursor, Directive, Error};
use pharos_server::{Lifecycle, ListenerKey, Router, Server, Transport};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

#[cfg(feature = "plugin-log")]
pub mod log;
#[cfg(feature = "plugin-log")]
pub mod log_format;
#[cfg(feature = "plugin-whoami")]
pub mod whoami;

include!(concat!(env!("OUT_DIR"), "/plugins.rs"));

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
    for block in blocks {
        let keys = block.keys().to_vec();
        let addresses = block.listen_addresses.clone();
        let empty = pharos_server::Chain::is_empty(&block.config);
        lifecycle.extend(&block.config.lifecycle);
        let chain = Arc::new(block.config);
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
    Ok((
        groups
            .into_iter()
            .map(|(key, router)| (key, Server::with_registry(router, key, metrics.clone())))
            .collect(),
        lifecycle,
    ))
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

#[allow(dead_code)]
fn setup_unimplemented(cursor: &mut Cursor<'_>, _: &mut BlockContext<Chain>) -> Result<(), Error> {
    cursor.next();
    Err(cursor.error(format!("{}: plugin is not implemented", cursor.val())))
}

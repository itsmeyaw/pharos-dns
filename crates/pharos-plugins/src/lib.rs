#![forbid(unsafe_code)]
#![recursion_limit = "512"]
//! Plugins are enabled by `plugin-<directive>` Cargo features (underscores in
//! Directive names become hyphens). Only whoami is implemented; other enabled
//! Directives reject configuration rather than silently accepting it.

use pharos_corefile::{BlockContext, Cursor, Directive, Error};

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

#[allow(dead_code)]
fn setup_unimplemented(cursor: &mut Cursor<'_>, _: &mut BlockContext<Chain>) -> Result<(), Error> {
    cursor.next();
    Err(cursor.error(format!("{}: plugin is not implemented", cursor.val())))
}

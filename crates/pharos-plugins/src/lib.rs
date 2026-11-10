#![forbid(unsafe_code)]
//! Plugins are enabled by `plugin-<directive>` Cargo features (underscores in
//! Directive names become hyphens). Only whoami is implemented; other enabled
//! Directives reject configuration rather than silently accepting it.

use pharos_corefile::{BlockContext, Cursor, Directive, Error};

include!(concat!(env!("OUT_DIR"), "/plugins.rs"));

/// Directive registry in Plugin Order.
#[must_use]
pub fn directives() -> &'static [Directive<'static, Vec<Plugin>>] {
    DIRECTIVES
}

/// CoreDNS-style alphabetically sorted plugin listing, including final blank line.
#[must_use]
pub const fn plugins_listing() -> &'static str {
    PLUGINS_LISTING
}

#[cfg(feature = "plugin-whoami")]
fn setup_whoami(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<Vec<Plugin>>,
) -> Result<(), Error> {
    cursor.next();
    if cursor.next_arg() {
        return Err(cursor.arg_err());
    }
    block.config.push(Plugin::Whoami);
    Ok(())
}

#[allow(dead_code)]
fn setup_unimplemented(
    cursor: &mut Cursor<'_>,
    _: &mut BlockContext<Vec<Plugin>>,
) -> Result<(), Error> {
    cursor.next();
    Err(cursor.error(format!("{}: plugin is not implemented", cursor.val())))
}

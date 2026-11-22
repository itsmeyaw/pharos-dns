//! Serve A, AAAA and SRV records for services registered with Nomad.

pub(crate) mod setup;

use pharos_server::{Context, Next, Outcome, Plugin};

/// CoreDNS v1.15.0 plugin/nomad/nomad.go `defaultTTL`: seconds a Response record lives unless `ttl` says otherwise.
const DEFAULT_TTL: u32 = 30;

/// CoreDNS v1.15.0 plugin/nomad/setup.go `parse`: the values one `nomad` Directive configures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Settings {
    pub(crate) zone: String,
    pub(crate) ttl: u32,
    pub(crate) filter: String,
    pub(crate) token: Option<String>,
    pub(crate) addresses: Vec<String>,
}

/// One `nomad` Directive.
#[derive(Debug)]
pub struct Nomad {
    settings: Settings,
}

impl Nomad {
    pub(crate) fn new(settings: Settings) -> Self {
        Self { settings }
    }
}

impl Plugin for Nomad {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        next.run(cx).await
    }
}

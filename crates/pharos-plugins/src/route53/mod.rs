//! Authoritative Zones served from AWS Route 53 hosted zones.

pub(crate) mod setup;

use pharos_corefile::Fallthrough;
use pharos_server::{Context, Next, Outcome, Plugin};
use std::{path::PathBuf, time::Duration};

/// A secret that stays out of `Debug` output.
#[derive(Clone, Eq, PartialEq)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// One `route53` stanza as written in the Corefile; parsing never touches the network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// `ZONE:HOSTED_ZONE_ID` arguments grouped by ZONE in first-seen order.
    pub zones: Vec<(String, Vec<String>)>,
    /// `aws_access_key ID SECRET` (deprecated).
    pub access_key: Option<(String, Secret)>,
    /// `aws_endpoint URL`.
    pub endpoint: Option<String>,
    /// `credentials PROFILE`.
    pub profile: Option<String>,
    /// `credentials PROFILE FILE`, plus `~/.aws/config` when `AWS_SDK_LOAD_CONFIG` is truthy; `None` keeps the SDK default.
    pub shared_config_files: Option<Vec<PathBuf>>,
    pub fallthrough: Fallthrough,
    pub refresh: Duration,
}

/// The `route53` Plugin; serving Route 53 data is not wired yet, so a Query passes to the next Plugin.
#[derive(Debug)]
pub struct Route53;

impl Plugin for Route53 {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        next.run(cx).await
    }
}

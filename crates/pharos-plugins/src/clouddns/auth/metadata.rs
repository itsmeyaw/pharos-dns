//! The GCE metadata server as a token source (Google ADC's last resort).

use std::time::Duration;

use super::{
    oauth::fetch_token,
    token::{AuthError, Fetched},
};
use crate::clouddns::http::{Http, Request, form_encode};

// cloud.google.com/go/compute/metadata v0.10.0: the documented, stable metadata server address.
const METADATA_IP: &str = "169.254.169.254";

// Unlike a Google API, the metadata server is on the local network: fail fast when it is absent.
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(crate) struct Metadata {
    host: String,
    scopes: String,
}

impl Metadata {
    /// `host` is `GCE_METADATA_HOST` (cloud.google.com/go/compute/metadata metadataHostEnv), when set and non-empty.
    pub(super) fn new(host: Option<&str>, scopes: &[&str]) -> Self {
        Self {
            host: host
                .filter(|host| !host.is_empty())
                .unwrap_or(METADATA_IP)
                .to_owned(),
            scopes: scopes.join(","),
        }
    }

    pub(crate) async fn fetch(&self, http: &Http) -> Result<Fetched, AuthError> {
        // cloud.google.com/go/auth credentials/compute.go: GET instance/service-accounts/default/token?scopes=a,b.
        let query = form_encode(&[("scopes", &self.scopes)]);
        let url = format!(
            "http://{}/computeMetadata/v1/instance/service-accounts/default/token?{query}",
            self.host
        );
        // cloud.google.com/go/compute/metadata getETag: the Metadata-Flavor header is required.
        let request = Request::get(&url)
            .timeout(TIMEOUT)
            .header("metadata-flavor", "Google")
            .map_err(|error| AuthError::new(error.to_string()))?;
        let fetched = fetch_token(http, request)
            .await
            .map_err(|error| error.within("GCE metadata server"))?;
        // cloud.google.com/go/auth computeProvider.Token: a token without a lifetime is "incomplete".
        if fetched.lifetime.is_none() {
            return Err(AuthError::new("incomplete token received").within("GCE metadata server"));
        }
        Ok(fetched)
    }
}

#[cfg(test)]
mod tests;

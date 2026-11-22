//! Application Default Credentials (Google ADC), as `google.FindDefaultCredentials` orders them.

use std::path::PathBuf;

use super::{
    DNS_SCOPES, Provider,
    metadata::Metadata,
    token::{AuthError, TokenSource},
};
use crate::clouddns::http::Http;

const ADC_ENV: &str = "GOOGLE_APPLICATION_CREDENTIALS";
const METADATA_HOST_ENV: &str = "GCE_METADATA_HOST";

/// The process environment ADC consults, as a value so tests need not mutate the real one.
#[derive(Clone, Debug, Default)]
pub(crate) struct Environment {
    pub google_application_credentials: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub gce_metadata_host: Option<String>,
}

impl Environment {
    pub(crate) fn from_process() -> Self {
        let var = |name| std::env::var_os(name).filter(|value| !value.is_empty());
        Self {
            google_application_credentials: var(ADC_ENV).map(PathBuf::from),
            home: var("HOME").map(PathBuf::from),
            gce_metadata_host: var(METADATA_HOST_ENV).and_then(|host| host.into_string().ok()),
        }
    }
}

impl TokenSource {
    /// Google ADC: `GOOGLE_APPLICATION_CREDENTIALS`, then the gcloud well-known file, then the GCE metadata server.
    ///
    /// cloud.google.com/go/auth DetectDefault asks `OnGCE()` before the last step; this does not probe, so a host
    /// with no credentials at all fails on the first token fetch instead.
    pub(crate) fn discover(env: &Environment, http: Http) -> Result<Self, AuthError> {
        if let Some(path) = &env.google_application_credentials {
            // An explicit path that cannot be used is an error, not a reason to try the next step.
            return Self::from_file(path, http)
                .map_err(|error| error.within(&format!("{ADC_ENV} {}", path.display())));
        }
        if let Some(home) = &env.home {
            let well_known = home
                .join(".config")
                .join("gcloud")
                .join("application_default_credentials.json");
            // cloud.google.com/go/auth DetectDefault: an unreadable well-known file means "not there".
            if let Ok(data) = std::fs::read(&well_known) {
                return Self::from_json(&data, http)
                    .map_err(|error| error.within(&format!("{}", well_known.display())));
            }
        }
        let metadata = Metadata::new(env.gce_metadata_host.as_deref(), &DNS_SCOPES);
        Ok(Self::new(Provider::Metadata(metadata), http))
    }
}

#[cfg(test)]
mod tests;

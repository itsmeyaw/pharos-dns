//! Google credentials: credential files, Application Default Credentials and cached access tokens.

mod adc;
mod authorized_user;
mod external_account;
mod file;
mod impersonated;
mod metadata;
mod oauth;
mod service_account;
mod token;

use std::fmt;

use token::Fetched;

pub(crate) use adc::Environment;
pub(crate) use file::{CredentialType, credential_type};
pub(crate) use oauth::{error_code, json_error};
pub(crate) use token::{AccessToken, AuthError, TokenSource};

use super::http::Http;

// Google OAuth 2.0: the token endpoint credential files fall back to.
const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

// google.golang.org/api v0.301.0 dns/v1 NewService: the default scopes the CoreDNS client asks for.
const DNS_SCOPES: [&str; 4] = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/cloud-platform.read-only",
    "https://www.googleapis.com/auth/ndev.clouddns.readonly",
    "https://www.googleapis.com/auth/ndev.clouddns.readwrite",
];

/// Where an access token comes from.
pub(crate) enum Provider {
    ServiceAccount(service_account::ServiceAccount),
    AuthorizedUser(authorized_user::AuthorizedUser),
    Metadata(metadata::Metadata),
    Impersonated(impersonated::Impersonated),
    ExternalAccount(external_account::ExternalAccount),
}

impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServiceAccount(source) => source.fmt(f),
            Self::AuthorizedUser(source) => source.fmt(f),
            Self::Metadata(source) => source.fmt(f),
            Self::Impersonated(source) => source.fmt(f),
            Self::ExternalAccount(source) => source.fmt(f),
        }
    }
}

impl Provider {
    pub(crate) async fn fetch(&self, http: &Http) -> Result<Fetched, AuthError> {
        match self {
            Self::ServiceAccount(source) => source.fetch(http).await,
            Self::AuthorizedUser(source) => source.fetch(http).await,
            Self::Metadata(source) => source.fetch(http).await,
            Self::Impersonated(source) => source.fetch(http).await,
            Self::ExternalAccount(source) => source.fetch(http).await,
        }
    }
}

#[cfg(test)]
pub(crate) mod testing;

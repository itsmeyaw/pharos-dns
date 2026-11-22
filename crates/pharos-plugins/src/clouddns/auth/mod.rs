//! Google credentials: credential files, Application Default Credentials and cached access tokens.

mod authorized_user;
mod metadata;
mod oauth;
mod service_account;
mod token;

use std::fmt;

use token::{AuthError, Fetched};

pub(crate) use token::TokenSource;

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
}

impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServiceAccount(source) => source.fmt(f),
            Self::AuthorizedUser(source) => source.fmt(f),
            Self::Metadata(source) => source.fmt(f),
        }
    }
}

impl Provider {
    pub(crate) async fn fetch(&self, http: &Http) -> Result<Fetched, AuthError> {
        match self {
            Self::ServiceAccount(source) => source.fetch(http).await,
            Self::AuthorizedUser(source) => source.fetch(http).await,
            Self::Metadata(source) => source.fetch(http).await,
        }
    }
}

#[cfg(test)]
mod testing;

//! Values every credential source shares: secrets that never print, errors that never echo, and the token cache.

use std::{fmt, sync::Arc, time::Duration};

use tokio::{sync::Mutex, time::Instant};

use super::Provider;
use crate::clouddns::http::Http;

// Google cloud.google.com/go/auth v0.24 defaultExpiryDelta: a token is refreshed when it expires within 225 s.
const EXPIRY_MARGIN: Duration = Duration::from_secs(225);

/// A string that must not reach logs, errors or `Debug` output.
#[derive(Clone, Default)]
pub(crate) struct Secret(String);

impl Secret {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<'de> serde::Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

/// An OAuth 2.0 access token (RFC 6749 §1.4).
#[derive(Clone, Debug)]
pub(crate) struct AccessToken(Secret);

impl AccessToken {
    pub(crate) fn as_str(&self) -> &str {
        self.0.expose()
    }
}

/// Why a token could not be had. The text carries a source name, an HTTP status and a sanitized OAuth error
/// code at most: never a request body, header, token or key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthError(String);

impl AuthError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// Prefix the message with the credential source that failed.
    pub(crate) fn within(self, source: &str) -> Self {
        Self(format!("{source}: {}", self.0))
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AuthError {}

/// What a credential source returns: the token and how long it lives (`None` = no stated expiry).
pub(crate) struct Fetched {
    pub token: Secret,
    pub lifetime: Option<Duration>,
}

#[derive(Debug)]
struct Cached {
    token: AccessToken,
    expires_at: Option<Instant>,
}

impl Cached {
    // cloud.google.com/go/auth Token.isValidWithEarlyExpiry: no expiry means valid; else valid until expiry - margin.
    fn is_fresh(&self, margin: Duration) -> bool {
        self.expires_at
            .is_none_or(|expires_at| Instant::now() + margin < expires_at)
    }

    fn is_alive(&self) -> bool {
        self.expires_at
            .is_none_or(|expires_at| Instant::now() < expires_at)
    }
}

struct Shared {
    provider: Provider,
    http: Http,
    margin: Duration,
    cached: Mutex<Option<Cached>>,
}

/// Hands out access tokens, fetching one only when the cached token expires within the margin.
/// Cloning shares the cache. Only the background refresh task calls `token`, never the Query path.
#[derive(Clone)]
pub(crate) struct TokenSource(Arc<Shared>);

impl fmt::Debug for TokenSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TokenSource")
            .field(&self.0.provider)
            .finish()
    }
}

impl TokenSource {
    pub(crate) fn new(provider: Provider, http: Http) -> Self {
        Self::with_margin(provider, http, EXPIRY_MARGIN)
    }

    pub(crate) fn with_margin(provider: Provider, http: Http, margin: Duration) -> Self {
        Self(Arc::new(Shared {
            provider,
            http,
            margin,
            cached: Mutex::new(None),
        }))
    }

    /// A valid access token; concurrent callers share one fetch because the cache lock is held across it.
    pub(crate) async fn token(&self) -> Result<AccessToken, AuthError> {
        let mut cached = self.0.cached.lock().await;
        if let Some(cached) = cached
            .as_ref()
            .filter(|cached| cached.is_fresh(self.0.margin))
        {
            return Ok(cached.token.clone());
        }
        match self.0.provider.fetch(&self.0.http).await {
            Ok(fetched) => {
                let token = AccessToken(fetched.token);
                *cached = Some(Cached {
                    token: token.clone(),
                    expires_at: fetched.lifetime.map(|lifetime| Instant::now() + lifetime),
                });
                Ok(token)
            }
            // cloud.google.com/go/auth cachedTokenProvider: a stale token is still served while it has not expired.
            Err(error) => cached
                .as_ref()
                .filter(|cached| cached.is_alive())
                .map(|cached| cached.token.clone())
                .ok_or(error),
        }
    }
}

#[cfg(test)]
mod tests;

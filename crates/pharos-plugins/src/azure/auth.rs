//! Azure AD access tokens: client credentials, and managed identity (MSI) on IMDS, App Service and Cloud Shell.

use std::{
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use hyper::Method;
use serde_json::Value;

use super::{
    config::{Config, Environment, Secret},
    http::{Call, Http, Url, percent_encode},
};

/// go-autorest v0.11.30 autorest/adal/token.go `defaultRefresh`: a token expiring within five minutes is refreshed.
const REFRESH_WITHIN: Duration = Duration::from_secs(5 * 60);
/// A failing endpoint's body is quoted in errors only up to this many bytes.
pub(super) const QUOTED_BODY: usize = 512;
/// go-autorest v0.11.30 autorest/adal/token.go `msiEndpoint`.
const IMDS_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";

/// Where Resource Manager and Active Directory live; tests point these at local stubs.
#[derive(Clone, Debug)]
pub(super) struct Endpoints {
    pub resource_manager: String,
    pub active_directory: String,
    pub imds: String,
}

impl Endpoints {
    /// go-autorest v0.11.30 autorest/azure/environments.go: each cloud has its own endpoints.
    pub(super) fn for_environment(environment: Environment) -> Self {
        Self {
            resource_manager: environment.resource_manager_endpoint().to_owned(),
            active_directory: environment.active_directory_endpoint().to_owned(),
            imds: IMDS_ENDPOINT.to_owned(),
        }
    }
}

/// How a token is obtained.
#[derive(Debug)]
enum Source {
    /// go-autorest v0.11.30 autorest/azure/auth/auth.go `GetClientCredentials`.
    ClientCredentials {
        url: Url,
        client: String,
        secret: Secret,
    },
    /// go-autorest v0.11.30 autorest/adal/token.go `msiTypeAppServiceV20170901`.
    AppService {
        url: Url,
        client: String,
        secret: Secret,
    },
    /// go-autorest v0.11.30 autorest/adal/token.go `msiTypeCloudShell`.
    CloudShell { url: Url, client: String },
    /// go-autorest v0.11.30 autorest/adal/token.go `msiTypeIMDS`.
    Imds { url: Url, client: String },
}

#[derive(Debug)]
struct Cached {
    token: Secret,
    expires: Instant,
}

/// Fetches and caches the bearer token for Resource Manager; only the sync task asks for it.
#[derive(Debug)]
pub(super) struct TokenSource {
    method: Source,
    /// The `resource` parameter: the Resource Manager endpoint as configured.
    resource: String,
    cached: Mutex<Option<Cached>>,
}

impl TokenSource {
    /// go-autorest v0.11.30 autorest/azure/auth/auth.go `GetAuthorizer`: a client secret selects client credentials, else MSI.
    ///
    /// `env` answers `MSI_ENDPOINT` and `MSI_SECRET`; no request is made here.
    pub(super) fn new(
        config: &Config,
        endpoints: &Endpoints,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, String> {
        let parse = |text: &str| {
            text.parse::<Url>()
                .map_err(|()| format!("invalid endpoint {text:?}"))
        };
        let method = if !config.secret.expose().is_empty() {
            // adal config.go NewOAuthConfig: `{AAD endpoint}{tenant}/oauth2/token?api-version=1.0`.
            let base = endpoints.active_directory.trim_end_matches('/');
            let tenant = percent_encode(&config.tenant, false);
            let path = if tenant.is_empty() {
                String::new()
            } else {
                format!("/{tenant}")
            };
            Source::ClientCredentials {
                url: parse(&format!("{base}{path}/oauth2/token?api-version=1.0"))?,
                client: config.client.clone(),
                secret: config.secret.clone(),
            }
        } else {
            // adal token.go getMSIType: MSI_ENDPOINT with MSI_SECRET is App Service, alone is Cloud Shell, neither is IMDS.
            let endpoint = env("MSI_ENDPOINT").filter(|value| !value.is_empty());
            let secret = env("MSI_SECRET").filter(|value| !value.is_empty());
            match (endpoint, secret) {
                (Some(endpoint), Some(secret)) => Source::AppService {
                    url: parse(&endpoint)?,
                    client: config.client.clone(),
                    secret: Secret::new(secret),
                },
                (Some(endpoint), None) => Source::CloudShell {
                    url: parse(&endpoint)?,
                    client: config.client.clone(),
                },
                (None, _) => Source::Imds {
                    url: parse(&endpoints.imds)?,
                    client: config.client.clone(),
                },
            }
        };
        Ok(Self {
            method,
            resource: endpoints.resource_manager.clone(),
            cached: Mutex::new(None),
        })
    }

    /// A bearer token that stays valid for at least five more minutes, fetched when the cached one does not.
    pub(super) async fn token(&self, http: &Http) -> Result<Secret, String> {
        // adal token.go `WillExpireIn(defaultRefresh)`: reuse a token unless it expires within five minutes.
        if let Some(cached) = self.cached.lock().unwrap().as_ref()
            && cached.expires > Instant::now() + REFRESH_WITHIN
        {
            return Ok(cached.token.clone());
        }
        let fresh = self.fetch(http).await?;
        let token = fresh.token.clone();
        *self.cached.lock().unwrap() = Some(fresh);
        Ok(token)
    }

    /// Removes the client secret and the cached token from text bound for logs or errors.
    pub(super) fn scrub(&self, mut text: String) -> String {
        let mut hide = |secret: &str| {
            if !secret.is_empty() && text.contains(secret) {
                text = text.replace(secret, "<redacted>");
            }
        };
        match &self.method {
            Source::ClientCredentials { secret, .. } | Source::AppService { secret, .. } => {
                hide(secret.expose());
            }
            _ => {}
        }
        if let Some(cached) = self.cached.lock().unwrap().as_ref() {
            hide(cached.token.expose());
        }
        text
    }

    async fn fetch(&self, http: &Http) -> Result<Cached, String> {
        let resource = percent_encode(&self.resource, true);
        let form = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(key, value)| format!("{key}={}", percent_encode(value, true)))
                .collect::<Vec<_>>()
                .join("&")
        };
        let response = match &self.method {
            Source::ClientCredentials {
                url,
                client,
                secret,
            } => {
                // adal token.go refreshInternal: POST a form of client_id, client_secret, grant_type and resource.
                let body = form(&[
                    ("client_id", client),
                    ("client_secret", secret.expose()),
                    ("grant_type", "client_credentials"),
                    ("resource", &self.resource),
                ]);
                http.request(
                    url,
                    Call {
                        method: Method::POST,
                        headers: &[],
                        body: Some(("application/x-www-form-urlencoded", body.into_bytes())),
                    },
                )
                .await
            }
            Source::AppService {
                url,
                client,
                secret,
            } => {
                // adal token.go newServicePrincipalTokenFromMSI: App Service takes `clientid` and a `secret` header over GET.
                let mut query = String::from("api-version=2017-09-01&");
                if !client.is_empty() {
                    query.push_str(&format!("clientid={}&", percent_encode(client, true)));
                }
                query.push_str(&format!("resource={resource}"));
                http.request(
                    &with_query(url, &query),
                    Call::get(&[("secret", secret.expose())]),
                )
                .await
            }
            Source::CloudShell { url, client } => {
                // adal token.go refreshInternal: Cloud Shell POSTs `client_id` and `resource` as a form with `Metadata: true`.
                let mut pairs = Vec::with_capacity(2);
                if !client.is_empty() {
                    pairs.push(("client_id", client.as_str()));
                }
                pairs.push(("resource", self.resource.as_str()));
                http.request(
                    url,
                    Call {
                        method: Method::POST,
                        headers: &[("metadata", "true")],
                        body: Some((
                            "application/x-www-form-urlencoded",
                            form(&pairs).into_bytes(),
                        )),
                    },
                )
                .await
            }
            Source::Imds { url, client } => {
                // adal token.go newServicePrincipalTokenFromMSI: IMDS takes `api-version`, `client_id` and `resource` over GET.
                let mut query = String::from("api-version=2018-02-01&");
                if !client.is_empty() {
                    query.push_str(&format!("client_id={}&", percent_encode(client, true)));
                }
                query.push_str(&format!("resource={resource}"));
                http.request(&with_query(url, &query), Call::get(&[("metadata", "true")]))
                    .await
            }
        };
        let response =
            response.map_err(|error| self.scrub(format!("token request failed: {error}")))?;
        // adal token.go refreshInternal: only 200 carries a token.
        // The body is left out: an error page may echo the form with the secret percent-encoded, which `scrub` cannot match.
        if response.status != 200 {
            return Err(format!(
                "token endpoint returned status {}",
                response.status
            ));
        }
        // adal token.go refreshInternal: the body is JSON with `access_token`, `expires_in` and `expires_on`.
        let json: Value = serde_json::from_slice(&response.body)
            .map_err(|_| "token response is not valid JSON".to_owned())?;
        let token = json
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or("token response has no access_token")?;
        Ok(Cached {
            token: Secret::new(token),
            expires: expiry(&json),
        })
    }
}

fn with_query(url: &Url, query: &str) -> Url {
    let path = url.target.split('?').next().unwrap_or("/");
    url.with_target(format!("{path}?{query}"))
}

/// adal token.go `parseExpiresOn`: `expires_on` is epoch seconds as a number or string; AAD sends `expires_in` as a string, ADFS as a number.
fn expiry(json: &Value) -> Instant {
    let seconds = |key: &str| match json.get(key)? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    };
    let now = Instant::now();
    if let Some(on) = seconds("expires_on") {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        return now + Duration::from_secs(on.saturating_sub(epoch));
    }
    match seconds("expires_in") {
        Some(seconds) => now + Duration::from_secs(seconds),
        // A token without an expiry is used once.
        None => now,
    }
}

/// An error body, cut to `QUOTED_BODY` bytes with control characters flattened so a hostile endpoint cannot forge log lines.
pub(super) fn quote(body: &[u8]) -> String {
    let cut = &body[..body.len().min(QUOTED_BODY)];
    String::from_utf8_lossy(cut)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

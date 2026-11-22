//! `external_account` credentials (workload identity federation): a subject token read from a file or a URL is
//! exchanged at the Security Token Service (RFC 8693).

use std::{collections::HashMap, fmt, io::Read};

use serde::Deserialize;
use serde_json::Value;

use super::{
    oauth::{fetch_token, send},
    token::{AuthError, Fetched, Secret},
};
use crate::clouddns::http::{Http, Request};

// Google STS: the token endpoint credential files fall back to.
const DEFAULT_TOKEN_URL: &str = "https://sts.googleapis.com/v1/token";

// RFC 8693 §2.1 and §3: the grant type, and the requested token type of an access token.
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const REQUESTED_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

// A subject token is a JWT or a SAML assertion; bound it against a runaway file or URL.
const MAX_SUBJECT_TOKEN: u64 = 1 << 20;

#[derive(Deserialize)]
pub(super) struct File {
    audience: Option<String>,
    subject_token_type: Option<String>,
    token_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<Secret>,
    credential_source: Option<CredentialSource>,
    workforce_pool_user_project: Option<String>,
    pub service_account_impersonation_url: Option<String>,
    service_account_impersonation: Option<Impersonation>,
}

#[derive(Deserialize)]
struct Impersonation {
    token_lifetime_seconds: Option<u64>,
}

#[derive(Deserialize)]
struct CredentialSource {
    file: Option<String>,
    url: Option<String>,
    headers: Option<HashMap<String, Secret>>,
    format: Option<FormatFile>,
    environment_id: Option<String>,
    executable: Option<Value>,
    certificate: Option<Value>,
}

#[derive(Deserialize)]
struct FormatFile {
    #[serde(rename = "type")]
    kind: Option<String>,
    subject_token_field_name: Option<String>,
}

#[derive(Debug)]
enum Format {
    Text,
    Json { field: String },
}

#[derive(Debug)]
enum Subject {
    File {
        path: String,
        format: Format,
    },
    Url {
        url: String,
        headers: Vec<(String, Secret)>,
        format: Option<Format>,
    },
}

pub(crate) struct ExternalAccount {
    audience: String,
    subject_token_type: String,
    token_url: String,
    client_id: String,
    client_secret: Secret,
    subject: Subject,
    scope: String,
    user_project: Option<String>,
    pub(super) lifetime_seconds: Option<u64>,
}

impl fmt::Debug for ExternalAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalAccount")
            .field("audience", &self.audience)
            .field("token_url", &self.token_url)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl ExternalAccount {
    /// `scopes` are what the STS exchange asks for: the DNS scopes, or cloud-platform when impersonating.
    pub(super) fn from_file(file: File, scopes: &[&str]) -> Result<Self, AuthError> {
        let required = |value: Option<String>, field: &str| {
            value.filter(|value| !value.is_empty()).ok_or_else(|| {
                AuthError::new(format!("external_account credentials have no {field}"))
            })
        };
        // cloud.google.com/go/auth externalaccount Options.validate: audience, subject token type and a source.
        let audience = required(file.audience, "audience")?;
        let subject_token_type = required(file.subject_token_type, "subject_token_type")?;
        let source = file.credential_source.ok_or_else(|| {
            AuthError::new("external_account credentials have no credential_source")
        })?;
        Ok(Self {
            audience,
            subject_token_type,
            token_url: file
                .token_url
                .filter(|url| !url.is_empty())
                .unwrap_or_else(|| DEFAULT_TOKEN_URL.to_owned()),
            client_id: file.client_id.unwrap_or_default(),
            client_secret: file.client_secret.unwrap_or_default(),
            subject: Subject::from_source(source)?,
            scope: scopes.join(" "),
            user_project: file
                .workforce_pool_user_project
                .filter(|project| !project.is_empty()),
            lifetime_seconds: file
                .service_account_impersonation
                .and_then(|impersonation| impersonation.token_lifetime_seconds),
        })
    }

    pub(crate) async fn fetch(&self, http: &Http) -> Result<Fetched, AuthError> {
        let subject_token = self
            .subject
            .token(http)
            .await
            .map_err(|error| error.within("subject token"))?;
        // RFC 8693 §2.1: the token exchange request parameters.
        let mut fields = vec![
            ("audience", self.audience.as_str()),
            ("grant_type", GRANT_TYPE),
            ("requested_token_type", REQUESTED_TOKEN_TYPE),
            ("subject_token_type", self.subject_token_type.as_str()),
            ("subject_token", subject_token.expose()),
            ("scope", self.scope.as_str()),
        ];
        // cloud.google.com/go/auth externalaccount tokenProvider.Token: workforce pools bill a user project.
        let options = self
            .user_project
            .as_ref()
            .filter(|_| self.client_id.is_empty())
            .map(|project| serde_json::json!({"userProject": project}).to_string());
        if let Some(options) = &options {
            fields.push(("options", options));
        }
        let mut request = Request::post_form(&self.token_url, &fields);
        // RFC 6749 §2.3.1: client authentication with HTTP Basic, as cloud.google.com/go/auth StyleInHeader does.
        if !self.client_id.is_empty() && !self.client_secret.is_empty() {
            request = request
                .basic(&self.client_id, self.client_secret.expose())
                .map_err(|error| AuthError::new(error.to_string()))?;
        }
        let fetched = fetch_token(http, request)
            .await
            .map_err(|error| error.within("security token service"))?;
        // cloud.google.com/go/auth externalaccount tokenProvider.Token: a non-positive expires_in is invalid.
        if fetched.lifetime.is_none() {
            return Err(AuthError::new("response has an invalid expires_in")
                .within("security token service"));
        }
        Ok(fetched)
    }
}

impl Subject {
    // cloud.google.com/go/auth externalaccount newSubjectTokenProvider: aws, file, url, executable, certificate.
    fn from_source(source: CredentialSource) -> Result<Self, AuthError> {
        let unsupported =
            |kind: &str| AuthError::new(format!("unsupported credential_source: {kind}"));
        if source
            .environment_id
            .as_deref()
            .is_some_and(|id| id.starts_with("aws"))
        {
            return Err(unsupported("aws"));
        }
        let format = source.format.map(Format::from_file).transpose()?;
        if let Some(path) = source.file.filter(|path| !path.is_empty()) {
            return Ok(Self::File {
                path,
                format: format.unwrap_or(Format::Text),
            });
        }
        if let Some(url) = source.url.filter(|url| !url.is_empty()) {
            let mut headers: Vec<_> = source.headers.unwrap_or_default().into_iter().collect();
            headers.sort_by(|a, b| a.0.cmp(&b.0));
            return Ok(Self::Url {
                url,
                headers,
                format,
            });
        }
        if source.executable.is_some() {
            return Err(unsupported("executable"));
        }
        if source.certificate.is_some() {
            return Err(unsupported("certificate"));
        }
        Err(AuthError::new("unable to parse credential_source"))
    }

    async fn token(&self, http: &Http) -> Result<Secret, AuthError> {
        match self {
            Self::File { path, format } => {
                let path = path.clone();
                let bytes = tokio::task::spawn_blocking(move || read_bounded(&path))
                    .await
                    .map_err(|_| AuthError::new("cannot read the credential file"))??;
                // cloud.google.com/go/auth fileSubjectProvider: the file content is trimmed.
                format.extract(String::from_utf8_lossy(&bytes).trim())
            }
            Self::Url {
                url,
                headers,
                format,
            } => {
                let mut request = Request::get(url);
                for (name, value) in headers {
                    request = request
                        .header(name, value.expose())
                        .map_err(|error| AuthError::new(error.to_string()))?;
                }
                let response = send(http, request).await?;
                let body = String::from_utf8_lossy(&response.body);
                // cloud.google.com/go/auth urlSubjectProvider: the response body is used as is.
                match format {
                    None => Ok(Secret::new(body)),
                    Some(format) => format.extract(&body),
                }
            }
        }
    }
}

impl Format {
    fn from_file(file: FormatFile) -> Result<Self, AuthError> {
        match file.kind.as_deref() {
            Some("text") => Ok(Self::Text),
            Some("json") => file
                .subject_token_field_name
                .filter(|field| !field.is_empty())
                .map(|field| Self::Json { field })
                .ok_or_else(|| {
                    AuthError::new("credential_source format has no subject_token_field_name")
                }),
            _ => Err(AuthError::new("invalid credential_source format type")),
        }
    }

    fn extract(&self, text: &str) -> Result<Secret, AuthError> {
        match self {
            Self::Text => Ok(Secret::new(text)),
            Self::Json { field } => {
                let value: Value = serde_json::from_str(text)
                    .map_err(|_| AuthError::new("subject token is not valid JSON"))?;
                value
                    .get(field)
                    .and_then(Value::as_str)
                    .map(Secret::new)
                    .ok_or_else(|| AuthError::new("subject token field not found"))
            }
        }
    }
}

fn read_bounded(path: &str) -> Result<Vec<u8>, AuthError> {
    let file = std::fs::File::open(path)
        .map_err(|error| AuthError::new(format!("cannot open the credential file: {error}")))?;
    let mut bytes = Vec::new();
    file.take(MAX_SUBJECT_TOKEN + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| AuthError::new(format!("cannot read the credential file: {error}")))?;
    if bytes.len() as u64 > MAX_SUBJECT_TOKEN {
        return Err(AuthError::new("the credential file is too large"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;

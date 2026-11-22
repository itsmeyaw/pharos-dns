//! Credential files: the `type` check CoreDNS runs at Corefile parse time, and the dispatch that builds a token source.

use std::path::Path;

use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

use super::{
    DNS_SCOPES, Provider, authorized_user,
    external_account::{self, ExternalAccount},
    impersonated::{self, Impersonated},
    oauth::json_error,
    service_account,
    token::{AuthError, TokenSource},
};
use crate::clouddns::http::Http;

// The scope a source credential needs to call IAM Credentials (cloud.google.com/go/auth cloudPlatformScope).
const CLOUD_PLATFORM: &str = "https://www.googleapis.com/auth/cloud-platform";

// cloud.google.com/go/auth follows `source_credentials` without limit; a file that nests itself must still end.
const MAX_NESTING: u8 = 3;

/// The credential types CoreDNS accepts (plugin/clouddns/setup.go getCredType).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialType {
    ServiceAccount,
    AuthorizedUser,
    ImpersonatedServiceAccount,
    ExternalAccount,
}

impl CredentialType {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "service_account" => Some(Self::ServiceAccount),
            "authorized_user" => Some(Self::AuthorizedUser),
            "impersonated_service_account" => Some(Self::ImpersonatedServiceAccount),
            "external_account" => Some(Self::ExternalAccount),
            _ => None,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::ServiceAccount => "service_account",
            Self::AuthorizedUser => "authorized_user",
            Self::ImpersonatedServiceAccount => "impersonated_service_account",
            Self::ExternalAccount => "external_account",
        }
    }
}

#[derive(Deserialize)]
struct Typed {
    #[serde(rename = "type")]
    kind: Option<String>,
}

/// CoreDNS v1.15.0 plugin/clouddns/setup.go getCredType: read the file and accept only the four known `type`s.
/// It needs no network, so the Corefile parser can call it.
pub(crate) fn credential_type(path: &Path) -> Result<CredentialType, AuthError> {
    let data = std::fs::read(path).map_err(|error| AuthError::new(error.to_string()))?;
    type_of(&data)
}

fn type_of(data: &[u8]) -> Result<CredentialType, AuthError> {
    let typed: Typed = serde_json::from_slice(data).map_err(|error| json_error(&error))?;
    check_type(typed.kind.as_deref())
}

fn check_type(kind: Option<&str>) -> Result<CredentialType, AuthError> {
    let kind = kind.unwrap_or_default();
    if kind.is_empty() {
        return Err(AuthError::new("missing `type` field in credential"));
    }
    CredentialType::from_name(kind).ok_or_else(|| {
        // The type names a kind of file, not a secret; cap it so a wrong file cannot flood the error.
        let shown: String = kind.chars().take(64).collect();
        AuthError::new(format!("unknown credential type: {shown}"))
    })
}

impl TokenSource {
    /// A token source for the credential file at `path`, asking for the Cloud DNS scopes.
    pub(crate) fn from_file(path: &Path, http: Http) -> Result<Self, AuthError> {
        let data = std::fs::read(path).map_err(|error| AuthError::new(error.to_string()))?;
        Self::from_json(&data, http)
    }

    pub(crate) fn from_json(data: &[u8], http: Http) -> Result<Self, AuthError> {
        let value: Value = serde_json::from_slice(data).map_err(|error| json_error(&error))?;
        let provider = provider(value, &DNS_SCOPES, &http, 0)?;
        Ok(Self::new(provider, http))
    }
}

fn provider(value: Value, scopes: &[&str], http: &Http, depth: u8) -> Result<Provider, AuthError> {
    let kind = check_type(value.get("type").and_then(Value::as_str))?;
    match kind {
        CredentialType::ServiceAccount => {
            let file: service_account::File = parse(value, kind)?;
            service_account::ServiceAccount::from_file(file, scopes).map(Provider::ServiceAccount)
        }
        CredentialType::AuthorizedUser => {
            let file: authorized_user::File = parse(value, kind)?;
            authorized_user::AuthorizedUser::from_file(file).map(Provider::AuthorizedUser)
        }
        CredentialType::ExternalAccount => {
            let file: external_account::File = parse(value, kind)?;
            let Some(url) = file
                .service_account_impersonation_url
                .clone()
                .filter(|url| !url.is_empty())
            else {
                return ExternalAccount::from_file(file, scopes).map(Provider::ExternalAccount);
            };
            // cloud.google.com/go/auth externalaccount NewTokenProvider: the exchange asks for cloud-platform and
            // the impersonated token carries the requested scopes.
            let account = ExternalAccount::from_file(file, &[CLOUD_PLATFORM])?;
            let lifetime = account.lifetime_seconds;
            let source = TokenSource::new(Provider::ExternalAccount(account), http.clone());
            Ok(Provider::Impersonated(Impersonated::new(
                source,
                url,
                scopes,
                Vec::new(),
                lifetime,
            )))
        }
        CredentialType::ImpersonatedServiceAccount => {
            let file: impersonated::File = parse(value, kind)?;
            // cloud.google.com/go/auth handleImpersonatedServiceAccount: both fields are required.
            let (Some(url), Some(source)) = (
                file.service_account_impersonation_url
                    .filter(|url| !url.is_empty()),
                file.source_credentials,
            ) else {
                return Err(AuthError::new(
                    "missing 'source_credentials' field or 'service_account_impersonation_url' in credentials",
                ));
            };
            if depth >= MAX_NESTING {
                return Err(AuthError::new("source_credentials are nested too deeply"));
            }
            // The source credential needs the cloud-platform scope to call IAM Credentials.
            let source = provider(source, &[CLOUD_PLATFORM], http, depth + 1)
                .map_err(|error| error.within("source_credentials"))?;
            Ok(Provider::Impersonated(Impersonated::new(
                TokenSource::new(source, http.clone()),
                url,
                scopes,
                file.delegates.unwrap_or_default(),
                None,
            )))
        }
    }
}

// A deserialization error can quote the offending value, so it is replaced by the credential type.
fn parse<T: DeserializeOwned>(value: Value, kind: CredentialType) -> Result<T, AuthError> {
    serde_json::from_value(value).map_err(|_| {
        AuthError::new(format!(
            "invalid {} credentials: a field has the wrong type",
            kind.name()
        ))
    })
}

#[cfg(test)]
mod tests;

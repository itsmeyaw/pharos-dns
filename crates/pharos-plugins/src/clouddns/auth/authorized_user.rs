//! `authorized_user` credentials (`gcloud auth application-default login`): a refresh token grant (RFC 6749 §6).

use std::sync::Mutex;

use serde::Deserialize;

use super::{
    DEFAULT_TOKEN_URI,
    oauth::fetch_token,
    token::{AuthError, Fetched, Secret},
};
use crate::clouddns::http::{Http, Request};

#[derive(Deserialize)]
pub(super) struct File {
    client_id: Option<String>,
    client_secret: Option<Secret>,
    refresh_token: Option<Secret>,
    // Deviation from cloud.google.com/go/auth, which has no such field and always uses Google's endpoint: it lets
    // the token endpoint be stubbed. gcloud files never carry it.
    token_uri: Option<String>,
}

#[derive(Debug)]
pub(crate) struct AuthorizedUser {
    client_id: String,
    client_secret: Secret,
    refresh_token: Mutex<Secret>,
    token_uri: String,
}

impl AuthorizedUser {
    pub(super) fn from_file(file: File) -> Result<Self, AuthError> {
        // cloud.google.com/go/auth Options3LO.validate: client ID, client secret and refresh token are required.
        let missing =
            |field: &str| AuthError::new(format!("authorized_user credentials have no {field}"));
        Ok(Self {
            client_id: file
                .client_id
                .filter(|id| !id.is_empty())
                .ok_or_else(|| missing("client_id"))?,
            client_secret: file
                .client_secret
                .filter(|secret| !secret.is_empty())
                .ok_or_else(|| missing("client_secret"))?,
            refresh_token: Mutex::new(
                file.refresh_token
                    .filter(|token| !token.is_empty())
                    .ok_or_else(|| missing("refresh_token"))?,
            ),
            token_uri: file
                .token_uri
                .filter(|uri| !uri.is_empty())
                .unwrap_or_else(|| DEFAULT_TOKEN_URI.to_owned()),
        })
    }

    pub(crate) async fn fetch(&self, http: &Http) -> Result<Fetched, AuthError> {
        let refresh_token = self.refresh_token.lock().map_or_else(
            |poisoned| poisoned.into_inner().clone(),
            |token| token.clone(),
        );
        // RFC 6749 §6: grant_type=refresh_token; cloud.google.com/go/auth uses StyleInParams for the client secret.
        let request = Request::post_form(
            &self.token_uri,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.expose()),
                ("client_id", &self.client_id),
                ("client_secret", self.client_secret.expose()),
            ],
        );
        let fetched = fetch_token(http, request)
            .await
            .map_err(|error| error.within("authorized user token request"))?;
        // RFC 6749 §6: the server MAY issue a new refresh token, which replaces the old one.
        if let Some(rotated) = &fetched.refresh_token {
            *self
                .refresh_token
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = rotated.clone();
        }
        Ok(fetched)
    }
}

#[cfg(test)]
mod tests;

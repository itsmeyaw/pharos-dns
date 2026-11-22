//! `service_account` credentials: an RS256 JWT bearer grant (RFC 7523 §2.1).

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use serde_json::json;

use super::{
    DEFAULT_TOKEN_URI, DNS_SCOPES,
    oauth::fetch_token,
    token::{AuthError, Fetched, Secret},
};
use crate::clouddns::http::{Http, Request};

// cloud.google.com/go/auth internal/jwt Claims.encode: iat is backdated 10 s for clock skew, exp is one hour later.
const SKEW_SECONDS: u64 = 10;
const LIFETIME_SECONDS: u64 = 3600;

/// RFC 7523 §2.1: the grant type of a JWT bearer assertion.
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

#[derive(Deserialize)]
pub(super) struct File {
    client_email: Option<String>,
    private_key: Option<Secret>,
    private_key_id: Option<String>,
    token_uri: Option<String>,
}

pub(crate) struct ServiceAccount {
    client_email: String,
    private_key_id: String,
    key: RsaKeyPair,
    token_uri: String,
}

impl fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("client_email", &self.client_email)
            .field("token_uri", &self.token_uri)
            .finish_non_exhaustive()
    }
}

impl ServiceAccount {
    pub(super) fn from_file(file: File) -> Result<Self, AuthError> {
        // cloud.google.com/go/auth Options2LO.validate: the email and the private key are required.
        let client_email = file
            .client_email
            .filter(|email| !email.is_empty())
            .ok_or_else(|| AuthError::new("service_account credentials have no client_email"))?;
        let private_key = file
            .private_key
            .filter(|key| !key.is_empty())
            .ok_or_else(|| AuthError::new("service_account credentials have no private_key"))?;
        Ok(Self {
            client_email,
            private_key_id: file.private_key_id.unwrap_or_default(),
            key: parse_private_key(private_key.expose())?,
            // cloud.google.com/go/auth handleServiceAccount: an absent token_uri is the Google token URL.
            token_uri: file
                .token_uri
                .filter(|uri| !uri.is_empty())
                .unwrap_or_else(|| DEFAULT_TOKEN_URI.to_owned()),
        })
    }

    pub(crate) async fn fetch(&self, http: &Http) -> Result<Fetched, AuthError> {
        let assertion = self.assertion(now_seconds())?;
        let request = Request::post_form(
            &self.token_uri,
            &[
                ("grant_type", GRANT_TYPE),
                ("assertion", assertion.expose()),
            ],
        );
        fetch_token(http, request)
            .await
            .map_err(|error| error.within("service account token request"))
    }

    // RFC 7523 §3: iss, aud and exp are required; the scope claim is Google's (Google ADC service account flow).
    fn assertion(&self, now: u64) -> Result<Secret, AuthError> {
        let issued = now.saturating_sub(SKEW_SECONDS);
        let header = json!({"alg": "RS256", "typ": "JWT", "kid": self.private_key_id});
        let claims = json!({
            "iss": self.client_email,
            "scope": DNS_SCOPES.join(" "),
            "aud": self.token_uri,
            "iat": issued,
            "exp": issued + LIFETIME_SECONDS,
        });
        // RFC 7515 §5.1: the signing input is BASE64URL(header) "." BASE64URL(payload).
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut signature = vec![0; self.key.public_modulus_len()];
        // RFC 7518 §3.3: RS256 is RSASSA-PKCS1-v1_5 with SHA-256.
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| AuthError::new("cannot sign the JWT assertion"))?;
        Ok(Secret::new(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        )))
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

// RFC 7468 §10 / RFC 5958: Google key files hold a PKCS#8 "PRIVATE KEY"; cloud.google.com/go/auth internal.ParseKey
// also accepts a PKCS#1 "RSA PRIVATE KEY" (RFC 8017 Appendix A.1.2).
fn parse_private_key(pem: &str) -> Result<RsaKeyPair, AuthError> {
    let invalid = || AuthError::new("service_account private_key is not a valid RSA key");
    let (label, der) = pem_decode(pem).ok_or_else(invalid)?;
    let key = match label {
        "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&der),
        "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der),
        _ => return Err(invalid()),
    };
    key.map_err(|_| invalid())
}

/// RFC 7468 §3: the label and the Base64 body of the first PEM block, whitespace ignored.
fn pem_decode(pem: &str) -> Option<(&str, Vec<u8>)> {
    let begin = pem.find("-----BEGIN ")?;
    let rest = &pem[begin + "-----BEGIN ".len()..];
    let (label, rest) = rest.split_once("-----")?;
    let (body, _) = rest.split_once(&format!("-----END {label}-----"))?;
    let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    Some((label, STANDARD.decode(body).ok()?))
}

#[cfg(test)]
mod tests;

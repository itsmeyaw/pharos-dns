//! Token endpoint plumbing shared by the credential sources: send, check status, read `access_token`.

use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use super::token::{AuthError, Fetched, Secret};
use crate::clouddns::http::{Http, Request, Response};

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<Secret>,
    expires_in: Option<Value>,
}

/// Send `request` to a token-issuing endpoint and read an RFC 6749 §5.1 response.
pub(crate) async fn fetch_token(http: &Http, request: Request) -> Result<Fetched, AuthError> {
    let response = send(http, request).await?;
    let parsed: TokenResponse =
        serde_json::from_slice(&response.body).map_err(|error| json_error(&error))?;
    // RFC 6749 §5.1: "access_token" is REQUIRED in a successful response.
    let token = parsed
        .access_token
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AuthError::new("response has no access_token"))?;
    Ok(Fetched {
        token,
        lifetime: parsed.expires_in.as_ref().and_then(seconds),
    })
}

/// Send `request` and return its response when the status is 2xx; otherwise an error naming the status and
/// the endpoint's error code.
pub(crate) async fn send(http: &Http, request: Request) -> Result<Response, AuthError> {
    let response = http
        .send(request)
        .await
        .map_err(|error| AuthError::new(format!("request failed: {error}")))?;
    if response.is_success() {
        return Ok(response);
    }
    // RFC 6749 §5.2: error responses carry an "error" code; the description may echo input, so it is dropped.
    Err(AuthError::new(match error_code(&response.body) {
        Some(code) => format!("HTTP {}: {code}", response.status),
        None => format!("HTTP {}", response.status),
    }))
}

/// `serde_json` messages can quote the offending value; keep only the position.
pub(crate) fn json_error(error: &serde_json::Error) -> AuthError {
    AuthError::new(format!(
        "invalid JSON at line {} column {}",
        error.line(),
        error.column()
    ))
}

// RFC 6749 §5.2 "error" is a string; Google API errors nest it as `error.status` (Google Cloud DNS API v1).
pub(crate) fn error_code(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let code = match value.get("error")? {
        Value::String(code) => code.as_str(),
        Value::Object(error) => error.get("status")?.as_str()?,
        _ => return None,
    };
    // A hostile endpoint must not smuggle text through the code: keep short identifier-like codes only.
    let plain = !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    plain.then(|| code.to_owned())
}

// RFC 6749 §5.1: "expires_in" is the lifetime in seconds; Google sends a number, some servers a string.
fn seconds(value: &Value) -> Option<Duration> {
    let seconds = match value {
        Value::Number(number) => number.as_u64()?,
        Value::String(text) => text.parse().ok()?,
        _ => return None,
    };
    // cloud.google.com/go/auth tokenProvider2LO: a zero lifetime means the token states no expiry.
    (seconds > 0).then(|| Duration::from_secs(seconds))
}

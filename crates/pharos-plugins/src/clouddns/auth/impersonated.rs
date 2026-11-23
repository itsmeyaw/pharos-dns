//! Service account impersonation: a source credential mints a token, which asks IAM Credentials
//! `generateAccessToken` for a token of the target service account.

use std::{
    future::Future,
    pin::Pin,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    oauth::{json_error, send},
    token::{AccessToken, AuthError, Fetched, Secret, TokenSource},
};
use crate::clouddns::http::{Http, Request};

// cloud.google.com/go/auth credentials/internal/impersonate defaultTokenLifetime.
const DEFAULT_LIFETIME_SECONDS: u64 = 3600;

#[derive(Deserialize)]
pub(super) struct File {
    pub service_account_impersonation_url: Option<String>,
    pub delegates: Option<Vec<String>>,
    pub source_credentials: Option<Value>,
}

#[derive(Debug)]
pub(crate) struct Impersonated {
    source: TokenSource,
    url: String,
    scopes: Vec<String>,
    delegates: Vec<String>,
    lifetime_seconds: u64,
}

#[derive(Deserialize)]
struct GeneratedToken {
    #[serde(rename = "accessToken")]
    access_token: Option<Secret>,
    #[serde(rename = "expireTime")]
    expire_time: Option<String>,
}

impl Impersonated {
    pub(super) fn new(
        source: TokenSource,
        url: String,
        scopes: &[&str],
        delegates: Vec<String>,
        lifetime_seconds: Option<u64>,
    ) -> Self {
        Self {
            source,
            url,
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            delegates,
            lifetime_seconds: lifetime_seconds
                .filter(|seconds| *seconds > 0)
                .unwrap_or(DEFAULT_LIFETIME_SECONDS),
        }
    }

    pub(crate) async fn fetch(&self, http: &Http) -> Result<Fetched, AuthError> {
        let source = self
            .source_token()
            .await
            .map_err(|error| error.within("impersonation source credentials"))?;
        // Google IAM Credentials API v1 generateAccessToken: body {delegates, lifetime, scope}.
        let mut body = json!({
            "lifetime": format!("{}s", self.lifetime_seconds),
            "scope": self.scopes,
        });
        if !self.delegates.is_empty() {
            body["delegates"] = json!(self.delegates);
        }
        let request = Request::post_json(&self.url, body.to_string())
            .bearer(source.as_str())
            .map_err(|error| AuthError::new(error.to_string()))?;
        let response = send(http, request)
            .await
            .map_err(|error| error.within("impersonation request"))?;
        let generated: GeneratedToken = serde_json::from_slice(&response.body)
            .map_err(|error| json_error(&error).within("impersonation response"))?;
        let token = generated
            .access_token
            .filter(|token| !token.is_empty())
            .ok_or_else(|| AuthError::new("impersonation response has no accessToken"))?;
        // Google IAM Credentials API v1: expireTime is an RFC 3339 timestamp.
        let expires = generated
            .expire_time
            .as_deref()
            .and_then(unix_seconds)
            .ok_or_else(|| AuthError::new("impersonation response has no valid expireTime"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let lifetime = Duration::from_secs(u64::try_from(expires).unwrap_or(0).saturating_sub(now));
        Ok(Fetched::new(token, Some(lifetime)))
    }

    // The boxed future ends the cycle Impersonated -> TokenSource -> Provider -> Impersonated.
    fn source_token(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<AccessToken, AuthError>> + Send + '_>> {
        Box::pin(self.source.token())
    }
}

/// RFC 3339 §5.6 `date-time` as Unix seconds; fractional seconds are dropped.
fn unix_seconds(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = text.get(range)?;
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse().ok())?
    };
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let (hours, minutes) = rest[1..].split_once(':')?;
            sign * (hours.parse::<i64>().ok()? * 3600 + minutes.parse::<i64>().ok()? * 60)
        }
    };
    // Howard Hinnant's days_from_civil: days since 1970-01-01 of a proleptic Gregorian date.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

#[cfg(test)]
mod tests;

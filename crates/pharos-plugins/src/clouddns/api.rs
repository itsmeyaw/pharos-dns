//! Cloud DNS API v1 client: the two calls CoreDNS's clouddns Plugin makes (`ManagedZones.Get`, `ResourceRecordSets.List`).

use std::{collections::HashSet, fmt};

use serde::Deserialize;

use super::{
    auth::{TokenSource, error_code, json_error},
    http::{Http, Request, form_encode, path_segment},
};

// Google Cloud DNS API v1 basePath (google.golang.org/api/dns/v1).
pub(crate) const DEFAULT_ENDPOINT: &str = "https://dns.googleapis.com";

// A zone's rrsets arrive 100 at a time by default; this bounds a server that never stops paging.
const MAX_PAGES: usize = 10_000;
const MAX_RRSETS: usize = 1_000_000;

/// One resource record set; `rrdatas` are in zone-file presentation form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Rrset {
    pub name: String,
    pub rtype: String,
    pub ttl: u32,
    pub rrdatas: Vec<String>,
}

/// A failed API call. The message holds the status and Google's error code, never a response body or a token.
#[derive(Debug)]
pub(crate) struct ApiError(String);

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ApiError {}

#[derive(Deserialize)]
struct Page {
    #[serde(default)]
    rrsets: Vec<Wire>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct Wire {
    name: String,
    #[serde(rename = "type")]
    rtype: String,
    #[serde(default)]
    ttl: u32,
    #[serde(default)]
    rrdatas: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Api {
    endpoint: String,
    tokens: TokenSource,
    http: Http,
}

impl Api {
    /// `endpoint` is the scheme and authority, without a trailing slash.
    pub(crate) fn new(endpoint: &str, tokens: TokenSource, http: Http) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            tokens,
            http,
        }
    }

    /// `ManagedZones.Get`: `false` when the zone does not exist (HTTP 404), an error for anything else that fails.
    pub(crate) async fn zone_exists(&self, project: &str, zone: &str) -> Result<bool, ApiError> {
        let response = self.get(&self.zone_url(project, zone)).await?;
        match response.status {
            // RFC 9110 §15.3.1: 200 OK carries the zone.
            200 => Ok(true),
            // RFC 9110 §15.5.5: 404 Not Found.
            404 => Ok(false),
            _ => Err(status_error(&response)),
        }
    }

    /// `ResourceRecordSets.List`, following `nextPageToken` until it is absent.
    pub(crate) async fn list_rrsets(
        &self,
        project: &str,
        zone: &str,
    ) -> Result<Vec<Rrset>, ApiError> {
        let base = format!("{}/rrsets", self.zone_url(project, zone));
        let mut rrsets = Vec::new();
        let mut seen = HashSet::new();
        let mut token: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let url = match &token {
                Some(token) => format!("{base}?{}", form_encode(&[("pageToken", token)])),
                None => base.clone(),
            };
            let response = self.get(&url).await?;
            if !response.is_success() {
                return Err(status_error(&response));
            }
            let page: Page = serde_json::from_slice(&response.body)
                .map_err(|error| ApiError(format!("list response: {}", json_error(&error))))?;
            rrsets.extend(page.rrsets.into_iter().map(|wire| Rrset {
                name: wire.name,
                rtype: wire.rtype,
                ttl: wire.ttl,
                rrdatas: wire.rrdatas,
            }));
            if rrsets.len() > MAX_RRSETS {
                return Err(ApiError(format!(
                    "zone has more than {MAX_RRSETS} record sets"
                )));
            }
            match page.next_page_token.filter(|token| !token.is_empty()) {
                None => return Ok(rrsets),
                // A repeated token would page forever.
                Some(next) if !seen.insert(next.clone()) => {
                    return Err(ApiError("list response repeats a page token".to_owned()));
                }
                Some(next) => token = Some(next),
            }
        }
        Err(ApiError(format!(
            "zone has more than {MAX_PAGES} pages of record sets"
        )))
    }

    // Google Cloud DNS API v1: dns/v1/projects/{project}/managedZones/{managedZone}.
    fn zone_url(&self, project: &str, zone: &str) -> String {
        format!(
            "{}/dns/v1/projects/{}/managedZones/{}",
            self.endpoint,
            path_segment(project),
            path_segment(zone)
        )
    }

    async fn get(&self, url: &str) -> Result<crate::clouddns::http::Response, ApiError> {
        let token = self
            .tokens
            .token()
            .await
            .map_err(|error| ApiError(format!("credentials: {error}")))?;
        let request = Request::get(url)
            .bearer(token.as_str())
            .map_err(|error| ApiError(error.to_string()))?;
        self.http
            .send(request)
            .await
            .map_err(|error| ApiError(format!("request failed: {error}")))
    }
}

fn status_error(response: &crate::clouddns::http::Response) -> ApiError {
    ApiError(match error_code(&response.body) {
        Some(code) => format!("HTTP {}: {code}", response.status),
        None => format!("HTTP {}", response.status),
    })
}

#[cfg(test)]
mod tests;

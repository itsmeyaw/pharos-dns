//! Azure DNS REST API: list every record set of one hosted zone.

use std::{collections::HashSet, time::Duration};

use pharos_proto::zone::ZoneRecord;

use super::{
    auth::{Endpoints, TokenSource, quote},
    config::{Config, ZoneSpec},
    http::{Call, Http, MAX_BODY, Url, percent_encode},
    records::parse_page,
};

/// Retry and deadline settings; tests shrink them.
#[derive(Clone, Copy, Debug)]
pub(super) struct Tuning {
    /// go-autorest v0.11.30 autorest/client.go `DefaultRetryAttempts`: retries after the first attempt.
    pub retries: u32,
    /// go-autorest v0.11.30 autorest/client.go `DefaultRetryDuration`: the first backoff; each retry doubles it.
    pub backoff: Duration,
    /// CoreDNS v1.15.0 plugin/azure/azure.go updateZone: all pages and retries of one hosted zone share one minute.
    pub list_timeout: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            retries: 3,
            backoff: Duration::from_secs(30),
            list_timeout: Duration::from_secs(60),
        }
    }
}

/// A listing larger than this in total is a hostile or broken endpoint.
const MAX_LISTING: usize = 8 * MAX_BODY;

/// go-autorest v0.11.30 autorest/client.go `StatusCodesForRetry`.
const RETRY_STATUS: [u16; 6] = [408, 429, 500, 502, 503, 504];

#[derive(Debug)]
pub(super) struct Client {
    http: Http,
    auth: TokenSource,
    /// The Resource Manager origin; a `nextLink` must share it before a bearer token goes there.
    base: Url,
    subscription: String,
    tuning: Tuning,
}

impl Client {
    pub(super) fn new(
        config: &Config,
        endpoints: &Endpoints,
        env: impl Fn(&str) -> Option<String>,
        tuning: Tuning,
    ) -> Result<Self, String> {
        let mut base: Url = endpoints
            .resource_manager
            .parse()
            .map_err(|()| format!("invalid endpoint {:?}", endpoints.resource_manager))?;
        // autorest `WithPath`: the base path loses its trailing slash before the request path is appended.
        base.target = base.target.trim_end_matches('/').to_owned();
        Ok(Self {
            http: Http::default(),
            auth: TokenSource::new(config, endpoints, env)?,
            base,
            subscription: config.subscription.clone(),
            tuning,
        })
    }

    pub(super) fn scrub(&self, text: String) -> String {
        self.auth.scrub(text)
    }

    /// Azure DNS REST API 2018-05-01 `RecordSets - List By Dns Zone` and Private DNS API 2018-09-01 `Record Sets - List`.
    fn first_page(&self, spec: &ZoneSpec) -> Url {
        let (kind, tail, version) = if spec.private {
            ("privateDnsZones", "ALL", "2018-09-01")
        } else {
            ("dnsZones", "recordsets", "2018-05-01")
        };
        let path = format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/{kind}/{}/{tail}?api-version={version}",
            self.base.target,
            percent_encode(&self.subscription, false),
            percent_encode(&spec.resource_group, false),
            percent_encode(&spec.zone, false),
        );
        self.base.with_target(path)
    }

    /// Every record of the hosted zone, or the first error; the caller bounds the time.
    pub(super) async fn list(&self, spec: &ZoneSpec) -> Result<Vec<ZoneRecord>, String> {
        let mut url = self.first_page(spec);
        let mut seen = HashSet::from([url.target.clone()]);
        let mut records = Vec::new();
        let mut total = 0;
        loop {
            let body = self.get(&url).await?;
            total += body.len();
            if total > MAX_LISTING {
                return Err("listing is too large".to_owned());
            }
            let page = parse_page(&body, spec.private)?;
            records.extend(page.records);
            // autorest `hasNextLink`: no link ends the listing; an empty page with a link is followed.
            let Some(link) = page.next_link else {
                return Ok(records);
            };
            let next: Url = link
                .parse()
                .map_err(|()| "nextLink is not an absolute http(s) URL".to_owned())?;
            // The bearer token goes only to Resource Manager.
            if !next.same_origin(&self.base) {
                return Err("nextLink points outside Resource Manager".to_owned());
            }
            // A repeated nextLink would page forever.
            if !seen.insert(next.target.clone()) {
                return Err("nextLink repeats an earlier page".to_owned());
            }
            url = next;
        }
    }

    /// GET one page, retrying like go-autorest `DoRetryForStatusCodes`: transport errors and `RETRY_STATUS`, `Retry-After` first.
    async fn get(&self, url: &Url) -> Result<Vec<u8>, String> {
        let mut attempt = 0_u32;
        loop {
            // adal: the bearer token is refreshed per request, so a long listing never uses an expired one.
            let token = self.auth.token(&self.http).await?;
            let bearer = format!("Bearer {}", token.expose());
            let outcome = self
                .http
                .request(url, Call::get(&[("authorization", &bearer)]))
                .await;
            let (retry_after, error) = match outcome {
                Ok(response) if response.status == 200 => return Ok(response.body),
                Ok(response) => {
                    let retry_after = response
                        .headers
                        .get("retry-after")
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.trim().parse::<u64>().ok())
                        .filter(|seconds| *seconds > 0)
                        .map(Duration::from_secs);
                    let error = format!(
                        "unexpected status {}: {}",
                        response.status,
                        quote(&response.body)
                    );
                    if !RETRY_STATUS.contains(&response.status) {
                        return Err(self.auth.scrub(error));
                    }
                    (retry_after, error)
                }
                Err(error) => (None, format!("request failed: {error}")),
            };
            if attempt >= self.tuning.retries {
                return Err(self.auth.scrub(error));
            }
            let delay = retry_after
                .unwrap_or_else(|| self.tuning.backoff.saturating_mul(1_u32 << attempt.min(16)));
            tokio::time::sleep(delay).await;
            attempt += 1;
        }
    }
}

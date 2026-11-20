//! The RFC 8555 client flow for one certificate: account, order, DNS-01 authorization, finalize, download.

use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aws_lc_rs::digest::{SHA256, digest};
use hyper::Method;
use serde_json::{Value, json};
use tokio::time::{Instant, sleep};

use super::{
    Solver, der,
    http::{Http, Response},
    jws::{AccountKey, Identity, b64},
};

// RFC 8555 §6.2: ACME request bodies are flattened JWS.
const JOSE: &str = "application/jose+json";
/// How long a CA may take to validate or issue before the attempt is abandoned.
const DEADLINE: Duration = Duration::from_secs(120);
/// RFC 8555 §7.5.1 gives no polling interval; use `Retry-After` when sent, else this.
const POLL: Duration = Duration::from_secs(1);

fn fail(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// One session with an ACME server under one account.
pub(crate) struct Client<'a> {
    http: &'a Http,
    key: &'a AccountKey,
    new_nonce: String,
    new_account: String,
    new_order: String,
    nonce: Option<String>,
    kid: String,
    secure: bool,
}

/// What a certificate order produced.
pub(crate) struct Issued {
    /// PEM certificate chain, leaf first.
    pub chain: String,
    /// PKCS#8 private key of the leaf.
    pub key: Vec<u8>,
}

// RFC 8555 §7.5.1: a server may send Retry-After; RFC 9110 §10.2.3 allows delay-seconds or an HTTP-date, honoured up to 30 s.
fn retry_after_of(response: &Response) -> Duration {
    retry_delay(response.header("retry-after"), SystemTime::now())
}

fn retry_delay(value: Option<&str>, now: SystemTime) -> Duration {
    let Some(value) = value else { return POLL };
    let seconds = value.parse().ok().or_else(|| {
        http_date(value).map(|at| at.duration_since(now).map_or(0, |wait| wait.as_secs()))
    });
    seconds.map_or(POLL, |seconds: u64| {
        Duration::from_secs(seconds.clamp(1, 30))
    })
}

// RFC 9110 §5.6.7: IMF-fixdate, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`. The obsolete RFC 850 and asctime forms are not parsed.
fn http_date(text: &str) -> Option<SystemTime> {
    let mut parts = text.split(' ');
    let (day_name, day, month, year, time, zone) = (
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
    );
    if parts.next().is_some()
        || zone != "GMT"
        || !["Mon,", "Tue,", "Wed,", "Thu,", "Fri,", "Sat,", "Sun,"].contains(&day_name)
        || [day.len(), year.len(), time.len()] != [2, 4, 8]
    {
        return None;
    }
    let month = 1 + [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|name| *name == month)? as i64;
    let digits = |text: &str| {
        text.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| text.parse::<i64>().ok())
            .flatten()
    };
    let (hour, minute, second) = (
        digits(time.get(..2)?)?,
        digits(time.get(3..5)?)?,
        digits(time.get(6..)?)?,
    );
    let (day, year) = (digits(day)?, digits(year)?);
    if time.as_bytes()[2] != b':'
        || time.as_bytes()[5] != b':'
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let seconds =
        der::days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).ok()?))
}

fn field(value: &Value, name: &str) -> io::Result<String> {
    value[name]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| fail(format!("ACME response lacks {name:?}")))
}

fn json_body(response: &Response) -> io::Result<Value> {
    serde_json::from_slice(&response.body)
        .map_err(|error| fail(format!("ACME response is not JSON: {error}")))
}

impl<'a> Client<'a> {
    /// Fetch the directory (RFC 8555 §7.1.1) and register or find the account (§7.3).
    pub(crate) async fn connect(
        http: &'a Http,
        directory: &str,
        key: &'a AccountKey,
        email: Option<&str>,
    ) -> io::Result<Client<'a>> {
        let response = http
            .request(Method::GET, directory, None, Vec::new())
            .await?;
        if response.status != 200 {
            return Err(fail(format!(
                "ACME directory {directory}: HTTP {}",
                response.status
            )));
        }
        let secure = directory.starts_with("https://");
        let directory = json_body(&response)?;
        let mut client = Client {
            http,
            key,
            new_nonce: field(&directory, "newNonce")?,
            new_account: field(&directory, "newAccount")?,
            new_order: field(&directory, "newOrder")?,
            nonce: None,
            kid: String::new(),
            secure,
        };
        // RFC 8555 §7.3: the client agrees to the terms of service as CoreDNS does (`Agreed: true`).
        let mut payload = json!({"termsOfServiceAgreed": true});
        if let Some(email) = email {
            payload["contact"] = json!([format!("mailto:{email}")]);
        }
        let url = client.new_account.clone();
        let response = client.post(&url, Some(&payload), Identity::Jwk).await?;
        // RFC 8555 §7.3: 201 for a new account and 200 for an existing one, with the account URL in Location.
        client.kid = response
            .header("location")
            .ok_or_else(|| fail("ACME newAccount response lacks Location"))?
            .to_owned();
        Ok(client)
    }

    // RFC 8555 §6.1: ACME is HTTPS; a CA reached over HTTPS cannot point the client at plain HTTP.
    fn require_https(&self, url: &str) -> io::Result<()> {
        if self.secure && !url.starts_with("https://") {
            return Err(fail(format!("ACME refuses the non-HTTPS URL {url}")));
        }
        Ok(())
    }

    // RFC 8555 §7.2: a nonce comes from a HEAD request to newNonce unless a response supplied one.
    async fn nonce(&mut self) -> io::Result<String> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }
        self.require_https(&self.new_nonce)?;
        let response = self
            .http
            .request(Method::HEAD, &self.new_nonce, None, Vec::new())
            .await?;
        response
            .header("replay-nonce")
            .map(str::to_owned)
            .ok_or_else(|| fail("ACME newNonce response lacks Replay-Nonce"))
    }

    /// POST a signed request; `payload` of `None` is a POST-as-GET (RFC 8555 §6.3).
    async fn post(
        &mut self,
        url: &str,
        payload: Option<&Value>,
        identity: Identity<'_>,
    ) -> io::Result<Response> {
        self.require_https(url)?;
        for attempt in 0..2 {
            let nonce = self.nonce().await?;
            let body = self
                .key
                .sign(identity, &nonce, url, payload)
                .map_err(|_| fail("signing an ACME request failed"))?;
            let response = self
                .http
                .request(Method::POST, url, Some(JOSE), body.into_bytes())
                .await?;
            // RFC 8555 §6.5: every response may carry the nonce for the next request.
            self.nonce = response.header("replay-nonce").map(str::to_owned);
            if response.status < 400 {
                return Ok(response);
            }
            let problem: Value = serde_json::from_slice(&response.body).unwrap_or_default();
            let kind = problem["type"].as_str().unwrap_or("unknown");
            // RFC 8555 §6.5: on badNonce the client retries once with the fresh nonce from the error.
            if kind.ends_with(":badNonce") && attempt == 0 {
                continue;
            }
            // RFC 7807 §3.1: a problem document has "type" and "detail".
            return Err(fail(format!(
                "ACME {url}: HTTP {} {kind}: {}",
                response.status,
                problem["detail"].as_str().unwrap_or("no detail")
            )));
        }
        Err(fail(format!(
            "ACME {url}: the server keeps rejecting nonces"
        )))
    }

    async fn authenticated(&mut self, url: &str, payload: Option<&Value>) -> io::Result<Response> {
        let kid = self.kid.clone();
        self.post(url, payload, Identity::Kid(&kid)).await
    }

    /// Obtain a certificate for `name` (a DNS name, `*.` prefix for a wildcard) by answering DNS-01 with `solver`.
    ///
    /// `propagated` is awaited after the challenge is presented and before the CA is told to validate it.
    pub(crate) async fn obtain<F, Fut>(
        &mut self,
        name: &str,
        solver: &Solver,
        propagated: F,
    ) -> io::Result<Issued>
    where
        F: Fn(String, String) -> Fut,
        Fut: Future<Output = io::Result<()>>,
    {
        let deadline = Instant::now() + DEADLINE;
        // RFC 8555 §7.4: the order lists the identifiers; a wildcard identifier keeps its "*." prefix (§7.1.3).
        let order_payload = json!({"identifiers": [{"type": "dns", "value": name}]});
        let new_order = self.new_order.clone();
        let response = self.authenticated(&new_order, Some(&order_payload)).await?;
        let order_url = response
            .header("location")
            .ok_or_else(|| fail("ACME newOrder response lacks Location"))?
            .to_owned();
        let order = json_body(&response)?;
        let finalize = field(&order, "finalize")?;
        for authorization in order["authorizations"].as_array().into_iter().flatten() {
            let url = authorization
                .as_str()
                .ok_or_else(|| fail("ACME authorization is not a URL"))?;
            self.authorize(url, solver, &propagated, deadline).await?;
        }

        // RFC 8555 §7.4: the CSR is signed by a key the client never shares with the CA, one per certificate.
        let pkcs8 = der::generate_certificate_key()
            .map_err(|_| fail("generating a certificate key failed"))?;
        let key =
            der::certificate_key(&pkcs8).map_err(|_| fail("loading the certificate key failed"))?;
        let csr = der::csr(&key, &[name.to_owned()])
            .map_err(|_| fail("signing the certificate request failed"))?;
        let response = self
            .authenticated(&finalize, Some(&json!({"csr": b64(csr)})))
            .await?;
        let mut retry_after = retry_after_of(&response);
        let mut order = json_body(&response)?;
        // RFC 8555 §7.4: poll the order until it is "valid" (a certificate URL appears) or "invalid".
        loop {
            match order["status"].as_str() {
                Some("valid") => break,
                Some("invalid") => {
                    return Err(fail(format!(
                        "ACME order for {name} is invalid: {}",
                        order["error"]
                    )));
                }
                Some("pending" | "ready" | "processing") => {}
                other => return Err(fail(format!("ACME order has unknown status {other:?}"))),
            }
            if Instant::now() >= deadline {
                return Err(fail(format!(
                    "ACME order for {name} did not become valid in time"
                )));
            }
            sleep(retry_after).await;
            let response = self.authenticated(&order_url, None).await?;
            retry_after = retry_after_of(&response);
            order = json_body(&response)?;
        }
        let response = self
            .authenticated(&field(&order, "certificate")?, None)
            .await?;
        let chain = String::from_utf8(response.body)
            .map_err(|_| fail("ACME certificate is not PEM text"))?;
        Ok(Issued { chain, key: pkcs8 })
    }

    // RFC 8555 §7.5 and §8.4: answer the dns-01 challenge of one authorization.
    async fn authorize<F, Fut>(
        &mut self,
        url: &str,
        solver: &Solver,
        propagated: &F,
        deadline: Instant,
    ) -> io::Result<()>
    where
        F: Fn(String, String) -> Fut,
        Fut: Future<Output = io::Result<()>>,
    {
        let response = self.authenticated(url, None).await?;
        let authorization = json_body(&response)?;
        match authorization["status"].as_str() {
            Some("valid") => return Ok(()),
            Some("pending") => {}
            other => return Err(fail(format!("ACME authorization has status {other:?}"))),
        }
        let identifier = authorization["identifier"]["value"]
            .as_str()
            .ok_or_else(|| fail("ACME authorization lacks an identifier"))?;
        let challenge = authorization["challenges"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|challenge| challenge["type"] == "dns-01")
            .ok_or_else(|| {
                fail(format!(
                    "the CA offers no dns-01 challenge for {identifier}"
                ))
            })?;
        let (token, challenge_url) = (field(challenge, "token")?, field(challenge, "url")?);
        // RFC 8555 §8.4: the TXT value is base64url(SHA-256(key authorization)) at _acme-challenge.<identifier>.
        let value = b64(digest(
            &SHA256,
            self.key.key_authorization(&token).as_bytes(),
        ));
        let record = format!("_acme-challenge.{identifier}.");
        solver.present(&record, &value);
        let _cleanup = Presented {
            solver,
            record: &record,
            value: &value,
        };
        propagated(record.clone(), value.clone()).await?;
        // RFC 8555 §7.5.1: an empty JSON object tells the server the challenge is ready.
        self.authenticated(&challenge_url, Some(&json!({}))).await?;
        // RFC 8555 §7.5.1: poll the authorization until "valid" or "invalid".
        loop {
            let response = self.authenticated(url, None).await?;
            let authorization = json_body(&response)?;
            match authorization["status"].as_str() {
                Some("valid") => return Ok(()),
                Some("pending" | "processing") => {}
                other => {
                    let error = authorization["challenges"][0]["error"].to_string();
                    return Err(fail(format!(
                        "ACME authorization for {identifier} is {other:?}: {error}"
                    )));
                }
            }
            if Instant::now() >= deadline {
                return Err(fail(format!(
                    "ACME authorization for {identifier} did not complete in time"
                )));
            }
            sleep(retry_after_of(&response)).await;
        }
    }
}

/// Withdraws a presented challenge when dropped, including when the attempt is cancelled.
struct Presented<'a> {
    solver: &'a Solver,
    record: &'a str,
    value: &'a str,
}

impl Drop for Presented<'_> {
    fn drop(&mut self) {
        self.solver.clean_up(self.record, self.value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9110 §5.6.7: the example IMF-fixdate.
    const DATE: &str = "Sun, 06 Nov 1994 08:49:37 GMT";

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn http_date_parses_the_rfc_9110_example() {
        assert_eq!(http_date(DATE), Some(at(784_111_777)));
    }

    #[test]
    fn http_date_rejects_other_shapes() {
        for text in [
            "",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 06 Nov 1994 08:49:37 GMT ",
            "Sun, 06 Nov 94 08:49:37 GMT",
            "Sun, 06 Nov 1994 25:49:37 GMT",
            "Sun, 06 Nov 1994 08-49-37 GMT",
            "Sun, 06 Foo 1994 08:49:37 GMT",
            "Sun, +6 Nov 1994 08:49:37 GMT",
        ] {
            assert_eq!(http_date(text), None, "{text:?}");
        }
    }

    #[test]
    fn retry_delay_honours_seconds_and_dates_within_bounds() {
        let now = at(784_111_777 - 10);
        assert_eq!(retry_delay(None, now), POLL);
        assert_eq!(retry_delay(Some("7"), now), Duration::from_secs(7));
        assert_eq!(retry_delay(Some("0"), now), Duration::from_secs(1));
        assert_eq!(retry_delay(Some("3600"), now), Duration::from_secs(30));
        assert_eq!(retry_delay(Some("soon"), now), POLL);
        assert_eq!(retry_delay(Some(DATE), now), Duration::from_secs(10));
        assert_eq!(retry_delay(Some(DATE), at(0)), Duration::from_secs(30));
        assert_eq!(
            retry_delay(Some(DATE), at(784_111_777 + 60)),
            Duration::from_secs(1)
        );
    }
}

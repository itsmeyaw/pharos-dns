//! The HTTP/1.1 client Azure REST and token requests need: one connection per request, no redirects.

use std::{io, str::FromStr, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Method, Request, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use pharos_server::tls::{ClientConfig, ClientOptions, ServerName, TlsConnector, client_config};
use tokio::{net::TcpStream, sync::OnceCell, time::timeout};

/// A response body larger than this is a hostile or broken endpoint, not a record set page.
pub(super) const MAX_BODY: usize = 32 << 20;
/// One request's budget; the caller's deadline bounds the whole listing.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// An `http` or `https` URL with a host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Url {
    pub https: bool,
    /// The host without brackets.
    pub host: String,
    pub port: u16,
    /// The path and query, always starting with `/`.
    pub target: String,
}

impl FromStr for Url {
    type Err = ();

    // RFC 3986 §3: scheme "://" authority path-abempty ["?" query]; fragments and userinfo are refused.
    fn from_str(value: &str) -> Result<Self, ()> {
        let (https, rest) = if let Some(rest) = value.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = value.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(());
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, target) = rest.split_at(end);
        if authority.is_empty() || authority.contains('@') || target.contains('#') {
            return Err(());
        }
        let default = if https { 443 } else { 80 };
        let (host, port) = match authority.strip_prefix('[') {
            Some(bracketed) => {
                let (host, tail) = bracketed.split_once(']').ok_or(())?;
                let port = match tail.strip_prefix(':') {
                    Some(port) => port.parse().map_err(|_| ())?,
                    None if tail.is_empty() => default,
                    None => return Err(()),
                };
                (host, port)
            }
            None => match authority.split_once(':') {
                Some((host, port)) => (host, port.parse().map_err(|_| ())?),
                None => (authority, default),
            },
        };
        if host.is_empty() || port == 0 {
            return Err(());
        }
        let target = if target.starts_with('/') {
            target.to_owned()
        } else {
            format!("/{target}")
        };
        Ok(Self {
            https,
            host: host.to_owned(),
            port,
            target,
        })
    }
}

impl Url {
    /// RFC 6454 §4: two URLs share an origin when scheme, host and port agree; hosts compare without case (RFC 4343 §3).
    pub(super) fn same_origin(&self, other: &Self) -> bool {
        self.https == other.https
            && self.port == other.port
            && self.host.eq_ignore_ascii_case(&other.host)
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        // RFC 9110 §7.2: the Host header omits the scheme's default port.
        if self.port == if self.https { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The same origin with another path and query.
    pub(super) fn with_target(&self, target: String) -> Self {
        Self {
            target,
            ..self.clone()
        }
    }
}

/// Azure REST API / autorest `Encode`: percent-encode everything but RFC 3986 unreserved bytes; a space is `+` in a form and `%20` in a path.
pub(super) fn percent_encode(value: &str, form: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' if form => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// A complete HTTP response.
pub(super) struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// A request's method, extra headers and body.
pub(super) struct Call<'a> {
    pub method: Method,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: Option<(&'a str, Vec<u8>)>,
}

impl<'a> Call<'a> {
    pub(super) fn get(headers: &'a [(&'a str, &'a str)]) -> Self {
        Self {
            method: Method::GET,
            headers,
            body: None,
        }
    }
}

/// Sends Azure requests; the TLS configuration (and its system root store) is built on the first `https` request.
#[derive(Debug, Default)]
pub(super) struct Http {
    tls: OnceCell<Arc<ClientConfig>>,
}

impl Http {
    /// Send one request; redirects are not followed (a 3xx is an unexpected status for the caller).
    pub(super) async fn request(&self, url: &Url, call: Call<'_>) -> io::Result<Response> {
        timeout(REQUEST_TIMEOUT, self.exchange(url, call))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timed out"))?
    }

    async fn exchange(&self, url: &Url, call: Call<'_>) -> io::Result<Response> {
        let tcp = TcpStream::connect((url.host.as_str(), url.port)).await?;
        let mut request = Request::builder()
            .method(call.method)
            .uri(&url.target)
            .header(header::HOST, url.authority())
            .header(
                header::USER_AGENT,
                concat!("pharos/", env!("CARGO_PKG_VERSION")),
            )
            .header(header::ACCEPT, "application/json");
        for (name, value) in call.headers {
            request = request.header(*name, *value);
        }
        let body = match call.body {
            Some((content_type, body)) => {
                request = request.header(header::CONTENT_TYPE, content_type);
                body
            }
            None => Vec::new(),
        };
        let request = request
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid request"))?;
        if url.https {
            let tls = self
                .tls
                .get_or_try_init(|| async { client_config(&ClientOptions::default()) })
                .await?;
            let name = ServerName::try_from(url.host.clone()).map_err(io::Error::other)?;
            // Azure REST API: Resource Manager and Active Directory are reached over verified TLS.
            let stream = TlsConnector::from(Arc::clone(tls))
                .connect(name, tcp)
                .await?;
            send(TokioIo::new(stream), request).await
        } else {
            send(TokioIo::new(tcp), request).await
        }
    }
}

async fn send<I>(io: I, request: Request<Full<Bytes>>) -> io::Result<Response>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(io).await.map_err(io::Error::other)?;
    // The connection task ends when `sender` drops, including when this future is aborted.
    tokio::spawn(connection);
    let response = sender
        .send_request(request)
        .await
        .map_err(io::Error::other)?;
    let (parts, mut incoming) = response.into_parts();
    let mut body = Vec::new();
    while let Some(frame) = incoming.frame().await {
        if let Ok(data) = frame.map_err(io::Error::other)?.into_data() {
            if body.len() + data.len() > MAX_BODY {
                return Err(io::Error::other("response is too large"));
            }
            body.extend_from_slice(&data);
        }
    }
    Ok(Response {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::Url;

    #[test]
    fn urls_compare_by_origin() {
        let base: Url = "https://Management.Azure.com/".parse().unwrap();
        for (other, same) in [
            ("https://management.azure.com/next?page=2", true),
            ("https://management.azure.com:443/x", true),
            ("http://management.azure.com/x", false),
            ("https://management.azure.com:8443/x", false),
            ("https://evil.example/x", false),
            ("https://management.azure.com.evil.example/x", false),
        ] {
            assert_eq!(base.same_origin(&other.parse().unwrap()), same, "{other}");
        }
    }

    #[test]
    fn urls_reject_userinfo_fragments_and_other_schemes() {
        for bad in [
            "ftp://a/",
            "https://u@a/",
            "https://a/#x",
            "/relative",
            "https://",
            "http://a:0/",
        ] {
            assert!(bad.parse::<Url>().is_err(), "{bad}");
        }
    }
}

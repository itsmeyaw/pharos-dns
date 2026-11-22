//! A minimal HTTP/1.1 client for the Google endpoints: one connection per request, bounded bodies, bounded time.
//!
//! CoreDNS v1.15.0 builds google.golang.org/api clients that retry nothing by default
//! (plugin/clouddns/setup.go passes no retry option), so this client does not retry either.

use std::{fmt, io, str::FromStr, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request as HyperRequest,
    client::conn::http1,
    header::{self, HeaderName, HeaderValue},
};
use hyper_util::rt::TokioIo;
use pharos_server::tls::{ClientConfig, ServerName, TlsConnector, client_config_with_roots};
use tokio::{net::TcpStream, sync::OnceCell, time::timeout};

// Google Cloud DNS API v1: a full rrsets page is at most a few MiB; bound it against a hostile or broken endpoint.
const MAX_BODY: usize = 32 << 20;
const TIMEOUT: Duration = Duration::from_secs(30);

/// An `http` or `https` URL with a host.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Url {
    https: bool,
    /// The host without brackets.
    host: String,
    port: u16,
    /// The path and query, always starting with `/`.
    target: String,
}

impl FromStr for Url {
    type Err = ();

    // RFC 3986 §3: scheme "://" authority path-abempty ["?" query]; fragments and userinfo are never sent.
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
}

/// A request under construction; `Debug` never shows headers, which may carry credentials.
pub(crate) struct Request {
    method: Method,
    url: String,
    headers: Vec<(HeaderName, HeaderValue)>,
    content_type: Option<&'static str>,
    body: Vec<u8>,
    timeout: Option<Duration>,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

impl Request {
    pub(crate) fn get(url: &str) -> Self {
        Self::new(Method::GET, url, None, Vec::new())
    }

    /// RFC 6749 §4.1.3: token requests are `application/x-www-form-urlencoded`.
    pub(crate) fn post_form(url: &str, fields: &[(&str, &str)]) -> Self {
        Self::new(
            Method::POST,
            url,
            Some("application/x-www-form-urlencoded"),
            form_encode(fields).into_bytes(),
        )
    }

    pub(crate) fn post_json(url: &str, body: String) -> Self {
        Self::new(
            Method::POST,
            url,
            Some("application/json"),
            body.into_bytes(),
        )
    }

    fn new(method: Method, url: &str, content_type: Option<&'static str>, body: Vec<u8>) -> Self {
        Self {
            method,
            url: url.to_owned(),
            headers: Vec::new(),
            content_type,
            body,
            timeout: None,
        }
    }

    /// Shorten the time allowed for this request; it never extends the client's limit.
    pub(crate) fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// A header that is not secret; errors when the name or value is not valid HTTP.
    pub(crate) fn header(mut self, name: &str, value: &str) -> io::Result<Self> {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid("header name"))?;
        let value = HeaderValue::from_str(value).map_err(|_| invalid("header value"))?;
        self.headers.push((name, value));
        Ok(self)
    }

    /// RFC 6750 §2.1: the Bearer scheme; the value is marked sensitive so hyper never prints it.
    pub(crate) fn bearer(mut self, token: &str) -> io::Result<Self> {
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| invalid("bearer token"))?;
        value.set_sensitive(true);
        self.headers.push((header::AUTHORIZATION, value));
        Ok(self)
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid {what}"))
}

/// A complete HTTP response; `Debug` hides the body, which may carry tokens.
pub(crate) struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl Response {
    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Sends requests; the TLS configuration (system roots) is built on the first `https` request.
#[derive(Clone, Debug)]
pub(crate) struct Http {
    tls: Arc<OnceCell<Arc<ClientConfig>>>,
    max_body: usize,
    timeout: Duration,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            tls: Arc::new(OnceCell::new()),
            max_body: MAX_BODY,
            timeout: TIMEOUT,
        }
    }
}

impl Http {
    #[cfg(test)]
    pub(crate) fn with_limits(max_body: usize, timeout: Duration) -> Self {
        Self {
            max_body,
            timeout,
            ..Self::default()
        }
    }

    /// Send one request; redirects are not followed. Errors never repeat request headers or bodies.
    pub(crate) async fn send(&self, request: Request) -> io::Result<Response> {
        let url: Url = request.url.parse().map_err(|()| invalid("URL"))?;
        let limit = request
            .timeout
            .map_or(self.timeout, |own| own.min(self.timeout));
        timeout(limit, self.exchange(request, &url))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timed out"))?
    }

    async fn exchange(&self, request: Request, url: &Url) -> io::Result<Response> {
        let tcp = TcpStream::connect((url.host.as_str(), url.port)).await?;
        let mut builder = HyperRequest::builder()
            .method(request.method)
            .uri(&url.target)
            .header(header::HOST, url.authority())
            .header(
                header::USER_AGENT,
                concat!("pharos/", env!("CARGO_PKG_VERSION")),
            )
            .header(header::ACCEPT, "application/json");
        if let Some(content_type) = request.content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        let hyper_request = builder
            .body(Full::new(Bytes::from(request.body)))
            .map_err(|_| invalid("request"))?;
        if url.https {
            let name = ServerName::try_from(url.host.clone()).map_err(|_| invalid("host"))?;
            let config = self
                .tls
                .get_or_try_init(|| async {
                    // The roots load reads files; keep that off the runtime threads.
                    tokio::task::spawn_blocking(|| client_config_with_roots(None))
                        .await
                        .map_err(io::Error::other)?
                })
                .await?;
            // Google Cloud DNS API v1 and OAuth 2.0 endpoints are https; verify the server certificate (RFC 6125).
            let stream = TlsConnector::from(Arc::clone(config))
                .connect(name, tcp)
                .await?;
            send(TokioIo::new(stream), hyper_request, self.max_body).await
        } else {
            send(TokioIo::new(tcp), hyper_request, self.max_body).await
        }
    }
}

async fn send<I>(io: I, request: HyperRequest<Full<Bytes>>, max_body: usize) -> io::Result<Response>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(io).await.map_err(io::Error::other)?;
    tokio::spawn(connection);
    let response = sender
        .send_request(request)
        .await
        .map_err(io::Error::other)?;
    let (parts, mut incoming) = response.into_parts();
    let mut body = Vec::new();
    while let Some(frame) = incoming.frame().await {
        if let Ok(data) = frame.map_err(io::Error::other)?.into_data() {
            if body.len() + data.len() > max_body {
                return Err(io::Error::other("response is too large"));
            }
            body.extend_from_slice(&data);
        }
    }
    Ok(Response {
        status: parts.status.as_u16(),
        body,
    })
}

/// WHATWG URL §5.1 `application/x-www-form-urlencoded` serializer: RFC 6749 Appendix B.
pub(crate) fn form_encode(fields: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        push_encoded(&mut out, name, true);
        out.push('=');
        push_encoded(&mut out, value, true);
    }
    out
}

/// RFC 3986 §3.3: a path segment keeps unreserved characters and `:` unescaped (Go's `url.PathEscape`).
pub(crate) fn path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    push_encoded(&mut out, segment, false);
    out
}

fn push_encoded(out: &mut String, text: &str, form: bool) {
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            b':' if !form => out.push(':'),
            b' ' if form => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
}

#[cfg(test)]
mod tests;

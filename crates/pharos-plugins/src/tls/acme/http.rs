//! The HTTP/1.1 client an ACME client needs: one connection per request, TLS verified against the configured roots.

use std::{io, str::FromStr, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Method, Request, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use pharos_server::tls::{ClientConfig, ServerName, TlsConnector};
use tokio::{net::TcpStream, time::timeout};

// RFC 8555 §6.1: responses are small JSON documents or certificate chains; bound them against a hostile CA.
const MAX_BODY: usize = 1 << 20;
const TIMEOUT: Duration = Duration::from_secs(30);

/// An `http` or `https` URL with a host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Url {
    pub https: bool,
    /// The host without brackets.
    pub host: String,
    pub port: u16,
    /// The path and query, always starting with `/`.
    pub target: String,
}

impl FromStr for Url {
    type Err = ();

    // RFC 3986 §3: scheme "://" authority path-abempty ["?" query]; fragments and userinfo are not used by ACME.
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

/// A complete HTTP response.
pub(crate) struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Response {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }
}

/// Where ACME requests go and whom they trust.
#[derive(Clone)]
pub(crate) struct Http {
    tls: Arc<ClientConfig>,
}

impl Http {
    pub(crate) fn new(tls: Arc<ClientConfig>) -> Self {
        Self { tls }
    }

    /// Send one request; redirects are not followed (RFC 8555 §6.1 names no redirect semantics).
    pub(crate) async fn request(
        &self,
        method: Method,
        url: &str,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> io::Result<Response> {
        let url: Url = url.parse().map_err(|()| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid URL {url:?}"))
        })?;
        timeout(TIMEOUT, self.exchange(method, &url, content_type, body))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ACME request timed out"))?
    }

    async fn exchange(
        &self,
        method: Method,
        url: &Url,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> io::Result<Response> {
        let tcp = TcpStream::connect((url.host.as_str(), url.port)).await?;
        let mut request = Request::builder()
            .method(method)
            .uri(&url.target)
            .header(header::HOST, url.authority())
            // RFC 8555 §6.1: clients SHOULD send a User-Agent identifying the implementation.
            .header(
                header::USER_AGENT,
                concat!("pharos/", env!("CARGO_PKG_VERSION")),
            )
            .header(
                header::ACCEPT,
                "application/json, application/pem-certificate-chain",
            );
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        let request = request
            .body(Full::new(Bytes::from(body)))
            .map_err(io::Error::other)?;
        let response = if url.https {
            let name = ServerName::try_from(url.host.clone()).map_err(io::Error::other)?;
            // RFC 8555 §6.1: ACME clients verify the server's certificate.
            let stream = TlsConnector::from(Arc::clone(&self.tls))
                .connect(name, tcp)
                .await?;
            send(TokioIo::new(stream), request).await?
        } else {
            send(TokioIo::new(tcp), request).await?
        };
        Ok(response)
    }
}

async fn send<I>(io: I, request: Request<Full<Bytes>>) -> io::Result<Response>
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
            if body.len() + data.len() > MAX_BODY {
                return Err(io::Error::other("ACME response is too large"));
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
    fn parses_scheme_host_port_and_target() {
        let url: Url = "https://ca.example/directory".parse().unwrap();
        assert_eq!(
            url,
            Url {
                https: true,
                host: "ca.example".into(),
                port: 443,
                target: "/directory".into()
            }
        );
        let url: Url = "http://[::1]:14000/dir?x=1".parse().unwrap();
        assert_eq!(
            (url.https, url.host.as_str(), url.port),
            (false, "::1", 14000)
        );
        assert_eq!(url.target, "/dir?x=1");
        assert_eq!("https://ca.example".parse::<Url>().unwrap().target, "/");
    }

    #[test]
    fn rejects_other_schemes_and_malformed_authorities() {
        for url in [
            "ftp://ca.example",
            "https://",
            "https:///x",
            "https://u@ca.example",
            "https://ca.example:0",
            "https://ca.example:x",
            "https://[::1",
            "ca.example",
        ] {
            assert!(url.parse::<Url>().is_err(), "{url}");
        }
    }
}

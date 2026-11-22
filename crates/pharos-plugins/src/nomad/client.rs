//! The Nomad HTTP API client: `GET /v1/service/<name>` against one of several endpoints.

use std::{
    fmt, io,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{
    Request,
    client::conn::http1::{self, SendRequest},
    header::{self, HeaderName, HeaderValue},
};
use hyper_util::rt::TokioIo;
use pharos_server::tls::{ClientConfig, ServerName, TlsConnector};
use tokio::{
    net::{TcpStream, UnixStream},
    time::timeout,
};

use super::{
    escape,
    registration::{self, Registration},
};

/// The largest reply body read; a Nomad service listing is far smaller.
const MAX_BODY: usize = 8 << 20;
/// Hashicorp nomad api v1.10.5 api/api.go has no timeout; one request here ends after this long.
const TIMEOUT: Duration = Duration::from_secs(5);
// shortcut: idle connections are never aged out, only dropped when the peer closes them; add an idle timeout if Nomad sits behind a proxy that holds them half-open.
const MAX_IDLE: usize = 8;

const TOKEN_HEADER: HeaderName = HeaderName::from_static("x-nomad-token");

/// What a failed lookup says; it never contains the token or other credentials.
#[derive(Debug)]
pub(super) enum Error {
    Io(io::Error),
    Http(hyper::Error),
    Timeout,
    /// Hashicorp nomad api v1.10.5 api/api.go `requireOK`: only 200 is success.
    Status(u16),
    TooLarge,
    /// Where the body went wrong. serde's own message quotes the offending value, which Nomad chose, so it is dropped.
    Decode {
        line: usize,
        column: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "connection failed: {error}"),
            Self::Http(error) => write!(f, "HTTP exchange failed: {error}"),
            Self::Timeout => f.write_str("request timed out"),
            Self::Status(status) => write!(f, "unexpected response code: {status}"),
            Self::TooLarge => f.write_str("response body too large"),
            Self::Decode { line, column } => {
                write!(f, "invalid response body at line {line} column {column}")
            }
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Credentials and TLS settings shared by every endpoint.
#[derive(Default)]
pub(super) struct Options {
    pub(super) token: Option<String>,
    pub(super) region: Option<String>,
    /// `user:password`.
    pub(super) basic_auth: Option<String>,
    pub(super) tls: Option<Arc<ClientConfig>>,
    pub(super) tls_server_name: Option<String>,
}

// The token and password stay out of Debug output.
impl fmt::Debug for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options").finish_non_exhaustive()
    }
}

impl Options {
    /// Hashicorp nomad api v1.10.5 api/api.go `DefaultConfig`: the `NOMAD_*` environment, minus what a Corefile `token` overrides.
    pub(super) fn from_env(
        env: &dyn Fn(&str) -> Option<String>,
        token: Option<String>,
        https: bool,
    ) -> Result<Self, String> {
        let get = |name: &str| env(name).filter(|value| !value.is_empty());
        for unsupported in ["NOMAD_SKIP_VERIFY", "NOMAD_CAPATH"] {
            if get(unsupported).is_some() {
                return Err(format!("{unsupported} is not supported"));
            }
        }
        let tls = if https {
            let identity = match (get("NOMAD_CLIENT_CERT"), get("NOMAD_CLIENT_KEY")) {
                (Some(cert), Some(key)) => Some((cert.into(), key.into())),
                (None, None) => None,
                _ => return Err("NOMAD_CLIENT_CERT and NOMAD_CLIENT_KEY go together".to_owned()),
            };
            let options = pharos_server::tls::ClientOptions {
                ca: get("NOMAD_CACERT").map(Into::into),
                identity,
            };
            Some(pharos_server::tls::client_config(&options).map_err(|error| error.to_string())?)
        } else {
            None
        };
        Ok(Self {
            token: token.or_else(|| get("NOMAD_TOKEN")),
            region: get("NOMAD_REGION"),
            basic_auth: get("NOMAD_HTTP_AUTH"),
            tls,
            tls_server_name: get("NOMAD_TLS_SERVER_NAME"),
        })
    }
}

enum Transport {
    Tcp { host: String, port: u16, tls: bool },
    Unix(PathBuf),
}

struct Endpoint {
    transport: Transport,
    /// The `Host` header: the address authority as written.
    host: String,
    idle: Mutex<Vec<SendRequest<Empty<Bytes>>>>,
}

impl Endpoint {
    // Hashicorp nomad api v1.10.5 api/api.go NewClient: `http`, `https` and `unix` addresses; a `unix` one talks HTTP to `127.0.0.1`.
    fn parse(address: &str) -> Result<Self, String> {
        if let Some(path) = address.strip_prefix("unix://") {
            if !path.starts_with('/') {
                return Err("a unix address needs an absolute socket path".to_owned());
            }
            return Ok(Self::new(
                Transport::Unix(path.into()),
                "127.0.0.1".to_owned(),
            ));
        }
        let (tls, rest) = if let Some(rest) = address.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = address.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err("an address starts with http://, https:// or unix://".to_owned());
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err("credentials in an address are not supported".to_owned());
        }
        // Go drops the path of the address; refuse one rather than ignore it silently.
        if !(tail.is_empty() || tail == "/") {
            return Err("an address has no path, query or fragment".to_owned());
        }
        let default = if tls { 443 } else { 80 };
        // RFC 3986 §3.2.2 and §3.2.3: an IP literal is bracketed, the port is decimal.
        let (host, port) = match authority.strip_prefix('[') {
            Some(bracketed) => {
                let (host, tail) = bracketed
                    .split_once(']')
                    .ok_or("unterminated IPv6 literal")?;
                match tail.strip_prefix(':') {
                    Some(port) => (host, port),
                    None if tail.is_empty() => (host, ""),
                    None => return Err("invalid host".to_owned()),
                }
            }
            None => authority.split_once(':').unwrap_or((authority, "")),
        };
        let port = if port.is_empty() && !authority.ends_with(':') {
            default
        } else {
            port.parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or("invalid port")?
        };
        if host.is_empty() {
            return Err("an address needs a host".to_owned());
        }
        Ok(Self::new(
            Transport::Tcp {
                host: host.to_owned(),
                port,
                tls,
            },
            authority.to_owned(),
        ))
    }

    fn new(transport: Transport, host: String) -> Self {
        Self {
            transport,
            host,
            idle: Mutex::new(Vec::new()),
        }
    }

    async fn take_idle(&self) -> Option<SendRequest<Empty<Bytes>>> {
        loop {
            let mut sender = self.idle.lock().unwrap().pop()?;
            if sender.ready().await.is_ok() {
                return Some(sender);
            }
        }
    }

    fn give_back(&self, sender: SendRequest<Empty<Bytes>>) {
        let mut idle = self.idle.lock().unwrap();
        if idle.len() < MAX_IDLE && !sender.is_closed() {
            idle.push(sender);
        }
    }
}

/// Every configured Nomad endpoint and the one that answered last.
pub(super) struct Client {
    endpoints: Vec<Endpoint>,
    current: AtomicUsize,
    token: Option<HeaderValue>,
    basic_auth: Option<HeaderValue>,
    region: Option<String>,
    tls: Option<Arc<ClientConfig>>,
    tls_server_name: Option<ServerName<'static>>,
    timeout: Duration,
    max_body: usize,
}

// The token and password stay out of Debug output.
impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("endpoints", &self.endpoints.len())
            .finish_non_exhaustive()
    }
}

impl Client {
    pub(super) fn new(addresses: &[String], options: Options) -> Result<Self, String> {
        let endpoints = addresses
            .iter()
            .map(|address| {
                Endpoint::parse(address).map_err(|error| format!("invalid address: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let tls_needed = endpoints
            .iter()
            .any(|endpoint| matches!(endpoint.transport, Transport::Tcp { tls: true, .. }));
        if endpoints.is_empty() || (tls_needed && options.tls.is_none()) {
            return Err("no usable endpoint".to_owned());
        }
        // Hashicorp nomad api v1.10.5 api/api.go toHTTP: the token travels in `X-Nomad-Token`.
        let token = options
            .token
            .map(|token| header_value(&token, "token"))
            .transpose()?;
        // Hashicorp nomad api v1.10.5 api/api.go toHTTP: `SetBasicAuth`, RFC 7617 §2.
        let basic_auth = options
            .basic_auth
            .map(|auth| {
                header_value(
                    &format!("Basic {}", base64(auth.as_bytes())),
                    "NOMAD_HTTP_AUTH",
                )
            })
            .transpose()?;
        let tls_server_name = options
            .tls_server_name
            .map(|name| {
                ServerName::try_from(name).map_err(|_| "invalid NOMAD_TLS_SERVER_NAME".to_owned())
            })
            .transpose()?;
        Ok(Self {
            endpoints,
            current: AtomicUsize::new(0),
            token,
            basic_auth,
            region: options.region,
            tls: options.tls,
            tls_server_name,
            timeout: TIMEOUT,
            max_body: MAX_BODY,
        })
    }

    /// The registrations of one service. Endpoints are tried from the last good one onwards; the first to answer becomes the current one.
    pub(super) async fn registrations(
        &self,
        service: &[u8],
        namespace: &[u8],
        filter: &str,
    ) -> Result<Vec<Registration>, Error> {
        let target = self.target(service, namespace, filter);
        let start = self.current.load(Ordering::Relaxed);
        let mut last = Error::Timeout;
        for step in 0..self.endpoints.len() {
            let index = (start + step) % self.endpoints.len();
            match self.get(&self.endpoints[index], &target).await {
                Ok(registrations) => {
                    self.current.store(index, Ordering::Relaxed);
                    return Ok(registrations);
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    // Hashicorp nomad api v1.10.5 api/services.go Get: `/v1/service/` + `url.PathEscape(name)`; params are `url.Values.Encode`d, so sorted by key.
    fn target(&self, service: &[u8], namespace: &[u8], filter: &str) -> String {
        let mut target = String::from("/v1/service/");
        escape::path_segment(&mut target, service);
        if !filter.is_empty() {
            target.push_str("?filter=");
            escape::query_component(&mut target, filter.as_bytes());
        }
        target.push(if filter.is_empty() { '?' } else { '&' });
        target.push_str("namespace=");
        escape::query_component(&mut target, namespace);
        if let Some(region) = &self.region {
            target.push_str("&region=");
            escape::query_component(&mut target, region.as_bytes());
        }
        target
    }

    async fn get(&self, endpoint: &Endpoint, target: &str) -> Result<Vec<Registration>, Error> {
        let body = self.fetch(endpoint, target).await?;
        registration::decode(&body).map_err(|error| Error::Decode {
            line: error.line(),
            column: error.column(),
        })
    }

    async fn fetch(&self, endpoint: &Endpoint, target: &str) -> Result<Vec<u8>, Error> {
        let (status, body) = timeout(self.timeout, self.exchange(endpoint, target))
            .await
            .map_err(|_| Error::Timeout)??;
        if status != 200 {
            return Err(Error::Status(status));
        }
        Ok(body)
    }

    /// Whether any endpoint answers `/v1/agent/self`, trying them from the last good one onwards.
    // CoreDNS v1.15.0 plugin/nomad/setup.go getClient: `Agent().Self()` decodes a JSON body after `requireOK`.
    pub(super) async fn probe(&self) -> bool {
        let mut target = String::from("/v1/agent/self");
        if let Some(region) = &self.region {
            target.push_str("?region=");
            escape::query_component(&mut target, region.as_bytes());
        }
        let start = self.current.load(Ordering::Relaxed);
        for step in 0..self.endpoints.len() {
            let index = (start + step) % self.endpoints.len();
            let answered = match self.fetch(&self.endpoints[index], &target).await {
                Ok(body) => serde_json::from_slice::<serde::de::IgnoredAny>(&body).is_ok(),
                Err(_) => false,
            };
            if answered {
                self.current.store(index, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    pub(super) fn endpoints(&self) -> usize {
        self.endpoints.len()
    }

    async fn exchange(&self, endpoint: &Endpoint, target: &str) -> Result<(u16, Vec<u8>), Error> {
        // An idle connection may have been closed by the peer since it was parked; that fails before any reply, so try a fresh one once.
        if let Some(sender) = endpoint.take_idle().await {
            match self.send(endpoint, sender, target).await {
                Err(Error::Http(_) | Error::Io(_)) => {}
                result => return result,
            }
        }
        let sender = self.connect(endpoint).await?;
        self.send(endpoint, sender, target).await
    }

    async fn connect(&self, endpoint: &Endpoint) -> Result<SendRequest<Empty<Bytes>>, Error> {
        match &endpoint.transport {
            Transport::Unix(path) => handshake(UnixStream::connect(path).await?).await,
            Transport::Tcp { host, port, tls } => {
                let tcp = TcpStream::connect((host.as_str(), *port)).await?;
                let _ = tcp.set_nodelay(true);
                if !*tls {
                    return handshake(tcp).await;
                }
                let name = match &self.tls_server_name {
                    Some(name) => name.clone(),
                    None => ServerName::try_from(host.clone()).map_err(io::Error::other)?,
                };
                let config = self.tls.clone().expect("checked in Client::new");
                handshake(TlsConnector::from(config).connect(name, tcp).await?).await
            }
        }
    }

    async fn send(
        &self,
        endpoint: &Endpoint,
        mut sender: SendRequest<Empty<Bytes>>,
        target: &str,
    ) -> Result<(u16, Vec<u8>), Error> {
        let mut request = Request::get(target)
            .header(header::HOST, &endpoint.host)
            .header(
                header::USER_AGENT,
                concat!("pharos/", env!("CARGO_PKG_VERSION")),
            )
            .body(Empty::new())
            .map_err(|error| Error::Io(io::Error::other(error)))?;
        let headers = request.headers_mut();
        if let Some(auth) = &self.basic_auth {
            headers.insert(header::AUTHORIZATION, auth.clone());
        }
        if let Some(token) = &self.token {
            headers.insert(TOKEN_HEADER, token.clone());
        }
        let response = sender.send_request(request).await.map_err(Error::Http)?;
        let (parts, mut incoming) = response.into_parts();
        let mut body = Vec::new();
        while let Some(frame) = incoming.frame().await {
            if let Ok(data) = frame.map_err(Error::Http)?.into_data() {
                // Bound the reply against a hostile or broken endpoint.
                if body.len() + data.len() > self.max_body {
                    return Err(Error::TooLarge);
                }
                body.extend_from_slice(&data);
            }
        }
        endpoint.give_back(sender);
        Ok((parts.status.as_u16(), body))
    }
}

async fn handshake<I>(io: I) -> Result<SendRequest<Empty<Bytes>>, Error>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = http1::handshake(TokioIo::new(io))
        .await
        .map_err(Error::Http)?;
    tokio::spawn(connection);
    Ok(sender)
}

fn header_value(text: &str, what: &str) -> Result<HeaderValue, String> {
    let mut value = HeaderValue::from_str(text)
        .map_err(|_| format!("{what} is not valid in an HTTP header"))?;
    value.set_sensitive(true);
    Ok(value)
}

// RFC 4648 §4: standard base64 with padding.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for (index, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[(group >> shift & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;

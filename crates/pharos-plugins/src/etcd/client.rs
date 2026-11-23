//! An etcd v3 gRPC client: `Range`, `LeaseTimeToLive` and `Watch`, with endpoint failover and
//! password authentication.
//!
//! The calls are hand-written protobuf over HTTP/2 (see [`proto`]), like `pharos_server::grpc`
//! does for `DnsPacket`; neither tonic nor prost is needed.

pub mod proto;
mod transport;

use std::{
    fmt,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use pharos_server::{
    grpc::{self, Code},
    tls::{ClientConfig, ClientOptions, ServerName, client_config},
};
use tokio::time::{Instant, timeout};

pub use proto::{KeyValue, RangeResponse, WatchResponse};
use transport::{Connection, Op, Reply, Security, Streaming, frame};

use super::{Config, Credentials};

/// CoreDNS v1.15.0 plugin/etcd/etcd.go `etcdTimeout`: the time one call may take, failover included.
pub const ETCD_TIMEOUT: Duration = Duration::from_secs(5);

/// How long an endpoint that failed is tried last.
// shortcut: a fixed one second where etcd clientv3's balancer probes unhealthy addresses on its own schedule; make it adaptive if probes cost too much.
pub const ENDPOINT_BACKOFF: Duration = Duration::from_secs(1);

const RANGE: &str = "/etcdserverpb.KV/Range";
const LEASE_TIME_TO_LIVE: &str = "/etcdserverpb.Lease/LeaseTimeToLive";
const AUTHENTICATE: &str = "/etcdserverpb.Auth/Authenticate";
const WATCH: &str = "/etcdserverpb.Watch/Watch";

/// Why a call failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// etcd answered with a gRPC status other than OK.
    Status { code: Code, message: String },
    /// No endpoint could be reached, or the connection broke.
    Unavailable(String),
    /// The call did not finish within its time.
    Timeout,
    /// etcd sent something that is not a valid gRPC reply.
    Protocol(String),
    /// The client was stopped.
    Stopped,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status { code, message } => write!(f, "etcd status {code:?}: {message}"),
            Self::Unavailable(reason) => write!(f, "etcd unavailable: {reason}"),
            Self::Timeout => f.write_str("etcd call timed out"),
            Self::Protocol(reason) => write!(f, "etcd protocol error: {reason}"),
            Self::Stopped => f.write_str("etcd client stopped"),
        }
    }
}

impl std::error::Error for Error {}

impl From<proto::DecodeError> for Error {
    fn from(error: proto::DecodeError) -> Self {
        Self::Protocol(error.to_string())
    }
}

impl Error {
    /// Whether another endpoint may answer where this one did not.
    fn fails_over(&self) -> bool {
        match self {
            // etcd clientv3 retry.go: `Unavailable` is retried on another endpoint for reads.
            Self::Status { code, .. } => matches!(code, Code::Unavailable | Code::DeadlineExceeded),
            Self::Unavailable(_) | Self::Timeout | Self::Protocol(_) => true,
            Self::Stopped => false,
        }
    }

    /// etcd clientv3 retry_interceptor.go: the token is refreshed on `ErrInvalidAuthToken` and `ErrAuthOldRevision`.
    fn refreshes_token(&self) -> bool {
        matches!(self, Self::Status { code, message }
            if *code == Code::Unauthenticated
                || message == "etcdserver: revision of auth store is old")
    }
}

/// The times that bound a call; tests shorten them.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// The time one call may take, failover included.
    pub call: Duration,
    /// How long an endpoint that failed is tried last.
    pub backoff: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            call: ETCD_TIMEOUT,
            backoff: ENDPOINT_BACKOFF,
        }
    }
}

/// A client of one etcd cluster. It dials on first use and makes no connection when created.
pub struct Client {
    connections: Vec<Connection>,
    /// The endpoint that answered last; the next call starts there.
    last_good: AtomicUsize,
    credentials: Option<Credentials>,
    token: Mutex<Option<Arc<str>>>,
    authenticating: tokio::sync::Mutex<()>,
    timeouts: Timeouts,
    stopped: AtomicBool,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("endpoints", &self.connections.len())
            .finish_non_exhaustive()
    }
}

impl Client {
    #[must_use]
    pub fn new(config: &Config) -> Self {
        Self::with_timeouts(config, Timeouts::default())
    }

    #[must_use]
    pub fn with_timeouts(config: &Config, timeouts: Timeouts) -> Self {
        // etcd clientv3 endpoint.go: an endpoint that needs TLS but has no `tls` Directive verifies against the system roots.
        let fallback = config
            .endpoints
            .iter()
            .any(|endpoint| endpoint.tls)
            .then(|| config.tls.clone().map_or_else(system_roots, Ok));
        let connections = config
            .endpoints
            .iter()
            .map(|endpoint| {
                let security = match (endpoint.tls, &fallback) {
                    (false, _) | (true, None) => Security::Plain,
                    (true, Some(Err(reason))) => Security::Broken(reason.clone()),
                    (true, Some(Ok(tls))) => match ServerName::try_from(endpoint.host.clone()) {
                        Ok(name) => Security::Tls {
                            config: tls.clone(),
                            name,
                        },
                        Err(error) => Security::Broken(error.to_string()),
                    },
                };
                Connection::new(&endpoint.host, endpoint.port, security)
            })
            .collect();
        Self {
            connections,
            last_good: AtomicUsize::new(0),
            credentials: config.credentials.clone(),
            token: Mutex::new(None),
            authenticating: tokio::sync::Mutex::new(()),
            timeouts,
            stopped: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    /// Close every connection and refuse new calls; open watches end.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        for connection in &self.connections {
            connection.reset();
        }
    }

    /// `KV/Range` of `key` alone, or of every key that starts with `key` when `prefix` is set.
    ///
    /// # Errors
    ///
    /// [`Error`] when no endpoint answered in time or etcd refused the call.
    pub async fn range(&self, key: &[u8], prefix: bool) -> Result<RangeResponse, Error> {
        let end = if prefix { prefix_end(key) } else { Vec::new() };
        let message = frame(&proto::range_request(key, &end, false));
        let reply = self
            .call(&Op::Unary {
                path: RANGE,
                message: &message,
            })
            .await?;
        Ok(proto::range_response(&reply.unary()?)?)
    }

    /// `Lease/LeaseTimeToLive`: the remaining seconds of lease `id`, -1 when it does not exist.
    ///
    /// # Errors
    ///
    /// [`Error`] when no endpoint answered in time or etcd refused the call.
    pub async fn lease_ttl(&self, id: i64) -> Result<i64, Error> {
        let message = frame(&proto::lease_time_to_live_request(id));
        let reply = self
            .call(&Op::Unary {
                path: LEASE_TIME_TO_LIVE,
                message: &message,
            })
            .await?;
        Ok(proto::lease_time_to_live_response(&reply.unary()?)?.ttl)
    }

    /// Open a `Watch/Watch` stream with one watcher on `key`, or on every key that starts with it
    /// when `prefix` is set, from the next revision. The first message of the stream acknowledges it.
    ///
    /// # Errors
    ///
    /// [`Error`] when no endpoint accepted the stream in time or etcd refused it.
    pub async fn watch(&self, key: &[u8], prefix: bool) -> Result<Watch, Error> {
        let end = if prefix { prefix_end(key) } else { Vec::new() };
        let first = frame(&proto::watch_create_request(key, &end));
        match self
            .call(&Op::Stream {
                path: WATCH,
                first: &first,
            })
            .await?
        {
            Reply::Stream(stream) => Ok(Watch { stream }),
            Reply::Unary(_) => Err(Error::Protocol("unary reply to a stream".into())),
        }
    }

    async fn call(&self, op: &Op<'_>) -> Result<Reply, Error> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::Stopped);
        }
        let deadline = Instant::now() + self.timeouts.call;
        let mut refreshed = false;
        loop {
            let token = match &self.credentials {
                Some(credentials) => Some(self.token(credentials, deadline).await?),
                None => None,
            };
            match self.dispatch(op, token.as_deref(), deadline).await {
                // etcd clientv3 retry_interceptor.go: authenticate again once and repeat the call.
                Err(error) if token.is_some() && !refreshed && error.refreshes_token() => {
                    refreshed = true;
                    self.forget(token.as_deref().unwrap_or_default());
                }
                result => return result,
            }
        }
    }

    /// The auth token, from `Authenticate` when there is none.
    async fn token(&self, credentials: &Credentials, deadline: Instant) -> Result<Arc<str>, Error> {
        if let Some(token) = lock(&self.token).clone() {
            return Ok(token);
        }
        // Calls that need a token together make one `Authenticate` between them.
        let _turn = self.authenticating.lock().await;
        if let Some(token) = lock(&self.token).clone() {
            return Ok(token);
        }
        let message = frame(&proto::authenticate_request(
            &credentials.username,
            &credentials.password,
        ));
        let reply = self
            .dispatch(
                &Op::Unary {
                    path: AUTHENTICATE,
                    message: &message,
                },
                None,
                deadline,
            )
            .await?;
        let token: Arc<str> = proto::authenticate_response(&reply.unary()?)?.into();
        *lock(&self.token) = Some(token.clone());
        Ok(token)
    }

    fn forget(&self, stale: &str) {
        let mut token = lock(&self.token);
        if token.as_deref() == Some(stale) {
            *token = None;
        }
    }

    /// The endpoints in the order to try: from the last good one, those that failed recently last.
    fn order(&self) -> Vec<usize> {
        let count = self.connections.len();
        let start = self.last_good.load(Ordering::Relaxed) % count.max(1);
        let now = Instant::now();
        let (mut up, down): (Vec<_>, Vec<_>) = (0..count)
            .map(|offset| (start + offset) % count)
            .partition(|&index| !self.connections[index].is_down(now));
        up.extend(down);
        up
    }

    /// Run `op` on the first endpoint that answers.
    async fn dispatch(
        &self,
        op: &Op<'_>,
        token: Option<&str>,
        deadline: Instant,
    ) -> Result<Reply, Error> {
        let order = self.order();
        let mut failure = Error::Unavailable("no etcd endpoint".into());
        for (attempt, &index) in order.iter().enumerate() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Error::Timeout);
            }
            // The endpoints that are left share the time that is left, so one that hangs cannot use it all.
            let share = remaining / (order.len() - attempt) as u32;
            let connection = &self.connections[index];
            match timeout(share, connection.execute(op, token, Instant::now() + share)).await {
                Ok(Ok(reply)) => {
                    self.last_good.store(index, Ordering::Relaxed);
                    connection.recovered();
                    return Ok(reply);
                }
                Ok(Err(error)) if error.fails_over() => {
                    connection.failed(self.timeouts.backoff);
                    failure = error;
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    connection.reset();
                    connection.failed(self.timeouts.backoff);
                    failure = Error::Timeout;
                }
            }
        }
        Err(failure)
    }
}

impl Reply {
    fn unary(self) -> Result<Bytes, Error> {
        match self {
            Self::Unary(message) => Ok(message),
            Self::Stream(_) => Err(Error::Protocol("stream reply to a unary call".into())),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The configuration of an endpoint that needs TLS when the Directive has no `tls`: the system roots, ALPN `h2`.
fn system_roots() -> Result<Arc<ClientConfig>, String> {
    let config = client_config(&ClientOptions::default()).map_err(|error| error.to_string())?;
    let mut config = (*config).clone();
    config.alpn_protocols = grpc::ALPN
        .iter()
        .map(|protocol| protocol.to_vec())
        .collect();
    Ok(Arc::new(config))
}

/// etcd clientv3 op.go `getPrefix`: the key that follows every key which starts with `key`.
fn prefix_end(key: &[u8]) -> Vec<u8> {
    let mut end = key.to_vec();
    while let Some(last) = end.last_mut() {
        if *last < 0xff {
            *last += 1;
            return end;
        }
        end.pop();
    }
    // etcd rpc.proto RangeRequest: `\0` is every key from `key`, and so is the range of a prefix with no end.
    vec![0]
}

/// A watch stream, which delivers a [`WatchResponse`] for each message of the server.
pub struct Watch {
    stream: Streaming,
}

impl Watch {
    /// The next response, or `None` when the server ended the stream normally.
    ///
    /// # Errors
    ///
    /// [`Error`] when the stream broke or a message is invalid.
    pub async fn next(&mut self) -> Result<Option<WatchResponse>, Error> {
        match self.stream.message().await? {
            Some(message) => Ok(Some(proto::watch_response(&message)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests;

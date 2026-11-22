//! A stub etcd v3 server for tests: gRPC over HTTP/2 on a local TCP port, with TLS on request.
//!
//! It implements the calls the `etcd` Plugin makes (`KV/Range`, `Lease/LeaseTimeToLive`,
//! `Auth/Authenticate`, `Watch/Watch`) over an in-memory store with revisions, and lets a test
//! change data, turn authentication on, hang or fail every call, and drop every connection. It is
//! `#[path]`-included by unit tests and by integration tests, so it names no item of the crate.
//!
//! Its protobuf codec is written separately from the client's, so a mistake in one shows up in the other.
#![allow(dead_code)]

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::{
    HeaderMap, Request, Response,
    body::{Body, Frame, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pharos_server::{
    grpc::{self, Code},
    tls::{ClientAuth, ServerOptions, ServerTls},
};
use tokio::{net::TcpListener, sync::mpsc, task::AbortHandle};

pub const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

/// What the stub does with every call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Normal,
    /// Accept the call and never answer.
    Hang,
    /// Answer every call but `Authenticate` with this gRPC status.
    Fail(Code),
}

/// A request the stub received.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: &'static str,
    pub headers: HeaderMap,
}

#[derive(Clone)]
struct Kv {
    value: Vec<u8>,
    create_revision: i64,
    mod_revision: i64,
    version: i64,
    lease: i64,
}

struct Watcher {
    stream: u64,
    id: i64,
    key: Vec<u8>,
    range_end: Vec<u8>,
    tx: mpsc::UnboundedSender<Bytes>,
}

struct Store {
    revision: i64,
    kvs: BTreeMap<Vec<u8>, Kv>,
    // Lease ID to remaining TTL; an ID that is absent has expired.
    leases: HashMap<i64, i64>,
    watchers: Vec<Watcher>,
}

struct Auth {
    user: String,
    password: String,
    tokens: HashSet<String>,
}

struct State {
    store: Mutex<Store>,
    auth: Mutex<Option<Auth>>,
    mode: Mutex<Mode>,
    calls: Mutex<HashMap<&'static str, usize>>,
    seen: Mutex<Vec<Seen>>,
    connections: Mutex<Vec<AbortHandle>>,
    watch_down: AtomicBool,
    range_delay: Mutex<Duration>,
    accepted: AtomicUsize,
    tokens_issued: AtomicU64,
    streams: AtomicU64,
}

pub struct EtcdStub {
    pub address: SocketAddr,
    state: Arc<State>,
    acceptor: AbortHandle,
}

impl Drop for EtcdStub {
    fn drop(&mut self) {
        self.acceptor.abort();
        self.drop_connections();
    }
}

impl EtcdStub {
    pub async fn start() -> Self {
        Self::bind(false).await
    }

    /// A stub that speaks TLS with the `tests/fixtures/tls` server certificate, valid for `localhost` and `127.0.0.1`.
    pub async fn start_tls() -> Self {
        Self::bind(true).await
    }

    async fn bind(tls: bool) -> Self {
        let acceptor = tls.then(|| {
            ServerTls::load(&ServerOptions {
                cert: format!("{FIXTURES}/server.pem").into(),
                key: format!("{FIXTURES}/server.key.pem").into(),
                ca: None,
                client_auth: ClientAuth::NoCert,
                keylog: None,
            })
            .unwrap()
            .with_alpn(grpc::ALPN)
            .acceptor()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state = Arc::new(State {
            store: Mutex::new(Store {
                revision: 1,
                kvs: BTreeMap::new(),
                leases: HashMap::new(),
                watchers: Vec::new(),
            }),
            auth: Mutex::new(None),
            mode: Mutex::new(Mode::Normal),
            calls: Mutex::default(),
            seen: Mutex::default(),
            connections: Mutex::default(),
            watch_down: AtomicBool::new(false),
            range_delay: Mutex::new(Duration::ZERO),
            accepted: AtomicUsize::new(0),
            tokens_issued: AtomicU64::new(0),
            streams: AtomicU64::new(0),
        });
        let address = listener.local_addr().unwrap();
        let shared = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                shared.accepted.fetch_add(1, Ordering::SeqCst);
                let (state, acceptor) = (shared.clone(), acceptor.clone());
                let connection = tokio::spawn(async move {
                    match acceptor {
                        Some(acceptor) => {
                            if let Ok(stream) = acceptor.accept(tcp).await {
                                serve_connection(stream, state).await;
                            }
                        }
                        None => serve_connection(tcp, state).await,
                    }
                });
                shared
                    .connections
                    .lock()
                    .unwrap()
                    .push(connection.abort_handle());
            }
        });
        Self {
            address,
            state,
            acceptor: task.abort_handle(),
        }
    }

    /// `http://127.0.0.1:PORT`, or `https://` for a TLS stub.
    pub fn endpoint(&self, tls: bool) -> String {
        format!("{}://{}", if tls { "https" } else { "http" }, self.address)
    }

    pub fn put(&self, key: &str, value: &str) -> i64 {
        self.put_lease(key, value, 0)
    }

    /// Store `value` under `key`, attached to lease `lease` (0 for none); returns the new revision.
    pub fn put_lease(&self, key: &str, value: &str, lease: i64) -> i64 {
        let mut store = self.state.store.lock().unwrap();
        store.revision += 1;
        let revision = store.revision;
        let previous = store.kvs.get(key.as_bytes()).cloned();
        let kv = Kv {
            value: value.as_bytes().to_vec(),
            create_revision: previous.as_ref().map_or(revision, |kv| kv.create_revision),
            mod_revision: revision,
            version: previous.map_or(1, |kv| kv.version + 1),
            lease,
        };
        store.kvs.insert(key.as_bytes().to_vec(), kv.clone());
        notify(&mut store, key.as_bytes(), Some(&kv), revision);
        revision
    }

    /// Delete `key`; returns whether it existed.
    pub fn delete(&self, key: &str) -> bool {
        let mut store = self.state.store.lock().unwrap();
        if store.kvs.remove(key.as_bytes()).is_none() {
            return false;
        }
        store.revision += 1;
        let revision = store.revision;
        notify(&mut store, key.as_bytes(), None, revision);
        true
    }

    /// Set the remaining TTL of lease `id`; the lease exists from now on.
    pub fn set_lease(&self, id: i64, ttl: i64) {
        self.state.store.lock().unwrap().leases.insert(id, ttl);
    }

    /// Expire lease `id`: `LeaseTimeToLive` answers -1 from now on.
    pub fn expire_lease(&self, id: i64) {
        self.state.store.lock().unwrap().leases.remove(&id);
    }

    /// Require the token `Authenticate` hands out for `user` and `password` on every other call.
    pub fn enable_auth(&self, user: &str, password: &str) {
        *self.state.auth.lock().unwrap() = Some(Auth {
            user: user.to_owned(),
            password: password.to_owned(),
            tokens: HashSet::new(),
        });
    }

    /// Make every token issued so far invalid, as an etcd token TTL does.
    pub fn expire_tokens(&self) {
        if let Some(auth) = self.state.auth.lock().unwrap().as_mut() {
            auth.tokens.clear();
        }
    }

    /// Refuse every new `Watch` call with `Unavailable` while `down`; other calls work.
    pub fn fail_watch(&self, down: bool) {
        self.state.watch_down.store(down, Ordering::SeqCst);
    }

    /// Hold every `Range` response back for `delay`; the data it carries is read before the wait.
    pub fn delay_range(&self, delay: Duration) {
        *self.state.range_delay.lock().unwrap() = delay;
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.state.mode.lock().unwrap() = mode;
    }

    /// Close every open connection, watch streams included; the stub keeps accepting new ones.
    pub fn drop_connections(&self) {
        for connection in self.state.connections.lock().unwrap().drain(..) {
            connection.abort();
        }
    }

    /// The calls of `method` (`Range`, `LeaseTimeToLive`, `Authenticate` or `Watch`) received so far.
    pub fn calls(&self, method: &str) -> usize {
        self.state
            .calls
            .lock()
            .unwrap()
            .get(method)
            .copied()
            .unwrap_or(0)
    }

    pub fn seen(&self, method: &str) -> Vec<Seen> {
        let seen = self.state.seen.lock().unwrap();
        seen.iter()
            .filter(|seen| seen.method == method)
            .cloned()
            .collect()
    }

    /// TCP connections accepted so far.
    pub fn accepted(&self) -> usize {
        self.state.accepted.load(Ordering::SeqCst)
    }

    /// Watchers that are registered and whose stream is still open.
    pub fn watchers(&self) -> usize {
        let mut store = self.state.store.lock().unwrap();
        store.watchers.retain(|watcher| !watcher.tx.is_closed());
        store.watchers.len()
    }
}

/// A local address nothing listens on, so a dial is refused at once.
pub async fn refused_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// etcd api/etcdserverpb/rpc.proto Range: `range_end` empty is the key alone, `\0` is every key from `key`, else `[key, range_end)`.
fn in_range(key: &[u8], start: &[u8], end: &[u8]) -> bool {
    match end {
        [] => key == start,
        [0] => key >= start,
        end => key >= start && key < end,
    }
}

fn notify(store: &mut Store, key: &[u8], put: Option<&Kv>, revision: i64) {
    let mut event = Vec::new();
    pb::int(&mut event, 1, i64::from(put.is_none()));
    let kv = match put {
        Some(kv) => kv_message(key, kv),
        None => {
            let mut deleted = Vec::new();
            pb::bytes(&mut deleted, 1, key);
            pb::int(&mut deleted, 3, revision);
            deleted
        }
    };
    pb::message(&mut event, 2, &kv);
    store.watchers.retain(|watcher| {
        if !in_range(key, &watcher.key, &watcher.range_end) {
            return !watcher.tx.is_closed();
        }
        let mut response = Vec::new();
        pb::message(&mut response, 1, &header(revision));
        pb::int(&mut response, 2, watcher.id);
        pb::message(&mut response, 11, &event);
        watcher.tx.send(frame(&response)).is_ok()
    });
}

fn header(revision: i64) -> Vec<u8> {
    let mut header = Vec::new();
    pb::int(&mut header, 3, revision);
    header
}

fn kv_message(key: &[u8], kv: &Kv) -> Vec<u8> {
    let mut out = Vec::new();
    pb::bytes(&mut out, 1, key);
    pb::int(&mut out, 2, kv.create_revision);
    pb::int(&mut out, 3, kv.mod_revision);
    pb::int(&mut out, 4, kv.version);
    pb::bytes(&mut out, 5, &kv.value);
    pb::int(&mut out, 6, kv.lease);
    out
}

/// PROTOCOL-HTTP2 "Length-Prefixed-Message": an uncompressed message.
fn frame(payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(grpc::HEADER_LEN + payload.len());
    out.extend_from_slice(&[0]);
    out.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(payload);
    out.freeze()
}

/// The response body: queued messages, then the `grpc-status` trailers once every sender is gone.
struct Out {
    messages: mpsc::UnboundedReceiver<Bytes>,
    trailers: Option<HeaderMap>,
}

impl Body for Out {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.messages.poll_recv(cx) {
            Poll::Ready(Some(message)) => Poll::Ready(Some(Ok(Frame::data(message)))),
            Poll::Ready(None) => Poll::Ready(
                self.trailers
                    .take()
                    .map(|trailers| Ok(Frame::trailers(trailers))),
            ),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn ok_trailers() -> HeaderMap {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().unwrap());
    trailers
}

/// PROTOCOL-HTTP2 "Responses": a failed call is a Trailers-Only response.
fn trailers_only(code: Code, message: &str) -> Response<Out> {
    let (_, messages) = mpsc::unbounded_channel();
    Response::builder()
        .header("content-type", grpc::CONTENT_TYPE)
        .header("grpc-status", (code as u8).to_string())
        .header("grpc-message", grpc::escape_message(message))
        .body(Out {
            messages,
            trailers: None,
        })
        .unwrap()
}

fn unary(payload: &[u8]) -> Response<Out> {
    let (tx, messages) = mpsc::unbounded_channel();
    tx.send(frame(payload)).unwrap();
    Response::builder()
        .header("content-type", grpc::CONTENT_TYPE)
        .body(Out {
            messages,
            trailers: Some(ok_trailers()),
        })
        .unwrap()
}

async fn serve_connection<T>(stream: T, state: Arc<State>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(handle(state, request).await) }
    });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

async fn handle(state: Arc<State>, request: Request<Incoming>) -> Response<Out> {
    let (parts, body) = request.into_parts();
    let method = match parts.uri.path() {
        "/etcdserverpb.KV/Range" => "Range",
        "/etcdserverpb.Lease/LeaseTimeToLive" => "LeaseTimeToLive",
        "/etcdserverpb.Auth/Authenticate" => "Authenticate",
        "/etcdserverpb.Watch/Watch" => "Watch",
        _ => return trailers_only(Code::Unimplemented, "unknown method"),
    };
    *state.calls.lock().unwrap().entry(method).or_default() += 1;
    state.seen.lock().unwrap().push(Seen {
        method,
        headers: parts.headers.clone(),
    });
    let mode = *state.mode.lock().unwrap();
    match mode {
        Mode::Normal => {}
        Mode::Hang => std::future::pending::<()>().await,
        Mode::Fail(code) if method != "Authenticate" => return trailers_only(code, "stub failure"),
        Mode::Fail(_) => {}
    }
    if method != "Authenticate" {
        let token = parts.headers.get("token").and_then(|v| v.to_str().ok());
        if let Some(auth) = state.auth.lock().unwrap().as_ref()
            && !token.is_some_and(|token| auth.tokens.contains(token))
        {
            return trailers_only(Code::Unauthenticated, "etcdserver: invalid auth token");
        }
    }
    if method == "Watch" {
        if state.watch_down.load(Ordering::SeqCst) {
            return trailers_only(Code::Unavailable, "watch down");
        }
        return watch(state, body);
    }
    let body = body.collect().await.unwrap().to_bytes();
    let payload = message_payload(&body).expect("one complete request message");
    match method {
        "Range" => {
            let response = range(&state, payload);
            let delay = *state.range_delay.lock().unwrap();
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            unary(&response)
        }
        "LeaseTimeToLive" => unary(&lease_time_to_live(&state, payload)),
        _ => match authenticate(&state, payload) {
            Ok(response) => unary(&response),
            Err((code, message)) => trailers_only(code, message),
        },
    }
}

fn message_payload(buffer: &[u8]) -> Option<&[u8]> {
    let header = grpc::parse_header(buffer)?.ok()?;
    buffer.get(grpc::HEADER_LEN..grpc::HEADER_LEN + header.len)
}

fn range(state: &State, request: &[u8]) -> Vec<u8> {
    let (mut key, mut end, mut limit, mut count_only) = (&[][..], &[][..], 0, false);
    for (field, value) in pb::parse(request) {
        match (field, value) {
            (1, pb::Value::Bytes(value)) => key = value,
            (2, pb::Value::Bytes(value)) => end = value,
            (3, pb::Value::Varint(value)) => limit = value as i64,
            (9, pb::Value::Varint(value)) => count_only = value != 0,
            _ => {}
        }
    }
    let store = state.store.lock().unwrap();
    let matching: Vec<_> = store
        .kvs
        .iter()
        .filter(|(candidate, _)| in_range(candidate, key, end))
        .collect();
    let mut response = Vec::new();
    pb::message(&mut response, 1, &header(store.revision));
    let shown = if count_only {
        0
    } else if limit > 0 {
        matching.len().min(limit as usize)
    } else {
        matching.len()
    };
    for (key, kv) in &matching[..shown] {
        pb::message(&mut response, 2, &kv_message(key, kv));
    }
    pb::int(
        &mut response,
        3,
        i64::from(!count_only && shown < matching.len()),
    );
    pb::int(&mut response, 4, matching.len() as i64);
    response
}

fn lease_time_to_live(state: &State, request: &[u8]) -> Vec<u8> {
    let id = pb::parse(request)
        .into_iter()
        .find_map(|field| match field {
            (1, pb::Value::Varint(id)) => Some(id as i64),
            _ => None,
        })
        .unwrap_or(0);
    let store = state.store.lock().unwrap();
    // etcd api/etcdserverpb/rpc.proto LeaseTimeToLiveResponse: the TTL of a lease that does not exist is -1.
    let ttl = store.leases.get(&id).copied().unwrap_or(-1);
    let mut response = Vec::new();
    pb::message(&mut response, 1, &header(store.revision));
    pb::int(&mut response, 2, id);
    pb::int(&mut response, 3, ttl);
    pb::int(&mut response, 4, ttl.max(0));
    response
}

fn authenticate(state: &State, request: &[u8]) -> Result<Vec<u8>, (Code, &'static str)> {
    let (mut name, mut password) = (Vec::new(), Vec::new());
    for (field, value) in pb::parse(request) {
        match (field, value) {
            (1, pb::Value::Bytes(value)) => name = value.to_vec(),
            (2, pb::Value::Bytes(value)) => password = value.to_vec(),
            _ => {}
        }
    }
    let mut auth = state.auth.lock().unwrap();
    let Some(auth) = auth.as_mut() else {
        return Err((
            Code::FailedPrecondition,
            "etcdserver: authentication is not enabled",
        ));
    };
    if name != auth.user.as_bytes() || password != auth.password.as_bytes() {
        return Err((
            Code::InvalidArgument,
            "etcdserver: authentication failed, invalid user ID or password",
        ));
    }
    let token = format!(
        "token-{}",
        state.tokens_issued.fetch_add(1, Ordering::SeqCst)
    );
    auth.tokens.insert(token.clone());
    let mut response = Vec::new();
    pb::message(
        &mut response,
        1,
        &header(state.store.lock().unwrap().revision),
    );
    pb::bytes(&mut response, 2, token.as_bytes());
    Ok(response)
}

/// A watch stream: the request stream creates and cancels watchers, events go out as they happen.
fn watch(state: Arc<State>, mut requests: Incoming) -> Response<Out> {
    let (tx, messages) = mpsc::unbounded_channel();
    let stream = state.streams.fetch_add(1, Ordering::SeqCst);
    let responses = tx.clone();
    tokio::spawn(async move {
        let mut buffer = BytesMut::new();
        let mut next_id = 0;
        while let Some(Ok(chunk)) = requests.frame().await {
            let Ok(data) = chunk.into_data() else {
                continue;
            };
            buffer.extend_from_slice(&data);
            while let Some(Ok(prefix)) = grpc::parse_header(&buffer) {
                let end = grpc::HEADER_LEN + prefix.len;
                if buffer.len() < end {
                    break;
                }
                let message = buffer.split_to(end);
                let request = &message[grpc::HEADER_LEN..];
                for (field, value) in pb::parse(request) {
                    match (field, value) {
                        (1, pb::Value::Bytes(create)) => {
                            let (mut key, mut end) = (Vec::new(), Vec::new());
                            for (field, value) in pb::parse(create) {
                                match (field, value) {
                                    (1, pb::Value::Bytes(value)) => key = value.to_vec(),
                                    (2, pb::Value::Bytes(value)) => end = value.to_vec(),
                                    _ => {}
                                }
                            }
                            let mut store = state.store.lock().unwrap();
                            let id = next_id;
                            next_id += 1;
                            store.watchers.push(Watcher {
                                stream,
                                id,
                                key,
                                range_end: end,
                                tx: responses.clone(),
                            });
                            let mut created = Vec::new();
                            pb::message(&mut created, 1, &header(store.revision));
                            pb::int(&mut created, 2, id);
                            pb::int(&mut created, 3, 1);
                            let _ = responses.send(frame(&created));
                        }
                        (2, pb::Value::Bytes(cancel)) => {
                            let id = pb::parse(cancel)
                                .into_iter()
                                .find_map(|field| match field {
                                    (1, pb::Value::Varint(id)) => Some(id as i64),
                                    _ => None,
                                })
                                .unwrap_or(0);
                            let mut store = state.store.lock().unwrap();
                            store
                                .watchers
                                .retain(|w| !(w.stream == stream && w.id == id));
                            let mut canceled = Vec::new();
                            pb::message(&mut canceled, 1, &header(store.revision));
                            pb::int(&mut canceled, 2, id);
                            pb::int(&mut canceled, 4, 1);
                            let _ = responses.send(frame(&canceled));
                        }
                        _ => {}
                    }
                }
            }
        }
        // The request stream ended: its watchers go, and with the last sender the response stream ends.
        state
            .store
            .lock()
            .unwrap()
            .watchers
            .retain(|watcher| watcher.stream != stream);
    });
    Response::builder()
        .header("content-type", grpc::CONTENT_TYPE)
        .body(Out {
            messages,
            trailers: Some(ok_trailers()),
        })
        .unwrap()
}

/// Just enough protobuf to read requests and write responses.
mod pb {
    pub enum Value<'a> {
        Varint(u64),
        Bytes(&'a [u8]),
    }

    pub fn varint(out: &mut Vec<u8>, mut value: u64) {
        loop {
            let low = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(low);
                return;
            }
            out.push(low | 0x80);
        }
    }

    /// proto3: a zero integer is the default and is not written.
    pub fn int(out: &mut Vec<u8>, field: u64, value: i64) {
        if value != 0 {
            varint(out, field << 3);
            varint(out, value as u64);
        }
    }

    pub fn bytes(out: &mut Vec<u8>, field: u64, value: &[u8]) {
        if !value.is_empty() {
            message(out, field, value);
        }
    }

    /// A length-delimited field, written even when empty (a message field with no content is present).
    pub fn message(out: &mut Vec<u8>, field: u64, value: &[u8]) {
        varint(out, (field << 3) | 2);
        varint(out, value.len() as u64);
        out.extend_from_slice(value);
    }

    /// The fields of `buffer`; test code, so a malformed buffer panics.
    pub fn parse(mut buffer: &[u8]) -> Vec<(u64, Value<'_>)> {
        let mut fields = Vec::new();
        while !buffer.is_empty() {
            let tag = read(&mut buffer);
            let value = match tag & 7 {
                0 => Value::Varint(read(&mut buffer)),
                2 => {
                    let len = read(&mut buffer) as usize;
                    let (value, rest) = buffer.split_at(len);
                    buffer = rest;
                    Value::Bytes(value)
                }
                other => panic!("wire type {other}"),
            };
            fields.push((tag >> 3, value));
        }
        fields
    }

    fn read(buffer: &mut &[u8]) -> u64 {
        let mut value = 0;
        for shift in (0..70).step_by(7) {
            let octet = buffer[0];
            *buffer = &buffer[1..];
            value |= u64::from(octet & 0x7f) << shift;
            if octet & 0x80 == 0 {
                break;
            }
        }
        value
    }
}

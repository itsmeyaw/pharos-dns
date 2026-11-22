//! A local HTTP/1.1 stub server for the Google endpoints (token, metadata, STS, impersonation, Cloud DNS).
//! Tests never touch the real network.

use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::{net::TcpListener, task::JoinHandle};

/// One request the stub received; header names are lowercase.
#[derive(Clone, Debug)]
pub(crate) struct Call {
    pub method: String,
    pub target: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl Call {
    pub(crate) fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or_default()
    }

    pub(crate) fn query(&self, name: &str) -> Option<String> {
        let query = self.target.split_once('?')?.1;
        decode_pairs(query).remove(name)
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// The `application/x-www-form-urlencoded` body as a map.
    pub(crate) fn form(&self) -> HashMap<String, String> {
        decode_pairs(&self.body)
    }

    pub(crate) fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }
}

/// What the stub answers.
pub(crate) struct Reply {
    pub status: u16,
    pub body: String,
}

impl Reply {
    pub(crate) fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            body: body.to_string(),
        }
    }

    pub(crate) fn ok(body: Value) -> Self {
        Self::json(200, body)
    }

    pub(crate) fn text(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.to_owned(),
        }
    }
}

pub(crate) struct Stub {
    pub addr: SocketAddr,
    calls: Arc<Mutex<Vec<Call>>>,
    task: JoinHandle<()>,
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type Handler = Arc<dyn Fn(&Call) -> Reply + Send + Sync>;

impl Stub {
    pub(crate) async fn start(handler: impl Fn(&Call) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let handler: Handler = Arc::new(handler);
        let log = Arc::clone(&calls);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handler = Arc::clone(&handler);
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let handler = Arc::clone(&handler);
                        let log = Arc::clone(&log);
                        async move { Ok::<_, Infallible>(answer(&handler, &log, request).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self { addr, calls, task }
    }

    /// `http://127.0.0.1:<port><path>`.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    pub(crate) fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
}

async fn answer(
    handler: &Handler,
    log: &Mutex<Vec<Call>>,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    let call = Call {
        method: parts.method.to_string(),
        target: parts.uri.to_string(),
        headers: parts
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.to_str().unwrap().to_owned()))
            .collect(),
        body: String::from_utf8(body.to_vec()).unwrap(),
    };
    let reply = handler(&call);
    log.lock().unwrap().push(call);
    Response::builder()
        .status(reply.status)
        .body(Full::new(Bytes::from(reply.body)))
        .unwrap()
}

fn decode_pairs(text: &str) -> HashMap<String, String> {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(name), percent_decode(value))
        })
        .collect()
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                index += 2;
            }
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8(out).unwrap()
}

//! A local HTTP/1.1 stub standing in for Azure Resource Manager, Active Directory and the MSI endpoints.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

#[derive(Clone, Debug)]
pub(super) struct Request {
    pub method: String,
    /// Path and query, as sent.
    pub target: String,
    /// Header names in lower case.
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl Request {
    pub(super) fn header(&self, name: &str) -> &str {
        self.headers.get(name).map_or("", String::as_str)
    }

    pub(super) fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }
}

pub(super) enum Reply {
    /// Status, extra headers, JSON body.
    Json(u16, Vec<(&'static str, String)>, String),
    /// Hold the connection open until the client gives up.
    Hang,
}

impl Reply {
    pub(super) fn ok(body: impl Into<String>) -> Self {
        Self::Json(200, Vec::new(), body.into())
    }

    pub(super) fn status(status: u16, message: &str) -> Self {
        Self::Json(
            status,
            Vec::new(),
            format!(r#"{{"error":{{"code":"Test","message":"{message}"}}}}"#),
        )
    }
}

type Handler = dyn Fn(&Request) -> Reply + Send + Sync;

pub(super) struct Stub {
    pub addr: std::net::SocketAddr,
    log: Arc<Mutex<Vec<Request>>>,
    task: JoinHandle<()>,
}

impl Stub {
    pub(super) async fn start(handler: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Handler> = Arc::new(handler);
        let task = tokio::spawn({
            let log = Arc::clone(&log);
            async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve(stream, Arc::clone(&handler), Arc::clone(&log)));
                }
            }
        });
        Self { addr, log, task }
    }

    /// `http://127.0.0.1:PORT/`, shaped like a Resource Manager endpoint.
    pub(super) fn base(&self) -> String {
        format!("http://{}/", self.addr)
    }

    pub(super) fn requests(&self) -> Vec<Request> {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(mut stream: TcpStream, handler: Arc<Handler>, log: Arc<Mutex<Vec<Request>>>) {
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    log.lock().unwrap().push(request.clone());
    match handler(&request) {
        Reply::Hang => {
            let _ = stream.read(&mut [0_u8; 1]).await;
        }
        Reply::Json(status, headers, body) => {
            let mut head = format!(
                "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                body.len()
            );
            for (name, value) in headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(body.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buffer = Vec::new();
    let end = loop {
        if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break at;
        }
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let target = first.next()?.to_owned();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[end + 4..].to_vec();
    while body.len() < length {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Some(Request {
        method,
        target,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

//! A local HTTP/1.1 server that plays Nomad for the tests.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use pharos_server::tls::{ClientAuth, ServerOptions, ServerTls};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UnixListener},
};

pub(super) const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

pub(super) struct Reply {
    pub(super) status: u16,
    pub(super) body: Vec<u8>,
    pub(super) close: bool,
    pub(super) stall: bool,
}

impl Reply {
    pub(super) fn ok(body: &str) -> Self {
        Self {
            status: 200,
            body: body.into(),
            close: false,
            stall: false,
        }
    }
}

pub(super) type Handler = Arc<dyn Fn(&str) -> Reply + Send + Sync>;

#[derive(Clone, Default)]
pub(super) struct Stub {
    pub(super) heads: Arc<Mutex<Vec<String>>>,
    pub(super) connections: Arc<AtomicUsize>,
}

impl Stub {
    pub(super) async fn tcp(
        &self,
        handler: impl Fn(&str) -> Reply + Send + Sync + 'static,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let (stub, handler) = (self.clone(), Arc::new(handler) as Handler);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(stub.clone().serve(stream, Arc::clone(&handler)));
            }
        });
        address
    }

    pub(super) async fn tls(
        &self,
        handler: impl Fn(&str) -> Reply + Send + Sync + 'static,
    ) -> String {
        let acceptor = ServerTls::load(&ServerOptions {
            cert: format!("{FIXTURES}/server.pem").into(),
            key: format!("{FIXTURES}/server.key.pem").into(),
            ca: None,
            client_auth: ClientAuth::NoCert,
            keylog: None,
        })
        .unwrap()
        .acceptor();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let (stub, handler) = (self.clone(), Arc::new(handler) as Handler);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (stub, handler, acceptor) =
                    (stub.clone(), Arc::clone(&handler), acceptor.clone());
                tokio::spawn(async move {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        stub.serve(stream, handler).await;
                    }
                });
            }
        });
        address
    }

    pub(super) async fn unix(
        &self,
        path: &std::path::Path,
        handler: impl Fn(&str) -> Reply + Send + Sync + 'static,
    ) {
        let listener = UnixListener::bind(path).unwrap();
        let (stub, handler) = (self.clone(), Arc::new(handler) as Handler);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(stub.clone().serve(stream, Arc::clone(&handler)));
            }
        });
    }

    async fn serve<S: AsyncRead + AsyncWrite + Unpin>(self, mut stream: S, handler: Handler) {
        self.connections.fetch_add(1, Ordering::SeqCst);
        let mut buffer = Vec::new();
        loop {
            while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0; 1024];
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                }
            }
            let end = buffer
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            let head = String::from_utf8(buffer.drain(..end).collect()).unwrap();
            self.heads.lock().unwrap().push(head.clone());
            let reply = handler(&head);
            if reply.stall {
                std::future::pending::<()>().await;
            }
            let connection = if reply.close {
                "Connection: close\r\n"
            } else {
                ""
            };
            let wire = format!(
                "HTTP/1.1 {} X\r\nContent-Length: {}\r\n{connection}\r\n",
                reply.status,
                reply.body.len()
            );
            let _ = stream.write_all(wire.as_bytes()).await;
            let _ = stream.write_all(&reply.body).await;
            if reply.close {
                let _ = stream.shutdown().await;
                return;
            }
        }
    }
}

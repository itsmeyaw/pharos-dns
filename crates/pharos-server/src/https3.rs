//! DNS over HTTPS over HTTP/3 (RFC 8484, RFC 9114): one h3 connection per accepted QUIC connection.
//!
//! [`crate::quic`] owns the endpoint, the handshake and the connection limit, and [`crate::doh`]
//! the request rules; this module owns each connection's request streams and its graceful close.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Buf;
use h3::{
    error::Code,
    server::{RequestResolver, RequestStream},
};
use hyper::{Request, StatusCode};
use quinn::{Connection, VarInt};
use tokio::{
    sync::watch,
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};

use crate::{
    Handler, TcpOptions,
    conn::{Pool, Pooled},
    doh::{self, Source, Status},
    https::{Chunk, dispatch, reply},
};

/// CoreDNS v1.15.0 core/dnsserver `DefaultHTTPS3MaxHeaderBytes`.
const MAX_HEADER_BYTES: u64 = 16 << 10;

/// The least time a draining connection waits for the client to close it.
const MIN_GRACE: Duration = Duration::from_millis(50);

// RFC 9114 §8.1: H3_NO_ERROR.
const H3_NO_ERROR: VarInt = VarInt::from_u32(0x100);

type Resolver = RequestResolver<h3_quinn::Connection, Chunk>;
type Stream = RequestStream<h3_quinn::BidiStream<Chunk>, Chunk>;

/// What every request of one connection needs.
struct Context<H> {
    handler: Arc<H>,
    peer: SocketAddr,
    tlv: Option<Arc<str>>,
    pool: Arc<Pool>,
    status: Option<Arc<Status>>,
    read: Duration,
}

/// Serve the requests of `connection` until it closes or the Listener stops.
pub(crate) async fn serve<H: Handler>(
    connection: Connection,
    handler: Arc<H>,
    pool: Arc<Pool>,
    tcp: TcpOptions,
    mut shutdown: watch::Receiver<bool>,
) {
    let context = Arc::new(Context {
        status: handler.https().status,
        peer: crate::canonical_peer(connection.remote_address()),
        tlv: None,
        handler,
        pool,
        read: tcp.read,
    });
    // RFC 9114 §4.2.2: bound the field section a request may carry, as CoreDNS does.
    let Ok(mut http3) = h3::server::builder()
        .max_field_section_size(MAX_HEADER_BYTES)
        .build::<_, Chunk>(h3_quinn::Connection::new(connection.clone()))
        .await
    else {
        return;
    };
    let mut requests = JoinSet::new();
    let mut draining = false;
    loop {
        if draining && requests.is_empty() {
            break;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed(), if !draining => {
                // RFC 9114 §5.2: GOAWAY stops new requests; accepted ones finish.
                draining = true;
                if http3.shutdown(0).await.is_err() {
                    break;
                }
            }
            _ = requests.join_next(), if !requests.is_empty() => {}
            accepted = http3.accept() => match accepted {
                Ok(Some(resolver)) => {
                    requests.spawn(request(resolver, Arc::clone(&context)));
                }
                // The peer finished its GOAWAY exchange, or the connection is gone.
                Ok(None) | Err(_) => break,
            },
        }
    }
    while requests.join_next().await.is_some() {}
    if draining {
        // A closing connection discards unacknowledged data and h3 hides its streams from `stopped`,
        // so give the client a few round trips to take the last Responses and close first.
        let grace = (connection.rtt() * 4).clamp(MIN_GRACE, tcp.write.max(MIN_GRACE));
        let _ = timeout(grace, connection.closed()).await;
    }
    connection.close(H3_NO_ERROR, b"");
}

async fn request<H: Handler>(resolver: Resolver, context: Arc<Context<H>>) {
    let deadline = Instant::now() + context.read;
    let mut query = context.pool.take();
    // The read timeout bounds the headers and the body; a stream with no headers by then is dropped.
    let Ok(Ok((request, mut stream))) = timeout_at(deadline, resolver.resolve_request()).await
    else {
        return;
    };
    let result = match read_query(&request, &mut stream, &mut query, deadline).await {
        Ok(()) => {
            dispatch(
                &context.handler,
                (context.peer, context.tlv.as_deref()),
                &context.pool,
                &query,
            )
            .await
        }
        Err(status) => Err(status),
    };
    let (head, chunk) = reply(result);
    if let Some(counters) = &context.status {
        counters.count(head.status());
    }
    // RFC 9114 §4.1: a request rejected before its body ended need not be sent in full.
    if head.status() != StatusCode::OK {
        stream.stop_sending(Code::H3_NO_ERROR);
    }
    if stream.send_response(head).await.is_err() || stream.send_data(chunk).await.is_err() {
        return;
    }
    let _ = stream.finish().await;
}

/// Collect the DNS Message of a request into `query`, or name the status that rejects it.
async fn read_query(
    request: &Request<()>,
    stream: &mut Stream,
    query: &mut Pooled,
    deadline: Instant,
) -> Result<(), StatusCode> {
    match doh::locate(request.method(), request.uri())? {
        Source::Get(value) => doh::decode_get(value, query),
        Source::Post => {
            let read = async {
                while let Some(mut data) = stream
                    .recv_data()
                    .await
                    .map_err(|_| StatusCode::BAD_REQUEST)?
                {
                    // CoreDNS v1.15.0 plugin/pkg/doh requestToMsgPost: http.MaxBytesReader(65536).
                    if query.len() + data.remaining() > doh::MAX_QUERY_LEN {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    while data.has_remaining() {
                        let chunk = data.chunk();
                        query.extend_from_slice(chunk);
                        let length = chunk.len();
                        data.advance(length);
                    }
                }
                Ok(())
            };
            timeout_at(deadline, read)
                .await
                .map_err(|_| StatusCode::BAD_REQUEST)?
        }
    }
}

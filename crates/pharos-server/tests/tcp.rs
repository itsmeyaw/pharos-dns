#![forbid(unsafe_code)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use pharos_server::{Action, Handler, Listener, Protocol, Stream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, Semaphore, mpsc as async_mpsc},
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(3);

struct Transfer;

impl Handler for Transfer {
    async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, _: &mut Vec<u8>) -> Action {
        let mut next = 0;
        Action::Stream(Stream::new(move |response: &mut Vec<u8>| {
            if next == 3 {
                return Ok(false);
            }
            response.push(next);
            next += 1;
            Ok(true)
        }))
    }
}

#[tokio::test]
async fn tcp_writes_every_transfer_message_on_the_same_connection() {
    let (listener, mut stream) = connect(Transfer).await;
    send(&mut stream, b"transfer").await;
    for message in 0..3 {
        assert_eq!(receive(&mut stream).await, [message]);
    }
    drop(stream);
    listener.shutdown().await.unwrap();
}

struct Echo;

impl Handler for Echo {
    async fn handle(
        &self,
        query: &[u8],
        _peer: SocketAddr,
        proto: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        assert!(matches!(proto, Protocol::Tcp));
        response.extend_from_slice(query);
        Action::Respond
    }
}

struct Slow {
    started: async_mpsc::UnboundedSender<()>,
    release: Mutex<async_mpsc::UnboundedReceiver<()>>,
}

struct Conditional;

struct BufferProbe {
    started: async_mpsc::UnboundedSender<usize>,
    release: Arc<Semaphore>,
}

struct RejectedBufferProbe {
    capacities: async_mpsc::UnboundedSender<usize>,
}

impl Handler for RejectedBufferProbe {
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        match query {
            b"drop" => {
                response.resize(1024, 0);
                self.capacities.send(0).unwrap();
                Action::Drop
            }
            b"oversized" => {
                response.resize(65536, 0);
                self.capacities.send(0).unwrap();
                Action::Respond
            }
            _ => {
                assert!(response.is_empty());
                self.capacities.send(response.capacity()).unwrap();
                response.extend_from_slice(b"ok");
                Action::Respond
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn dropped_and_oversized_responses_return_their_buffers() {
    let (capacities, mut observed) = async_mpsc::unbounded_channel();
    let (listener, mut stream) = connect(RejectedBufferProbe { capacities }).await;
    for (query, minimum) in [(b"drop".as_slice(), 1024), (b"oversized".as_slice(), 65536)] {
        send(&mut stream, query).await;
        timeout(TEST_TIMEOUT, observed.recv())
            .await
            .unwrap()
            .unwrap();
        send(&mut stream, b"probe").await;
        assert!(
            timeout(TEST_TIMEOUT, observed.recv())
                .await
                .unwrap()
                .unwrap()
                >= minimum
        );
        assert_eq!(receive(&mut stream).await, b"ok");
    }
    listener.shutdown().await.unwrap();
}

impl Handler for BufferProbe {
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        assert!(response.is_empty());
        self.started.send(response.capacity()).unwrap();
        response.resize(1024, query[0]);
        if query == b"warm" {
            self.release.acquire().await.unwrap().forget();
        }
        Action::Respond
    }
}

#[tokio::test]
async fn pipelined_tcp_queries_reuse_response_buffers() {
    let (started, mut capacities) = async_mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let (listener, mut stream) = connect(BufferProbe {
        started,
        release: Arc::clone(&release),
    })
    .await;
    for _ in 0..16 {
        send(&mut stream, b"warm").await;
    }
    for _ in 0..16 {
        timeout(TEST_TIMEOUT, capacities.recv())
            .await
            .unwrap()
            .unwrap();
    }
    release.add_permits(16);
    for _ in 0..16 {
        assert_eq!(receive(&mut stream).await, vec![b'w'; 1024]);
    }
    for _ in 0..16 {
        send(&mut stream, b"reuse").await;
    }
    for _ in 0..16 {
        let capacity = timeout(TEST_TIMEOUT, capacities.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(capacity >= 1024, "Response buffer was not reused");
    }
    for _ in 0..16 {
        assert_eq!(receive(&mut stream).await, vec![b'r'; 1024]);
    }
    listener.shutdown().await.unwrap();
}

struct NeverFinishes {
    started: async_mpsc::UnboundedSender<()>,
}

impl Handler for NeverFinishes {
    async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, _: &mut Vec<u8>) -> Action {
        self.started.send(()).unwrap();
        std::future::pending().await
    }
}

#[tokio::test]
async fn shutdown_closes_a_stalled_query_after_grace_period() {
    let (started, mut received) = async_mpsc::unbounded_channel();
    let (listener, mut stream) = connect(NeverFinishes { started }).await;
    send(&mut stream, b"query").await;
    timeout(TEST_TIMEOUT, received.recv())
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(7), listener.shutdown())
        .await
        .expect("shutdown exceeded grace period")
        .unwrap();
    let mut byte = [0];
    assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
}

impl Handler for Conditional {
    async fn handle(
        &self,
        query: &[u8],
        _peer: SocketAddr,
        _proto: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        match query {
            b"drop" => return Action::Drop,
            b"oversized" => response.resize(usize::from(u16::MAX) + 1, 0),
            _ => response.extend_from_slice(query),
        }
        Action::Respond
    }
}

impl Handler for Slow {
    async fn handle(
        &self,
        query: &[u8],
        _peer: SocketAddr,
        _proto: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        if query == b"slow" {
            self.started.send(()).unwrap();
            self.release.lock().await.recv().await.unwrap();
        }
        response.extend_from_slice(query);
        Action::Respond
    }
}

async fn connect<H: Handler>(handler: H) -> (Listener, TcpStream) {
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), handler)
        .await
        .unwrap();
    let stream = TcpStream::connect(listener.local_addr()).await.unwrap();
    (listener, stream)
}

async fn send(stream: &mut TcpStream, query: &[u8]) {
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(query).await.unwrap();
}

async fn receive(stream: &mut TcpStream) -> Vec<u8> {
    timeout(TEST_TIMEOUT, async {
        let len = stream.read_u16().await.unwrap();
        let mut response = vec![0; usize::from(len)];
        stream.read_exact(&mut response).await.unwrap();
        response
    })
    .await
    .expect("response timed out")
}

fn slow_handler() -> (
    Slow,
    async_mpsc::UnboundedReceiver<()>,
    async_mpsc::UnboundedSender<()>,
) {
    let (started, started_rx) = async_mpsc::unbounded_channel();
    let (release, release_rx) = async_mpsc::unbounded_channel();
    (
        Slow {
            started,
            release: Mutex::new(release_rx),
        },
        started_rx,
        release,
    )
}

#[tokio::test]
async fn reads_fragmented_frames_and_reuses_connection() {
    let (listener, mut stream) = connect(Echo).await;
    stream.write_all(&[0]).await.unwrap();
    stream.write_all(&[3, b'a']).await.unwrap();
    stream.write_all(b"bc").await.unwrap();
    assert_eq!(receive(&mut stream).await, b"abc");
    send(&mut stream, b"second").await;
    assert_eq!(receive(&mut stream).await, b"second");
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn pipelined_queries_can_complete_out_of_order() {
    let (handler, mut started, release) = slow_handler();
    let (listener, mut stream) = connect(handler).await;
    send(&mut stream, b"slow").await;
    timeout(TEST_TIMEOUT, started.recv())
        .await
        .unwrap()
        .unwrap();
    send(&mut stream, b"fast").await;
    let first = timeout(TEST_TIMEOUT, receive(&mut stream)).await;
    release.send(()).unwrap();
    assert_eq!(
        first.expect("fast response waited for slow handler"),
        b"fast"
    );
    assert_eq!(receive(&mut stream).await, b"slow");
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn slow_connections_do_not_throttle_other_connections() {
    // Fill the former global 256-Query limit across multiple connections.
    const CONNECTIONS: usize = 16;
    const QUERIES_PER_CONNECTION: usize = 16;
    const QUERIES: usize = CONNECTIONS * QUERIES_PER_CONNECTION;
    let (handler, mut started, release) = slow_handler();
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), handler)
        .await
        .unwrap();
    let mut slow = Vec::new();
    for _ in 0..CONNECTIONS {
        let mut stream = TcpStream::connect(listener.local_addr()).await.unwrap();
        for _ in 0..QUERIES_PER_CONNECTION {
            send(&mut stream, b"slow").await;
        }
        slow.push(stream);
    }
    for _ in 0..QUERIES {
        timeout(TEST_TIMEOUT, started.recv())
            .await
            .unwrap()
            .unwrap();
    }
    let mut fast = TcpStream::connect(listener.local_addr()).await.unwrap();
    send(&mut fast, b"fast").await;
    let result = timeout(TEST_TIMEOUT, receive(&mut fast)).await;
    for _ in 0..QUERIES {
        release.send(()).unwrap();
    }
    assert_eq!(result.expect("fast Query was throttled"), b"fast");
    drop(slow);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_drains_queries_already_being_handled() {
    let (handler, mut started, release) = slow_handler();
    let (listener, mut stream) = connect(handler).await;
    send(&mut stream, b"slow").await;
    timeout(TEST_TIMEOUT, started.recv())
        .await
        .unwrap()
        .unwrap();
    let shutdown = tokio::spawn(async move { listener.shutdown().await });
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished());
    release.send(()).unwrap();
    assert_eq!(receive(&mut stream).await, b"slow");
    timeout(TEST_TIMEOUT, shutdown)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn truncated_frame_is_not_handled() {
    let (listener, mut stream) = connect(Echo).await;
    stream.write_all(&[0, 4, b'a']).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes.is_empty());
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn half_close_still_receives_completed_query() {
    let (listener, mut stream) = connect(Echo).await;
    send(&mut stream, b"query").await;
    stream.shutdown().await.unwrap();
    assert_eq!(receive(&mut stream).await, b"query");
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn dropped_and_oversized_responses_do_not_corrupt_stream() {
    let (listener, mut stream) = connect(Conditional).await;
    send(&mut stream, b"drop").await;
    send(&mut stream, b"oversized").await;
    send(&mut stream, b"valid").await;
    assert_eq!(receive(&mut stream).await, b"valid");
    send(&mut stream, b"again").await;
    assert_eq!(receive(&mut stream).await, b"again");
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn connection_accepts_more_than_the_in_flight_limit() {
    let (listener, mut stream) = connect(Echo).await;
    for byte in 0..40 {
        send(&mut stream, &[byte; 1024]).await;
    }
    let mut received = Vec::new();
    for _ in 0..40 {
        let response = receive(&mut stream).await;
        assert_eq!(response, vec![response[0]; 1024]);
        received.push(response[0]);
    }
    received.sort_unstable();
    assert_eq!(received, (0..40).collect::<Vec<_>>());
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn maximum_sized_frame_round_trips() {
    let (listener, mut stream) = connect(Echo).await;
    let query = vec![42; usize::from(u16::MAX)];
    send(&mut stream, &query).await;
    assert_eq!(receive(&mut stream).await, query);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn incomplete_frame_times_out() {
    let (listener, mut stream) = connect(Echo).await;
    stream.write_all(&[0, 4, b'a']).await.unwrap();
    let mut byte = [0];
    let read = timeout(Duration::from_secs(5), stream.read(&mut byte)).await;
    assert_eq!(read.unwrap().unwrap(), 0);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn idle_connection_times_out() {
    let (listener, mut stream) = connect(Echo).await;
    let mut byte = [0];
    let read = timeout(Duration::from_secs(12), stream.read(&mut byte)).await;
    assert_eq!(read.unwrap().unwrap(), 0);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_does_not_wait_for_incomplete_frame() {
    let (listener, mut stream) = connect(Echo).await;
    stream.write_all(&[0, 4, b'a']).await.unwrap();
    timeout(TEST_TIMEOUT, listener.shutdown())
        .await
        .unwrap()
        .unwrap();
}

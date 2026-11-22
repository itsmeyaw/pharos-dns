//! Test collector and helpers shared by the dnstap tests.

use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use pharos_server::metrics::Registry;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    Config, Endpoint, Role,
    framestream::{CONTENT_TYPE, ControlType, put_control, read_control},
    msg::{Message, MessageType, SocketProtocol, decode},
    setup::DEFAULT_VERSION,
    tap::{Tap, Timing},
};

/// One frame as a collector sees it.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Frame {
    Data(Vec<u8>),
    /// STOP, already answered with FINISH.
    Stop,
}

/// The receiving end of a bidirectional Frame Streams connection, as golang-framestream's `Decoder`.
pub(crate) struct Collector<S> {
    stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Collector<S> {
    /// READY, ACCEPT, START.
    pub(crate) async fn accept(mut stream: S) -> io::Result<Self> {
        let ready = read_control(&mut stream).await?;
        assert_eq!(ready.kind, ControlType::Ready as u32);
        assert_eq!(ready.content_types, [CONTENT_TYPE]);
        let mut accept = Vec::new();
        put_control(&mut accept, ControlType::Accept, &[CONTENT_TYPE]);
        stream.write_all(&accept).await?;
        let start = read_control(&mut stream).await?;
        assert_eq!(start.kind, ControlType::Start as u32);
        Ok(Self { stream })
    }

    pub(crate) async fn frame(&mut self) -> io::Result<Frame> {
        let length = self.stream.read_u32().await?;
        if length != 0 {
            let mut payload = vec![0; length as usize];
            self.stream.read_exact(&mut payload).await?;
            return Ok(Frame::Data(payload));
        }
        let control = self.stream.read_u32().await?;
        let mut body = vec![0; control as usize];
        self.stream.read_exact(&mut body).await?;
        assert_eq!(body[..4], (ControlType::Stop as u32).to_be_bytes());
        let mut finish = Vec::new();
        put_control(&mut finish, ControlType::Finish, &[]);
        self.stream.write_all(&finish).await?;
        Ok(Frame::Stop)
    }

    pub(crate) async fn data(&mut self) -> Vec<u8> {
        match tokio::time::timeout(Duration::from_secs(10), self.frame()).await {
            Ok(Ok(Frame::Data(payload))) => payload,
            other => panic!("expected a data frame, got {other:?}"),
        }
    }

    /// The decoded query port of the next data frame, which tests use as a message number.
    pub(crate) async fn number(&mut self) -> u64 {
        decode::dnstap(&self.data().await)
            .message
            .unwrap()
            .query_port
            .unwrap()
    }
}

pub(crate) fn config(endpoint: Endpoint) -> Config {
    Config {
        role: Role::Dial,
        endpoint,
        full: false,
        write_buffer: 1,
        queue: 1,
        identity: b"test".to_vec(),
        version: DEFAULT_VERSION.as_bytes().to_vec(),
        extra: String::new(),
        skip_verify: false,
        tls: None,
    }
}

/// Short timings so tests do not wait on the 10 s and 1 s CoreDNS defaults.
pub(crate) fn fast() -> Timing {
    Timing {
        timeout: Duration::from_millis(500),
        flush: Duration::from_millis(30),
        report: Duration::from_millis(50),
        backoff_min: Duration::from_millis(10),
        backoff_max: Duration::from_millis(50),
    }
}

pub(crate) type Warnings = Arc<Mutex<Vec<String>>>;

/// A tap with fast timings, a metrics registry and a recorder for its warnings.
pub(crate) fn tap(config: Config) -> (Tap, Registry, Warnings) {
    let warnings = Warnings::default();
    let sink = Arc::clone(&warnings);
    let tap = Tap::with_options(
        config,
        fast(),
        Arc::new(move |text| sink.lock().unwrap().push(text.to_owned())),
    );
    let registry = Registry::default();
    tap.set_metrics(&registry);
    (tap, registry, warnings)
}

/// A CLIENT_QUERY whose query port is `number`.
pub(crate) fn query(number: u16) -> Message<'static> {
    let mut message = Message::new(MessageType::ClientQuery);
    message.set_query_address(([192, 0, 2, 1], number).into(), SocketProtocol::Udp);
    message
}

/// The value of a series, spelled as in the encoded metrics.
pub(crate) fn metric(registry: &Registry, series: &str) -> u64 {
    let mut text = String::new();
    registry.encode(&mut text);
    text.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
        .unwrap_or_else(|| panic!("no series {series} in\n{text}"))
}

/// Polls `condition` for up to ten seconds.
pub(crate) async fn eventually(mut condition: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not met in time");
}

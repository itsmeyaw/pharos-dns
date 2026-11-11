#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use pharos_proto::{Class, Message, MessageBuilder, Name, Rcode, Section, Type};
use pharos_server::{
    Action, Chain, Context, Error, Handler, ListenerKey, Outcome, Protocol, Router, Server,
    Transport,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

static DEPTH_VISITS: AtomicUsize = AtomicUsize::new(0);

struct DropSignal(Arc<std::sync::atomic::AtomicBool>);
impl Drop for DropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct CancelChain {
    started: Arc<Notify>,
    dropped: Arc<std::sync::atomic::AtomicBool>,
}
impl Chain for CancelChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        if cx.domain.to_string() == "example." {
            let _ = cx.self_lookup(&"b.other.".parse().unwrap(), Type::A).await;
            Outcome::Drop
        } else {
            let _guard = DropSignal(Arc::clone(&self.dropped));
            self.started.notify_one();
            std::future::pending().await
        }
    }
    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn cancelling_shared_lookup_aborts_its_child_task() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let started = Arc::new(Notify::new());
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut router = Router::default();
    for domain in ["example.", "other."] {
        router.add(
            key,
            domain.parse().unwrap(),
            Some(CancelChain {
                started: Arc::clone(&started),
                dropped: Arc::clone(&dropped),
            }),
            vec![],
        );
    }
    let server = Arc::new(Server::new(router, key));
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01a\x07example\0\0\x01\0\x01";
    let mut response = Vec::with_capacity(65535);
    let mut outer = Box::pin(Handler::handle_shared(
        &server,
        wire,
        "127.0.0.1:1234".parse().unwrap(),
        Protocol::Udp,
        &mut response,
    ));
    tokio::select! { _ = started.notified() => {}, _ = &mut outer => panic!("lookup finished") }
    drop(outer);
    for _ in 0..100 {
        if dropped.load(Ordering::Acquire) {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("cancelled lookup remained active");
}

enum TestChain {
    Lookup,
    Answer,
    Depth,
}

impl Chain for TestChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        match self {
            Self::Lookup => {
                let name: Name = "b.other.".parse().unwrap();
                let before = cx.response.clone();
                let response = cx.self_lookup(&name, Type::A).await.unwrap();
                assert_eq!(*cx.response, before);
                let captured = Message::parse(&response).unwrap();
                assert_eq!(captured.answers().next().unwrap().rdata, [192, 0, 2, 42]);
                assert_eq!(
                    captured.questions().next().unwrap().name.to_string(),
                    "b.other."
                );
                cx.response.extend_from_slice(&[7]);
                Outcome::Unanswered(Rcode::REFUSED)
            }
            Self::Answer => {
                assert_eq!(cx.client, "192.0.2.10:1234".parse().unwrap());
                assert_eq!(cx.protocol, Protocol::Tcp);
                assert_eq!(cx.domain.to_string(), "other.");
                assert_eq!(cx.query.id(), 0x1234);
                let opt = cx.query.opt().unwrap();
                assert!(opt.dnssec_ok());
                assert_eq!(opt.udp_payload_size(), 1232);
                assert_eq!(opt.options().as_bytes(), b"\xfd\xe9\0\x02\xc0\x01");
                let question = cx.query.questions().next().unwrap();
                let mut builder =
                    MessageBuilder::new(cx.response, 65535, cx.query.id(), 0x8000).unwrap();
                builder
                    .question(question.name, question.qtype, question.qclass)
                    .unwrap();
                builder
                    .record(
                        Section::Answer,
                        question.name,
                        Type::A,
                        Class::IN,
                        60,
                        &[192, 0, 2, 42],
                    )
                    .unwrap();
                let _ = builder.finish();
                Outcome::Response
            }
            Self::Depth => {
                DEPTH_VISITS.fetch_add(1, Ordering::Relaxed);
                let name: Name = "loop.example.".parse().unwrap();
                match cx.self_lookup(&name, Type::A).await {
                    Ok(response) => {
                        assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
                        Outcome::Error(Error::InvalidQuery)
                    }
                    Err(error) => {
                        assert_eq!(error, Error::SelfLookupDepth);
                        Outcome::Error(error)
                    }
                }
            }
        }
    }
    fn is_empty(&self) -> bool {
        false
    }
}

fn server(first: TestChain) -> Server<TestChain> {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, "example.".parse().unwrap(), Some(first), vec![]);
    router.add(
        key,
        "other.".parse().unwrap(),
        Some(TestChain::Answer),
        vec![],
    );
    Server::new(router, key)
}

#[test]
fn shared_self_lookup_can_be_polled_without_tokio_runtime() {
    use std::{
        future::Future,
        task::{Context as TaskContext, Poll, Waker},
    };
    let server = Arc::new(server(TestChain::Lookup));
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\x01\x01a\x07example\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\x80\0\0\x06\xfd\xe9\0\x02\xc0\x01";
    let mut response = vec![42];
    let future = Handler::handle_shared(
        &server,
        query,
        "192.0.2.10:1234".parse().unwrap(),
        Protocol::Tcp,
        &mut response,
    );
    let mut future = std::pin::pin!(future);
    assert_eq!(
        future
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop())),
        Poll::Ready(Action::Respond)
    );
}

#[tokio::test]
async fn self_lookup_routes_and_captures_without_touching_client_response() {
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\x01\x01a\x07example\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\x80\0\0\x06\xfd\xe9\0\x02\xc0\x01";
    let mut response = vec![42];
    assert_eq!(
        server(TestChain::Lookup)
            .handle(
                query,
                "192.0.2.10:1234".parse().unwrap(),
                Protocol::Tcp,
                &mut response
            )
            .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
}

#[tokio::test]
async fn self_lookup_depth_eleven_fails_and_returns_servfail() {
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x04loop\x07example\0\0\x01\0\x01";
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server(TestChain::Depth)
            .handle(
                query,
                "192.0.2.10:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
    assert_eq!(DEPTH_VISITS.load(Ordering::Relaxed), 11);
}

struct ReloadChain {
    address: u8,
    start: Arc<Notify>,
    resume: Arc<Notify>,
}

impl Chain for ReloadChain {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        let question = cx.query.questions().next().unwrap();
        if cx.domain.to_string() == "example." {
            self.start.notify_one();
            self.resume.notified().await;
            let answer = cx
                .self_lookup(&"b.other.".parse().unwrap(), Type::A)
                .await
                .unwrap();
            cx.response.clear();
            cx.response.extend_from_slice(&answer);
        } else {
            let mut builder =
                MessageBuilder::new(cx.response, 65535, cx.query.id(), 0x8000).unwrap();
            builder
                .question(question.name, question.qtype, question.qclass)
                .unwrap();
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::A,
                    Class::IN,
                    0,
                    &[192, 0, 2, self.address],
                )
                .unwrap();
            let _ = builder.finish();
        }
        Outcome::Response
    }
    fn is_empty(&self) -> bool {
        false
    }
}

fn reload_server(
    key: ListenerKey,
    address: u8,
    start: &Arc<Notify>,
    resume: &Arc<Notify>,
) -> Server<ReloadChain> {
    let mut router = Router::default();
    for domain in ["example.", "other."] {
        router.add(
            key,
            domain.parse().unwrap(),
            Some(ReloadChain {
                address,
                start: start.clone(),
                resume: resume.clone(),
            }),
            vec![],
        );
    }
    Server::new(router, key)
}

#[tokio::test]
async fn self_lookup_uses_state_held_before_reload() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let start = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let mut registry = pharos_server::ListenerRegistry::default();
    registry
        .apply([(key, reload_server(key, 1, &start, &resume))].into())
        .await
        .unwrap();
    let address = registry.get(&key).unwrap().local_addr();
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x01a\x07example\0\0\x01\0\x01";
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(query).await.unwrap();
    start.notified().await;
    let retired = registry
        .apply([(key, reload_server(key, 2, &start, &resume))].into())
        .await
        .unwrap();
    resume.notify_one();
    let len = stream.read_u16().await.unwrap();
    let mut response = vec![0; usize::from(len)];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 1]
    );
    drop(stream);
    drop(retired);
    registry.shutdown().await.unwrap();
}

struct DetachedDepth(Arc<AtomicUsize>);

impl Chain for DetachedDepth {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        let visit = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        if visit > 11 {
            return Outcome::Unanswered(Rcode::REFUSED);
        }
        if visit == 11 {
            let handle = cx.self_lookup_handle().expect("owned Listener state");
            let wire = cx.query.as_wire().to_vec();
            let client = cx.client;
            let local = cx.local;
            let domain = cx.domain.clone();
            let protocol = cx.protocol;
            let transport = cx.transport;
            let error = tokio::spawn(async move {
                let mut slots = [None; 8];
                let mut response = Vec::new();
                let context = Context {
                    query: Message::parse(&wire).unwrap(),
                    client,
                    local,
                    transport,
                    protocol,
                    domain: &domain,
                    metadata: pharos_server::Metadata::with_self_lookup(&mut slots, Some(&handle)),
                    response: &mut response,
                    max_response_size: 512,
                };
                context
                    .self_lookup(&"loop.example.".parse().unwrap(), Type::A)
                    .await
                    .unwrap_err()
            })
            .await
            .unwrap();
            assert_eq!(error, Error::SelfLookupDepth);
            return Outcome::Error(error);
        }
        let response = cx
            .self_lookup(&"loop.example.".parse().unwrap(), Type::A)
            .await
            .unwrap();
        assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
        Outcome::Error(Error::InvalidQuery)
    }
    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn detached_self_lookup_retains_depth_limit() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let visits = Arc::new(AtomicUsize::new(0));
    let mut router = Router::default();
    router.add(
        key,
        "example.".parse().unwrap(),
        Some(DetachedDepth(visits.clone())),
        vec![],
    );
    let server = Arc::new(Server::new(router, key));
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x04loop\x07example\0\0\x01\0\x01";
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        Handler::handle_shared(
            &server,
            query,
            "192.0.2.10:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response
        )
        .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
    assert_eq!(visits.load(Ordering::SeqCst), 11);
}

struct CountOwners {
    server: std::sync::Weak<Server<CountOwners>>,
    observed: Arc<AtomicUsize>,
}

impl Chain for CountOwners {
    async fn serve(&self, _: &mut Context<'_, '_>) -> Outcome {
        self.observed
            .store(self.server.strong_count(), Ordering::SeqCst);
        Outcome::Unanswered(Rcode::REFUSED)
    }

    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn ordinary_query_does_not_clone_listener_state() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let observed = Arc::new(AtomicUsize::new(0));
    let server = Arc::new_cyclic(|weak| {
        let mut router = Router::default();
        router.add(
            key,
            "example.".parse().unwrap(),
            Some(CountOwners {
                server: weak.clone(),
                observed: observed.clone(),
            }),
            vec![],
        );
        Server::new(router, key)
    });
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x01a\x07example\0\0\x01\0\x01";
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        Handler::handle_shared(
            &server,
            query,
            "192.0.2.10:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response
        )
        .await,
        Action::Respond
    );
    assert_eq!(observed.load(Ordering::SeqCst), 1);
}

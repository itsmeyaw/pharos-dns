#![forbid(unsafe_code)]

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Opcode, Rcode, Section, Type};
use pharos_server::{
    Action, Chain, Context, Error, Handler, ListenerKey, Outcome, Protocol, Router, Server,
    Transport, TsigSigning, panics_total,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

static LOGGED: AtomicUsize = AtomicUsize::new(0);
fn log(_: Error) {
    LOGGED.fetch_add(1, Ordering::Relaxed);
}

struct Broken {
    panic: bool,
}

struct LocalProbe;
impl Chain for LocalProbe {
    async fn serve(&self, context: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(context.local, "[::]:53".parse().unwrap());
        Outcome::Unanswered(Rcode::REFUSED)
    }
    fn is_empty(&self) -> bool {
        false
    }
}

struct NotifyProbe;
impl Chain for NotifyProbe {
    async fn serve(&self, context: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(context.query.opcode(), Opcode::NOTIFY);
        assert_eq!(context.query.questions().next().unwrap().qtype, Type::SOA);
        Outcome::Unanswered(Rcode::REFUSED)
    }
    fn is_empty(&self) -> bool {
        false
    }
}

struct ChildNodata;
impl Chain for ChildNodata {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        let question = cx.query.questions().next().unwrap();
        assert_eq!(question.qtype, Type::DS);
        let apex: Name = "child.example.org.".parse().unwrap();
        let apex = NameRef::parse(apex.as_wire(), 0).unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8400).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(Section::Authority, apex, Type::SOA, Class::IN, 60, &[0; 22])
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
    fn is_empty(&self) -> bool {
        false
    }
}

struct ForwardAdProbe;
impl Chain for ForwardAdProbe {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        let _ = cx
            .metadata
            .insert(pharos_server::metrics::WRITER_METADATA, "forward");
        cx.metadata.mark_forwarded_response();
        let question = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 1232, cx.query.id(), 0x80a0).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        if cx.query.opt().is_some() {
            let root = NameRef::parse(&[0], 0).unwrap();
            builder
                .record(
                    Section::Additional,
                    root,
                    Type::OPT,
                    Class(1232),
                    0x8000,
                    &[],
                )
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
    fn is_empty(&self) -> bool {
        false
    }
}

struct UpdateProbe(bool);
impl Chain for UpdateProbe {
    async fn serve(&self, context: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(context.query.opcode(), Opcode::UPDATE);
        assert_eq!(context.query.authority_count(), 2);
        Outcome::Unanswered(Rcode::REFUSED)
    }
    fn is_empty(&self) -> bool {
        false
    }
    fn accepts_update(&self) -> bool {
        self.0
    }
}

struct TkeyProbe(Arc<AtomicUsize>);
impl Chain for TkeyProbe {
    async fn serve(&self, _: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::SeqCst);
        Outcome::Unanswered(Rcode::REFUSED)
    }
    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn update_admission_is_listener_and_block_scoped() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        key,
        "dynamic.example.".parse().unwrap(),
        Some(UpdateProbe(true)),
        vec![],
    );
    router.add(
        key,
        "static.example.".parse().unwrap(),
        Some(UpdateProbe(false)),
        vec![],
    );
    router.add(key, "missing.example.".parse().unwrap(), None, vec![]);
    let server = Server::new(router, key);
    for (domain, expected) in [
        ("dynamic.example.", Rcode::REFUSED),
        ("static.example.", Rcode::NOTIMP),
        ("missing.example.", Rcode::NOTIMP),
        ("other.example.", Rcode::NOTAUTH),
    ] {
        let domain: Name = domain.parse().unwrap();
        let name = NameRef::parse(domain.as_wire(), 0).unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x2800).unwrap();
        builder.question(name, Type::SOA, Class::IN).unwrap();
        builder
            .record(
                Section::Authority,
                name,
                Type::A,
                Class::IN,
                60,
                &[192, 0, 2, 1],
            )
            .unwrap();
        builder
            .record(
                Section::Authority,
                name,
                Type::A,
                Class::IN,
                60,
                &[192, 0, 2, 2],
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        assert_eq!(
            server
                .handle(
                    &wire,
                    "127.0.0.1:1234".parse().unwrap(),
                    Protocol::Udp,
                    &mut response
                )
                .await,
            Action::Respond
        );
        assert_eq!(Message::parse(&response).unwrap().rcode(), expected);
    }
}

#[tokio::test]
async fn tkey_query_returns_notimp_without_running_chain() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    let chain_calls = Arc::new(AtomicUsize::new(0));
    router.add(
        key,
        ".".parse().unwrap(),
        Some(TkeyProbe(Arc::clone(&chain_calls))),
        vec![],
    );
    let server = Server::new(router, key);
    let name: Name = "example.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::TKEY,
            Class::ANY,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server
            .handle(
                &wire,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOTIMP);
    assert_eq!(chain_calls.load(Ordering::SeqCst), 0);
}

// RFC 2930 §3: TKEY over TCP receives NOTIMP on the same connection.
#[tokio::test]
async fn tkey_query_over_tcp_returns_notimp() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    let chain_calls = Arc::new(AtomicUsize::new(0));
    router.add(
        key,
        ".".parse().unwrap(),
        Some(TkeyProbe(Arc::clone(&chain_calls))),
        vec![],
    );
    let listener =
        pharos_server::Listener::bind("127.0.0.1:0".parse().unwrap(), Server::new(router, key))
            .await
            .unwrap();
    let name: Name = "example.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 0x4242, 0x0100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::TKEY,
            Class::ANY,
        )
        .unwrap();
    let _ = builder.finish();
    let mut stream = tokio::net::TcpStream::connect(listener.local_addr())
        .await
        .unwrap();
    stream.write_u16(wire.len() as u16).await.unwrap();
    stream.write_all(&wire).await.unwrap();
    let mut response = vec![0; usize::from(stream.read_u16().await.unwrap())];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..2], &[0x42, 0x42]);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOTIMP);
    assert_eq!(chain_calls.load(Ordering::SeqCst), 0);
    drop(stream);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn zero_question_query_is_not_rejected_as_malformed() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let server = Server::new(Router::<LocalProbe>::default(), key);
    let query = [0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server
            .handle(
                &query,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
}

#[tokio::test]
async fn child_only_authority_answers_ds_nodata_from_child_zone() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        key,
        "child.example.org.".parse().unwrap(),
        Some(ChildNodata),
        vec![],
    );
    let server = Server::new(router, key);
    let name: Name = "child.example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::DS,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server
            .handle(
                &wire,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await,
        Action::Respond
    );
    let message = Message::parse(&response).unwrap();
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert!(message.aa());
    assert_eq!(message.answer_count(), 0);
    assert_eq!(message.authorities().next().unwrap().rtype, Type::SOA);
}

#[tokio::test]
async fn unsigned_forwarded_response_preserves_upstream_ad() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(ForwardAdProbe), vec![]);
    let server = Server::new(router, key);
    let name: Name = "example.org.".parse().unwrap();
    for (flags, dnssec_ok) in [(0x0100, false), (0x0120, false), (0x0100, true)] {
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, flags).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
            )
            .unwrap();
        if dnssec_ok {
            builder
                .record(
                    Section::Additional,
                    NameRef::parse(&[0], 0).unwrap(),
                    Type::OPT,
                    Class(1232),
                    0x8000,
                    &[],
                )
                .unwrap();
        }
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        assert_eq!(
            server
                .handle(
                    &wire,
                    "127.0.0.1:1234".parse().unwrap(),
                    Protocol::Udp,
                    &mut response,
                )
                .await,
            Action::Respond
        );
        assert!(Message::parse(&response).unwrap().ad());
    }
}

struct ForwardSignedAdProbe(Arc<pharos_proto::TsigKey>);
impl Chain for ForwardSignedAdProbe {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        let question = cx.query.questions().next().unwrap();
        cx.metadata.set_tsig_signing(TsigSigning::Signed {
            key: Arc::clone(&self.0),
            time: 1_000,
            fudge: 300,
            reserved: 5 + 26 + 13 + 32,
        });
        let _ = cx
            .metadata
            .insert(pharos_server::metrics::WRITER_METADATA, "forward");
        cx.metadata.mark_forwarded_response();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x80a0).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn forwarded_response_without_upstream_transaction_security_clears_ad_before_tsig() {
    let key = Arc::new(pharos_proto::TsigKey::new(
        "key.".parse().unwrap(),
        pharos_proto::TsigAlgorithm::Sha256,
        b"secret",
    ));
    let listener_key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(
        listener_key,
        ".".parse().unwrap(),
        Some(ForwardSignedAdProbe(Arc::clone(&key))),
        vec![],
    );
    let server = Server::new(router, listener_key);
    let name: Name = "example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    key.sign(&mut wire, 1_000, 300, None).unwrap();
    let request_mac = key.verify(&wire, 1_000, None, 0).unwrap().mac;
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server
            .handle(
                &wire,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await,
        Action::Respond
    );
    let message = Message::parse(&response).unwrap();
    assert!(!message.ad());
    assert!(message.additionals().any(|rr| rr.rtype == Type::TSIG));
    key.verify(&response, 1_000, Some(request_mac), 0).unwrap();
}

#[tokio::test]
async fn notify_reaches_the_plugin_chain_over_udp_and_tcp() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(NotifyProbe), vec![]);
    let server = Server::new(router, key);
    // RFC 1996 §3.7: NOTIFY carries opcode 4 and an SOA Question.
    // RFC 1996 §4.5: NOTIFY uses opcode 4 and an SOA Question.
    let query = [
        0, 1, 0x20, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 6, 0, 1,
    ];
    for protocol in [Protocol::Udp, Protocol::Tcp] {
        let mut response = Vec::with_capacity(512);
        assert_eq!(
            server
                .handle(
                    &query,
                    "127.0.0.1:1234".parse().unwrap(),
                    protocol,
                    &mut response
                )
                .await,
            Action::Respond
        );
        // RFC 1035 §4.1.1: The server copies the request opcode into its response.
        let response = Message::parse(&response).unwrap();
        assert_eq!(response.opcode(), Opcode::NOTIFY);
        assert_eq!(response.rcode(), Rcode::REFUSED);
    }
}

#[tokio::test]
async fn wildcard_context_keeps_configured_local_address() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "[::]:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(LocalProbe), vec![]);
    let server = Server::new(router, key);
    let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server
            .handle(
                &query,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
}
impl Chain for Broken {
    async fn serve(&self, _: &mut Context<'_, '_>) -> Outcome {
        if self.panic {
            panic!("broken plugin");
        }
        Outcome::Error(Error::InvalidQuery)
    }
    fn is_empty(&self) -> bool {
        false
    }
}

fn server(panic: bool) -> Server<Broken> {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(Broken { panic }), vec![]);
    let mut server = Server::new(router, key);
    server.logger = log;
    server
}

// RFC 1035 §4.1.1: RCODE 2 means the server could not process the query.
#[tokio::test]
async fn plugin_error_is_logged_and_answered_servfail() {
    let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
    let mut response = Vec::with_capacity(512);
    let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let before = LOGGED.load(Ordering::Relaxed);
    assert_eq!(
        server(false)
            .handle(&query, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    assert_eq!(LOGGED.load(Ordering::Relaxed), before + 1);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
    let before = panics_total();
    assert_eq!(
        server(true)
            .handle(&query, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    assert_eq!(panics_total(), before + 1);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
}

#[tokio::test]
async fn debug_server_does_not_contain_plugin_panics() {
    let mut server = server(true);
    server.debug = true;
    let result = tokio::spawn(async move {
        let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
        let mut response = Vec::with_capacity(512);
        server
            .handle(
                &query,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await
    })
    .await;
    assert!(result.unwrap_err().is_panic());
}

#![forbid(unsafe_code)]
#![cfg(feature = "plugin-forward")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name, Rcode};
use pharos_server::{
    Action, Context, Handler, ListenerKey, ListenerRegistry, Metadata, Outcome, Protocol,
    Transport,
    tls::{ClientAuth, ServerOptions, ServerTls},
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

const QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

/// Answers every Query with itself, flagged as a Response that claims authenticated data.
struct Answer {
    tls: ServerTls,
    served: Arc<AtomicUsize>,
}

impl Handler for Answer {
    fn tls(&self) -> Option<ServerTls> {
        Some(self.tls.clone())
    }

    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        // RFC 9250 §4.2.1: a DoQ Query reaches the server with Message ID zero.
        assert_eq!(&query[..2], &[0, 0]);
        self.served.fetch_add(1, Ordering::SeqCst);
        response.extend_from_slice(query);
        response[2] |= 0x80;
        // RFC 4035 §3.2.3: an upstream sets AD on validated data.
        response[3] |= 0x20;
        Action::Respond
    }
}

// RFC 9250 §5.3: the Pharos `quic://` Listener is the DoQ Upstream.
async fn doq_server() -> (SocketAddr, Arc<AtomicUsize>, ListenerRegistry) {
    let tls = ServerTls::load(&ServerOptions {
        cert: format!("{FIXTURES}/server.pem").into(),
        key: format!("{FIXTURES}/server.key.pem").into(),
        ca: None,
        client_auth: ClientAuth::NoCert,
        keylog: None,
    })
    .unwrap();
    let served = Arc::new(AtomicUsize::new(0));
    let key = || ListenerKey {
        transport: pharos_server::Transport::Quic,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let mut listeners = ListenerRegistry::default();
    listeners
        .apply(HashMap::from([(
            key(),
            Answer {
                tls,
                served: Arc::clone(&served),
            },
        )]))
        .await
        .unwrap();
    let address = listeners.get(&key()).unwrap().local_addr();
    (address, served, listeners)
}

fn chain(text: &str) -> Chain {
    let blocks = parse("Corefile", text).unwrap();
    configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config
}

async fn run(chain: &Chain) -> (Outcome, Vec<u8>) {
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let mut slots = [];
    let mut context = Context {
        query: Message::parse(QUERY).unwrap(),
        client: "127.0.0.1:1000".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let outcome = chain.serve(&mut context).await;
    (outcome, response)
}

#[tokio::test]
async fn forwards_over_quic_and_reuses_the_connection() {
    let (address, served, listeners) = doq_server().await;
    let chain = chain(&format!(
        ".:0 {{\n forward . quic://{address} {{\n  tls {FIXTURES}/ca.pem\n  tls_servername localhost\n }}\n}}"
    ));
    for _ in 0..3 {
        let (outcome, response) = run(&chain).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&response).unwrap();
        assert_eq!(response.rcode(), Rcode::NOERROR);
        // RFC 9250 §4.2.1: the client's own Message ID returns.
        assert_eq!(response.id(), 0x1234);
        // Issue #110: AD from an upstream is dropped even over an authenticated channel.
        assert!(!response.ad());
    }
    assert_eq!(served.load(Ordering::SeqCst), 3);
    listeners.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 plugin/forward/README: `force_tcp` and `prefer_udp` do not change a DoQ upstream.
#[tokio::test]
async fn force_tcp_does_not_change_a_quic_upstream() {
    let (address, served, listeners) = doq_server().await;
    let chain = chain(&format!(
        ".:0 {{\n forward . quic://{address}%localhost {{\n  tls {FIXTURES}/ca.pem\n  force_tcp\n }}\n}}"
    ));
    let (outcome, _) = run(&chain).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(served.load(Ordering::SeqCst), 1);
    listeners.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 plugin/forward/setup.go: the endpoint zone and `tls_servername` select the verified name.
#[tokio::test]
async fn quic_server_name_selects_the_verified_name() {
    let (address, served, listeners) = doq_server().await;
    let ip = address.ip();
    let port = address.port();
    for (name, ok) in [("localhost", true), ("wrong.example", false)] {
        for forward in [
            format!("forward . quic://{ip}%{name}:{port} {{\n  tls {FIXTURES}/ca.pem\n }}"),
            format!(
                "forward . quic://{address} {{\n  tls {FIXTURES}/ca.pem\n  tls_servername {name}\n }}"
            ),
        ] {
            let chain = chain(&format!(".:0 {{\n {forward}\n}}"));
            let (outcome, response) = run(&chain).await;
            let rcode =
                (outcome == Outcome::Response).then(|| Message::parse(&response).unwrap().rcode());
            assert_eq!(
                rcode == Some(Rcode::NOERROR),
                ok,
                "{name}: {outcome:?} {rcode:?}"
            );
        }
    }
    assert_eq!(served.load(Ordering::SeqCst), 2);
    listeners.shutdown().await.unwrap();
}

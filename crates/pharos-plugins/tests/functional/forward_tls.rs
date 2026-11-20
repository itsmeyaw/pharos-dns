#![forbid(unsafe_code)]
#![cfg(feature = "plugin-forward")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name, Rcode};
use pharos_server::{
    Context, Metadata, Outcome, Protocol, Transport,
    tls::{ClientAuth, ServerOptions, ServerTls},
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

// RFC 7858 §3.3: DNS Messages over TLS use the two-octet length framing of RFC 1035 §4.2.2.
async fn dot_server() -> (SocketAddr, Arc<AtomicUsize>) {
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
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut wire = [0; 512];
                while let Ok(len) = stream.read_u16().await {
                    let len = usize::from(len);
                    stream.read_exact(&mut wire[..len]).await.unwrap();
                    wire[2] |= 0x80;
                    // RFC 4035 §3.2.3: an upstream sets AD on validated data.
                    wire[3] |= 0x20;
                    stream.write_u16(len as u16).await.unwrap();
                    stream.write_all(&wire[..len]).await.unwrap();
                    stream.flush().await.unwrap();
                }
            });
        }
    });
    (address, accepted)
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
async fn forwards_over_tls_and_reuses_the_connection() {
    let (address, accepted) = dot_server().await;
    let chain = chain(&format!(
        ".:0 {{\n forward . tls://{address} {{\n  tls {FIXTURES}/ca.pem\n }}\n}}"
    ));
    for _ in 0..3 {
        let (outcome, response) = run(&chain).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&response).unwrap();
        assert_eq!(response.rcode(), Rcode::NOERROR);
        // Issue #110: AD from an upstream is dropped even over an authenticated channel.
        assert!(!response.ad());
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

// CoreDNS v1.15.0 plugin/forward/README: `tls_servername` is the name the certificate must match.
#[tokio::test]
async fn tls_servername_selects_the_verified_name() {
    let (address, _) = dot_server().await;
    for (name, ok) in [("localhost", true), ("wrong.example", false)] {
        let chain = chain(&format!(
            ".:0 {{\n forward . tls://{address} {{\n  tls {FIXTURES}/ca.pem\n  tls_servername {name}\n }}\n}}"
        ));
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

#[tokio::test]
async fn endpoint_zone_selects_the_verified_name() {
    let (address, _) = dot_server().await;
    let ip = address.ip();
    let port = address.port();
    for (name, ok) in [("localhost", true), ("wrong.example", false)] {
        let chain = chain(&format!(
            ".:0 {{\n forward . tls://{ip}%{name}:{port} {{\n  tls {FIXTURES}/ca.pem\n }}\n}}"
        ));
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

// RFC 6125 §6.4.1: without a name the IP address is verified, and the fixture certificate has it as a SAN.
#[tokio::test]
async fn ip_address_is_verified_when_no_name_is_given() {
    let (address, _) = dot_server().await;
    let chain = chain(&format!(
        ".:0 {{\n forward . tls://{address} {{\n  tls {FIXTURES}/ca.pem\n }}\n}}"
    ));
    let (outcome, _) = run(&chain).await;
    assert_eq!(outcome, Outcome::Response);
}

#[tokio::test]
async fn an_untrusted_certificate_is_rejected() {
    let (address, _) = dot_server().await;
    let chain = chain(&format!(
        ".:0 {{\n forward . tls://{address} {{\n  tls {FIXTURES}/other-ca.pem\n }}\n}}"
    ));
    let (outcome, response) = run(&chain).await;
    let rcode = (outcome == Outcome::Response).then(|| Message::parse(&response).unwrap().rcode());
    assert_ne!(rcode, Some(Rcode::NOERROR), "{outcome:?}");
}

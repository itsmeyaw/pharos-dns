#![forbid(unsafe_code)]

use std::{collections::HashMap, net::SocketAddr, path::PathBuf, time::Duration};

use pharos_server::{
    Action, Handler, ListenerKey, ListenerRegistry, Protocol, Transport,
    tls::{CertSlot, ClientOptions, ServerTls, TlsConnector, client_config},
};
use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::{net::TcpStream, time::timeout};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/tls")
        .join(name)
}

struct Echo(ServerTls);

impl Handler for Echo {
    fn tls(&self) -> Option<ServerTls> {
        Some(self.0.clone())
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        response.extend_from_slice(query);
        Action::Respond
    }
}

async fn listening(slot: &std::sync::Arc<CertSlot>) -> (ListenerRegistry, SocketAddr) {
    let key = ListenerKey {
        transport: Transport::Tls,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let tls = ServerTls::from_slot(slot, "test").unwrap();
    let mut registry = ListenerRegistry::default();
    registry
        .apply(HashMap::from([(key, Echo(tls))]))
        .await
        .unwrap();
    let address = registry.get(&key).unwrap().local_addr();
    (registry, address)
}

async fn handshake(address: SocketAddr, name: &str) -> Option<CertificateDer<'static>> {
    let config = client_config(&ClientOptions {
        ca: Some(fixture("ca.pem")),
        identity: None,
    })
    .unwrap();
    let tcp = TcpStream::connect(address).await.unwrap();
    let stream = timeout(
        Duration::from_secs(3),
        TlsConnector::from(config).connect(ServerName::try_from(name.to_owned()).unwrap(), tcp),
    )
    .await
    .unwrap()
    .ok()?;
    Some(stream.get_ref().1.peer_certificates().unwrap()[0].clone())
}

fn load(slot: &CertSlot, name: &str, prefix: &str) {
    slot.load(
        name,
        &fixture(&format!("{prefix}.pem")),
        &fixture(&format!("{prefix}.key.pem")),
    )
    .unwrap();
}

// CoreDNS v1.15.0 plugin/tls/acme.go acmeEntry.getCertificate: no certificate yet is an error.
#[tokio::test]
async fn handshake_fails_until_a_certificate_is_loaded() {
    let slot = CertSlot::new(&["localhost".to_owned()]);
    let (registry, address) = listening(&slot).await;
    assert!(handshake(address, "localhost").await.is_none());
    assert!(!slot.ready("localhost"));
    load(&slot, "localhost", "server");
    assert!(slot.ready("localhost"));
    assert!(handshake(address, "localhost").await.is_some());
    registry.shutdown().await.unwrap();
}

// RFC 8555 §7.1.3: a renewed certificate replaces the old one for new connections on the same Listener.
#[tokio::test]
async fn renewed_certificate_is_served_without_restarting_the_listener() {
    let slot = CertSlot::new(&["localhost".to_owned()]);
    load(&slot, "localhost", "server");
    let (registry, address) = listening(&slot).await;
    let first = handshake(address, "localhost").await.unwrap();
    load(&slot, "localhost", "server-renewed");
    let second = handshake(address, "localhost").await.unwrap();
    assert_ne!(first, second);
    registry.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 plugin/tls/acme.go acmeEntry.getCertificate: an unmanaged server name is rejected.
#[tokio::test]
async fn unmanaged_server_name_is_rejected() {
    let slot = CertSlot::new(&["other.example".to_owned()]);
    load(&slot, "other.example", "server");
    let (registry, address) = listening(&slot).await;
    assert!(handshake(address, "localhost").await.is_none());
    registry.shutdown().await.unwrap();
}

#[test]
fn loading_an_unmanaged_name_fails() {
    let slot = CertSlot::new(&["localhost".to_owned()]);
    let error = slot
        .load(
            "other.example",
            &fixture("server.pem"),
            &fixture("server.key.pem"),
        )
        .unwrap_err();
    assert!(error.to_string().contains("not managed"), "{error}");
}

#[test]
fn mismatched_key_is_rejected() {
    let slot = CertSlot::new(&["localhost".to_owned()]);
    let error = slot
        .load(
            "localhost",
            &fixture("server.pem"),
            &fixture("server-renewed.key.pem"),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("could not load TLS cert"),
        "{error}"
    );
    assert!(!slot.ready("localhost"));
}

#[test]
fn identities_conflict_unless_they_name_the_same_slot_configuration() {
    let slot = CertSlot::new(&["localhost".to_owned()]);
    let a = ServerTls::from_slot(&slot, "one").unwrap();
    let same = ServerTls::from_slot(&slot, "one").unwrap();
    let other = ServerTls::from_slot(&slot, "two").unwrap();
    assert_eq!(a.conflict(&same), None);
    assert_eq!(a.conflict(&other), Some("server certificates differ"));
}

async fn listening_quic(tls: ServerTls) -> (ListenerRegistry, SocketAddr) {
    let key = ListenerKey {
        transport: Transport::Quic,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let mut registry = ListenerRegistry::default();
    registry
        .apply(HashMap::from([(key, Echo(tls))]))
        .await
        .unwrap();
    let address = registry.get(&key).unwrap().local_addr();
    (registry, address)
}

async fn quic_handshake(address: SocketAddr, alpn: &[u8]) -> Option<CertificateDer<'static>> {
    let tls = client_config(&ClientOptions {
        ca: Some(fixture("ca.pem")),
        identity: None,
    })
    .unwrap();
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(ClientConfig::new(std::sync::Arc::new(
        QuicClientConfig::try_from(tls).unwrap(),
    )));
    let connection = timeout(
        Duration::from_secs(3),
        endpoint.connect(address, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .ok()?;
    let chain = connection
        .peer_identity()
        .unwrap()
        .downcast::<Vec<CertificateDer<'static>>>()
        .unwrap();
    Some(chain[0].clone())
}

// RFC 9250 §4.1.1, RFC 9114 §3.1: one slot feeds DoT (TCP), DoQ and HTTP/3 (QUIC) configs, so a renewal reaches all of them.
#[tokio::test]
async fn renewed_certificate_is_served_over_tls_and_quic() {
    let slot = CertSlot::new(&["localhost".to_owned()]);
    load(&slot, "localhost", "server");
    let (dot, dot_address) = listening(&slot).await;
    let tls = ServerTls::from_slot(&slot, "test").unwrap();
    let (doq, doq_address) = listening_quic(tls.clone()).await;
    let h3 = tls.with_alpn(&[b"h2"]).with_quic_alpn(&[b"h3"]).unwrap();
    let (h3, h3_address) = listening_quic(h3).await;
    let before = (
        handshake(dot_address, "localhost").await.unwrap(),
        quic_handshake(doq_address, b"doq").await.unwrap(),
        quic_handshake(h3_address, b"h3").await.unwrap(),
    );
    load(&slot, "localhost", "server-renewed");
    assert_ne!(handshake(dot_address, "localhost").await.unwrap(), before.0);
    assert_ne!(quic_handshake(doq_address, b"doq").await.unwrap(), before.1);
    assert_ne!(quic_handshake(h3_address, b"h3").await.unwrap(), before.2);
    for registry in [dot, doq, h3] {
        registry.shutdown().await.unwrap();
    }
}

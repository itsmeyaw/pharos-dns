//! The ACME client against a local stub ACME server (Pebble is not available to the test suite).
//!
//! The stub verifies every JWS, enforces single-use nonces, checks the dns-01 TXT value against the
//! Solver the way a CA would query DNS, and issues a certificate for the CSR's key.

use std::{
    collections::HashSet,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use aws_lc_rs::{
    digest::{SHA256, digest},
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED, EcdsaKeyPair, UnparsedPublicKey,
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use pharos_corefile::{configure, parse};
use pharos_server::Phase;
use serde_json::{Value, json};
use tokio::net::{TcpListener, UdpSocket};

use super::{
    Entry, Options, Solver, der, jws::b64, link, manager, solver::tests::answer, store::pem_encode,
};
use crate::{Chain, directives, tls::Tls};

fn decode(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).unwrap()
}

#[derive(Default)]
struct State {
    nonces: HashSet<String>,
    issued: u64,
    jwk: Option<Value>,
    authorized: bool,
    finalized: bool,
    certificate: Option<String>,
    rejected_nonce: bool,
    refused: bool,
    log: Vec<String>,
}

struct Stub {
    base: String,
    /// The identifier of the order, as the order lists it.
    name: String,
    /// Refuse every challenge, as a CA that cannot see the TXT record would.
    refuse: bool,
    solver: Arc<Solver>,
    ca: EcdsaKeyPair,
    state: Mutex<State>,
}

type Reply = (u16, Vec<(&'static str, String)>, Vec<u8>);

fn problem(status: u16, kind: &str, detail: &str) -> Reply {
    (
        status,
        vec![("content-type", "application/problem+json".into())],
        json!({"type": format!("urn:ietf:params:acme:error:{kind}"), "detail": detail})
            .to_string()
            .into_bytes(),
    )
}

fn thumbprint(jwk: &Value) -> String {
    let json = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap()
    );
    b64(digest(&SHA256, json.as_bytes()))
}

impl Stub {
    fn identifier(&self) -> &str {
        self.name.strip_prefix("*.").unwrap_or(&self.name)
    }

    fn order(&self, status: &str, state: &State) -> Value {
        let mut order = json!({
            "status": status,
            "identifiers": [{"type": "dns", "value": self.name}],
            "authorizations": [format!("{}/authz/1", self.base)],
            "finalize": format!("{}/order/1/finalize", self.base),
        });
        if state.finalized && status == "valid" {
            order["certificate"] = json!(format!("{}/cert/1", self.base));
        }
        order
    }

    fn handle(&self, method: &str, path: &str, body: &[u8]) -> Reply {
        let mut state = self.state.lock().unwrap();
        state.issued += 1;
        let nonce = format!("nonce-{}", state.issued);
        state.nonces.insert(nonce.clone());
        state.log.push(format!("{method} {path}"));
        let (status, mut headers, body) = self.route(&mut state, method, path, body);
        headers.push(("replay-nonce", nonce));
        (status, headers, body)
    }

    fn route(&self, state: &mut State, method: &str, path: &str, body: &[u8]) -> Reply {
        let json = |value: Value| {
            (
                200,
                vec![("content-type", "application/json".to_owned())],
                value.to_string().into_bytes(),
            )
        };
        match (method, path) {
            ("GET", "/directory") => {
                return json(json!({
                    "newNonce": format!("{}/nonce", self.base),
                    "newAccount": format!("{}/acct", self.base),
                    "newOrder": format!("{}/order", self.base),
                }));
            }
            ("HEAD", "/nonce") => return (200, vec![], vec![]),
            ("POST", _) => {}
            _ => return problem(404, "malformed", "no such resource"),
        }
        // RFC 8555 §6.5: the first request is refused with badNonce to show clients retry with the fresh nonce.
        if !state.rejected_nonce {
            state.rejected_nonce = true;
            return problem(400, "badNonce", "try again");
        }
        let envelope: Value = serde_json::from_slice(body).unwrap();
        let protected = envelope["protected"].as_str().unwrap();
        let header: Value = serde_json::from_slice(&decode(protected)).unwrap();
        // RFC 8555 §6.4: the signed URL must be the request URL.
        assert_eq!(header["url"], format!("{}{path}", self.base));
        assert_eq!(header["alg"], "ES256");
        // RFC 8555 §6.5: a nonce is accepted once.
        let nonce = header["nonce"].as_str().unwrap();
        if !state.nonces.remove(nonce) {
            return problem(400, "badNonce", "unknown or reused nonce");
        }
        let jwk = if path == "/acct" {
            assert!(header.get("kid").is_none());
            header["jwk"].clone()
        } else {
            assert_eq!(header["kid"], format!("{}/acct/1", self.base));
            state.jwk.clone().unwrap()
        };
        let mut point = vec![4];
        point.extend(decode(jwk["x"].as_str().unwrap()));
        point.extend(decode(jwk["y"].as_str().unwrap()));
        let payload = envelope["payload"].as_str().unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
            .verify(
                format!("{protected}.{payload}").as_bytes(),
                &decode(envelope["signature"].as_str().unwrap()),
            )
            .expect("the JWS signature verifies");
        let payload: Option<Value> =
            (!payload.is_empty()).then(|| serde_json::from_slice(&decode(payload)).unwrap());

        match path {
            "/acct" => {
                assert_eq!(payload.unwrap()["termsOfServiceAgreed"], true);
                state.jwk = Some(jwk);
                (
                    201,
                    vec![
                        ("location", format!("{}/acct/1", self.base)),
                        ("content-type", "application/json".into()),
                    ],
                    br#"{"status":"valid"}"#.to_vec(),
                )
            }
            "/order" => {
                assert_eq!(payload.unwrap()["identifiers"][0]["value"], self.name);
                let (_, mut headers, body) = json(self.order("pending", state));
                headers.push(("location", format!("{}/order/1", self.base)));
                (201, headers, body)
            }
            "/authz/1" => {
                assert!(
                    payload.is_none(),
                    "an authorization is fetched with POST-as-GET"
                );
                json(json!({
                    "status": if state.authorized { "valid" } else if state.refused { "invalid" } else { "pending" },
                    "identifier": {"type": "dns", "value": self.identifier()},
                    "wildcard": self.name.starts_with("*."),
                    "challenges": [
                        {"type": "http-01", "url": format!("{}/chall/0", self.base), "token": "ignored", "status": "pending"},
                        {"type": "dns-01", "url": format!("{}/chall/1", self.base), "token": "tok123", "status": "pending"},
                    ],
                }))
            }
            "/chall/1" => {
                assert_eq!(payload.unwrap(), json!({}));
                // RFC 8555 §8.4: the CA looks for base64url(SHA-256(token "." thumbprint)) at _acme-challenge.<identifier>.
                let expected = b64(digest(
                    &SHA256,
                    format!("tok123.{}", thumbprint(state.jwk.as_ref().unwrap())).as_bytes(),
                ));
                let seen = self
                    .solver
                    .values(&format!("_acme-challenge.{}.", self.identifier()));
                if seen.contains(&expected) && !self.refuse {
                    state.authorized = true;
                } else {
                    state.refused = true;
                }
                json(json!({"status": "processing", "type": "dns-01"}))
            }
            "/order/1/finalize" => {
                assert!(
                    state.authorized,
                    "finalize only after the authorization is valid"
                );
                let csr = decode(payload.unwrap()["csr"].as_str().unwrap());
                state.certificate = Some(self.issue(&csr));
                state.finalized = true;
                json(self.order("processing", state))
            }
            "/order/1" => json(self.order(
                if state.certificate.is_some() {
                    "valid"
                } else {
                    "pending"
                },
                state,
            )),
            "/cert/1" => (
                200,
                vec![("content-type", "application/pem-certificate-chain".into())],
                state.certificate.clone().unwrap().into_bytes(),
            ),
            _ => problem(404, "malformed", "no such resource"),
        }
    }

    // RFC 5280 §4.1: a v3 certificate for the CSR's subject and key, signed by the stub CA.
    fn issue(&self, csr: &[u8]) -> String {
        use der::{sequence, tlv};
        let mut csr = der::Reader::new(der::Reader::new(csr).expect(0x30).unwrap());
        let mut info = der::Reader::new(csr.expect(0x30).unwrap());
        info.next().unwrap();
        let (_, _, subject) = info.next().unwrap();
        let (_, _, spki) = info.next().unwrap();
        let signature_algorithm = sequence(&[&tlv(6, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2])]);
        let issuer = sequence(&[&tlv(
            0x31,
            &sequence(&[&tlv(6, &[0x55, 4, 3]), &tlv(0x0c, b"Stub CA")]),
        )]);
        let san = tlv(0x30, &tlv(0x82, self.name.as_bytes()));
        let extensions = tlv(
            0xa3,
            &sequence(&[&sequence(&[&tlv(6, &[0x55, 0x1d, 0x11]), &tlv(4, &san)])]),
        );
        let tbs = sequence(&[
            &tlv(0xa0, &tlv(2, &[2])),
            &tlv(2, &[1]),
            &signature_algorithm,
            &issuer,
            &sequence(&[&tlv(0x17, b"200101000000Z"), &tlv(0x17, b"491231235959Z")]),
            subject,
            spki,
            &extensions,
        ]);
        let signature = self.ca.sign(&SystemRandom::new(), &tbs).unwrap();
        let mut bits = vec![0];
        bits.extend_from_slice(signature.as_ref());
        pem_encode(
            "CERTIFICATE",
            &sequence(&[&tbs, &signature_algorithm, &tlv(3, &bits)]),
        )
    }
}

async fn serve(listener: TcpListener, name: &str, refuse: bool, solver: Arc<Solver>) -> Arc<Stub> {
    let ca_key =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .unwrap();
    let stub = Arc::new(Stub {
        base: format!("http://{}", listener.local_addr().unwrap()),
        name: name.to_owned(),
        refuse,
        solver,
        ca: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, ca_key.as_ref()).unwrap(),
        state: Mutex::default(),
    });
    let served = Arc::clone(&stub);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let stub = Arc::clone(&served);
            tokio::spawn(hyper::server::conn::http1::Builder::new().serve_connection(
                TokioIo::new(stream),
                service_fn(move |request: Request<Incoming>| {
                    let stub = Arc::clone(&stub);
                    async move {
                        let (parts, body) = request.into_parts();
                        let body = body.collect().await?.to_bytes();
                        let (status, headers, body) =
                            stub.handle(parts.method.as_str(), parts.uri.path(), &body);
                        let mut response = Response::builder().status(status);
                        for (name, value) in headers {
                            response = response.header(name, value);
                        }
                        Ok::<_, hyper::Error>(response.body(Full::new(Bytes::from(body))).unwrap())
                    }
                }),
            ));
        }
    });
    stub
}

/// A UDP DNS server answering `_acme-challenge` TXT Queries from `solver`, as the `resolver` option expects.
fn serve_dns(socket: UdpSocket, solver: &Arc<Solver>) {
    let tls = Tls::challenge_only(Arc::clone(solver));
    tokio::spawn(async move {
        let mut buffer = [0; 512];
        loop {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let (outcome, wire) = answer(&tls, &buffer[..len]).await;
            if outcome == pharos_server::Outcome::Response {
                socket.send_to(&wire, peer).await.unwrap();
            }
        }
    });
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pharos-acme-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn options(name: &str, base: &str, storage: PathBuf, resolver: Option<SocketAddr>) -> Options {
    Options {
        domains: vec![name.to_owned()],
        email: Some("admin@example.org".into()),
        ca: format!("{base}/directory"),
        storage,
        ca_root: None,
        resolver: resolver.map(|address| address.to_string()),
    }
}

fn blocks(options: &Options) -> Vec<pharos_corefile::BlockContext<Chain>> {
    let text = format!(
        "tls://.:853 {{\n tls {{\n  acme {}\n  email admin@example.org\n  ca {}\n  storage {}\n  resolver {}\n }}\n}}\n",
        options.domains[0],
        options.ca,
        options.storage.display(),
        options.resolver.as_deref().unwrap()
    );
    configure(&parse("Corefile", &text).unwrap(), directives()).unwrap()
}

async fn issued(name: &str) {
    let dir = scratch(&name.replace('*', "w"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let options = options(name, &base, dir.clone(), Some(socket.local_addr().unwrap()));
    let mut blocks = blocks(&options);
    let runtime = link(&mut blocks).unwrap().unwrap();
    let stub = serve(listener, name, false, Arc::clone(&runtime.solver)).await;
    serve_dns(socket, &runtime.solver);
    let mut lifecycle = pharos_server::Lifecycle::default();
    runtime.register(&mut lifecycle);
    lifecycle.run(Phase::Startup).await.unwrap();
    lifecycle.run(Phase::Started).await.unwrap();

    let entry = Arc::clone(&runtime.entries[0]);
    tokio::time::timeout(Duration::from_secs(30), async {
        while !entry.slot.ready(name) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the certificate is installed");
    lifecycle.run(Phase::Shutdown).await.unwrap();

    let state = stub.state.lock().unwrap();
    assert_eq!(state.log[0], "GET /directory");
    assert!(state.log.iter().any(|line| line == "POST /cert/1"));
    drop(state);
    assert!(
        runtime
            .solver
            .values(&format!("_acme-challenge.{}.", stub.identifier()))
            .is_empty(),
        "the TXT record is withdrawn"
    );

    // A restart serves the stored certificate before the CA is contacted.
    let fresh = Entry::new(options).unwrap();
    assert!(!fresh.slot.ready(name));
    manager::load_stored(&fresh);
    assert!(fresh.slot.ready(name));
    let store = super::store::Store::new(&fresh.options);
    assert!(store.account(Some("admin@example.org")).is_some());
    let (_, _, validity) = store.certificate(name).unwrap();
    assert!(validity.not_before < validity.not_after);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_certificate_is_obtained_over_dns_01_and_reused_after_a_restart() {
    issued("dns.example").await;
}

// RFC 8555 §7.1.3: a wildcard order's authorization names the base domain, and its TXT record goes there.
#[tokio::test]
async fn a_wildcard_certificate_is_validated_at_the_base_domain() {
    issued("*.dns.example").await;
}

#[tokio::test]
async fn a_refused_challenge_fails_and_withdraws_the_record() {
    let solver = Arc::new(Solver::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let dir = scratch("refused");
    serve(listener, "dns.example", true, Arc::clone(&solver)).await;
    let entry = Entry::new(options("dns.example", &base, dir.clone(), None)).unwrap();
    let store = super::store::Store::new(&entry.options);
    let error = manager::obtain(&entry, &solver, &store, "dns.example")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("invalid"), "{error}");
    assert!(solver.values("_acme-challenge.dns.example.").is_empty());
    assert!(!entry.slot.ready("dns.example"));
    std::fs::remove_dir_all(dir).unwrap();
}

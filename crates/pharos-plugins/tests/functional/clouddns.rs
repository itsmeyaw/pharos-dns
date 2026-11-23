#![cfg(feature = "plugin-clouddns")]

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Context, Metadata, Outcome, Phase, Protocol, Transport};
use serde_json::{Value, json};
use tokio::{net::TcpListener, task::JoinHandle};

const SECRET: &str = "SECRET-MARKER";

#[derive(Default)]
struct State {
    zones: HashMap<String, Vec<Value>>,
    failing: HashSet<String>,
    page_size: usize,
    tokens: usize,
    listings: usize,
    rejected: usize,
}

// Google Cloud DNS API v1 and the OAuth token endpoint, on a local port.
struct Cloud {
    state: Arc<Mutex<State>>,
    address: SocketAddr,
    task: JoinHandle<()>,
    dir: tempfile::TempDir,
}

impl Drop for Cloud {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn respond(state: &Mutex<State>, target: &str, authorization: Option<&str>) -> (u16, Value) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut state = state.lock().unwrap();
    if path == "/token" {
        state.tokens += 1;
        // Short-lived, so every refresh round has to fetch a new one.
        let body = json!({"access_token": format!("token-{}", state.tokens), "expires_in": 1, "token_type": "Bearer"});
        return (200, body);
    }
    let latest = format!("Bearer token-{}", state.tokens);
    if authorization != Some(latest.as_str()) {
        state.rejected += 1;
        return (401, json!({"error": {"status": "UNAUTHENTICATED"}}));
    }
    let Some(rest) = path.strip_prefix("/dns/v1/projects/") else {
        return (404, json!({}));
    };
    let parts: Vec<&str> = rest.split('/').collect();
    let key = format!("{}/{}", parts[0], parts[2]);
    let Some(rrsets) = state.zones.get(&key).cloned() else {
        return (404, json!({"error": {"status": "NOT_FOUND"}}));
    };
    if parts.len() == 3 {
        return (200, json!({"name": parts[2]}));
    }
    state.listings += 1;
    if state.failing.contains(&key) {
        return (500, json!({"error": {"status": "INTERNAL"}}));
    }
    let start: usize = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("pageToken="))
        .map_or(0, |token| token.parse().unwrap());
    let size = if state.page_size == 0 {
        rrsets.len().max(1)
    } else {
        state.page_size
    };
    let end = (start + size).min(rrsets.len());
    let mut body = json!({"rrsets": rrsets[start..end]});
    if end < rrsets.len() {
        body["nextPageToken"] = json!(end.to_string());
    }
    (200, body)
}

impl Cloud {
    async fn new() -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shared = Arc::clone(&state);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let authorization = request
                            .headers()
                            .get("authorization")
                            .map(|value| value.to_str().unwrap().to_owned());
                        let target = request.uri().to_string();
                        let (status, body) = respond(&shared, &target, authorization.as_deref());
                        async move {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::from(body.to_string())))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let credentials = json!({
            "type": "authorized_user",
            "client_id": "client",
            "client_secret": SECRET,
            "refresh_token": SECRET,
            "token_uri": format!("http://{address}/token"),
        });
        std::fs::write(dir.path().join("creds.json"), credentials.to_string()).unwrap();
        Self {
            state,
            address,
            task,
            dir,
        }
    }

    fn set(&self, zone: &str, rrsets: Vec<Value>) {
        self.state
            .lock()
            .unwrap()
            .zones
            .insert(format!("p/{zone}"), rrsets);
    }

    fn fail(&self, zone: &str, failing: bool) {
        let mut state = self.state.lock().unwrap();
        if failing {
            state.failing.insert(format!("p/{zone}"));
        } else {
            state.failing.remove(&format!("p/{zone}"));
        }
    }

    fn corefile(&self, zones: &str, options: &str, after: &str) -> String {
        format!(
            "org:53 {{\n clouddns {zones} {{\n credentials {}\n endpoint http://{}\n {options}\n }}\n {after}\n}}",
            self.dir.path().join("creds.json").display(),
            self.address
        )
    }
}

fn rr(name: &str, rtype: &str, data: &[&str]) -> Value {
    json!({"name": name, "type": rtype, "ttl": 300, "rrdatas": data})
}

fn apex(server: &str) -> Vec<Value> {
    vec![
        rr(
            "example.org.",
            "SOA",
            &[&format!(
                "{server}.example.net. hostmaster.example.net. 1 21600 300 259200 300"
            )],
        ),
        rr("example.org.", "NS", &[&format!("{server}.example.net.")]),
    ]
}

fn zone_with(records: Vec<Value>) -> Vec<Value> {
    let mut rrsets = records;
    rrsets.extend(apex("ns-a"));
    rrsets
}

async fn ask(chain: &Chain, name: &str, kind: Type) -> (Outcome, Vec<u8>) {
    let domain: Name = name.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
    builder
        .question(
            NameRef::parse(domain.as_wire(), 0).unwrap(),
            kind,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut context = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let outcome = chain.serve(&mut context).await;
    drop(context);
    (outcome, response)
}

fn addresses(response: &[u8]) -> Vec<Vec<u8>> {
    Message::parse(response)
        .unwrap()
        .answers()
        .map(|record| record.rdata.to_vec())
        .collect()
}

async fn eventually<F: Future<Output = bool>>(mut check: impl FnMut() -> F) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !check().await {
        assert!(Instant::now() < deadline, "condition not reached in time");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn configure_chain(text: &str) -> Vec<pharos_corefile::BlockContext<Chain>> {
    configure::<Chain>(&parse("Corefile", text).unwrap(), directives()).unwrap()
}

#[tokio::test]
async fn serves_the_loaded_zone_and_stops_with_shutdown() {
    let cloud = Cloud::new().await;
    cloud.set(
        "z",
        zone_with(vec![rr("www.example.org.", "A", &["192.0.2.1"])]),
    );
    let configured = configure_chain(&cloud.corefile("example.org.:p:z", "", ""));
    let chain = &configured[0].config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    let (outcome, response) = ask(chain, "www.example.org.", Type::A).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(addresses(&response), [vec![192, 0, 2, 1]]);
    let (outcome, response) = ask(chain, "absent.example.org.", Type::A).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NXDOMAIN);
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

// Before Startup no Zone is loaded, which CoreDNS answers with SERVFAIL.
#[tokio::test]
async fn an_unloaded_zone_is_servfail() {
    let cloud = Cloud::new().await;
    cloud.set("z", zone_with(vec![]));
    let configured = configure_chain(&cloud.corefile("example.org.:p:z", "", ""));
    let (outcome, _) = ask(&configured[0].config, "www.example.org.", Type::A).await;
    assert_eq!(outcome, Outcome::Unanswered(Rcode::SERVFAIL));
}

#[tokio::test]
async fn a_new_token_is_fetched_when_the_old_one_expires() {
    let cloud = Cloud::new().await;
    cloud.set(
        "z",
        zone_with(vec![rr("www.example.org.", "A", &["192.0.2.1"])]),
    );
    let configured = configure_chain(&cloud.corefile("example.org.:p:z", "refresh 50ms", ""));
    let chain = &configured[0].config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    cloud.set(
        "z",
        zone_with(vec![rr("www.example.org.", "A", &["192.0.2.2"])]),
    );
    eventually(|| async {
        addresses(&ask(chain, "www.example.org.", Type::A).await.1) == [vec![192, 0, 2, 2]]
    })
    .await;
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    let state = cloud.state.lock().unwrap();
    assert!(state.tokens >= 2, "{} tokens", state.tokens);
    assert_eq!(state.rejected, 0);
}

#[tokio::test]
async fn every_page_of_a_listing_is_read() {
    let cloud = Cloud::new().await;
    let records = (0..7)
        .map(|index| {
            rr(
                &format!("h{index}.example.org."),
                "A",
                &[&format!("192.0.2.{index}")],
            )
        })
        .collect();
    cloud.set("z", zone_with(records));
    cloud.state.lock().unwrap().page_size = 3;
    let configured = configure_chain(&cloud.corefile("example.org.:p:z", "", ""));
    let chain = &configured[0].config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    // Nine record sets in pages of three.
    assert_eq!(cloud.state.lock().unwrap().listings, 3);
    for index in 0..7u8 {
        let (_, response) = ask(chain, &format!("h{index}.example.org."), Type::A).await;
        assert_eq!(addresses(&response), [vec![192, 0, 2, index]]);
    }
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn a_failing_api_keeps_the_last_good_data() {
    let cloud = Cloud::new().await;
    cloud.set(
        "z",
        zone_with(vec![rr("www.example.org.", "A", &["192.0.2.1"])]),
    );
    let configured = configure_chain(&cloud.corefile("example.org.:p:z", "refresh 30ms", ""));
    let chain = &configured[0].config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    cloud.fail("z", true);
    let before = cloud.state.lock().unwrap().listings;
    eventually(|| async { cloud.state.lock().unwrap().listings >= before + 3 }).await;
    let (outcome, response) = ask(chain, "www.example.org.", Type::A).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(addresses(&response), [vec![192, 0, 2, 1]]);
    cloud.fail("z", false);
    cloud.set(
        "z",
        zone_with(vec![rr("www.example.org.", "A", &["192.0.2.7"])]),
    );
    eventually(|| async {
        addresses(&ask(chain, "www.example.org.", Type::A).await.1) == [vec![192, 0, 2, 7]]
    })
    .await;
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn a_first_load_that_fails_stops_startup_without_leaking_secrets() {
    let cloud = Cloud::new().await;
    cloud.set("z", zone_with(vec![]));
    cloud.fail("z", true);
    let configured = configure_chain(&cloud.corefile("example.org.:p:z", "", ""));
    let error = configured[0]
        .config
        .lifecycle
        .run(Phase::Startup)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("clouddns") && !error.contains(SECRET),
        "{error}"
    );
    let configured = configure_chain(&cloud.corefile("example.org.:p:absent", "", ""));
    let error = configured[0]
        .config
        .lifecycle
        .run(Phase::Startup)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("absent") && !error.contains(SECRET),
        "{error}"
    );
}

#[tokio::test]
async fn hosted_zones_of_one_name_are_searched_in_order() {
    let cloud = Cloud::new().await;
    cloud.set(
        "first",
        zone_with(vec![rr("one.example.org.", "A", &["192.0.2.1"])]),
    );
    cloud.set(
        "second",
        zone_with(vec![rr("two.example.org.", "A", &["192.0.2.2"])]),
    );
    let configured =
        configure_chain(&cloud.corefile("example.org.:p:first example.org.:p:second", "", ""));
    let chain = &configured[0].config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    for (name, last) in [("one.example.org.", 1), ("two.example.org.", 2)] {
        let (outcome, response) = ask(chain, name, Type::A).await;
        assert_eq!(outcome, Outcome::Response, "{name}");
        assert_eq!(addresses(&response), [vec![192, 0, 2, last]], "{name}");
    }
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[cfg(feature = "plugin-whoami")]
#[tokio::test]
async fn fallthrough_hands_a_missing_name_to_the_next_plugin() {
    let cloud = Cloud::new().await;
    cloud.set("z", zone_with(vec![]));
    for (options, rcode) in [("", Rcode::NXDOMAIN), ("fallthrough", Rcode::NOERROR)] {
        let configured = configure_chain(&cloud.corefile("example.org.:p:z", options, "whoami"));
        let chain = &configured[0].config;
        chain.lifecycle.run(Phase::Startup).await.unwrap();
        let (outcome, response) = ask(chain, "absent.example.org.", Type::A).await;
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(
            Message::parse(&response).unwrap().rcode(),
            rcode,
            "{options}"
        );
        chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    }
}

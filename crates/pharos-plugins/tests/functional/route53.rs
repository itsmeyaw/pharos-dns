#![forbid(unsafe_code)]
#![cfg(feature = "plugin-route53")]

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Action, Handler, Lifecycle, Phase, Protocol, Server};
use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpListener;

type Dns = Server<Arc<Chain>>;

const SOA: &str = "ns-1.awsdns-00.org. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400";
const XMLNS: &str = "https://route53.amazonaws.com/doc/2013-04-01/";

type Sets = Vec<(String, &'static str, Vec<String>)>;

#[derive(Default)]
struct State {
    sets: HashMap<String, Sets>,
    page_size: usize,
    status: u16,
    requests: Vec<String>,
}

/// A local stand-in for the Route 53 REST API: the two calls the Plugin makes.
struct Stub {
    endpoint: String,
    state: Arc<Mutex<State>>,
}

fn query_of(request: &Request<Incoming>) -> HashMap<String, String> {
    request
        .uri()
        .query()
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

fn answer(state: &State, path: &str, query: &HashMap<String, String>) -> (u16, String) {
    if state.status != 200 {
        let error = "<ErrorResponse><Error><Type>Sender</Type><Code>Stub</Code><Message>stub failure</Message></Error><RequestId>1</RequestId></ErrorResponse>";
        return (state.status, error.to_owned());
    }
    if path.ends_with("/hostedzonesbyname") {
        return (
            200,
            format!(
                "<ListHostedZonesByNameResponse xmlns=\"{XMLNS}\"><HostedZones></HostedZones><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems></ListHostedZonesByNameResponse>"
            ),
        );
    }
    // GET /2013-04-01/hostedzone/{id}/rrset
    let id = path.split('/').nth_back(1).unwrap_or_default();
    let Some(sets) = state.sets.get(id) else {
        return (404, "<ErrorResponse><Error><Type>Sender</Type><Code>NoSuchHostedZone</Code><Message>none</Message></Error><RequestId>1</RequestId></ErrorResponse>".to_owned());
    };
    // The stub's NextRecordName is the index of the first record set of the next page.
    let from = query
        .get("name")
        .and_then(|name| name.parse::<usize>().ok())
        .unwrap_or(0);
    let size = if state.page_size == 0 {
        sets.len().max(1)
    } else {
        state.page_size
    };
    let end = (from + size).min(sets.len());
    let mut body =
        format!("<ListResourceRecordSetsResponse xmlns=\"{XMLNS}\"><ResourceRecordSets>");
    for (name, rtype, values) in &sets[from..end] {
        body += &format!("<ResourceRecordSet><Name>{name}</Name><Type>{rtype}</Type>");
        if values.is_empty() {
            body += "<AliasTarget><HostedZoneId>Z</HostedZoneId><DNSName>alias.example.net.</DNSName><EvaluateTargetHealth>false</EvaluateTargetHealth></AliasTarget>";
        } else {
            body += "<TTL>300</TTL><ResourceRecords>";
            for value in values {
                body += &format!("<ResourceRecord><Value>{value}</Value></ResourceRecord>");
            }
            body += "</ResourceRecords>";
        }
        body += "</ResourceRecordSet>";
    }
    body += "</ResourceRecordSets>";
    if end < sets.len() {
        body += &format!(
            "<IsTruncated>true</IsTruncated><NextRecordName>{end}</NextRecordName><NextRecordType>A</NextRecordType>"
        );
    } else {
        body += "<IsTruncated>false</IsTruncated>";
    }
    body += "<MaxItems>1000</MaxItems></ListResourceRecordSetsResponse>";
    (200, body)
}

impl Stub {
    /// Serves on its own thread and runtime, because Plugin setup blocks the test's runtime.
    fn start() -> Self {
        let state = Arc::new(Mutex::new(State {
            status: 200,
            ..State::default()
        }));
        let (sender, receiver) = std::sync::mpsc::channel();
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                sender.send(listener.local_addr().unwrap()).unwrap();
                loop {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let state = Arc::clone(&shared);
                    tokio::spawn(async move {
                        let service = service_fn(move |request: Request<Incoming>| {
                            let state = Arc::clone(&state);
                            async move {
                                let query = query_of(&request);
                                let path = request.uri().path().to_owned();
                                let (status, body) = {
                                    let mut state = state.lock().unwrap();
                                    state.requests.push(request.uri().to_string());
                                    answer(&state, &path, &query)
                                };
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(status)
                                        .header("content-type", "text/xml")
                                        .body(Full::new(Bytes::from(body)))
                                        .unwrap(),
                                )
                            }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(tcp), service)
                            .await;
                    });
                }
            });
        });
        Self {
            endpoint: format!("http://{}", receiver.recv().unwrap()),
            state,
        }
    }

    fn zone(&self, id: &str, sets: Sets) {
        self.state.lock().unwrap().sets.insert(id.to_owned(), sets);
    }

    fn status(&self, status: u16) {
        self.state.lock().unwrap().status = status;
    }

    fn requests(&self) -> Vec<String> {
        self.state.lock().unwrap().requests.clone()
    }
}

fn set(name: &str, rtype: &'static str, values: &[&str]) -> (String, &'static str, Vec<String>) {
    (
        name.to_owned(),
        rtype,
        values.iter().map(|value| (*value).to_owned()).collect(),
    )
}

fn apex(name: &str) -> Sets {
    vec![
        set(name, "SOA", &[SOA]),
        set(name, "NS", &["ns-1.awsdns-00.org."]),
    ]
}

/// A config file the SDK reads instead of the environment: region and static credentials.
fn profile() -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        file.path(),
        "[profile stub]\nregion = us-east-1\naws_access_key_id = AKIDEXAMPLE\naws_secret_access_key = secret\n",
    )
    .unwrap();
    file
}

fn corefile(stub: &Stub, profile: &tempfile::NamedTempFile, lines: &str, options: &str) -> String {
    format!(
        ".:0 {{\n {lines} {{\n  aws_endpoint {}\n  credentials stub {}\n  refresh 200ms\n  {options}\n }}\n}}",
        stub.endpoint,
        profile.path().display()
    )
}

async fn start(text: &str) -> Result<(Dns, Lifecycle), String> {
    let blocks = parse("Corefile", text).unwrap();
    let configured =
        configure::<Chain>(&blocks, directives()).map_err(|error| error.to_string())?;
    let (mut servers, lifecycle) = servers(configured).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();
    Ok((server, lifecycle))
}

struct Reply {
    rcode: Rcode,
    answers: Vec<String>,
}

async fn ask(server: &Dns, qname: &str, qtype: Type) -> Reply {
    let name: Name = qname.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x0100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(65535);
    let action = server
        .handle(
            &wire,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    assert_eq!(action, Action::Respond, "{qname} {qtype}");
    let message = Message::parse(&response).unwrap();
    Reply {
        rcode: message.rcode(),
        answers: message
            .answers()
            .map(|record| record.data().unwrap().to_string())
            .collect(),
    }
}

async fn eventually(server: &Dns, qname: &str, qtype: Type, expected: &[&str]) {
    for _ in 0..200 {
        if ask(server, qname, qtype).await.answers == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{qname} never answered {expected:?}");
}

#[tokio::test]
async fn loads_every_page_and_skips_aliases() {
    let stub = Stub::start();
    let mut sets = apex("example.org.");
    sets.push(set("www.example.org.", "A", &["192.0.2.1"]));
    sets.push(set("alias.example.org.", "A", &[]));
    sets.push(set("\\052.wild.example.org.", "A", &["192.0.2.9"]));
    for index in 0..7 {
        sets.push(set(&format!("h{index}.example.org."), "A", &["192.0.2.2"]));
    }
    stub.zone("Z1", sets);
    stub.state.lock().unwrap().page_size = 3;
    let profile = profile();
    let text = corefile(&stub, &profile, "route53 example.org.:Z1", "");
    let (server, lifecycle) = start(&text).await.unwrap();

    assert_eq!(
        ask(&server, "www.example.org.", Type::A).await.answers,
        ["192.0.2.1"]
    );
    assert_eq!(
        ask(&server, "h6.example.org.", Type::A).await.answers,
        ["192.0.2.2"]
    );
    // The `\052` of Route 53 is a literal `*`, so the record is a wildcard.
    assert_eq!(
        ask(&server, "x.wild.example.org.", Type::A).await.answers,
        ["192.0.2.9"]
    );
    // An alias set has no value to serve.
    assert_eq!(
        ask(&server, "alias.example.org.", Type::A).await.rcode,
        Rcode::NXDOMAIN
    );
    let requests = stub.requests();
    assert!(requests[0].contains("/hostedzonesbyname"), "{requests:?}");
    assert!(
        requests
            .iter()
            .any(|request| request.contains("/hostedzone/Z1/rrset")
                && request.contains("maxitems=1000")),
        "{requests:?}"
    );
    assert!(
        requests.iter().any(|request| request.contains("name=3")),
        "{requests:?}"
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn refresh_picks_up_changes_and_keeps_the_last_good_data_on_errors() {
    let stub = Stub::start();
    let mut sets = apex("example.org.");
    sets.push(set("www.example.org.", "A", &["192.0.2.1"]));
    stub.zone("Z1", sets.clone());
    let profile = profile();
    let text = corefile(&stub, &profile, "route53 example.org.:Z1", "");
    let (server, lifecycle) = start(&text).await.unwrap();
    assert_eq!(
        ask(&server, "www.example.org.", Type::A).await.answers,
        ["192.0.2.1"]
    );

    sets[2] = set("www.example.org.", "A", &["192.0.2.7"]);
    stub.zone("Z1", sets.clone());
    eventually(&server, "www.example.org.", Type::A, &["192.0.2.7"]).await;

    // A failing API keeps serving what was loaded last.
    stub.status(500);
    sets[2] = set("www.example.org.", "A", &["192.0.2.8"]);
    stub.zone("Z1", sets);
    let before = stub.requests().len();
    for _ in 0..200 {
        if stub.requests().len() > before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(stub.requests().len() > before, "no refresh attempt");
    assert_eq!(
        ask(&server, "www.example.org.", Type::A).await.answers,
        ["192.0.2.7"]
    );
    stub.status(200);
    eventually(&server, "www.example.org.", Type::A, &["192.0.2.8"]).await;
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn several_zones_and_two_hosted_zones_of_one_zone() {
    let stub = Stub::start();
    let mut first = apex("example.org.");
    first.push(set("one.example.org.", "A", &["192.0.2.1"]));
    first.push(set("both.example.org.", "A", &["192.0.2.2"]));
    let mut second = apex("example.org.");
    second.push(set("two.example.org.", "A", &["192.0.2.3"]));
    second.push(set("both.example.org.", "A", &["192.0.2.4"]));
    let mut other = apex("example.net.");
    other.push(set("www.example.net.", "A", &["192.0.2.5"]));
    stub.zone("Z1", first);
    stub.zone("Z2", second);
    stub.zone("Z3", other);
    let profile = profile();
    let text = corefile(
        &stub,
        &profile,
        "route53 example.org.:Z1 example.org.:Z2 example.net.:Z3",
        "",
    );
    let (server, lifecycle) = start(&text).await.unwrap();
    assert_eq!(
        ask(&server, "one.example.org.", Type::A).await.answers,
        ["192.0.2.1"]
    );
    assert_eq!(
        ask(&server, "two.example.org.", Type::A).await.answers,
        ["192.0.2.3"]
    );
    assert_eq!(
        ask(&server, "both.example.org.", Type::A).await.answers,
        ["192.0.2.2"]
    );
    assert_eq!(
        ask(&server, "www.example.net.", Type::A).await.answers,
        ["192.0.2.5"]
    );
    assert_eq!(
        ask(&server, "none.example.org.", Type::A).await.rcode,
        Rcode::NXDOMAIN
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn fallthrough_hands_a_missing_name_to_the_rest_of_the_chain() {
    let stub = Stub::start();
    stub.zone("Z1", apex("example.org."));
    let profile = profile();
    let text = corefile(&stub, &profile, "route53 example.org.:Z1", "fallthrough");
    let (server, lifecycle) = start(&text).await.unwrap();
    // Nothing follows route53 here, so the Chain answers SERVFAIL instead of NXDOMAIN.
    assert_eq!(
        ask(&server, "none.example.org.", Type::A).await.rcode,
        Rcode::SERVFAIL
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn a_failing_initial_load_fails_startup() {
    let stub = Stub::start();
    stub.zone("Z1", apex("example.org."));
    // 400 is not retried by the SDK.
    stub.status(400);
    let profile = profile();
    let text = corefile(&stub, &profile, "route53 example.org.:Z1", "");
    let error = start(&text).await.err().expect("setup must fail");
    assert!(error.contains("plugin/route53:"), "{error}");
}

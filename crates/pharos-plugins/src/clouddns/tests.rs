use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use pharos_corefile::{Cursor, lex};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Lifecycle, Metadata, Phase, Protocol, Transport};
use serde_json::{Value, json};

use super::*;
use crate::clouddns::{
    auth::testing::token_response,
    stub::{Call, Reply, Stub},
};

const TOKEN: &str = "ya29.TOKEN-SECRET-MARKER";
const REFRESH_TOKEN: &str = "REFRESH-SECRET-MARKER";
const CLIENT_SECRET: &str = "CLIENT-SECRET-MARKER";

#[derive(Default)]
struct State {
    zones: HashMap<String, Vec<Value>>,
    failing: HashSet<String>,
    page_size: usize,
}

/// A stub of the OAuth token endpoint and the Cloud DNS API, with a credentials file that points at it.
struct Cloud {
    stub: Stub,
    state: Arc<Mutex<State>>,
    dir: tempfile::TempDir,
}

impl Cloud {
    async fn new() -> Self {
        let state = Arc::new(Mutex::new(State::default()));
        let shared = Arc::clone(&state);
        let stub = Stub::start(move |call| serve_cloud(&shared, call)).await;
        let dir = tempfile::tempdir().unwrap();
        let file = json!({
            "type": "authorized_user",
            "client_id": "client",
            "client_secret": CLIENT_SECRET,
            "refresh_token": REFRESH_TOKEN,
            "token_uri": stub.url("/token"),
        });
        std::fs::write(dir.path().join("creds.json"), file.to_string()).unwrap();
        Self { stub, state, dir }
    }

    fn set(&self, project: &str, zone: &str, rrsets: Vec<Value>) {
        let mut state = self.state.lock().unwrap();
        state.zones.insert(format!("{project}/{zone}"), rrsets);
    }

    fn fail(&self, project: &str, zone: &str, failing: bool) {
        let mut state = self.state.lock().unwrap();
        let key = format!("{project}/{zone}");
        if failing {
            state.failing.insert(key);
        } else {
            state.failing.remove(&key);
        }
    }

    fn listings(&self) -> usize {
        self.stub
            .calls()
            .iter()
            .filter(|call| call.path().ends_with("/rrsets"))
            .count()
    }

    fn corefile(&self, zones: &str, options: &str) -> String {
        format!(
            "clouddns {zones} {{\ncredentials {}\nendpoint {}\n{options}\n}}",
            self.dir.path().join("creds.json").display(),
            self.stub.url("")
        )
    }

    fn plugin(&self, zones: &str, options: &str) -> CloudDns {
        let tokens = lex("Corefile", &self.corefile(zones, options));
        setup::parse(&mut Cursor::new("Corefile", &tokens)).unwrap()
    }

    async fn started(&self, zones: &str, options: &str) -> CloudDns {
        let plugin = self.plugin(zones, options);
        plugin.shared.start().await.unwrap();
        plugin
    }
}

fn serve_cloud(state: &Mutex<State>, call: &Call) -> Reply {
    if call.path() == "/token" {
        return Reply::ok(token_response(TOKEN, 3600));
    }
    let Some(rest) = call.path().strip_prefix("/dns/v1/projects/") else {
        return Reply::text(404, "");
    };
    // [project, "managedZones", zone] or [project, "managedZones", zone, "rrsets"]
    let parts: Vec<&str> = rest.split('/').collect();
    let key = format!("{}/{}", parts[0], parts[2]);
    let state = state.lock().unwrap();
    let Some(rrsets) = state.zones.get(&key) else {
        return Reply::json(404, json!({"error": {"status": "NOT_FOUND"}}));
    };
    if parts.len() == 3 {
        return Reply::ok(json!({"name": parts[2]}));
    }
    if state.failing.contains(&key) {
        return Reply::json(500, json!({"error": {"status": "INTERNAL"}}));
    }
    // Google Cloud DNS API v1: `pageToken` resumes a listing and `nextPageToken` continues it.
    let start: usize = call
        .query("pageToken")
        .map_or(0, |token| token.parse().unwrap());
    let size = if state.page_size == 0 {
        rrsets.len().max(1)
    } else {
        state.page_size
    };
    let end = (start + size).min(rrsets.len());
    let mut body = json!({ "rrsets": rrsets[start..end] });
    if end < rrsets.len() {
        body["nextPageToken"] = json!(end.to_string());
    }
    Reply::ok(body)
}

fn rr(name: &str, rtype: &str, ttl: u32, data: &[&str]) -> Value {
    json!({"name": name, "type": rtype, "ttl": ttl, "rrdatas": data})
}

fn apex(origin: &str, server: &str) -> Vec<Value> {
    vec![
        rr(
            origin,
            "SOA",
            300,
            &[&format!(
                "{server}.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 300 259200 300"
            )],
        ),
        rr(
            origin,
            "NS",
            300,
            &[&format!("{server}.googledomains.com.")],
        ),
    ]
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns_test.go fakeGCPClient.listRRSets, "sample-zone-1".
// Adaptations: Pharos needs an apex NS and in-zone owners; the out-of-zone `com.` NS and `split-example.gov.` A
// are kept to show they are skipped, and `swag.` YOLO moves inside the zone so it is skipped for its type.
fn sample_zone_1() -> Vec<Value> {
    let mut rrsets = vec![
        rr("example.org.", "A", 300, &["1.2.3.4"]),
        rr("www.example.org", "A", 300, &["1.2.3.4"]),
        rr("*.www.example.org", "CNAME", 300, &["www.example.org"]),
        rr(
            "example.org.",
            "AAAA",
            300,
            &["2001:db8:85a3::8a2e:370:7334"],
        ),
        rr("sample.example.org", "CNAME", 300, &["example.org"]),
        rr("example.org.", "PTR", 300, &["ptr.example.org."]),
        rr("com.", "NS", 300, &["ns-cloud-c4.googledomains.com."]),
        rr("split-example.gov.", "A", 300, &["1.2.3.4"]),
        rr("swag.org.", "YOLO", 300, &["foobar"]),
    ];
    rrsets.extend(apex("org.", "ns-cloud-c1"));
    rrsets
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns_test.go fakeGCPClient.listRRSets, every other zone.
// Adaptation: the SRV owner is `_dummy._tcp.split-example.org.`, not `.example.org.`: Pharos treats `example.org.`
// as an empty non-terminal in this zone (RFC 8020 §2) and answers NODATA there, where CoreDNS tries the next hosted zone.
fn sample_zone_2() -> Vec<Value> {
    let mut rrsets = vec![
        rr("split-example.org.", "A", 300, &["1.2.3.4"]),
        rr("other-example.org.", "A", 300, &["3.5.7.9"]),
        rr(
            "_dummy._tcp.split-example.org.",
            "SRV",
            300,
            &["0 0 5269 split-example.org", "0 0 5269 other-example.org"],
        ),
    ];
    rrsets.extend(apex("org.", "ns-cloud-e1"));
    rrsets
}

// Adaptation: CoreDNS serves `gov.` from the same two zones, which holds `org.` data; Pharos needs a zone of its own.
fn sample_zone_3() -> Vec<Value> {
    let mut rrsets = vec![rr("split-example.gov.", "A", 300, &["1.2.3.4"])];
    rrsets.extend(apex("gov.", "ns-cloud-g1"));
    rrsets
}

const SAMPLE: &str = "org.:p:sample-zone-2 org.:p:sample-zone-1 gov.:p:sample-zone-3";

async fn sample_cloud() -> Cloud {
    let cloud = Cloud::new().await;
    cloud.set("p", "sample-zone-1", sample_zone_1());
    cloud.set("p", "sample-zone-2", sample_zone_2());
    cloud.set("p", "sample-zone-3", sample_zone_3());
    cloud
}

struct DropNext;

impl Next for DropNext {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Drop
    }
}

struct Answer {
    outcome: Outcome,
    wire: Vec<u8>,
}

fn show(record: &pharos_proto::Record<'_>) -> String {
    format!(
        "{} {} {} {}",
        record.name,
        record.ttl,
        record.rtype,
        record.data().unwrap()
    )
}

impl Answer {
    fn message(&self) -> Message<'_> {
        Message::parse(&self.wire).unwrap()
    }

    fn answers(&self) -> Vec<String> {
        self.message()
            .answers()
            .map(|record| show(&record))
            .collect()
    }

    fn authority(&self) -> Vec<String> {
        self.message()
            .authorities()
            .map(|record| show(&record))
            .collect()
    }

    fn rcode(&self) -> Rcode {
        self.message().rcode()
    }

    fn passed(&self) -> bool {
        matches!(self.outcome, Outcome::Drop)
    }
}

async fn ask(plugin: &CloudDns, name: &str, kind: Type) -> Answer {
    ask_class(plugin, name, kind, Class::IN).await
}

async fn ask_class(plugin: &CloudDns, name: &str, kind: Type, class: Class) -> Answer {
    let name: Name = name.parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, class)
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [None; 8];
    let domain: Name = ".".parse().unwrap();
    let mut context = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    let outcome = plugin.serve(&mut context, DropNext).await;
    drop(context);
    Answer {
        outcome,
        wire: response,
    }
}

fn assert_answer(answer: &Answer, expected: &[&str]) {
    assert!(
        matches!(answer.outcome, Outcome::Response),
        "not a Response"
    );
    assert_eq!(answer.rcode(), Rcode::NOERROR);
    assert!(answer.message().aa());
    assert_eq!(answer.answers(), expected);
}

async fn eventually<F: Future<Output = bool>>(mut check: impl FnMut() -> F) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !check().await {
        assert!(Instant::now() < deadline, "condition not reached in time");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

const SOA_C1: &str = "org. 300 SOA ns-cloud-c1.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 300 259200 300";
const SOA_E1: &str = "org. 300 SOA ns-cloud-e1.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 300 259200 300";
const SOA_G1: &str = "gov. 300 SOA ns-cloud-g1.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 300 259200 300";

// CoreDNS v1.15.0 plugin/clouddns/clouddns_test.go TestCloudDNS: the data-driven cases, numbered as upstream.
#[tokio::test]
async fn coredns_cases() {
    let cloud = sample_cloud().await;
    let plugin = cloud.started(SAMPLE, "fallthrough gov.").await;
    // 0. example.org A found - success.
    assert_answer(
        &ask(&plugin, "example.org.", Type::A).await,
        &["example.org. 300 A 1.2.3.4"],
    );
    // 1. example.org AAAA found - success.
    assert_answer(
        &ask(&plugin, "example.org.", Type::AAAA).await,
        &["example.org. 300 AAAA 2001:db8:85a3::8a2e:370:7334"],
    );
    // 2. example.org PTR found - success.
    assert_answer(
        &ask(&plugin, "example.org.", Type::PTR).await,
        &["example.org. 300 PTR ptr.example.org."],
    );
    // 3. sample.example.org is a CNAME to example.org: the query returns both the CNAME and the A.
    assert_answer(
        &ask(&plugin, "sample.example.org.", Type::A).await,
        &[
            "sample.example.org. 300 CNAME example.org.",
            "example.org. 300 A 1.2.3.4",
        ],
    );
    // 4. An explicit CNAME query returns just the CNAME.
    assert_answer(
        &ask(&plugin, "sample.example.org.", Type::CNAME).await,
        &["sample.example.org. 300 CNAME example.org."],
    );
    // 5. example.org has no NS: NODATA, with the SOA of the hosted zone that has the name.
    let answer = ask(&plugin, "example.org.", Type::NS).await;
    assert_answer(&answer, &[]);
    assert_eq!(answer.authority(), [SOA_C1]);
    // 6. AAAA for a name that only has an A: NODATA.
    let answer = ask(&plugin, "split-example.gov.", Type::AAAA).await;
    assert_answer(&answer, &[]);
    assert_eq!(answer.authority(), [SOA_G1]);
    // 7. Zone not configured: the Query goes on to the next Plugin (CoreDNS: SERVFAIL when there is none).
    assert!(ask(&plugin, "badexample.com.", Type::A).await.passed());
    // 8. No record found: NXDOMAIN with the SOA of the last hosted zone.
    let answer = ask(&plugin, "bad.org.", Type::A).await;
    assert!(matches!(answer.outcome, Outcome::Response));
    assert_eq!(answer.rcode(), Rcode::NXDOMAIN);
    assert!(answer.message().aa());
    assert_eq!(answer.authority(), [SOA_C1]);
    // 9. No record found: fallthrough reaches the next Plugin.
    assert!(ask(&plugin, "example.gov.", Type::A).await.passed());
    // 10. other-example.org is only in the second hosted zone.
    assert_answer(
        &ask(&plugin, "other-example.org.", Type::A).await,
        &["other-example.org. 300 A 3.5.7.9"],
    );
    // 11. split-example.org only has an A in the first hosted zone: NODATA, with that zone's SOA.
    let answer = ask(&plugin, "split-example.org.", Type::AAAA).await;
    assert_answer(&answer, &[]);
    assert_eq!(answer.authority(), [SOA_E1]);
    // 12. *.www.example.org is a wildcard CNAME to www.example.org.
    assert_answer(
        &ask(&plugin, "a.www.example.org.", Type::A).await,
        &[
            "a.www.example.org. 300 CNAME www.example.org.",
            "www.example.org. 300 A 1.2.3.4",
        ],
    );
    // 13. SRV found with two answers, in the order Cloud DNS lists them.
    assert_answer(
        &ask(&plugin, "_dummy._tcp.split-example.org.", Type::SRV).await,
        &[
            "_dummy._tcp.split-example.org. 300 SRV 0 0 5269 split-example.org.",
            "_dummy._tcp.split-example.org. 300 SRV 0 0 5269 other-example.org.",
        ],
    );
}

// ADR-0002: records that Pharos cannot hold are skipped, the rest of the zone is served.
#[tokio::test]
async fn skipped_record_sets_do_not_reach_the_zone() {
    let cloud = sample_cloud().await;
    let plugin = cloud.started(SAMPLE, "").await;
    // `swag.org.` has an unknown type, `com.` is not under `org.` or `gov.`.
    assert_eq!(
        ask(&plugin, "swag.org.", Type::A).await.rcode(),
        Rcode::NXDOMAIN
    );
    assert!(ask(&plugin, "com.", Type::NS).await.passed());
    // CoreDNS serves the fixture's `split-example.gov.` from the `org.` zone only by accident; here `gov.` has its own.
    assert_answer(
        &ask(&plugin, "split-example.gov.", Type::A).await,
        &["split-example.gov. 300 A 1.2.3.4"],
    );
}

// RFC 8020 §2: the first hosted zone holds `_dummy._tcp.example.org.`, so `example.org.` exists there and is NODATA.
// CoreDNS v1.15.0 plugin/clouddns tries the next hosted zone instead; this deviation comes from the shared Zone code.
#[tokio::test]
async fn an_empty_non_terminal_in_a_hosted_zone_is_nodata() {
    let cloud = Cloud::new().await;
    let mut first = vec![rr(
        "_dummy._tcp.example.org.",
        "SRV",
        300,
        &["0 0 1 t.example.org."],
    )];
    first.extend(apex("org.", "ns-a"));
    let mut second = vec![rr("example.org.", "A", 300, &["192.0.2.1"])];
    second.extend(apex("org.", "ns-b"));
    cloud.set("p", "first", first);
    cloud.set("p", "second", second);
    let plugin = cloud.started("org.:p:first org.:p:second", "").await;
    let answer = ask(&plugin, "example.org.", Type::A).await;
    assert_answer(&answer, &[]);
    assert_eq!(answer.authority().len(), 1);
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns.go ServeDNS: a Delegation clears AA.
#[tokio::test]
async fn a_delegation_is_not_authoritative() {
    let cloud = Cloud::new().await;
    let mut rrsets = vec![rr("sub.example.org.", "NS", 300, &["ns.sub.example.org."])];
    rrsets.push(rr("ns.sub.example.org.", "A", 300, &["192.0.2.53"]));
    rrsets.extend(apex("example.org.", "ns-a"));
    cloud.set("p", "z", rrsets);
    let plugin = cloud.started("example.org.:p:z", "").await;
    let answer = ask(&plugin, "www.sub.example.org.", Type::A).await;
    assert!(matches!(answer.outcome, Outcome::Response));
    assert!(!answer.message().aa());
    assert_eq!(answer.rcode(), Rcode::NOERROR);
    assert!(answer.answers().is_empty());
    assert_eq!(
        answer.authority(),
        ["sub.example.org. 300 NS ns.sub.example.org."]
    );
    // CoreDNS: the delegation is not NODATA, so `fallthrough` hands it to the next Plugin.
    let plugin = cloud.started("example.org.:p:z", "fallthrough").await;
    assert!(ask(&plugin, "www.sub.example.org.", Type::A).await.passed());
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns.go ServeDNS: without `fallthrough` the Query never leaves the Plugin.
#[tokio::test]
async fn without_fallthrough_nxdomain_is_the_answer() {
    let cloud = sample_cloud().await;
    let plugin = cloud.started(SAMPLE, "").await;
    let answer = ask(&plugin, "example.gov.", Type::A).await;
    assert!(matches!(answer.outcome, Outcome::Response));
    assert_eq!(answer.rcode(), Rcode::NXDOMAIN);
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns.go ServeDNS: a hosted zone with no data is a failed lookup, so SERVFAIL.
#[tokio::test]
async fn a_zone_that_never_loaded_is_servfail() {
    let cloud = sample_cloud().await;
    let plugin = cloud.plugin(SAMPLE, "");
    let answer = ask(&plugin, "example.org.", Type::A).await;
    assert!(matches!(
        answer.outcome,
        Outcome::Unanswered(Rcode::SERVFAIL)
    ));
    // `fallthrough` still applies to a zone without data.
    let plugin = cloud.plugin(SAMPLE, "fallthrough");
    assert!(ask(&plugin, "example.org.", Type::A).await.passed());
}

#[tokio::test]
async fn other_classes_and_names_go_to_the_next_plugin() {
    let cloud = sample_cloud().await;
    let plugin = cloud.started(SAMPLE, "").await;
    assert!(
        ask_class(&plugin, "example.org.", Type::A, Class::CH)
            .await
            .passed()
    );
    assert!(ask(&plugin, "example.com.", Type::A).await.passed());
}

// CoreDNS v1.15.0 plugin/clouddns/setup.go: every line is a handler; a Query falls from one to the next.
#[tokio::test]
async fn lines_are_tried_in_order() {
    let cloud = sample_cloud().await;
    let creds = cloud.dir.path().join("creds.json");
    let text = format!(
        "clouddns org.:p:sample-zone-1 {{\ncredentials {c}\nendpoint {e}\nfallthrough\n}}\nclouddns gov.:p:sample-zone-3 {{\ncredentials {c}\nendpoint {e}\n}}",
        c = creds.display(),
        e = cloud.stub.url("")
    );
    let tokens = lex("Corefile", &text);
    let plugin = setup::parse(&mut Cursor::new("Corefile", &tokens)).unwrap();
    plugin.shared.start().await.unwrap();
    assert_answer(
        &ask(&plugin, "split-example.gov.", Type::A).await,
        &["split-example.gov. 300 A 1.2.3.4"],
    );
    assert_answer(
        &ask(&plugin, "example.org.", Type::A).await,
        &["example.org. 300 A 1.2.3.4"],
    );
    // `org.` falls through on NXDOMAIN, but no later line serves it.
    assert!(ask(&plugin, "bad.org.", Type::A).await.passed());
    // The second line has no `fallthrough`.
    let answer = ask(&plugin, "bad.gov.", Type::A).await;
    assert_eq!(answer.rcode(), Rcode::NXDOMAIN);
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns_test.go TestCloudDNS: a bad project or zone is an error, not a load.
#[tokio::test]
async fn a_missing_hosted_zone_stops_startup() {
    let cloud = sample_cloud().await;
    let plugin = cloud.plugin("bad.:bad-project:bad-zone", "");
    let error = plugin.shared.start().await.unwrap_err().to_string();
    assert!(error.contains("failed to create plugin"), "{error}");
    assert!(
        error.contains("bad-zone") && error.contains("bad-project"),
        "{error}"
    );
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns.go Run: the first load is fatal.
#[tokio::test]
async fn a_failing_first_load_stops_startup() {
    let cloud = sample_cloud().await;
    cloud.fail("p", "sample-zone-1", true);
    let plugin = cloud.plugin(SAMPLE, "");
    let error = plugin.shared.start().await.unwrap_err().to_string();
    assert!(error.contains("failed to initialize plugin"), "{error}");
    assert!(error.contains("HTTP 500: INTERNAL"), "{error}");
    assert!(plugin.shared.tasks.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_zone_without_an_soa_stops_startup() {
    let cloud = Cloud::new().await;
    cloud.set(
        "p",
        "z",
        vec![rr("www.example.org.", "A", 300, &["192.0.2.1"])],
    );
    let error = cloud
        .plugin("example.org.:p:z", "")
        .shared
        .start()
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("failed to initialize plugin"), "{error}");
}

// CoreDNS v1.15.0 plugin/clouddns/gcp.go listRRSets: every page is read.
#[tokio::test]
async fn every_page_is_listed() {
    let cloud = sample_cloud().await;
    cloud.state.lock().unwrap().page_size = 2;
    let plugin = cloud.started(SAMPLE, "").await;
    assert!(cloud.listings() >= 3 * 3, "{}", cloud.listings());
    assert_answer(
        &ask(&plugin, "example.org.", Type::A).await,
        &["example.org. 300 A 1.2.3.4"],
    );
    assert_answer(
        &ask(&plugin, "other-example.org.", Type::A).await,
        &["other-example.org. 300 A 3.5.7.9"],
    );
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns.go updateZones: a failed update keeps the last good Zone, a later
// successful one replaces it.
#[tokio::test]
async fn a_failed_refresh_keeps_the_last_good_zone() {
    let cloud = sample_cloud().await;
    let plugin = cloud.started(SAMPLE, "refresh 30ms").await;
    cloud.fail("p", "sample-zone-1", true);
    let before = cloud.listings();
    eventually(|| async { cloud.listings() >= before + 6 }).await;
    assert_answer(
        &ask(&plugin, "example.org.", Type::A).await,
        &["example.org. 300 A 1.2.3.4"],
    );
    // The other hosted zones kept refreshing while one failed.
    let mut changed = sample_zone_2();
    changed.push(rr("new-example.org.", "A", 300, &["192.0.2.9"]));
    cloud.set("p", "sample-zone-2", changed);
    eventually(|| async {
        ask(&plugin, "new-example.org.", Type::A).await.answers()
            == ["new-example.org. 300 A 192.0.2.9"]
    })
    .await;
    cloud.fail("p", "sample-zone-1", false);
    let mut changed = sample_zone_1();
    changed[0] = rr("example.org.", "A", 300, &["1.2.3.4", "1.2.3.5"]);
    cloud.set("p", "sample-zone-1", changed);
    eventually(|| async { ask(&plugin, "example.org.", Type::A).await.answers().len() == 2 }).await;
    plugin.shared.stop().await;
}

// RFC 6749 §6: the token is cached, so refreshes do not hit the token endpoint again.
#[tokio::test]
async fn refreshes_reuse_the_cached_token() {
    let cloud = sample_cloud().await;
    let plugin = cloud.started(SAMPLE, "refresh 20ms").await;
    let before = cloud.listings();
    eventually(|| async { cloud.listings() >= before + 9 }).await;
    plugin.shared.stop().await;
    let tokens = cloud
        .stub
        .calls()
        .iter()
        .filter(|call| call.path() == "/token")
        .count();
    assert_eq!(tokens, 1);
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns_test.go TestCloudDNSConcurrentServeDNS: queries race refreshes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queries_run_while_zones_refresh() {
    let cloud = sample_cloud().await;
    let plugin = Arc::new(cloud.started(SAMPLE, "").await);
    let refresher = {
        let plugin = Arc::clone(&plugin);
        tokio::spawn(async move {
            let instance = Arc::clone(&plugin.shared.instances[0]);
            let api = instance.api().unwrap();
            for _ in 0..30 {
                instance.update(&api).await.unwrap();
            }
        })
    };
    let queries = [
        ("example.org.", Type::A),
        ("example.org.", Type::AAAA),
        ("sample.example.org.", Type::A),
        ("a.www.example.org.", Type::A),
        ("split-example.org.", Type::A),
        ("other-example.org.", Type::A),
        ("_dummy._tcp.split-example.org.", Type::SRV),
    ];
    let mut workers = Vec::new();
    for id in 0..16 {
        let plugin = Arc::clone(&plugin);
        workers.push(tokio::spawn(async move {
            for round in 0..150 {
                let (name, kind) = queries[(id + round) % queries.len()];
                let answer = ask(&plugin, name, kind).await;
                assert!(matches!(answer.outcome, Outcome::Response), "{name}");
                assert_eq!(answer.rcode(), Rcode::NOERROR, "{name}");
                assert!(!answer.answers().is_empty(), "{name}");
            }
        }));
    }
    for worker in workers {
        worker.await.unwrap();
    }
    refresher.await.unwrap();
}

// Lifecycle: Startup loads and starts the loops, Shutdown stops them, RestartFailed brings them back.
#[tokio::test]
async fn hooks_start_stop_and_resume_the_refresh_loop() {
    let cloud = sample_cloud().await;
    let plugin = cloud.plugin(SAMPLE, "refresh 20ms");
    let mut lifecycle = Lifecycle::default();
    plugin.register_hooks(&mut lifecycle);
    lifecycle.run(Phase::Startup).await.unwrap();
    assert_answer(
        &ask(&plugin, "example.org.", Type::A).await,
        &["example.org. 300 A 1.2.3.4"],
    );
    let before = cloud.listings();
    eventually(|| async { cloud.listings() > before + 3 }).await;
    lifecycle.run(Phase::Restart).await.unwrap();
    assert!(plugin.shared.tasks.lock().unwrap().is_empty());
    // A request already on the wire may still land.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stopped = cloud.listings();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(cloud.listings(), stopped);
    lifecycle.run(Phase::RestartFailed).await.unwrap();
    eventually(|| async { cloud.listings() > stopped }).await;
    lifecycle.run(Phase::Shutdown).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stopped = cloud.listings();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(cloud.listings(), stopped);
}

// A directive without zones has nothing to check, load or refresh.
#[tokio::test]
async fn a_bare_directive_starts_without_the_network() {
    let tokens = lex("Corefile", "clouddns");
    let plugin = setup::parse(&mut Cursor::new("Corefile", &tokens)).unwrap();
    plugin.shared.start().await.unwrap();
    assert!(ask(&plugin, "example.org.", Type::A).await.passed());
}

// Security: no token, refresh token or client secret in `Debug` output or errors.
#[tokio::test]
async fn secrets_stay_out_of_debug_output_and_errors() {
    let cloud = sample_cloud().await;
    let plugin = cloud.started(SAMPLE, "").await;
    let debug = format!("{plugin:?}");
    for marker in [TOKEN, REFRESH_TOKEN, CLIENT_SECRET, "SECRET-MARKER"] {
        assert!(!debug.contains(marker), "{marker} in Debug output");
    }
    cloud.fail("p", "sample-zone-1", true);
    let error = plugin.shared.instances[0]
        .update(&plugin.shared.instances[0].api().unwrap())
        .await
        .unwrap_err();
    assert!(!error.contains("SECRET-MARKER"), "{error}");
    assert!(error.contains("HTTP 500"), "{error}");
}

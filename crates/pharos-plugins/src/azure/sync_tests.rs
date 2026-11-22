//! The sync loop against local Azure stubs; ports CoreDNS v1.15.0 plugin/azure/sync_test.go and covers token refresh, MSI and secrecy.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use pharos_proto::Type;
use pharos_server::{Lifecycle, Outcome, Phase};
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};

use super::{
    Azure, Environment,
    auth::Endpoints,
    client::Tuning,
    stub::{Reply, Request, Stub},
    tests::{ask, config},
};
use crate::zone::Zone;

const SECRET: &str = "s3cr3t-DISTINCT";

struct Opts {
    private: bool,
    zones: &'static str,
    secret: &'static str,
    expiry: String,
    tuning: Tuning,
    env: Vec<(&'static str, &'static str)>,
    refresh: &'static str,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            private: false,
            zones: "rg:healthy.example rg:missing.example",
            secret: SECRET,
            expiry: r#""expires_in":"3600""#.to_owned(),
            // Azure retries are shrunk to milliseconds; one retry bounds the attempts like CoreDNS's sync_test.go.
            tuning: Tuning {
                retries: 1,
                backoff: Duration::from_millis(1),
                list_timeout: Duration::from_secs(30),
            },
            env: Vec::new(),
            refresh: "1m",
        }
    }
}

struct Rig {
    azure: Arc<Azure>,
    stub: Stub,
    tokens: Arc<AtomicUsize>,
}

impl Rig {
    /// The requests that are API calls rather than token calls.
    fn api(&self) -> Vec<Request> {
        self.stub
            .requests()
            .into_iter()
            .filter(|request| request.path().starts_with("/subscriptions/"))
            .collect()
    }

    async fn update(&self) -> Result<(), String> {
        self.azure.syncer.update_zones().await
    }

    fn zone(&self, index: usize) -> Option<Arc<Zone>> {
        self.azure.hosted_zones()[index].current.load_full()
    }
}

fn is_token(path: &str) -> bool {
    path.ends_with("/oauth2/token") || path.starts_with("/imds/") || path.starts_with("/msi")
}

/// The hosted zone name a REST path addresses.
fn zone_of(path: &str) -> Option<&str> {
    let rest = path
        .split_once("/privateDnsZones/")
        .or_else(|| path.split_once("/dnsZones/"))?
        .1;
    rest.split('/').next()
}

/// CoreDNS v1.15.0 plugin/azure/sync_test.go writeAzureRecords: an SOA and `www A 192.0.2.10`, in either API shape.
fn records_body(private: bool, name: &str, next: &str, soa: bool, address: bool) -> String {
    let (ttl, soa_key, a_key, minimum) = if private {
        ("ttl", "soaRecord", "aRecords", "minimumTtl")
    } else {
        ("TTL", "SOARecord", "ARecords", "minimumTTL")
    };
    let mut values = Vec::new();
    if soa {
        values.push(json!({"name": "@", "properties": {
            "fqdn": format!("{name}."), ttl: 60,
            soa_key: {"host": format!("ns.{name}."), "email": format!("hostmaster.{name}."),
                "serialNumber": 1, "refreshTime": 3600, "retryTime": 300, "expireTime": 86400, minimum: 60}}}));
    }
    if address {
        values.push(json!({"name": "www", "properties": {
            "fqdn": format!("www.{name}."), ttl: 60, a_key: [{"ipv4Address": "192.0.2.10"}]}}));
    }
    let mut body = json!({ "value": values });
    if !next.is_empty() {
        body["nextLink"] = Value::String(next.to_owned());
    }
    body.to_string()
}

async fn rig(opts: Opts, extra: impl Fn(&Request) -> Option<Reply> + Send + Sync + 'static) -> Rig {
    let tokens = Arc::new(AtomicUsize::new(0));
    let handler_tokens = Arc::clone(&tokens);
    let (private, expiry) = (opts.private, opts.expiry.clone());
    let stub = Stub::start(move |request| {
        if let Some(reply) = extra(request) {
            return reply;
        }
        if is_token(request.path()) {
            let n = handler_tokens.fetch_add(1, Ordering::SeqCst) + 1;
            return Reply::ok(format!(
                r#"{{"access_token":"token-{n}",{expiry},"token_type":"Bearer"}}"#
            ));
        }
        match zone_of(request.path()) {
            Some(name @ ("healthy.example" | "missing.example")) => {
                Reply::ok(records_body(private, name, "", true, true))
            }
            _ => Reply::status(400, "unexpected API path"),
        }
    })
    .await;
    let base = stub.base();
    let mut text = format!(
        "azure {} {{\n tenant tenant-1\n client client-1\n subscription sub-1\n access {}\n refresh {}\n",
        opts.zones,
        if opts.private { "private" } else { "public" },
        opts.refresh
    );
    if !opts.secret.is_empty() {
        text.push_str(&format!(" secret {}\n", opts.secret));
    }
    text.push('}');
    let endpoints = Endpoints {
        resource_manager: base.clone(),
        active_directory: base.clone(),
        imds: format!("{base}imds/metadata/identity/oauth2/token"),
    };
    let env = opts.env;
    let azure = Azure::with_settings(
        config(&text),
        &endpoints,
        move |name| {
            env.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.replace("{base}", &base))
        },
        opts.tuning,
    )
    .unwrap();
    Rig {
        azure: Arc::new(azure),
        stub,
        tokens,
    }
}

async fn has_answer(azure: &Azure, name: &str) -> bool {
    let reply = ask(azure, &format!("www.{name}"), Type::A).await;
    reply.outcome == Outcome::Response
        && reply.answers() == [format!("www.{name}.\t60\tIN\tA\t192.0.2.10")]
}

async fn wait_for_answer(azure: &Azure, name: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !has_answer(azure, name).await {
        assert!(Instant::now() < deadline, "no answer for {name}");
        sleep(Duration::from_millis(2)).await;
    }
}

async fn wait_until(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting");
        sleep(Duration::from_millis(2)).await;
    }
}

fn lifecycle(azure: &Azure) -> Lifecycle {
    let mut lifecycle = Lifecycle::default();
    azure.register_hooks(&mut lifecycle);
    lifecycle
}

fn same(a: &Option<Arc<Zone>>, b: &Option<Arc<Zone>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    }
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestNewDoesNotContactAzure.
#[tokio::test]
async fn construction_makes_no_http_request() {
    for private in [true, false] {
        for secret in [SECRET, ""] {
            let rig = rig(
                Opts {
                    private,
                    secret,
                    ..Opts::default()
                },
                |_| Some(Reply::status(404, "gone")),
            )
            .await;
            let _ = lifecycle(&rig.azure);
            sleep(Duration::from_millis(20)).await;
            assert!(rig.stub.requests().is_empty(), "private={private}");
            assert_eq!(rig.azure.zone_names().len(), 2);
        }
    }
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestRunWithUnavailableZone.
#[tokio::test]
async fn unavailable_zone_does_not_block_the_healthy_zone() {
    for private in [true, false] {
        let rig = rig(
            Opts {
                private,
                ..Opts::default()
            },
            |request| {
                request
                    .path()
                    .contains("/missing.example/")
                    .then(|| Reply::status(404, "zone unavailable in test"))
            },
        )
        .await;
        let lifecycle = lifecycle(&rig.azure);
        lifecycle.run(Phase::Startup).await.unwrap();
        wait_for_answer(&rig.azure, "healthy.example").await;
        let reply = ask(&rig.azure, "www.missing.example", Type::A).await;
        assert_eq!(
            reply.outcome,
            Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL)
        );
        lifecycle.run(Phase::Shutdown).await.unwrap();
    }
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestRunDoesNotWaitForAzure.
#[tokio::test]
async fn startup_does_not_wait_for_azure_and_shutdown_cancels_a_blocked_sync() {
    for hang_on_token in [true, false] {
        for private in [true, false] {
            let rig = rig(
                Opts {
                    private,
                    ..Opts::default()
                },
                move |request| {
                    let token = is_token(request.path());
                    (token == hang_on_token || !token).then_some(Reply::Hang)
                },
            )
            .await;
            let lifecycle = lifecycle(&rig.azure);
            timeout(Duration::from_secs(5), lifecycle.run(Phase::Startup))
                .await
                .expect("Startup blocked on Azure")
                .unwrap();
            // The Query path never waits on Azure.
            let reply = ask(&rig.azure, "www.healthy.example", Type::A).await;
            assert_eq!(
                reply.outcome,
                Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL)
            );
            let expected = if hang_on_token { 1 } else { 2 };
            wait_until(|| rig.stub.requests().len() >= expected).await;
            timeout(Duration::from_secs(5), lifecycle.run(Phase::Shutdown))
                .await
                .expect("Shutdown did not cancel the blocked sync")
                .unwrap();
            sleep(Duration::from_millis(50)).await;
            // One blocked request: the sync never moved on to the other zone.
            assert_eq!(rig.stub.requests().len(), expected);
            assert_eq!(rig.api().len(), usize::from(!hang_on_token));
        }
    }
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestZoneRecovery.
#[tokio::test]
async fn a_failing_zone_recovers_on_a_later_refresh() {
    for private in [true, false] {
        let missing = Arc::new(AtomicBool::new(true));
        let failures = Arc::new(AtomicUsize::new(0));
        let (flag, count) = (Arc::clone(&missing), Arc::clone(&failures));
        let rig = rig(
            Opts {
                private,
                refresh: "5ms",
                ..Opts::default()
            },
            move |request| {
                (request.path().contains("/missing.example/") && flag.load(Ordering::SeqCst)).then(
                    || {
                        count.fetch_add(1, Ordering::SeqCst);
                        Reply::status(404, "zone unavailable in test")
                    },
                )
            },
        )
        .await;
        let lifecycle = lifecycle(&rig.azure);
        lifecycle.run(Phase::Startup).await.unwrap();
        wait_for_answer(&rig.azure, "healthy.example").await;
        wait_until(|| failures.load(Ordering::SeqCst) > 0).await;
        missing.store(false, Ordering::SeqCst);
        wait_for_answer(&rig.azure, "missing.example").await;
        lifecycle.run(Phase::Shutdown).await.unwrap();
    }
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestFailedUpdatePreservesZone.
#[tokio::test]
async fn a_failed_update_keeps_the_last_good_zone_and_refreshes_the_others() {
    for private in [true, false] {
        for status in [404, 403, 503] {
            let fail = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&fail);
            let rig = rig(
                Opts {
                    private,
                    ..Opts::default()
                },
                move |request| {
                    (flag.load(Ordering::SeqCst) && request.path().contains("/missing.example/"))
                        .then(|| Reply::status(status, "zone unavailable in test"))
                },
            )
            .await;
            rig.update().await.unwrap();
            let healthy = rig.zone(0);
            let missing = rig.zone(1);
            fail.store(true, Ordering::SeqCst);
            let error = rig.update().await.unwrap_err();
            assert!(error.contains(&status.to_string()), "{error}");
            assert!(
                same(&rig.zone(1), &missing),
                "{status}: lost the last good zone"
            );
            assert!(
                !same(&rig.zone(0), &healthy),
                "{status}: healthy zone not refreshed"
            );
            assert!(has_answer(&rig.azure, "missing.example").await);
            assert!(has_answer(&rig.azure, "healthy.example").await);
        }
    }
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestZonePagination.
#[tokio::test]
async fn pages_publish_together_or_not_at_all() {
    for private in [true, false] {
        for status in [200, 404, 503] {
            let paginated = Arc::new(AtomicBool::new(false));
            let page_requests = Arc::new(AtomicUsize::new(0));
            let (on, count) = (Arc::clone(&paginated), Arc::clone(&page_requests));
            let rig = rig(
                Opts {
                    private,
                    ..Opts::default()
                },
                move |request| {
                    if !on.load(Ordering::SeqCst) || !request.path().contains("/missing.example/") {
                        return None;
                    }
                    if request.target.contains("page=2") {
                        // Bounds a regression that retries the unchanged page forever.
                        if count.fetch_add(1, Ordering::SeqCst) < 4 && status != 200 {
                            return Some(Reply::status(status, "page unavailable"));
                        }
                        return Some(Reply::ok(records_body(
                            private,
                            "missing.example",
                            "",
                            false,
                            true,
                        )));
                    }
                    let next =
                        format!("http://{}{}?page=2", request.header("host"), request.path());
                    Some(Reply::ok(records_body(
                        private,
                        "missing.example",
                        &next,
                        true,
                        false,
                    )))
                },
            )
            .await;
            rig.update().await.unwrap();
            let healthy = rig.zone(0);
            let missing = rig.zone(1);
            paginated.store(true, Ordering::SeqCst);
            let result = rig.update().await;
            assert_eq!(result.is_ok(), status == 200, "{status}: {result:?}");
            let attempts = page_requests.load(Ordering::SeqCst);
            assert!(
                (1..=2).contains(&attempts),
                "{status}: {attempts} next-page attempts"
            );
            if status != 200 {
                assert!(
                    same(&rig.zone(1), &missing),
                    "{status}: partial zone published"
                );
            } else {
                assert!(!same(&rig.zone(1), &missing));
            }
            assert!(has_answer(&rig.azure, "missing.example").await);
            assert!(has_answer(&rig.azure, "healthy.example").await);
            assert!(
                !same(&rig.zone(0), &healthy),
                "{status}: healthy zone not refreshed"
            );
        }
    }
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestCanceledPaginationPreservesZone.
#[tokio::test]
async fn cancelled_pagination_keeps_the_zone() {
    for private in [true, false] {
        let paginated = Arc::new(AtomicBool::new(false));
        let on = Arc::clone(&paginated);
        let rig = rig(
            Opts {
                private,
                ..Opts::default()
            },
            move |request| {
                if !on.load(Ordering::SeqCst) || !request.path().contains("/missing.example/") {
                    return None;
                }
                if request.target.contains("page=2") {
                    return Some(Reply::Hang);
                }
                let next = format!("http://{}{}?page=2", request.header("host"), request.path());
                Some(Reply::ok(records_body(
                    private,
                    "missing.example",
                    &next,
                    true,
                    false,
                )))
            },
        )
        .await;
        rig.update().await.unwrap();
        let missing = rig.zone(1);
        paginated.store(true, Ordering::SeqCst);
        let syncer = Arc::clone(&rig.azure.syncer);
        let task = tokio::spawn(async move { syncer.update_zones().await });
        wait_until(|| {
            rig.stub
                .requests()
                .iter()
                .any(|request| request.target.contains("page=2"))
        })
        .await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(same(&rig.zone(1), &missing));
        assert!(has_answer(&rig.azure, "missing.example").await);
    }
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestIncompleteZoneIsNotPublished.
#[tokio::test]
async fn a_listing_without_an_soa_is_not_published() {
    for private in [true, false] {
        let rig = rig(
            Opts {
                private,
                ..Opts::default()
            },
            move |request| {
                request
                    .path()
                    .contains("/missing.example/")
                    .then(|| Reply::ok(records_body(private, "missing.example", "", false, true)))
            },
        )
        .await;
        let error = rig.update().await.unwrap_err();
        assert!(error.contains("zone has no SOA record"), "{error}");
        assert!(rig.zone(1).is_none());
        assert!(has_answer(&rig.azure, "healthy.example").await);
    }
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestSameZoneInMultipleResourceGroups.
#[tokio::test]
async fn a_missing_resource_group_does_not_mask_the_healthy_copy() {
    for private in [true, false] {
        let rig = rig(
            Opts {
                private,
                zones: "missing-rg:healthy.example rg:healthy.example",
                ..Opts::default()
            },
            |request| {
                request
                    .path()
                    .contains("/resourceGroups/missing-rg/")
                    .then(|| Reply::status(404, "no such resource group"))
            },
        )
        .await;
        let error = rig.update().await.unwrap_err();
        assert!(error.contains("missing-rg:healthy.example"), "{error}");
        assert!(has_answer(&rig.azure, "healthy.example").await);
    }
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestConcurrentZoneUpdates.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queries_keep_their_answers_while_zones_are_swapped() {
    for private in [true, false] {
        let rig = rig(
            Opts {
                private,
                ..Opts::default()
            },
            |_| None,
        )
        .await;
        rig.update().await.unwrap();
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let azure = Arc::clone(&rig.azure);
                tokio::spawn(async move {
                    for _ in 0..100 {
                        assert!(has_answer(&azure, "healthy.example").await);
                    }
                })
            })
            .collect();
        for _ in 0..20 {
            rig.update().await.unwrap();
        }
        for reader in readers {
            reader.await.unwrap();
        }
    }
}

// CoreDNS v1.15.0 plugin/azure/sync_test.go TestRunWithCanceledContext.
#[tokio::test]
async fn a_sync_stopped_before_it_starts_issues_no_request() {
    let rig = rig(Opts::default(), |_| None).await;
    let lifecycle = lifecycle(&rig.azure);
    lifecycle.run(Phase::Startup).await.unwrap();
    lifecycle.run(Phase::Shutdown).await.unwrap();
    sleep(Duration::from_millis(50)).await;
    assert!(rig.stub.requests().is_empty());
}

#[tokio::test]
async fn restart_stops_the_sync_and_startup_resumes_it() {
    let rig = rig(
        Opts {
            refresh: "5ms",
            ..Opts::default()
        },
        |_| None,
    )
    .await;
    let lifecycle = lifecycle(&rig.azure);
    lifecycle.run(Phase::Startup).await.unwrap();
    wait_for_answer(&rig.azure, "healthy.example").await;
    lifecycle.run(Phase::Restart).await.unwrap();
    let stopped = rig.stub.requests().len();
    sleep(Duration::from_millis(60)).await;
    assert_eq!(
        rig.stub.requests().len(),
        stopped,
        "sync kept running after Restart"
    );
    lifecycle.run(Phase::RestartFailed).await.unwrap();
    wait_until(|| rig.stub.requests().len() > stopped).await;
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn initial_load_sends_the_sdk_paths_and_a_bearer_token() {
    for (private, path, api_version) in [
        (
            false,
            "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/dnsZones/healthy.example/recordsets",
            "2018-05-01",
        ),
        (
            true,
            "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/healthy.example/ALL",
            "2018-09-01",
        ),
    ] {
        let rig = rig(
            Opts {
                private,
                zones: "rg:healthy.example",
                ..Opts::default()
            },
            |_| None,
        )
        .await;
        rig.update().await.unwrap();
        assert!(has_answer(&rig.azure, "healthy.example").await);
        let requests = rig.stub.requests();
        assert_eq!(requests.len(), 2);
        let token = &requests[0];
        assert_eq!(token.method, "POST");
        assert_eq!(token.target, "/tenant-1/oauth2/token?api-version=1.0");
        assert_eq!(
            token.header("content-type"),
            "application/x-www-form-urlencoded"
        );
        let resource = format!(
            "http%3A%2F%2F{}%2F",
            rig.stub.addr.to_string().replace(':', "%3A")
        );
        assert_eq!(
            token.body,
            format!(
                "client_id=client-1&client_secret={SECRET}&grant_type=client_credentials&resource={resource}"
            )
        );
        let api = &requests[1];
        assert_eq!(api.method, "GET");
        assert_eq!(api.target, format!("{path}?api-version={api_version}"));
        assert_eq!(api.header("authorization"), "Bearer token-1");
    }
}

#[tokio::test]
async fn a_token_expiring_within_five_minutes_is_fetched_again_for_the_next_request() {
    let rig = rig(
        Opts {
            expiry: r#""expires_in":"10""#.to_owned(),
            ..Opts::default()
        },
        |_| None,
    )
    .await;
    rig.update().await.unwrap();
    assert_eq!(rig.tokens.load(Ordering::SeqCst), 2);
    let bearers: Vec<_> = rig
        .api()
        .iter()
        .map(|request| request.header("authorization").to_owned())
        .collect();
    assert_eq!(bearers, ["Bearer token-1", "Bearer token-2"]);
    rig.update().await.unwrap();
    assert_eq!(rig.tokens.load(Ordering::SeqCst), 4);
    assert_eq!(rig.api()[3].header("authorization"), "Bearer token-4");
}

#[tokio::test]
async fn a_long_lived_token_is_reused() {
    let rig = rig(Opts::default(), |_| None).await;
    rig.update().await.unwrap();
    rig.update().await.unwrap();
    assert_eq!(rig.tokens.load(Ordering::SeqCst), 1);
    assert!(
        rig.api()
            .iter()
            .all(|request| request.header("authorization") == "Bearer token-1")
    );
}

#[tokio::test]
async fn expires_on_wins_over_expires_in_and_may_be_a_number_or_a_string() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (expiry, fetches) in [
        (format!(r#""expires_on":"{}""#, now + 3600), 1),
        (format!(r#""expires_on":{}"#, now + 3600), 1),
        // Already expired although expires_in says otherwise.
        (
            format!(r#""expires_on":{},"expires_in":"3600""#, now - 10),
            2,
        ),
        // No expiry at all: a token is used once.
        (r#""resource":"x""#.to_owned(), 2),
    ] {
        let rig = rig(
            Opts {
                expiry: expiry.clone(),
                ..Opts::default()
            },
            |_| None,
        )
        .await;
        rig.update().await.unwrap();
        assert_eq!(rig.tokens.load(Ordering::SeqCst), fetches, "{expiry}");
    }
}

// go-autorest v0.11.30 autorest/adal/token.go: IMDS, App Service and Cloud Shell requests.
#[tokio::test]
async fn managed_identity_requests_follow_adal() {
    type Env = Vec<(&'static str, &'static str)>;
    let cases: [(Env, &str, &str); 3] = [
        (Vec::new(), "GET", "/imds/metadata/identity/oauth2/token"),
        (
            vec![("MSI_ENDPOINT", "{base}msi"), ("MSI_SECRET", "app-secret")],
            "GET",
            "/msi",
        ),
        (vec![("MSI_ENDPOINT", "{base}msi")], "POST", "/msi"),
    ];
    for (index, (env, method, path)) in cases.into_iter().enumerate() {
        let rig = rig(
            Opts {
                secret: "",
                zones: "rg:healthy.example",
                env,
                ..Opts::default()
            },
            |_| None,
        )
        .await;
        rig.update().await.unwrap();
        assert!(has_answer(&rig.azure, "healthy.example").await);
        let requests = rig.stub.requests();
        let token = &requests[0];
        let resource = format!(
            "http%3A%2F%2F{}%2F",
            rig.stub.addr.to_string().replace(':', "%3A")
        );
        assert_eq!((token.method.as_str(), token.path()), (method, path));
        match index {
            0 => {
                assert_eq!(
                    token.target,
                    format!("{path}?api-version=2018-02-01&client_id=client-1&resource={resource}")
                );
                assert_eq!(token.header("metadata"), "true");
            }
            1 => {
                assert_eq!(
                    token.target,
                    format!("{path}?api-version=2017-09-01&clientid=client-1&resource={resource}")
                );
                assert_eq!(token.header("secret"), "app-secret");
            }
            _ => {
                assert_eq!(token.target, path);
                assert_eq!(
                    token.body,
                    format!("client_id=client-1&resource={resource}")
                );
                assert_eq!(token.header("metadata"), "true");
                assert_eq!(
                    token.header("content-type"),
                    "application/x-www-form-urlencoded"
                );
            }
        }
        assert_eq!(requests[1].header("authorization"), "Bearer token-1");
    }
}

#[test]
fn an_invalid_msi_endpoint_is_a_setup_error() {
    let config = config("azure rg:example.org");
    let endpoints = Endpoints::for_environment(Environment::PublicCloud);
    let result = Azure::with_settings(
        config,
        &endpoints,
        |name| (name == "MSI_ENDPOINT").then(|| "not a url".to_owned()),
        Tuning::default(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn a_token_failure_keeps_the_zone_and_reaches_no_api() {
    for (reply, expected) in [
        (
            Reply::status(401, "invalid_client"),
            "token endpoint returned status 401",
        ),
        (Reply::ok("not json"), "not valid JSON"),
        (Reply::ok(r#"{"expires_in":"3600"}"#), "no access_token"),
        (
            Reply::ok(r#"{"access_token":"","expires_in":"3600"}"#),
            "no access_token",
        ),
    ] {
        let reply = std::sync::Mutex::new(Some(reply));
        let rig = rig(Opts::default(), move |request| {
            if is_token(request.path()) {
                // Each case serves its reply twice: once per hosted zone.
                return reply
                    .lock()
                    .unwrap()
                    .take()
                    .or_else(|| Some(Reply::status(500, "again")));
            }
            None
        })
        .await;
        let error = rig.update().await.unwrap_err();
        assert!(error.contains(expected), "{error}");
        assert!(rig.api().is_empty());
        assert!(rig.zone(0).is_none());
    }
}

#[tokio::test]
async fn a_next_link_outside_resource_manager_is_refused() {
    let other = Stub::start(|_| Reply::ok(r#"{"value":[]}"#)).await;
    let target = other.addr;
    for private in [true, false] {
        let rig = rig(
            Opts {
                private,
                zones: "rg:healthy.example",
                ..Opts::default()
            },
            move |request| {
                request.path().starts_with("/subscriptions/").then(|| {
                    Reply::ok(records_body(
                        private,
                        "healthy.example",
                        &format!("http://{target}/steal"),
                        true,
                        true,
                    ))
                })
            },
        )
        .await;
        let error = rig.update().await.unwrap_err();
        assert!(error.contains("outside Resource Manager"), "{error}");
        assert!(rig.zone(0).is_none(), "partial zone published");
    }
    assert!(
        other.requests().is_empty(),
        "the bearer token went to another origin"
    );
}

#[tokio::test]
async fn a_repeated_next_link_ends_the_listing_with_an_error() {
    let rig = rig(
        Opts {
            zones: "rg:healthy.example",
            ..Opts::default()
        },
        |request| {
            request.path().starts_with("/subscriptions/").then(|| {
                let next = format!("http://{}{}?page=2", request.header("host"), request.path());
                Reply::ok(records_body(false, "healthy.example", &next, true, true))
            })
        },
    )
    .await;
    let error = rig.update().await.unwrap_err();
    assert!(error.contains("repeats"), "{error}");
    assert_eq!(rig.api().len(), 2);
}

// go-autorest v0.11.30 autorest/sender.go DoRetryForStatusCodes: retry 408/429/5xx, not other statuses.
#[tokio::test]
async fn transient_statuses_are_retried_within_the_attempt_budget() {
    for (status, failures, retries, api_requests, ok) in [
        (429, 2, 3, 3, true),
        (503, 2, 3, 3, true),
        (503, 9, 1, 2, false),
        (403, 9, 3, 1, false),
        (404, 9, 3, 1, false),
    ] {
        let seen = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&seen);
        let rig = rig(
            Opts {
                zones: "rg:healthy.example",
                tuning: Tuning {
                    retries,
                    backoff: Duration::from_millis(1),
                    list_timeout: Duration::from_secs(30),
                },
                ..Opts::default()
            },
            move |request| {
                (request.path().starts_with("/subscriptions/")
                    && count.fetch_add(1, Ordering::SeqCst) < failures)
                    .then(|| Reply::status(status, "try later"))
            },
        )
        .await;
        assert_eq!(rig.update().await.is_ok(), ok, "{status}");
        assert_eq!(rig.api().len(), api_requests, "{status}");
    }
}

#[tokio::test]
async fn retry_after_sets_the_delay() {
    let seen = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&seen);
    let rig = rig(
        Opts {
            zones: "rg:healthy.example",
            tuning: Tuning {
                retries: 1,
                // A backoff this long would fail the deadline below if Retry-After did not replace it.
                backoff: Duration::from_secs(3600),
                list_timeout: Duration::from_secs(30),
            },
            ..Opts::default()
        },
        move |request| {
            (request.path().starts_with("/subscriptions/")
                && count.fetch_add(1, Ordering::SeqCst) == 0)
                .then(|| Reply::Json(429, vec![("retry-after", "1".to_owned())], "{}".to_owned()))
        },
    )
    .await;
    let started = Instant::now();
    rig.update().await.unwrap();
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn the_listing_deadline_bounds_a_hanging_zone_without_blocking_the_others() {
    let rig = rig(
        Opts {
            tuning: Tuning {
                retries: 1,
                backoff: Duration::from_millis(1),
                list_timeout: Duration::from_millis(100),
            },
            ..Opts::default()
        },
        |request| {
            request
                .path()
                .contains("/missing.example/")
                .then_some(Reply::Hang)
        },
    )
    .await;
    let error = rig.update().await.unwrap_err();
    assert!(error.contains("timed out"), "{error}");
    assert!(has_answer(&rig.azure, "healthy.example").await);
    assert!(rig.zone(1).is_none());
}

// Security: the client secret and access tokens never reach an error, a log line or Debug output.
#[tokio::test]
async fn secrets_and_tokens_never_appear_in_errors_or_logs() {
    const TOKEN: &str = "token-1";
    let echo = |request: &Request| {
        if is_token(request.path()) {
            return Some(Reply::status(401, &format!("echo {SECRET}")));
        }
        Some(Reply::status(500, &format!("echo {SECRET} {TOKEN}")))
    };
    // Token endpoint failure, then an API failure with a token in hand.
    let rig = rig(Opts::default(), echo).await;
    let mut texts = Vec::new();
    let token_failure = rig.update().await.unwrap_err();
    texts.push(rig.azure.syncer.failure_message(token_failure));
    assert!(texts[0].contains("status 401"), "{}", texts[0]);

    let rig = rig_with_token_then_api_errors().await;
    let api_failure = rig.update().await.unwrap_err();
    assert!(api_failure.contains("status 500"), "{api_failure}");
    texts.push(rig.azure.syncer.failure_message(api_failure));
    texts.push(format!("{:?} {:#?}", rig.azure, rig.azure));
    for text in &texts {
        for hidden in [SECRET, TOKEN] {
            assert!(!text.contains(hidden), "{hidden} leaked: {text}");
        }
    }
    assert!(texts[1].contains("<redacted>"), "{}", texts[1]);
}

async fn rig_with_token_then_api_errors() -> Rig {
    rig(Opts::default(), |request| {
        if is_token(request.path()) {
            return None;
        }
        Some(Reply::status(
            500,
            &format!("echo {SECRET} token-1 {}", request.header("authorization")),
        ))
    })
    .await
}

#[tokio::test]
async fn api_failure_after_a_good_load_keeps_serving_the_old_records() {
    let fail = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&fail);
    let rig = rig(Opts::default(), move |request| {
        (flag.load(Ordering::SeqCst) && request.path().starts_with("/subscriptions/"))
            .then(|| Reply::status(500, "boom"))
    })
    .await;
    rig.update().await.unwrap();
    fail.store(true, Ordering::SeqCst);
    assert!(rig.update().await.is_err());
    assert!(has_answer(&rig.azure, "healthy.example").await);
    assert!(has_answer(&rig.azure, "missing.example").await);
}

#[tokio::test]
async fn malformed_records_fail_the_update_and_keep_the_last_good_zone() {
    let broken = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&broken);
    let rig = rig(Opts::default(), move |request| {
        (flag.load(Ordering::SeqCst) && request.path().starts_with("/subscriptions/")).then(|| {
            Reply::ok(
                json!({"value": [{"properties": {"fqdn": "www.healthy.example.", "TTL": 1,
                    "ARecords": [{"ipv4Address": "999.1.1.1"}]}}]})
                .to_string(),
            )
        })
    })
    .await;
    rig.update().await.unwrap();
    broken.store(true, Ordering::SeqCst);
    let error = rig.update().await.unwrap_err();
    assert!(error.contains("invalid ipv4Address"), "{error}");
    assert!(has_answer(&rig.azure, "healthy.example").await);
}

use serde_json::{Value, json};

use super::{Api, Rrset};
use crate::clouddns::{
    auth::{TokenSource, testing::token_response},
    http::Http,
    stub::{Call, Reply, Stub},
};

const ZONE: &str = "/dns/v1/projects/proj/managedZones/zone";

/// One stub serving both the OAuth token endpoint and the Cloud DNS API.
async fn start(api: impl Fn(&Call) -> Reply + Send + Sync + 'static) -> (Stub, Api) {
    let stub = Stub::start(move |call| match call.path() {
        "/token" => Reply::ok(token_response("ya29.api", 3600)),
        _ => api(call),
    })
    .await;
    let file = json!({
        "type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r",
        "token_uri": stub.url("/token"),
    });
    let tokens = TokenSource::from_json(file.to_string().as_bytes(), Http::default()).unwrap();
    let api = Api::new(&format!("{}/", stub.url("")), tokens, Http::default());
    (stub, api)
}

fn rrset(name: &str) -> Value {
    json!({"name": name, "type": "A", "ttl": 300, "rrdatas": ["192.0.2.1"]})
}

fn api_calls(stub: &Stub) -> Vec<Call> {
    stub.calls()
        .into_iter()
        .filter(|call| call.path() != "/token")
        .collect()
}

#[tokio::test]
async fn an_existing_zone_is_found_with_the_bearer_token() {
    let (stub, api) = start(|_| Reply::ok(json!({"name": "zone"}))).await;
    assert!(api.zone_exists("proj", "zone").await.unwrap());
    let call = &api_calls(&stub)[0];
    assert_eq!((call.method.as_str(), call.path()), ("GET", ZONE));
    assert_eq!(call.header("authorization"), Some("Bearer ya29.api"));
}

#[tokio::test]
async fn a_missing_zone_is_false_not_an_error() {
    let (_stub, api) = start(|_| {
        Reply::json(404, json!({"error": {"code": 404, "status": "NOT_FOUND", "message": "The managed zone does not exist."}}))
    })
    .await;
    assert!(!api.zone_exists("proj", "zone").await.unwrap());
}

#[tokio::test]
async fn zone_lookup_errors_report_status_and_code_only() {
    let (_stub, api) = start(|_| {
        Reply::json(
            403,
            json!({"error": {"status": "PERMISSION_DENIED", "message": "SECRET-MESSAGE-MARKER"}}),
        )
    })
    .await;
    let error = api
        .zone_exists("proj", "zone")
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(error, "HTTP 403: PERMISSION_DENIED");
    let (_stub, api) = start(|_| Reply::text(500, "SECRET-BODY-MARKER")).await;
    assert_eq!(
        api.zone_exists("proj", "zone")
            .await
            .unwrap_err()
            .to_string(),
        "HTTP 500"
    );
}

#[tokio::test]
async fn lists_every_page() {
    let (stub, api) = start(|call| match call.query("pageToken").as_deref() {
        None => Reply::ok(json!({"rrsets": [rrset("a.example.org.")], "nextPageToken": "p2"})),
        Some("p2") => Reply::ok(json!({
            "rrsets": [{"name": "b.example.org.", "type": "TXT", "ttl": 60, "rrdatas": ["\"x\"", "\"y\""]}],
            "nextPageToken": "p3 /&",
        })),
        Some("p3 /&") => Reply::ok(json!({"rrsets": [rrset("c.example.org.")]})),
        Some(other) => panic!("unexpected token {other}"),
    })
    .await;

    let rrsets = api.list_rrsets("proj", "zone").await.unwrap();

    let names: Vec<_> = rrsets.iter().map(|rrset| rrset.name.as_str()).collect();
    assert_eq!(
        names,
        ["a.example.org.", "b.example.org.", "c.example.org."]
    );
    assert_eq!(
        rrsets[1],
        Rrset {
            name: "b.example.org.".into(),
            rtype: "TXT".into(),
            ttl: 60,
            rrdatas: vec!["\"x\"".into(), "\"y\"".into()],
        }
    );
    let calls = api_calls(&stub);
    assert_eq!(calls.len(), 3);
    assert!(
        calls
            .iter()
            .all(|call| call.path() == format!("{ZONE}/rrsets"))
    );
    assert!(
        calls[2].target.ends_with("?pageToken=p3+%2F%26"),
        "{}",
        calls[2].target
    );
}

#[tokio::test]
async fn an_empty_zone_has_no_rrsets_key() {
    let (_stub, api) =
        start(|_| Reply::ok(json!({"kind": "dns#resourceRecordSetsListResponse"}))).await;
    assert!(api.list_rrsets("proj", "zone").await.unwrap().is_empty());
}

#[tokio::test]
async fn a_record_set_without_rrdatas_is_kept_empty() {
    let (_stub, api) = start(|_| {
        Reply::ok(json!({"rrsets": [{"name": "w.example.org.", "type": "A", "ttl": 30}]}))
    })
    .await;
    assert!(
        api.list_rrsets("proj", "zone").await.unwrap()[0]
            .rrdatas
            .is_empty()
    );
}

#[tokio::test]
async fn a_repeated_page_token_is_a_loop() {
    let (stub, api) = start(|_| Reply::ok(json!({"rrsets": [], "nextPageToken": "same"}))).await;
    let error = api
        .list_rrsets("proj", "zone")
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(error, "list response repeats a page token");
    assert_eq!(api_calls(&stub).len(), 2);
}

#[tokio::test]
async fn list_failures_are_errors() {
    let (_stub, api) = start(|_| Reply::json(404, json!({"error": {"status": "NOT_FOUND"}}))).await;
    assert_eq!(
        api.list_rrsets("proj", "zone")
            .await
            .unwrap_err()
            .to_string(),
        "HTTP 404: NOT_FOUND"
    );

    let (_stub, api) = start(|_| Reply::text(503, "")).await;
    assert_eq!(
        api.list_rrsets("proj", "zone")
            .await
            .unwrap_err()
            .to_string(),
        "HTTP 503"
    );
}

#[tokio::test]
async fn a_failure_on_a_later_page_discards_the_earlier_ones() {
    let (_stub, api) = start(|call| match call.query("pageToken") {
        None => Reply::ok(json!({"rrsets": [rrset("a.example.org.")], "nextPageToken": "p2"})),
        Some(_) => Reply::text(500, ""),
    })
    .await;
    assert!(api.list_rrsets("proj", "zone").await.is_err());
}

#[tokio::test]
async fn malformed_json_is_an_error_without_the_body() {
    let (_stub, api) = start(|_| Reply::text(200, "{\"rrsets\": SECRET-BODY-MARKER")).await;
    let error = api
        .list_rrsets("proj", "zone")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.starts_with("list response: invalid JSON at line"),
        "{error}"
    );
    assert!(!error.contains("MARKER"));

    let (_stub, api) = start(|_| Reply::ok(json!({"rrsets": [{"name": 5}]}))).await;
    assert!(api.list_rrsets("proj", "zone").await.is_err());
}

#[tokio::test]
async fn project_and_zone_are_escaped_in_the_path() {
    let (stub, api) = start(|_| Reply::ok(json!({}))).await;
    api.zone_exists("a/b", "z z?").await.unwrap();
    assert_eq!(
        api_calls(&stub)[0].path(),
        "/dns/v1/projects/a%2Fb/managedZones/z%20z%3F"
    );
}

#[tokio::test]
async fn a_token_failure_is_reported_without_calling_the_api() {
    let stub = Stub::start(|_| {
        Reply::json(
            400,
            json!({"error": "invalid_grant", "error_description": "SECRET-DESC-MARKER"}),
        )
    })
    .await;
    let file = json!({
        "type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r",
        "token_uri": stub.url("/token"),
    });
    let tokens = TokenSource::from_json(file.to_string().as_bytes(), Http::default()).unwrap();
    let api = Api::new(&stub.url(""), tokens, Http::default());
    let error = api.zone_exists("p", "z").await.unwrap_err().to_string();
    assert_eq!(
        error,
        "credentials: authorized user token request: HTTP 400: invalid_grant"
    );
    assert_eq!(stub.calls().len(), 1);
}

#[test]
fn debug_hides_credentials() {
    let file = json!({
        "type": "authorized_user", "client_id": "c", "client_secret": "SECRET-MARKER", "refresh_token": "r",
    });
    let tokens = TokenSource::from_json(file.to_string().as_bytes(), Http::default()).unwrap();
    let text = format!("{:?}", Api::new("http://x", tokens, Http::default()));
    assert!(!text.contains("MARKER"), "{text}");
}

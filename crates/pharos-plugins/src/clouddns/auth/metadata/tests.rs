use serde_json::json;

use super::Metadata;
use crate::clouddns::{
    auth::{DNS_SCOPES, testing::token_response},
    http::Http,
    stub::{Reply, Stub},
};

#[tokio::test]
async fn fetches_the_default_service_account_token() {
    let stub = Stub::start(|_| Reply::ok(token_response("ya29.gce", 3000))).await;
    let host = stub.addr.to_string();
    let source = Metadata::new(Some(&host), &DNS_SCOPES);

    let fetched = source.fetch(&Http::default()).await.unwrap();

    assert_eq!(fetched.token.expose(), "ya29.gce");
    assert_eq!(fetched.lifetime.unwrap().as_secs(), 3000);
    let call = &stub.calls()[0];
    assert_eq!(call.method, "GET");
    assert_eq!(
        call.path(),
        "/computeMetadata/v1/instance/service-accounts/default/token"
    );
    assert_eq!(call.header("metadata-flavor"), Some("Google"));
    assert_eq!(call.query("scopes").unwrap(), DNS_SCOPES.join(","));
}

#[tokio::test]
async fn an_incomplete_token_is_rejected() {
    let stub = Stub::start(|_| Reply::ok(json!({"access_token": "t"}))).await;
    let host = stub.addr.to_string();
    let error = Metadata::new(Some(&host), &DNS_SCOPES)
        .fetch(&Http::default())
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "GCE metadata server: incomplete token received"
    );
}

#[tokio::test]
async fn a_missing_service_account_reports_the_status() {
    let stub = Stub::start(|_| Reply::text(404, "no service account")).await;
    let host = stub.addr.to_string();
    let error = Metadata::new(Some(&host), &DNS_SCOPES)
        .fetch(&Http::default())
        .await
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "GCE metadata server: HTTP 404");
}

#[test]
fn the_default_host_is_the_documented_address() {
    assert_eq!(Metadata::new(None, &[]).host, "169.254.169.254");
    assert_eq!(Metadata::new(Some(""), &[]).host, "169.254.169.254");
}

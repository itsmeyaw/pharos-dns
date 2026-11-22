use std::time::Duration;

use serde_json::json;

use super::{Impersonated, unix_seconds};
use crate::clouddns::{
    auth::{
        DNS_SCOPES, Provider, TokenSource,
        authorized_user::{AuthorizedUser, File},
        testing::token_response,
    },
    http::Http,
    stub::{Reply, Stub},
};

fn source(token_uri: &str) -> TokenSource {
    let file: File = serde_json::from_value(json!({
        "client_id": "id", "client_secret": "secret", "refresh_token": "refresh", "token_uri": token_uri,
    }))
    .unwrap();
    TokenSource::new(
        Provider::AuthorizedUser(AuthorizedUser::from_file(file).unwrap()),
        Http::default(),
    )
}

/// A stub that is both the source's token endpoint (`/token`) and IAM Credentials (`/iam`).
async fn stub(iam: impl Fn(&crate::clouddns::stub::Call) -> Reply + Send + Sync + 'static) -> Stub {
    Stub::start(move |call| match call.path() {
        "/token" => Reply::ok(token_response("ya29.source", 3600)),
        _ => iam(call),
    })
    .await
}

fn impersonated(stub: &Stub, delegates: Vec<String>, lifetime: Option<u64>) -> Impersonated {
    Impersonated::new(
        source(&stub.url("/token")),
        stub.url("/iam"),
        &DNS_SCOPES,
        delegates,
        lifetime,
    )
}

#[tokio::test]
async fn asks_iam_for_a_token_with_the_source_bearer() {
    let stub = stub(|_| {
        Reply::ok(json!({"accessToken": "ya29.target", "expireTime": "2099-01-01T00:00:00Z"}))
    })
    .await;
    let fetched = impersonated(&stub, vec!["d1".into()], None)
        .fetch(&Http::default())
        .await
        .unwrap();

    assert_eq!(fetched.token.expose(), "ya29.target");
    assert!(fetched.lifetime.unwrap() > Duration::from_secs(60 * 60 * 24 * 365 * 50));
    let call = stub
        .calls()
        .into_iter()
        .find(|c| c.path() == "/iam")
        .unwrap();
    assert_eq!(call.method, "POST");
    assert_eq!(call.header("authorization"), Some("Bearer ya29.source"));
    assert_eq!(call.header("content-type"), Some("application/json"));
    assert_eq!(
        call.json(),
        json!({"lifetime": "3600s", "scope": DNS_SCOPES, "delegates": ["d1"]})
    );
}

#[tokio::test]
async fn a_configured_lifetime_is_requested_and_no_delegates_are_omitted() {
    let stub =
        stub(|_| Reply::ok(json!({"accessToken": "t", "expireTime": "2099-01-01T00:00:00Z"})))
            .await;
    impersonated(&stub, Vec::new(), Some(1800))
        .fetch(&Http::default())
        .await
        .unwrap();
    let call = stub
        .calls()
        .into_iter()
        .find(|c| c.path() == "/iam")
        .unwrap();
    assert_eq!(call.json()["lifetime"], "1800s");
    assert!(call.json().get("delegates").is_none());
}

#[tokio::test]
async fn an_expired_expire_time_is_a_zero_lifetime() {
    let stub =
        stub(|_| Reply::ok(json!({"accessToken": "t", "expireTime": "2001-01-01T00:00:00Z"})))
            .await;
    let fetched = impersonated(&stub, Vec::new(), None)
        .fetch(&Http::default())
        .await
        .unwrap();
    assert_eq!(fetched.lifetime, Some(Duration::ZERO));
}

#[tokio::test]
async fn iam_denial_reports_status_and_code_only() {
    let stub = stub(|_| {
        Reply::json(
            403,
            json!({"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "caller robot@x lacks iam.serviceAccounts.getAccessToken"}}),
        )
    })
    .await;
    let error = impersonated(&stub, Vec::new(), None)
        .fetch(&Http::default())
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "impersonation request: HTTP 403: PERMISSION_DENIED"
    );
}

#[tokio::test]
async fn a_failing_source_is_named() {
    let stub = Stub::start(|_| Reply::json(400, json!({"error": "invalid_grant"}))).await;
    let error = impersonated(&stub, Vec::new(), None)
        .fetch(&Http::default())
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "impersonation source credentials: authorized user token request: HTTP 400: invalid_grant"
    );
}

#[tokio::test]
async fn incomplete_responses_are_errors() {
    for body in [
        json!({"expireTime": "2099-01-01T00:00:00Z"}),
        json!({"accessToken": "t"}),
        json!({"accessToken": "t", "expireTime": "tomorrow"}),
    ] {
        let stub = stub(move |_| Reply::ok(body.clone())).await;
        let result = impersonated(&stub, Vec::new(), None)
            .fetch(&Http::default())
            .await;
        assert!(result.is_err());
    }
}

#[test]
fn parses_rfc3339_timestamps() {
    assert_eq!(unix_seconds("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(unix_seconds("2000-03-01T00:00:00Z"), Some(951_868_800));
    assert_eq!(unix_seconds("2024-02-29T12:00:00Z"), Some(1_709_208_000));
    assert_eq!(
        unix_seconds("2024-02-29T12:00:00.123456789Z"),
        Some(1_709_208_000)
    );
    assert_eq!(
        unix_seconds("2024-02-29T12:00:00+01:00"),
        Some(1_709_204_400)
    );
    assert_eq!(
        unix_seconds("2024-02-29T12:00:00-05:30"),
        Some(1_709_227_800)
    );
    assert_eq!(unix_seconds("1969-12-31T23:59:59Z"), Some(-1));
}

#[test]
fn rejects_malformed_timestamps() {
    for text in [
        "",
        "2024-02-29",
        "2024-02-29 12:00:00Z",
        "2024-13-01T00:00:00Z",
        "2024-02-29T25:00:00Z",
        "2024-02-29T12:00:00",
        "2024-02-29T12:00:00.Z",
        "2024-02-29T12:00:00+0100",
        "abcd-02-29T12:00:00Z",
    ] {
        assert_eq!(unix_seconds(text), None, "{text}");
    }
}

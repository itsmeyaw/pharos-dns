use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use super::TokenSource;
use crate::clouddns::{
    auth::{
        Provider,
        service_account::{File, ServiceAccount},
        testing::{service_account_file, token_response},
    },
    http::Http,
    stub::{Reply, Stub},
};

fn source(stub: &Stub, margin: Duration) -> TokenSource {
    let file: File = serde_json::from_value(service_account_file(&stub.url("/token"))).unwrap();
    let provider = Provider::ServiceAccount(ServiceAccount::from_file(file).unwrap());
    TokenSource::with_margin(provider, Http::default(), margin)
}

async fn counting_stub(expires_in: u64) -> Stub {
    let hits = AtomicUsize::new(0);
    Stub::start(move |_| {
        let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
        Reply::ok(token_response(&format!("tok-{n}"), expires_in))
    })
    .await
}

#[tokio::test]
async fn a_fresh_token_is_served_from_the_cache() {
    let stub = counting_stub(3600).await;
    let tokens = source(&stub, Duration::from_secs(225));
    assert_eq!(tokens.token().await.unwrap().as_str(), "tok-1");
    assert_eq!(tokens.token().await.unwrap().as_str(), "tok-1");
    assert_eq!(stub.calls().len(), 1);
}

#[tokio::test]
async fn concurrent_callers_share_one_fetch() {
    let stub = counting_stub(3600).await;
    let tokens = source(&stub, Duration::from_secs(225));
    let other = tokens.clone();
    let (a, b, c) = tokio::join!(tokens.token(), other.token(), tokens.token());
    assert_eq!(a.unwrap().as_str(), b.unwrap().as_str());
    assert_eq!(c.unwrap().as_str(), "tok-1");
    assert_eq!(stub.calls().len(), 1);
}

#[tokio::test]
async fn a_token_inside_the_margin_is_refreshed() {
    // 10 s lifetime with a 9.85 s margin: stale after 150 ms.
    let stub = counting_stub(10).await;
    let tokens = source(&stub, Duration::from_millis(9850));
    assert_eq!(tokens.token().await.unwrap().as_str(), "tok-1");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(tokens.token().await.unwrap().as_str(), "tok-2");
    assert_eq!(stub.calls().len(), 2);
}

#[tokio::test]
async fn a_token_without_expiry_never_refreshes() {
    let stub = Stub::start(|_| Reply::ok(serde_json::json!({"access_token": "forever"}))).await;
    let tokens = source(&stub, Duration::from_secs(225));
    tokens.token().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(tokens.token().await.unwrap().as_str(), "forever");
    assert_eq!(stub.calls().len(), 1);
}

#[tokio::test]
async fn a_failed_refresh_keeps_serving_an_unexpired_token() {
    let hits = AtomicUsize::new(0);
    let stub = Stub::start(move |_| {
        if hits.fetch_add(1, Ordering::SeqCst) == 0 {
            Reply::ok(token_response("tok-1", 3600))
        } else {
            Reply::text(500, "")
        }
    })
    .await;
    let tokens = source(&stub, Duration::from_millis(3_599_900));
    tokens.token().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(tokens.token().await.unwrap().as_str(), "tok-1");
    assert_eq!(stub.calls().len(), 2);
}

#[tokio::test]
async fn a_failed_refresh_of_an_expired_token_is_an_error_then_recovers() {
    let hits = AtomicUsize::new(0);
    let stub = Stub::start(move |_| match hits.fetch_add(1, Ordering::SeqCst) {
        0 => Reply::ok(token_response("tok-1", 1)),
        1 => Reply::text(500, ""),
        _ => Reply::ok(token_response("tok-3", 3600)),
    })
    .await;
    let tokens = source(&stub, Duration::ZERO);
    tokens.token().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let error = tokens.token().await.unwrap_err();
    assert!(error.to_string().contains("HTTP 500"), "{error}");
    assert_eq!(tokens.token().await.unwrap().as_str(), "tok-3");
}

#[test]
fn debug_hides_tokens() {
    let token = super::AccessToken(super::Secret::new("ya29.MARKER"));
    assert!(!format!("{token:?}").contains("MARKER"));
}

use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use serde_json::json;

use super::{AuthorizedUser, File};
use crate::clouddns::{
    auth::testing::token_response,
    http::Http,
    stub::{Reply, Stub},
};

fn user(token_uri: &str) -> Result<AuthorizedUser, String> {
    let file: File = serde_json::from_value(json!({
        "type": "authorized_user",
        "client_id": "id.apps.googleusercontent.com",
        "client_secret": "SECRET-CLIENT-MARKER",
        "refresh_token": "1//REFRESH-MARKER",
        "token_uri": token_uri,
    }))
    .unwrap();
    AuthorizedUser::from_file(file).map_err(|error| error.to_string())
}

#[tokio::test]
async fn exchanges_the_refresh_token() {
    let stub = Stub::start(|_| Reply::ok(token_response("ya29.user", 3599))).await;
    let fetched = user(&stub.url("/token"))
        .unwrap()
        .fetch(&Http::default())
        .await
        .unwrap();
    assert_eq!(fetched.token.expose(), "ya29.user");
    assert_eq!(fetched.lifetime.unwrap().as_secs(), 3599);
    let form = stub.calls()[0].form();
    assert_eq!(form["grant_type"], "refresh_token");
    assert_eq!(form["refresh_token"], "1//REFRESH-MARKER");
    assert_eq!(form["client_id"], "id.apps.googleusercontent.com");
    assert_eq!(form["client_secret"], "SECRET-CLIENT-MARKER");
}

#[tokio::test]
async fn a_rotated_refresh_token_replaces_the_old_one() {
    let hits = AtomicUsize::new(0);
    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    let log = std::sync::Arc::clone(&seen);
    let stub = Stub::start(move |call| {
        log.lock()
            .unwrap()
            .push(call.form()["refresh_token"].clone());
        let mut body = token_response("t", 3600);
        if hits.fetch_add(1, Ordering::SeqCst) == 0 {
            body["refresh_token"] = "1//ROTATED".into();
        }
        Reply::ok(body)
    })
    .await;
    let source = user(&stub.url("/token")).unwrap();
    source.fetch(&Http::default()).await.unwrap();
    source.fetch(&Http::default()).await.unwrap();
    assert_eq!(*seen.lock().unwrap(), ["1//REFRESH-MARKER", "1//ROTATED"]);
}

#[tokio::test]
async fn a_revoked_token_reports_the_oauth_code() {
    let stub = Stub::start(|_| {
        Reply::json(
            400,
            json!({"error": "invalid_grant", "error_description": "Token has been expired or revoked."}),
        )
    })
    .await;
    let error = user(&stub.url("/token"))
        .unwrap()
        .fetch(&Http::default())
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "authorized user token request: HTTP 400: invalid_grant"
    );
}

#[test]
fn every_secret_field_is_required() {
    for field in ["client_id", "client_secret", "refresh_token"] {
        let mut file = json!({"client_id": "a", "client_secret": "b", "refresh_token": "c"});
        file.as_object_mut().unwrap().remove(field);
        let file: File = serde_json::from_value(file).unwrap();
        let error = AuthorizedUser::from_file(file).unwrap_err().to_string();
        assert!(error.contains(field), "{error}");
    }
}

#[test]
fn debug_hides_secrets() {
    let text = format!("{:?}", user("http://t/").unwrap());
    assert!(!text.contains("MARKER"), "{text}");
}

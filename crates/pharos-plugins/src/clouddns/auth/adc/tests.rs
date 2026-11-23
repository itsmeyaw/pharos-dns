use std::{fs, path::Path};

use serde_json::json;

use super::Environment;
use crate::clouddns::{
    auth::{TokenSource, testing::token_response},
    http::Http,
    stub::{Reply, Stub},
};

fn authorized_user(token_uri: &str) -> String {
    json!({
        "type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r",
        "token_uri": token_uri,
    })
    .to_string()
}

fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

/// A stub that names itself in the token it returns.
async fn named(name: &'static str) -> Stub {
    Stub::start(move |_| Reply::ok(token_response(name, 3600))).await
}

#[tokio::test]
async fn the_environment_variable_wins_over_the_gcloud_file_and_metadata() {
    let (from_env, from_home, from_metadata) = (
        named("env").await,
        named("home").await,
        named("metadata").await,
    );
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("creds.json");
    write(&env_file, &authorized_user(&from_env.url("/token")));
    write(
        &dir.path()
            .join("home/.config/gcloud/application_default_credentials.json"),
        &authorized_user(&from_home.url("/token")),
    );
    let env = Environment {
        google_application_credentials: Some(env_file),
        home: Some(dir.path().join("home")),
        gce_metadata_host: Some(from_metadata.addr.to_string()),
    };
    let tokens = TokenSource::discover(&env, Http::default()).unwrap();
    assert_eq!(tokens.token().await.unwrap().as_str(), "env");
}

#[tokio::test]
async fn the_gcloud_file_wins_over_metadata() {
    let (from_home, from_metadata) = (named("home").await, named("metadata").await);
    let dir = tempfile::tempdir().unwrap();
    write(
        &dir.path()
            .join(".config/gcloud/application_default_credentials.json"),
        &authorized_user(&from_home.url("/token")),
    );
    let env = Environment {
        google_application_credentials: None,
        home: Some(dir.path().to_owned()),
        gce_metadata_host: Some(from_metadata.addr.to_string()),
    };
    let tokens = TokenSource::discover(&env, Http::default()).unwrap();
    assert_eq!(tokens.token().await.unwrap().as_str(), "home");
    assert!(from_metadata.calls().is_empty());
}

#[tokio::test]
async fn metadata_is_the_last_resort() {
    let from_metadata = named("metadata").await;
    let dir = tempfile::tempdir().unwrap();
    let env = Environment {
        google_application_credentials: None,
        home: Some(dir.path().to_owned()),
        gce_metadata_host: Some(from_metadata.addr.to_string()),
    };
    let tokens = TokenSource::discover(&env, Http::default()).unwrap();
    assert_eq!(tokens.token().await.unwrap().as_str(), "metadata");
    assert_eq!(
        from_metadata.calls()[0].header("metadata-flavor"),
        Some("Google")
    );
}

#[test]
fn an_unusable_environment_file_is_an_error_not_a_fallback() {
    let env = Environment {
        google_application_credentials: Some("/nonexistent/creds.json".into()),
        home: None,
        gce_metadata_host: Some("127.0.0.1:1".into()),
    };
    let error = TokenSource::discover(&env, Http::default())
        .unwrap_err()
        .to_string();
    assert!(
        error.starts_with("GOOGLE_APPLICATION_CREDENTIALS /nonexistent/creds.json: "),
        "{error}"
    );
}

#[test]
fn a_malformed_gcloud_file_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    write(
        &dir.path()
            .join(".config/gcloud/application_default_credentials.json"),
        r#"{"type": "nope"}"#,
    );
    let env = Environment {
        home: Some(dir.path().to_owned()),
        ..Environment::default()
    };
    let error = TokenSource::discover(&env, Http::default())
        .unwrap_err()
        .to_string();
    assert!(error.ends_with("unknown credential type: nope"), "{error}");
}

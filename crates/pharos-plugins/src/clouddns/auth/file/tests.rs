use std::io::Write;

use serde_json::{Value, json};

use super::{CredentialType, credential_type};
use crate::clouddns::{
    auth::{
        DNS_SCOPES, TokenSource,
        testing::{rsa_key, service_account_file, token_response, verify_jwt},
    },
    http::Http,
    stub::{Call, Reply, Stub},
};

fn write(content: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file
}

// CoreDNS v1.15.0 plugin/clouddns/setup_test.go TestSetupCredentials and getCredType.
#[test]
fn accepts_the_four_credential_types() {
    for (name, expected) in [
        ("service_account", CredentialType::ServiceAccount),
        ("authorized_user", CredentialType::AuthorizedUser),
        (
            "impersonated_service_account",
            CredentialType::ImpersonatedServiceAccount,
        ),
        ("external_account", CredentialType::ExternalAccount),
    ] {
        let file = write(&json!({"type": name}).to_string());
        assert_eq!(credential_type(file.path()).unwrap(), expected);
        assert_eq!(expected.name(), name);
    }
}

#[test]
fn rejects_a_missing_empty_or_unknown_type() {
    let cases = [
        (
            r#"{"client_email": "x"}"#,
            "missing `type` field in credential",
        ),
        (r#"{"type": ""}"#, "missing `type` field in credential"),
        (
            r#"{"type": "gdch_service_account"}"#,
            "unknown credential type: gdch_service_account",
        ),
        (
            r#"{"type": "external_account_authorized_user"}"#,
            "unknown credential type: external_account_authorized_user",
        ),
    ];
    for (content, message) in cases {
        let error = credential_type(write(content).path()).unwrap_err();
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn rejects_unreadable_and_malformed_files_without_echoing_content() {
    assert!(credential_type("/nonexistent/credentials.json".as_ref()).is_err());
    let error = credential_type(write("{\"type\": 5, \"k\": \"SECRET-FILE-MARKER\"").path())
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("invalid JSON at line"), "{error}");
    let error = credential_type(write("\"SECRET-FILE-MARKER\"").path())
        .unwrap_err()
        .to_string();
    assert!(!error.contains("MARKER"), "{error}");
}

#[test]
fn a_long_unknown_type_is_truncated() {
    let content = json!({"type": "x".repeat(500)}).to_string();
    let error = credential_type(write(&content).path())
        .unwrap_err()
        .to_string();
    assert!(error.len() < 100, "{error}");
}

/// One stub: OAuth token endpoint, STS, IAM Credentials.
async fn google() -> Stub {
    Stub::start(|call: &Call| match call.path() {
        "/token" => {
            let form = call.form();
            let token = match form["grant_type"].as_str() {
                "refresh_token" => "ya29.user".to_owned(),
                _ => {
                    let _ = verify_jwt(&form["assertion"], &rsa_key().public);
                    "ya29.sa".to_owned()
                }
            };
            Reply::ok(token_response(&token, 3600))
        }
        "/sts" => Reply::ok(token_response("ya29.sts", 3600)),
        "/iam" => Reply::ok(
            json!({"accessToken": "ya29.impersonated", "expireTime": "2099-01-01T00:00:00Z"}),
        ),
        other => panic!("unexpected {other}"),
    })
    .await
}

fn source(file: &Value) -> Result<TokenSource, String> {
    TokenSource::from_json(file.to_string().as_bytes(), Http::default())
        .map_err(|error| error.to_string())
}

#[tokio::test]
async fn builds_a_service_account_source() {
    let google = google().await;
    let tokens = source(&service_account_file(&google.url("/token"))).unwrap();
    assert_eq!(tokens.token().await.unwrap().as_str(), "ya29.sa");
}

#[tokio::test]
async fn builds_an_authorized_user_source() {
    let google = google().await;
    let file = json!({
        "type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r",
        "token_uri": google.url("/token"),
    });
    assert_eq!(
        source(&file).unwrap().token().await.unwrap().as_str(),
        "ya29.user"
    );
}

#[tokio::test]
async fn impersonation_mints_with_the_source_token_and_cloud_platform_scope() {
    let google = google().await;
    let file = json!({
        "type": "impersonated_service_account",
        "service_account_impersonation_url": google.url("/iam"),
        "delegates": ["d"],
        "source_credentials": {
            "type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r",
            "token_uri": google.url("/token"),
        },
    });
    let token = source(&file).unwrap().token().await.unwrap();
    assert_eq!(token.as_str(), "ya29.impersonated");
    let iam = google
        .calls()
        .into_iter()
        .find(|call| call.path() == "/iam")
        .unwrap();
    assert_eq!(iam.header("authorization"), Some("Bearer ya29.user"));
    assert_eq!(iam.json()["scope"], json!(DNS_SCOPES));
    assert_eq!(iam.json()["delegates"], json!(["d"]));
}

#[tokio::test]
async fn a_service_account_source_is_asked_for_cloud_platform_only() {
    let google = google().await;
    let file = json!({
        "type": "impersonated_service_account",
        "service_account_impersonation_url": google.url("/iam"),
        "source_credentials": service_account_file(&google.url("/token")),
    });
    source(&file).unwrap().token().await.unwrap();
    let token_call = google
        .calls()
        .into_iter()
        .find(|call| call.path() == "/token")
        .unwrap();
    let (_, claims) = verify_jwt(&token_call.form()["assertion"], &rsa_key().public);
    assert_eq!(
        claims["scope"],
        "https://www.googleapis.com/auth/cloud-platform"
    );
}

#[tokio::test]
async fn external_account_impersonation_chains_sts_then_iam() {
    let google = google().await;
    let subject = write("subject-jwt");
    let file = json!({
        "type": "external_account",
        "audience": "aud", "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": google.url("/sts"),
        "credential_source": {"file": subject.path()},
        "service_account_impersonation_url": google.url("/iam"),
        "service_account_impersonation": {"token_lifetime_seconds": 1800},
    });
    let token = source(&file).unwrap().token().await.unwrap();
    assert_eq!(token.as_str(), "ya29.impersonated");
    let calls = google.calls();
    let sts = calls.iter().find(|call| call.path() == "/sts").unwrap();
    assert_eq!(
        sts.form()["scope"],
        "https://www.googleapis.com/auth/cloud-platform"
    );
    let iam = calls.iter().find(|call| call.path() == "/iam").unwrap();
    assert_eq!(iam.header("authorization"), Some("Bearer ya29.sts"));
    assert_eq!(iam.json()["scope"], json!(DNS_SCOPES));
    assert_eq!(iam.json()["lifetime"], "1800s");
}

#[tokio::test]
async fn external_account_without_impersonation_asks_for_the_dns_scopes() {
    let google = google().await;
    let subject = write("subject-jwt");
    let file = json!({
        "type": "external_account",
        "audience": "aud", "subject_token_type": "t", "token_url": google.url("/sts"),
        "credential_source": {"file": subject.path()},
    });
    assert_eq!(
        source(&file).unwrap().token().await.unwrap().as_str(),
        "ya29.sts"
    );
    assert_eq!(google.calls()[0].form()["scope"], DNS_SCOPES.join(" "));
}

#[test]
fn impersonation_needs_a_url_and_source_credentials() {
    let message =
        "missing 'source_credentials' field or 'service_account_impersonation_url' in credentials";
    let both = json!({
        "type": "impersonated_service_account",
        "service_account_impersonation_url": "http://x/iam",
        "source_credentials": {"type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r"},
    });
    assert!(source(&both).is_ok());
    for field in ["service_account_impersonation_url", "source_credentials"] {
        let mut file = both.clone();
        file.as_object_mut().unwrap().remove(field);
        assert_eq!(source(&file).unwrap_err(), message);
    }
}

#[test]
fn nested_source_credentials_are_bounded() {
    let mut file = json!({"type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r"});
    for _ in 0..4 {
        file = json!({
            "type": "impersonated_service_account",
            "service_account_impersonation_url": "http://x/iam",
            "source_credentials": file,
        });
    }
    assert!(source(&file).unwrap_err().contains("nested too deeply"));
}

#[test]
fn source_errors_are_prefixed() {
    let file = json!({
        "type": "impersonated_service_account",
        "service_account_impersonation_url": "http://x/iam",
        "source_credentials": {"type": "authorized_user"},
    });
    assert_eq!(
        source(&file).unwrap_err(),
        "source_credentials: authorized_user credentials have no client_id"
    );
}

#[test]
fn bad_files_are_rejected_without_echoing_values() {
    for file in [
        json!({"type": "service_account", "private_key": 5, "client_email": "SECRET-VALUE-MARKER"}),
        json!({"type": "authorized_user", "client_id": ["SECRET-VALUE-MARKER"]}),
        json!({"type": "nope", "client_id": "SECRET-VALUE-MARKER"}),
        json!({"client_id": "SECRET-VALUE-MARKER"}),
    ] {
        let error = source(&file).unwrap_err();
        assert!(!error.contains("MARKER"), "{error}");
    }
    assert!(
        source(&json!({"type": "service_account", "private_key": 5}))
            .unwrap_err()
            .contains("wrong type")
    );
}

#[test]
fn from_file_reads_the_path() {
    let file = write(&json!({"type": "authorized_user", "client_id": "c", "client_secret": "s", "refresh_token": "r"}).to_string());
    assert!(TokenSource::from_file(file.path(), Http::default()).is_ok());
    assert!(TokenSource::from_file("/nonexistent".as_ref(), Http::default()).is_err());
}

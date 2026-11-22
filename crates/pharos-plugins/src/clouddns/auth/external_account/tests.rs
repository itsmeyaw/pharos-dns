use std::io::Write;

use serde_json::{Value, json};

use super::{ExternalAccount, File};
use crate::clouddns::{
    auth::{DNS_SCOPES, testing::token_response},
    http::Http,
    stub::{Reply, Stub},
};

const AUDIENCE: &str =
    "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q";

fn account(source: Value, extra: Value, sts: &Stub) -> Result<ExternalAccount, String> {
    let mut file = json!({
        "type": "external_account",
        "audience": AUDIENCE,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": sts.url("/sts"),
        "credential_source": source,
    });
    for (key, value) in extra.as_object().unwrap() {
        file[key] = value.clone();
    }
    let file: File = serde_json::from_value(file).unwrap();
    ExternalAccount::from_file(file, &DNS_SCOPES).map_err(|error| error.to_string())
}

async fn sts() -> Stub {
    Stub::start(|_| Reply::ok(token_response("ya29.federated", 3600))).await
}

fn temp_file(content: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file
}

#[tokio::test]
async fn exchanges_a_text_file_subject_token() {
    let sts = sts().await;
    let subject = temp_file("  subject-jwt\n");
    let account = account(json!({"file": subject.path()}), json!({}), &sts).unwrap();

    let fetched = account.fetch(&Http::default()).await.unwrap();

    assert_eq!(fetched.token.expose(), "ya29.federated");
    assert_eq!(fetched.lifetime.unwrap().as_secs(), 3600);
    let call = &sts.calls()[0];
    assert_eq!((call.method.as_str(), call.path()), ("POST", "/sts"));
    let form = call.form();
    assert_eq!(
        form["grant_type"],
        "urn:ietf:params:oauth:grant-type:token-exchange"
    );
    assert_eq!(
        form["requested_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );
    assert_eq!(
        form["subject_token_type"],
        "urn:ietf:params:oauth:token-type:jwt"
    );
    assert_eq!(form["subject_token"], "subject-jwt");
    assert_eq!(form["audience"], AUDIENCE);
    assert_eq!(form["scope"], DNS_SCOPES.join(" "));
    assert!(call.header("authorization").is_none());
    assert!(!form.contains_key("options"));
}

#[tokio::test]
async fn reads_a_json_file_subject_token_field() {
    let sts = sts().await;
    let subject = temp_file(r#"{"id_token": "from-json", "other": "x"}"#);
    let source = json!({"file": subject.path(), "format": {"type": "json", "subject_token_field_name": "id_token"}});
    account(source, json!({}), &sts)
        .unwrap()
        .fetch(&Http::default())
        .await
        .unwrap();
    assert_eq!(sts.calls()[0].form()["subject_token"], "from-json");
}

#[tokio::test]
async fn a_missing_json_field_is_an_error() {
    let sts = sts().await;
    let subject = temp_file(r#"{"other": "x"}"#);
    let source = json!({"file": subject.path(), "format": {"type": "json", "subject_token_field_name": "id_token"}});
    let error = account(source, json!({}), &sts)
        .unwrap()
        .fetch(&Http::default())
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "subject token: subject token field not found"
    );
    assert!(sts.calls().is_empty());
}

#[tokio::test]
async fn fetches_a_url_subject_token_with_headers_untrimmed() {
    let sts = sts().await;
    let provider = Stub::start(|call| {
        assert_eq!(call.header("x-meta"), Some("v"));
        Reply::text(200, "url-jwt\n")
    })
    .await;
    let source = json!({"url": provider.url("/subject"), "headers": {"x-meta": "v"}});
    account(source, json!({}), &sts)
        .unwrap()
        .fetch(&Http::default())
        .await
        .unwrap();
    assert_eq!(sts.calls()[0].form()["subject_token"], "url-jwt\n");
}

#[tokio::test]
async fn reads_a_json_url_subject_token_field() {
    let sts = sts().await;
    let provider = Stub::start(|_| Reply::ok(json!({"value": "url-json"}))).await;
    let source = json!({"url": provider.url("/s"), "format": {"type": "json", "subject_token_field_name": "value"}});
    account(source, json!({}), &sts)
        .unwrap()
        .fetch(&Http::default())
        .await
        .unwrap();
    assert_eq!(sts.calls()[0].form()["subject_token"], "url-json");
}

#[tokio::test]
async fn a_failing_subject_url_is_reported_without_its_body() {
    let sts = sts().await;
    let provider = Stub::start(|_| Reply::text(500, "SUBJECT-BODY-MARKER")).await;
    let error = account(json!({"url": provider.url("/s")}), json!({}), &sts)
        .unwrap()
        .fetch(&Http::default())
        .await
        .err()
        .unwrap()
        .to_string();
    assert_eq!(error, "subject token: HTTP 500");
}

#[tokio::test]
async fn client_credentials_use_basic_authentication() {
    let sts = sts().await;
    let subject = temp_file("t");
    let extra = json!({"client_id": "cid", "client_secret": "csecret"});
    account(json!({"file": subject.path()}), extra, &sts)
        .unwrap()
        .fetch(&Http::default())
        .await
        .unwrap();
    // base64("cid:csecret")
    assert_eq!(
        sts.calls()[0].header("authorization"),
        Some("Basic Y2lkOmNzZWNyZXQ=")
    );
}

#[tokio::test]
async fn workforce_pools_send_the_user_project() {
    let sts = sts().await;
    let subject = temp_file("t");
    let extra = json!({"workforce_pool_user_project": "billing-1"});
    account(json!({"file": subject.path()}), extra, &sts)
        .unwrap()
        .fetch(&Http::default())
        .await
        .unwrap();
    let options: Value = serde_json::from_str(&sts.calls()[0].form()["options"]).unwrap();
    assert_eq!(options, json!({"userProject": "billing-1"}));
}

#[tokio::test]
async fn sts_rejection_reports_status_and_code_only() {
    let sts = Stub::start(|_| {
        Reply::json(
            400,
            json!({"error": "invalid_target", "error_description": "The target service indicated by the audience is invalid."}),
        )
    })
    .await;
    let subject = temp_file("t");
    let error = account(json!({"file": subject.path()}), json!({}), &sts)
        .unwrap()
        .fetch(&Http::default())
        .await
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "security token service: HTTP 400: invalid_target"
    );
}

#[tokio::test]
async fn a_response_without_a_lifetime_is_invalid() {
    let sts = Stub::start(|_| Reply::ok(json!({"access_token": "t"}))).await;
    let subject = temp_file("t");
    let error = account(json!({"file": subject.path()}), json!({}), &sts)
        .unwrap()
        .fetch(&Http::default())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("invalid expires_in"), "{error}");
}

#[tokio::test]
async fn an_unreadable_subject_file_is_an_error() {
    let sts = sts().await;
    let error = account(json!({"file": "/nonexistent/subject"}), json!({}), &sts)
        .unwrap()
        .fetch(&Http::default())
        .await
        .err()
        .unwrap();
    assert!(
        error.to_string().starts_with("subject token: cannot open"),
        "{error}"
    );
}

#[tokio::test]
async fn unsupported_credential_sources_are_rejected_at_build_time() {
    let sts = sts().await;
    for (source, kind) in [
        (
            json!({"environment_id": "aws1", "regional_cred_verification_url": "x"}),
            "aws",
        ),
        (json!({"executable": {"command": "x"}}), "executable"),
        (
            json!({"certificate": {"use_default_certificate_config": true}}),
            "certificate",
        ),
    ] {
        let error = account(source, json!({}), &sts).err().unwrap();
        assert_eq!(error, format!("unsupported credential_source: {kind}"));
    }
    assert_eq!(
        account(json!({}), json!({}), &sts).err().unwrap(),
        "unable to parse credential_source"
    );
}

#[tokio::test]
async fn required_fields_and_formats_are_validated() {
    let sts = sts().await;
    let source = json!({"file": "/x"});
    for field in ["audience", "subject_token_type", "credential_source"] {
        let mut file = json!({
            "audience": "a", "subject_token_type": "t", "credential_source": source,
        });
        file.as_object_mut().unwrap().remove(field);
        let file: File = serde_json::from_value(file).unwrap();
        let error = ExternalAccount::from_file(file, &DNS_SCOPES)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains(field), "{error}");
    }
    for format in [json!({"type": "xml"}), json!({"type": "json"}), json!({})] {
        let source = json!({"file": "/x", "format": format});
        assert!(account(source, json!({}), &sts).is_err());
    }
}

#[tokio::test]
async fn debug_hides_headers_and_client_secrets() {
    let sts = sts().await;
    let source =
        json!({"url": "http://127.0.0.1:1/s", "headers": {"authorization": "HEADER-MARKER"}});
    let extra = json!({"client_id": "cid", "client_secret": "SECRET-MARKER"});
    let text = format!("{:?}", account(source, extra, &sts).unwrap());
    assert!(!text.contains("MARKER"), "{text}");
}

#[tokio::test]
async fn debug_hides_source_and_token_endpoint_urls() {
    let sts = sts().await;
    let source = json!({"url": "http://127.0.0.1:1/s?sig=URL-MARKER"});
    let extra = json!({"token_url": "http://127.0.0.1:1/sts?key=STS-MARKER"});
    let text = format!("{:?}", account(source, extra, &sts).unwrap());
    assert!(!text.contains("MARKER"), "{text}");
}

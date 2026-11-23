use std::time::{SystemTime, UNIX_EPOCH};

use super::{File, ServiceAccount};
use crate::clouddns::{
    auth::{
        DNS_SCOPES, Provider,
        testing::{rsa_key, service_account_file, token_response, verify_jwt},
    },
    http::Http,
    stub::{Reply, Stub},
};

fn account(file: serde_json::Value) -> Result<ServiceAccount, String> {
    let file: File = serde_json::from_value(file).unwrap();
    ServiceAccount::from_file(file, &DNS_SCOPES).map_err(|error| error.to_string())
}

#[tokio::test]
async fn posts_a_signed_jwt_bearer_grant() {
    let stub = Stub::start(|call| {
        let form = call.form();
        assert_eq!(
            form["grant_type"],
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        );
        assert_eq!(
            call.header("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        let _ = verify_jwt(&form["assertion"], &rsa_key().public);
        Reply::ok(token_response("ya29.fresh", 3600))
    })
    .await;
    let token_uri = stub.url("/token");
    let source = account(service_account_file(&token_uri)).unwrap();

    let fetched = source.fetch(&Http::default()).await.unwrap();

    assert_eq!(fetched.token.expose(), "ya29.fresh");
    assert_eq!(fetched.lifetime.unwrap().as_secs(), 3600);
    let call = &stub.calls()[0];
    assert_eq!((call.method.as_str(), call.path()), ("POST", "/token"));
    let (header, claims) = verify_jwt(&call.form()["assertion"], &rsa_key().public);
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");
    assert_eq!(header["kid"], "key-id-1");
    assert_eq!(claims["iss"], "robot@p.iam.gserviceaccount.com");
    assert_eq!(claims["aud"], token_uri);
    assert_eq!(claims["scope"], DNS_SCOPES.join(" "));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let issued = claims["iat"].as_u64().unwrap();
    assert!(
        issued + 10 >= now - 2 && issued + 10 <= now + 2,
        "iat {issued} now {now}"
    );
    assert_eq!(claims["exp"].as_u64().unwrap() - issued, 3600);
}

#[tokio::test]
async fn token_endpoint_rejection_reports_status_and_code_only() {
    let stub = Stub::start(|_| {
        Reply::json(
            400,
            serde_json::json!({"error": "invalid_grant", "error_description": "Invalid JWT Signature."}),
        )
    })
    .await;
    let source = account(service_account_file(&stub.url("/token"))).unwrap();
    let error = source.fetch(&Http::default()).await.err().unwrap();
    assert_eq!(
        error.to_string(),
        "service account token request: HTTP 400: invalid_grant"
    );
}

#[tokio::test]
async fn malformed_token_response_is_an_error() {
    let stub = Stub::start(|_| Reply::text(200, "<html>")).await;
    let source = account(service_account_file(&stub.url("/token"))).unwrap();
    assert!(source.fetch(&Http::default()).await.is_err());
}

#[test]
fn missing_or_invalid_fields_are_rejected() {
    let mut file = service_account_file("http://t/");
    file.as_object_mut().unwrap().remove("private_key");
    assert!(account(file).unwrap_err().contains("private_key"));

    let mut file = service_account_file("http://t/");
    file.as_object_mut().unwrap().remove("client_email");
    assert!(account(file).unwrap_err().contains("client_email"));

    let mut file = service_account_file("http://t/");
    file["private_key"] = "not a pem SECRET-KEY-MARKER".into();
    let error = account(file).unwrap_err();
    assert!(error.contains("not a valid RSA key"));
    assert!(!error.contains("SECRET-KEY-MARKER"));
}

#[test]
fn an_absent_token_uri_is_googles() {
    let mut file = service_account_file("");
    file.as_object_mut().unwrap().remove("token_uri");
    let source = account(file).unwrap();
    assert!(
        format!("{:?}", Provider::ServiceAccount(source))
            .contains("https://oauth2.googleapis.com/token")
    );
}

#[test]
fn debug_hides_the_private_key() {
    let source = account(service_account_file("http://t/")).unwrap();
    let text = format!("{source:?}");
    let body = rsa_key().pem.lines().nth(1).unwrap();
    assert!(!text.contains(&body[..32]), "{text}");
    assert!(text.contains("robot@p.iam.gserviceaccount.com"));
}

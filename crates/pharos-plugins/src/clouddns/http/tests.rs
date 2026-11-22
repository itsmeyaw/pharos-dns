use std::{io, time::Duration};

use tokio::net::TcpListener;

use super::{Http, Request, Url, form_encode, path_segment};
use crate::clouddns::stub::{Reply, Stub};

#[tokio::test]
async fn get_sends_host_agent_and_custom_headers() {
    let stub = Stub::start(|_| Reply::text(200, "hello")).await;
    let request = Request::get(&stub.url("/a/b?x=1"))
        .header("x-custom", "v")
        .unwrap();
    let response = Http::default().send(request).await.unwrap();
    assert_eq!(
        (response.status, response.body.as_slice()),
        (200, &b"hello"[..])
    );
    let call = &stub.calls()[0];
    assert_eq!(
        (call.method.as_str(), call.target.as_str()),
        ("GET", "/a/b?x=1")
    );
    assert_eq!(call.header("host"), Some(stub.addr.to_string().as_str()));
    assert_eq!(call.header("x-custom"), Some("v"));
    assert!(call.header("user-agent").unwrap().starts_with("pharos/"));
}

#[tokio::test]
async fn bearer_is_sent_as_authorization() {
    let stub = Stub::start(|_| Reply::text(200, "")).await;
    let request = Request::get(&stub.url("/")).bearer("tok").unwrap();
    Http::default().send(request).await.unwrap();
    assert_eq!(stub.calls()[0].header("authorization"), Some("Bearer tok"));
}

#[tokio::test]
async fn post_form_encodes_fields() {
    let stub = Stub::start(|_| Reply::text(200, "")).await;
    let request = Request::post_form(&stub.url("/token"), &[("a b", "c&d="), ("x", "é")]);
    Http::default().send(request).await.unwrap();
    let call = &stub.calls()[0];
    assert_eq!(call.method, "POST");
    assert_eq!(
        call.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(call.body, "a+b=c%26d%3D&x=%C3%A9");
    assert_eq!(call.form()["a b"], "c&d=");
}

#[tokio::test]
async fn post_json_sets_content_type() {
    let stub = Stub::start(|_| Reply::text(200, "")).await;
    let request = Request::post_json(&stub.url("/j"), r#"{"k":1}"#.into());
    Http::default().send(request).await.unwrap();
    let call = &stub.calls()[0];
    assert_eq!(call.header("content-type"), Some("application/json"));
    assert_eq!(call.body, r#"{"k":1}"#);
}

#[tokio::test]
async fn error_status_is_a_response_not_an_error() {
    let stub = Stub::start(|_| Reply::text(500, "boom")).await;
    let response = Http::default()
        .send(Request::get(&stub.url("/")))
        .await
        .unwrap();
    assert_eq!(response.status, 500);
    assert!(!response.is_success());
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let stub = Stub::start(|_| Reply::text(302, "")).await;
    let response = Http::default()
        .send(Request::get(&stub.url("/")))
        .await
        .unwrap();
    assert_eq!(response.status, 302);
    assert_eq!(stub.calls().len(), 1);
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let stub = Stub::start(|_| Reply::text(200, &"x".repeat(100))).await;
    let http = Http::with_limits(99, Duration::from_secs(5));
    let error = http.send(Request::get(&stub.url("/"))).await.unwrap_err();
    assert!(error.to_string().contains("too large"), "{error}");
    let http = Http::with_limits(100, Duration::from_secs(5));
    assert!(http.send(Request::get(&stub.url("/"))).await.is_ok());
}

#[tokio::test]
async fn silent_server_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let http = Http::with_limits(1024, Duration::from_millis(100));
    let error = http.send(Request::get(&url)).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn refused_connection_is_an_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    drop(listener);
    assert!(Http::default().send(Request::get(&url)).await.is_err());
}

#[tokio::test]
async fn bad_url_and_headers_are_rejected_without_echo() {
    let http = Http::default();
    let error = http
        .send(Request::get("ftp://secret-host/"))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(!error.to_string().contains("secret-host"));
    let error = Request::get("http://h/").bearer("SECRET\nX").unwrap_err();
    assert!(!error.to_string().contains("SECRET"));
}

#[test]
fn debug_hides_credentials_and_bodies() {
    let request = Request::get("http://h/").bearer("TOKEN-MARKER").unwrap();
    assert!(!format!("{request:?}").contains("TOKEN-MARKER"));
    let response = super::Response {
        status: 200,
        body: b"TOKEN-MARKER".to_vec(),
    };
    assert!(!format!("{response:?}").contains("TOKEN-MARKER"));
}

#[test]
fn form_encoding_escapes_reserved_characters() {
    assert_eq!(
        form_encode(&[("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")]),
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
    );
    assert_eq!(form_encode(&[("a", "~-._ ")]), "a=~-._+");
}

#[test]
fn path_segments_escape_slash_and_keep_colon() {
    assert_eq!(
        path_segment("example.com:my-project"),
        "example.com:my-project"
    );
    assert_eq!(path_segment("a/b c%"), "a%2Fb%20c%25");
}

#[test]
fn parses_scheme_host_port_and_target() {
    let url: Url = "https://dns.googleapis.com/dns/v1".parse().unwrap();
    assert_eq!(
        url,
        Url {
            https: true,
            host: "dns.googleapis.com".into(),
            port: 443,
            target: "/dns/v1".into()
        }
    );
    let url: Url = "http://[::1]:14000?x=1".parse().unwrap();
    assert_eq!((url.host.as_str(), url.port), ("::1", 14000));
    assert_eq!(url.target, "/?x=1");
    assert_eq!(url.authority(), "[::1]:14000");
}

#[test]
fn rejects_other_schemes_and_malformed_authorities() {
    for url in [
        "ftp://h",
        "https://",
        "https://u@h",
        "https://h:0",
        "https://h:x",
        "https://[::1",
        "h",
    ] {
        assert!(url.parse::<Url>().is_err(), "{url}");
    }
}

use std::time::Duration;

use pharos_server::tls::{ClientOptions, client_config};
use tokio::net::TcpListener;

use super::*;
use crate::nomad::stub::{FIXTURES, Reply, Stub};

const EXAMPLE: &str =
    r#"[{"Address":"1.2.3.4","Namespace":"default","Port":23202,"ServiceName":"example"}]"#;

fn client(addresses: &[&str]) -> Client {
    let addresses: Vec<String> = addresses
        .iter()
        .map(|address| (*address).to_owned())
        .collect();
    Client::new(&addresses, Options::default()).unwrap()
}

async fn get(client: &Client, service: &str) -> Result<Vec<Registration>, Error> {
    client
        .registrations(service.as_bytes(), b"default", "")
        .await
}

fn get_port(address: &str) -> u16 {
    address.rsplit(':').next().unwrap().parse().unwrap()
}

// Hashicorp nomad api v1.10.5 api/services.go Get: path-escaped name, sorted and encoded params, token and basic-auth headers.
#[tokio::test]
async fn request_line_and_headers() {
    let stub = Stub::default();
    let address = stub.tcp(|_| Reply::ok(EXAMPLE)).await;
    let client = Client::new(
        std::slice::from_ref(&address),
        Options {
            token: Some("s3cret".to_owned()),
            region: Some("eu west".to_owned()),
            basic_auth: Some("Aladdin:open sesame".to_owned()),
            ..Options::default()
        },
    )
    .unwrap();
    client
        .registrations(b"a b", b"ns/1", "Tags not contains x")
        .await
        .unwrap();
    let head = stub.heads.lock().unwrap()[0].to_lowercase();
    assert!(
        head.starts_with("get /v1/service/a%20b?filter=tags+not+contains+x&namespace=ns%2f1&region=eu+west http/1.1\r\n"),
        "{head}"
    );
    assert!(head.contains("\r\nx-nomad-token: s3cret\r\n"), "{head}");
    // RFC 7617 §2: the example credentials from the RFC.
    assert!(
        head.contains("\r\nauthorization: basic qwxhzgrpbjpvcgvuihnlc2ftzq==\r\n"),
        "{head}"
    );
    assert!(
        head.contains(&format!(
            "\r\nhost: {}\r\n",
            address.trim_start_matches("http://")
        )),
        "{head}"
    );
}

#[tokio::test]
async fn no_filter_and_region_means_one_param() {
    let stub = Stub::default();
    let address = stub.tcp(|_| Reply::ok("[]")).await;
    get(&client(&[&address]), "example").await.unwrap();
    assert!(
        stub.heads.lock().unwrap()[0]
            .starts_with("GET /v1/service/example?namespace=default HTTP/1.1\r\n")
    );
}

#[tokio::test]
async fn decodes_registrations_and_null() {
    let stub = Stub::default();
    let address = stub
        .tcp(|head| {
            Reply::ok(if head.contains("/null") {
                "null"
            } else {
                EXAMPLE
            })
        })
        .await;
    let client = client(&[&address]);
    let found = get(&client, "example").await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].port, 23202);
    assert!(get(&client, "null").await.unwrap().is_empty());
}

#[tokio::test]
async fn idle_connection_is_reused() {
    let stub = Stub::default();
    let address = stub.tcp(|_| Reply::ok("[]")).await;
    let client = client(&[&address]);
    for _ in 0..3 {
        get(&client, "example").await.unwrap();
    }
    assert_eq!(stub.connections.load(Ordering::SeqCst), 1);
    assert_eq!(stub.heads.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn a_connection_closed_by_the_peer_is_replaced() {
    let stub = Stub::default();
    let address = stub
        .tcp(|_| Reply {
            close: true,
            ..Reply::ok("[]")
        })
        .await;
    let client = client(&[&address]);
    for _ in 0..3 {
        get(&client, "example").await.unwrap();
    }
    assert_eq!(stub.connections.load(Ordering::SeqCst), 3);
}

// Hashicorp nomad api v1.10.5 api/api.go requireOK: anything but 200 is an error.
#[tokio::test]
async fn non_200_is_an_error() {
    let stub = Stub::default();
    let address = stub
        .tcp(|_| Reply {
            status: 403,
            ..Reply::ok("Permission denied")
        })
        .await;
    let error = get(&client(&[&address]), "example").await.unwrap_err();
    assert!(matches!(error, Error::Status(403)), "{error}");
}

#[tokio::test]
async fn an_empty_or_malformed_body_is_an_error() {
    let stub = Stub::default();
    let address = stub
        .tcp(|head| Reply::ok(if head.contains("/empty") { "" } else { "{" }))
        .await;
    let client = client(&[&address]);
    for service in ["empty", "bad"] {
        let error = get(&client, service).await.unwrap_err();
        assert!(matches!(error, Error::Decode(_)), "{error}");
    }
}

#[tokio::test]
async fn an_oversized_body_is_refused() {
    let stub = Stub::default();
    let address = stub.tcp(|_| Reply::ok(EXAMPLE)).await;
    let mut client = client(&[&address]);
    client.max_body = EXAMPLE.len() - 1;
    assert!(matches!(
        get(&client, "example").await,
        Err(Error::TooLarge)
    ));
    client.max_body = EXAMPLE.len();
    assert!(get(&client, "example").await.is_ok());
}

#[tokio::test]
async fn a_silent_endpoint_times_out() {
    let stub = Stub::default();
    let address = stub
        .tcp(|_| Reply {
            stall: true,
            ..Reply::ok("")
        })
        .await;
    let mut client = client(&[&address]);
    client.timeout = Duration::from_millis(100);
    assert!(matches!(get(&client, "example").await, Err(Error::Timeout)));
}

// Port of plugin/nomad/nomad_test.go TestNomad: fail over from a dead server and remember the live one.
#[tokio::test]
async fn failover_remembers_the_endpoint_that_answered() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_address = format!("http://{}", dead.local_addr().unwrap());
    drop(dead);
    let first = Stub::default();
    let second = Stub::default();
    let one = first.tcp(|_| Reply::ok(EXAMPLE)).await;
    let two = second.tcp(|_| Reply::ok(EXAMPLE)).await;
    let client = client(&[&dead_address, &one, &two]);
    get(&client, "example").await.unwrap();
    assert_eq!(client.current.load(Ordering::Relaxed), 1);
    // The next lookup starts at the live endpoint.
    get(&client, "example").await.unwrap();
    assert_eq!(first.heads.lock().unwrap().len(), 2);
    assert!(second.heads.lock().unwrap().is_empty());
    // A bare 5xx fails over too.
    let broken = Stub::default();
    let broken_address = broken
        .tcp(|_| Reply {
            status: 500,
            ..Reply::ok("")
        })
        .await;
    let client = self::client(&[&broken_address, &two]);
    get(&client, "example").await.unwrap();
    assert_eq!(client.current.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn every_endpoint_failing_returns_the_last_error() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", dead.local_addr().unwrap());
    drop(dead);
    let client = client(&[&address, &address]);
    assert!(matches!(get(&client, "example").await, Err(Error::Io(_))));
}

#[tokio::test]
async fn unix_socket_endpoint() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nomad.sock");
    let stub = Stub::default();
    stub.unix(&path, |_| Reply::ok(EXAMPLE)).await;
    let client = client(&[&format!("unix://{}", path.display())]);
    assert_eq!(get(&client, "example").await.unwrap().len(), 1);
    // Hashicorp nomad api v1.10.5 api/api.go newRequest: a unix address sends `Host: 127.0.0.1`.
    assert!(stub.heads.lock().unwrap()[0].contains("\r\nhost: 127.0.0.1\r\n"));
}

#[tokio::test]
async fn https_verifies_the_server_certificate() {
    let stub = Stub::default();
    let address = stub.tls(|_| Reply::ok(EXAMPLE)).await;
    let trusted = client_config(&ClientOptions {
        ca: Some(format!("{FIXTURES}/ca.pem").into()),
        identity: None,
    })
    .unwrap();
    let client = Client::new(
        std::slice::from_ref(&address),
        Options {
            tls: Some(trusted),
            ..Options::default()
        },
    )
    .unwrap();
    assert_eq!(get(&client, "example").await.unwrap().len(), 1);
    let untrusted = client_config(&ClientOptions {
        ca: Some(format!("{FIXTURES}/other-ca.pem").into()),
        identity: None,
    })
    .unwrap();
    let client = Client::new(
        &[address],
        Options {
            tls: Some(untrusted),
            ..Options::default()
        },
    )
    .unwrap();
    assert!(get(&client, "example").await.is_err());
    // NOMAD_TLS_SERVER_NAME overrides the name checked: the fixture does not cover this one.
    let trusted = client_config(&ClientOptions {
        ca: Some(format!("{FIXTURES}/ca.pem").into()),
        identity: None,
    })
    .unwrap();
    let client = Client::new(
        &[format!(
            "https://127.0.0.1:{}",
            get_port(&stub.tls(|_| Reply::ok(EXAMPLE)).await)
        )],
        Options {
            tls: Some(trusted),
            tls_server_name: Some("wrong.example".to_owned()),
            ..Options::default()
        },
    )
    .unwrap();
    assert!(get(&client, "example").await.is_err());
}

#[test]
fn addresses_parse() {
    let cases = [
        ("http://127.0.0.1:4646", "127.0.0.1:4646"),
        ("https://nomad.example", "nomad.example"),
        ("http://[::1]:4646/", "[::1]:4646"),
        ("unix:///run/nomad.sock", "127.0.0.1"),
    ];
    for (address, host) in cases {
        assert_eq!(Endpoint::parse(address).unwrap().host, host, "{address}");
    }
    let Transport::Tcp { host, port, tls } = Endpoint::parse("https://[::1]").unwrap().transport
    else {
        panic!("tcp")
    };
    assert_eq!((host.as_str(), port, tls), ("::1", 443, true));
    for bad in [
        "127.0.0.1:4646",
        "ftp://x",
        "http://",
        "http://:80",
        "http://h:0",
        "http://h:",
        "http://h:99999",
        "http://u:p@h",
        "http://h/path",
        "http://h?x=1",
        "http://[::1",
        "unix://relative",
    ] {
        assert!(Endpoint::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn credentials_in_an_address_are_not_echoed() {
    let error = Client::new(&["http://u:hunter2@h".to_owned()], Options::default()).unwrap_err();
    assert!(!error.contains("hunter2"), "{error}");
}

#[test]
fn debug_hides_credentials() {
    let client = Client::new(
        &["http://h".to_owned()],
        Options {
            token: Some("s3cret".to_owned()),
            basic_auth: Some("u:hunter2".to_owned()),
            ..Options::default()
        },
    )
    .unwrap();
    let text = format!("{client:?}");
    assert!(
        !text.contains("s3cret") && !text.contains("hunter2"),
        "{text}"
    );
}

#[test]
fn credentials_must_fit_an_http_header() {
    let error = Client::new(
        &["http://h".to_owned()],
        Options {
            token: Some("bad\nvalue".to_owned()),
            ..Options::default()
        },
    )
    .unwrap_err();
    assert!(error.contains("token") && !error.contains("bad"), "{error}");
}

#[test]
fn https_needs_a_tls_configuration() {
    assert!(Client::new(&["https://h".to_owned()], Options::default()).is_err());
}

// RFC 4648 §10: the test vectors.
#[test]
fn base64_vectors() {
    for (plain, encoded) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64(plain.as_bytes()), encoded);
    }
}

fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |name| {
        pairs
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| (*value).to_owned())
    }
}

// Hashicorp nomad api v1.10.5 api/api.go DefaultConfig: the environment fills in, the Corefile token wins.
#[test]
fn options_come_from_the_environment() {
    let pairs = [
        ("NOMAD_TOKEN", "from-env"),
        ("NOMAD_REGION", "eu"),
        ("NOMAD_HTTP_AUTH", "u:p"),
        ("NOMAD_TLS_SERVER_NAME", ""),
    ];
    let options = Options::from_env(&env(&pairs), None, false).unwrap();
    assert_eq!(options.token.as_deref(), Some("from-env"));
    assert_eq!(options.region.as_deref(), Some("eu"));
    assert_eq!(options.basic_auth.as_deref(), Some("u:p"));
    assert_eq!(options.tls_server_name, None);
    let options = Options::from_env(&env(&pairs), Some("corefile".to_owned()), false).unwrap();
    assert_eq!(options.token.as_deref(), Some("corefile"));
}

#[test]
fn unsupported_and_lopsided_tls_environment_is_refused() {
    for pairs in [
        &[("NOMAD_SKIP_VERIFY", "true")][..],
        &[("NOMAD_CAPATH", "/etc/ca")][..],
    ] {
        let error = Options::from_env(&env(pairs), None, false).unwrap_err();
        assert!(error.contains("not supported"), "{error}");
    }
    let error = Options::from_env(&env(&[("NOMAD_CLIENT_CERT", "/c")]), None, true).unwrap_err();
    assert!(error.contains("NOMAD_CLIENT_KEY"), "{error}");
    let error =
        Options::from_env(&env(&[("NOMAD_CACERT", "/nonexistent.pem")]), None, true).unwrap_err();
    assert!(!error.is_empty());
}

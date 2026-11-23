use std::{net::SocketAddr, path::PathBuf, time::Duration};

use super::*;
use crate::etcd::{
    Endpoint,
    etcd_stub::{self, EtcdStub, Mode},
};
use pharos_server::tls::ClientOptions;

fn endpoint(address: SocketAddr, tls: bool) -> Endpoint {
    Endpoint {
        text: address.to_string(),
        host: address.ip().to_string(),
        port: address.port(),
        tls,
    }
}

fn config(endpoints: Vec<Endpoint>) -> Config {
    Config {
        zones: Vec::new(),
        fallthrough: Vec::new(),
        path_prefix: "skydns".into(),
        endpoints,
        tls: None,
        credentials: None,
        min_lease_ttl: 0,
        max_lease_ttl: 0,
        no_apex_fallback: false,
    }
}

fn credentials(user: &str, password: &str) -> Option<Credentials> {
    Some(Credentials {
        username: user.into(),
        password: password.into(),
    })
}

/// Times short enough for a test that waits for them.
fn fast() -> Timeouts {
    Timeouts {
        call: Duration::from_millis(800),
        backoff: Duration::from_millis(400),
    }
}

fn plain(stub: &EtcdStub) -> Client {
    Client::new(&config(vec![endpoint(stub.address, false)]))
}

fn tls_config(ca: &str) -> Arc<ClientConfig> {
    let config = client_config(&ClientOptions {
        ca: Some(PathBuf::from(format!("{}/{ca}", etcd_stub::FIXTURES))),
        identity: None,
    })
    .unwrap();
    let mut config = (*config).clone();
    config.alpn_protocols = grpc::ALPN.iter().map(|alpn| alpn.to_vec()).collect();
    Arc::new(config)
}

// etcd v3 rpc.proto RangeRequest: with no `range_end` only the key is read.
#[tokio::test]
async fn range_reads_one_key() {
    let stub = EtcdStub::start().await;
    let revision = stub.put("/skydns/a", r#"{"host":"1.2.3.4"}"#);
    let latest = stub.put("/skydns/b", "other");
    let reply = plain(&stub).range(b"/skydns/a", false).await.unwrap();
    assert_eq!(reply.count, 1);
    assert_eq!(reply.kvs[0].key, b"/skydns/a");
    assert_eq!(reply.kvs[0].value, br#"{"host":"1.2.3.4"}"#);
    assert_eq!(reply.kvs[0].mod_revision, revision);
    // etcd v3 rpc.proto ResponseHeader: the revision of the store when the request was applied.
    assert_eq!(reply.revision, latest);
}

// etcd clientv3 op.go getPrefix: the range ends at the key plus one, so `/a/` does not reach `/ab/`.
#[tokio::test]
async fn range_with_prefix_reads_every_key_under_it_in_order() {
    let stub = EtcdStub::start().await;
    for key in ["/a/y", "/a/x", "/ab/z", "/a"] {
        stub.put(key, "v");
    }
    let reply = plain(&stub).range(b"/a/", true).await.unwrap();
    let keys: Vec<_> = reply.kvs.iter().map(|kv| kv.key.clone()).collect();
    assert_eq!(keys, [b"/a/x".to_vec(), b"/a/y".to_vec()]);
    assert_eq!(reply.count, 2);
}

#[tokio::test]
async fn range_of_nothing_has_count_zero() {
    let stub = EtcdStub::start().await;
    let reply = plain(&stub).range(b"/none", false).await.unwrap();
    assert_eq!((reply.count, reply.kvs.len()), (0, 0));
}

// etcd v3 rpc.proto KeyValue: the lease a key is attached to travels with it.
#[tokio::test]
async fn range_carries_the_lease() {
    let stub = EtcdStub::start().await;
    stub.put_lease("/k", "v", 77);
    assert_eq!(
        plain(&stub).range(b"/k", false).await.unwrap().kvs[0].lease,
        77
    );
}

// etcd v3 rpc.proto LeaseTimeToLiveResponse: the remaining seconds, -1 for a lease that is gone.
#[tokio::test]
async fn lease_ttl_is_the_remaining_time_or_minus_one() {
    let stub = EtcdStub::start().await;
    stub.set_lease(7, 42);
    let client = plain(&stub);
    assert_eq!(client.lease_ttl(7).await.unwrap(), 42);
    assert_eq!(client.lease_ttl(8).await.unwrap(), -1);
    stub.expire_lease(7);
    assert_eq!(client.lease_ttl(7).await.unwrap(), -1);
}

// PROTOCOL-HTTP2 "Request-Headers": a gRPC content-type, `te: trailers` and the deadline.
#[tokio::test]
async fn a_call_names_a_deadline_and_the_content_type() {
    let stub = EtcdStub::start().await;
    plain(&stub).range(b"/k", false).await.unwrap();
    let seen = &stub.seen("Range")[0].headers;
    assert_eq!(seen["content-type"], "application/grpc");
    assert_eq!(seen["te"], "trailers");
    // CoreDNS v1.15.0 plugin/etcd/etcd.go etcdTimeout: five seconds.
    let timeout = seen["grpc-timeout"].to_str().unwrap();
    let millis: u64 = timeout.strip_suffix('m').unwrap().parse().unwrap();
    assert!((4000..=5000).contains(&millis), "{timeout}");
}

// RFC 9113 §9.1: calls share one connection.
#[tokio::test]
async fn calls_share_a_connection_even_when_they_start_together() {
    let stub = EtcdStub::start().await;
    stub.put("/k", "v");
    let client = plain(&stub);
    let (a, b, c, d) = tokio::join!(
        client.range(b"/k", false),
        client.range(b"/k", false),
        client.range(b"/k", false),
        client.range(b"/k", false),
    );
    for reply in [a, b, c, d] {
        assert_eq!(reply.unwrap().count, 1);
    }
    assert_eq!(stub.accepted(), 1);
}

// grpc-go retries a call transparently when the transport closed before the server saw it.
#[tokio::test]
async fn a_dropped_connection_is_dialled_again() {
    let stub = EtcdStub::start().await;
    stub.put("/k", "v");
    let client = plain(&stub);
    client.range(b"/k", false).await.unwrap();
    stub.drop_connections();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(client.range(b"/k", false).await.unwrap().count, 1);
    assert_eq!(stub.accepted(), 2);
}

// etcd clientv3 auth: `Authenticate` once, then the token goes in every call.
#[tokio::test]
async fn credentials_authenticate_once_and_the_token_is_sent() {
    let stub = EtcdStub::start().await;
    stub.enable_auth("root", "secret");
    stub.put("/k", "v");
    let mut config = config(vec![endpoint(stub.address, false)]);
    config.credentials = credentials("root", "secret");
    let client = Client::new(&config);
    assert_eq!(client.range(b"/k", false).await.unwrap().count, 1);
    assert_eq!(client.range(b"/k", false).await.unwrap().count, 1);
    assert_eq!(stub.calls("Authenticate"), 1);
    assert_eq!(stub.seen("Range")[1].headers["token"], "token-0");
}

#[tokio::test]
async fn a_wrong_password_fails_without_reading() {
    let stub = EtcdStub::start().await;
    stub.enable_auth("root", "secret");
    let mut config = config(vec![endpoint(stub.address, false)]);
    config.credentials = credentials("root", "wrong");
    let error = Client::new(&config).range(b"/k", false).await.unwrap_err();
    assert!(
        matches!(
            error,
            Error::Status {
                code: Code::InvalidArgument,
                ..
            }
        ),
        "{error}"
    );
    assert_eq!(stub.calls("Range"), 0);
}

// etcd clientv3 retry_interceptor.go: an invalid token is replaced once and the call repeated.
#[tokio::test]
async fn an_expired_token_is_replaced_and_the_call_repeated() {
    let stub = EtcdStub::start().await;
    stub.enable_auth("root", "secret");
    stub.put("/k", "v");
    let mut config = config(vec![endpoint(stub.address, false)]);
    config.credentials = credentials("root", "secret");
    let client = Client::new(&config);
    client.range(b"/k", false).await.unwrap();
    stub.expire_tokens();
    assert_eq!(client.range(b"/k", false).await.unwrap().count, 1);
    assert_eq!(stub.calls("Authenticate"), 2);
    assert_eq!(stub.calls("Range"), 3);
}

// etcd clientv3 retry_interceptor.go: one refresh only, so a server that keeps refusing is an error.
#[tokio::test]
async fn a_refused_new_token_is_an_error_not_a_loop() {
    let stub = EtcdStub::start().await;
    stub.enable_auth("root", "secret");
    let mut config = config(vec![endpoint(stub.address, false)]);
    config.credentials = credentials("root", "secret");
    let client = Client::new(&config);
    client.range(b"/k", false).await.unwrap();
    stub.set_mode(Mode::Fail(Code::Unauthenticated));
    let error = client.range(b"/k", false).await.unwrap_err();
    assert!(matches!(
        error,
        Error::Status {
            code: Code::Unauthenticated,
            ..
        }
    ));
    // The first read, the refused one, and its repeat after one new token; no more.
    assert_eq!(stub.calls("Range"), 3);
    assert_eq!(stub.calls("Authenticate"), 2);
}

#[tokio::test]
async fn without_credentials_an_auth_error_is_returned() {
    let stub = EtcdStub::start().await;
    stub.enable_auth("root", "secret");
    let error = plain(&stub).range(b"/k", false).await.unwrap_err();
    assert!(matches!(
        error,
        Error::Status {
            code: Code::Unauthenticated,
            ..
        }
    ));
    assert_eq!(stub.calls("Authenticate"), 0);
}

// RFC 8446 §4.4.3: the server certificate must chain to the configured CA and match the host.
#[tokio::test]
async fn tls_with_the_right_ca_works() {
    let stub = EtcdStub::start_tls().await;
    stub.put("/k", "v");
    let mut config = config(vec![endpoint(stub.address, true)]);
    config.tls = Some(tls_config("ca.pem"));
    assert_eq!(
        Client::new(&config)
            .range(b"/k", false)
            .await
            .unwrap()
            .count,
        1
    );
}

#[tokio::test]
async fn tls_with_another_ca_fails() {
    let stub = EtcdStub::start_tls().await;
    let mut config = config(vec![endpoint(stub.address, true)]);
    config.tls = Some(tls_config("other-ca.pem"));
    let error = Client::with_timeouts(&config, fast())
        .range(b"/k", false)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Unavailable(_)), "{error}");
    assert_eq!(stub.calls("Range"), 0);
}

// RFC 7301 §3.1: an endpoint that needs TLS and a server that speaks none cannot talk.
#[tokio::test]
async fn a_tls_endpoint_on_a_plain_server_fails() {
    let stub = EtcdStub::start().await;
    let mut config = config(vec![endpoint(stub.address, true)]);
    config.tls = Some(tls_config("ca.pem"));
    let error = Client::with_timeouts(&config, fast())
        .range(b"/k", false)
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::Unavailable(_) | Error::Timeout),
        "{error}"
    );
}

// etcd clientv3 balancer: a call moves to the next endpoint when one cannot be reached.
#[tokio::test]
async fn a_refused_endpoint_fails_over_to_the_next() {
    let good = EtcdStub::start().await;
    good.put("/k", "v");
    let dead = etcd_stub::refused_address().await;
    let client = Client::with_timeouts(
        &config(vec![endpoint(dead, false), endpoint(good.address, false)]),
        fast(),
    );
    assert_eq!(client.range(b"/k", false).await.unwrap().count, 1);
    // The next call starts at the endpoint that answered.
    assert_eq!(client.range(b"/k", false).await.unwrap().count, 1);
    assert_eq!(good.calls("Range"), 2);
}

// A hung endpoint gets a share of the time, not all of it, and later calls skip it.
#[tokio::test]
async fn a_hung_endpoint_fails_over_within_its_share_of_the_time() {
    let hung = EtcdStub::start().await;
    hung.set_mode(Mode::Hang);
    let good = EtcdStub::start().await;
    good.put("/k", "v");
    let client = Client::with_timeouts(
        &config(vec![
            endpoint(hung.address, false),
            endpoint(good.address, false),
        ]),
        fast(),
    );
    let started = tokio::time::Instant::now();
    assert_eq!(client.range(b"/k", false).await.unwrap().count, 1);
    assert!(started.elapsed() < fast().call, "{:?}", started.elapsed());
    let started = tokio::time::Instant::now();
    client.range(b"/k", false).await.unwrap();
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(hung.calls("Range"), 1);
}

// etcd clientv3 retry.go: only `Unavailable` moves on; any other status is the answer.
#[tokio::test]
async fn an_unavailable_status_fails_over_and_another_status_does_not() {
    let (first, second) = (EtcdStub::start().await, EtcdStub::start().await);
    second.put("/k", "v");
    let client = Client::with_timeouts(
        &config(vec![
            endpoint(first.address, false),
            endpoint(second.address, false),
        ]),
        fast(),
    );
    first.set_mode(Mode::Fail(Code::Unavailable));
    assert_eq!(client.range(b"/k", false).await.unwrap().count, 1);
    // Back to the first endpoint's turn: the second now answers with a status that ends the call.
    second.set_mode(Mode::Fail(Code::InvalidArgument));
    first.set_mode(Mode::Normal);
    let error = client.range(b"/k", false).await.unwrap_err();
    assert!(matches!(
        error,
        Error::Status {
            code: Code::InvalidArgument,
            ..
        }
    ));
    assert_eq!(first.calls("Range"), 1);
}

#[tokio::test]
async fn a_recovered_endpoint_serves_again() {
    let (first, second) = (EtcdStub::start().await, EtcdStub::start().await);
    first.put("/k", "v");
    second.put("/k", "v");
    let client = Client::with_timeouts(
        &config(vec![
            endpoint(first.address, false),
            endpoint(second.address, false),
        ]),
        fast(),
    );
    first.set_mode(Mode::Fail(Code::Unavailable));
    client.range(b"/k", false).await.unwrap();
    first.set_mode(Mode::Normal);
    second.set_mode(Mode::Fail(Code::Unavailable));
    // `second` is the last good endpoint and now fails, so the call moves on to `first`, which is no longer failing.
    client.range(b"/k", false).await.unwrap();
    assert_eq!((first.calls("Range"), second.calls("Range")), (2, 2));
}

#[tokio::test]
async fn every_endpoint_failing_is_the_last_error() {
    let dead = etcd_stub::refused_address().await;
    let failing = EtcdStub::start().await;
    failing.set_mode(Mode::Fail(Code::Unavailable));
    let client = Client::with_timeouts(
        &config(vec![
            endpoint(dead, false),
            endpoint(failing.address, false),
        ]),
        fast(),
    );
    let error = client.range(b"/k", false).await.unwrap_err();
    assert!(
        matches!(
            error,
            Error::Status {
                code: Code::Unavailable,
                ..
            }
        ),
        "{error}"
    );
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go etcdTimeout: a hung etcd is an error at the deadline, not a wait.
#[tokio::test]
async fn a_hung_cluster_times_out() {
    let stub = EtcdStub::start().await;
    stub.set_mode(Mode::Hang);
    let client = Client::with_timeouts(
        &config(vec![endpoint(stub.address, false)]),
        Timeouts {
            call: Duration::from_millis(300),
            backoff: Duration::from_millis(100),
        },
    );
    let started = tokio::time::Instant::now();
    assert_eq!(
        client.range(b"/k", false).await.unwrap_err(),
        Error::Timeout
    );
    let elapsed = started.elapsed();
    assert!(
        (Duration::from_millis(290)..Duration::from_secs(2)).contains(&elapsed),
        "{elapsed:?}"
    );
}

#[tokio::test]
async fn a_stopped_client_refuses_calls_and_closes_its_connection() {
    let stub = EtcdStub::start().await;
    let client = plain(&stub);
    client.range(b"/k", false).await.unwrap();
    client.stop();
    assert_eq!(
        client.range(b"/k", false).await.unwrap_err(),
        Error::Stopped
    );
    assert_eq!(stub.calls("Range"), 1);
}

// etcd v3 rpc.proto Watch: the first response acknowledges the watcher, then each change is an event.
#[tokio::test]
async fn a_watch_reports_creation_then_changes_under_the_prefix() {
    let stub = EtcdStub::start().await;
    let client = plain(&stub);
    let mut watch = client.watch(b"/a/", true).await.unwrap();
    let ack = watch.next().await.unwrap().unwrap();
    assert!(ack.created && ack.events.is_empty());
    let put = stub.put("/a/x", "1");
    stub.put("/other", "2");
    let event = watch.next().await.unwrap().unwrap();
    assert_eq!(event.events.len(), 1);
    assert_eq!(event.events[0].kind, proto::EventKind::Put);
    assert_eq!(event.events[0].kv.key, b"/a/x");
    assert_eq!(event.events[0].kv.mod_revision, put);
    stub.delete("/a/x");
    let event = watch.next().await.unwrap().unwrap();
    assert_eq!(event.events[0].kind, proto::EventKind::Delete);
    // The write outside the prefix produced no message in between.
    let quiet = tokio::time::timeout(Duration::from_millis(100), watch.next()).await;
    assert!(quiet.is_err());
}

#[tokio::test]
async fn a_watch_ends_with_an_error_when_the_connection_drops() {
    let stub = EtcdStub::start().await;
    let mut watch = plain(&stub).watch(b"/a/", true).await.unwrap();
    watch.next().await.unwrap();
    stub.drop_connections();
    assert!(watch.next().await.is_err());
}

#[tokio::test]
async fn a_watch_that_is_dropped_leaves_no_watcher() {
    let stub = EtcdStub::start().await;
    let client = plain(&stub);
    let mut watch = client.watch(b"/a/", true).await.unwrap();
    watch.next().await.unwrap();
    assert_eq!(stub.watchers(), 1);
    drop(watch);
    for _ in 0..100 {
        if stub.watchers() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the watcher outlived its stream");
}

#[tokio::test]
async fn a_watch_needs_the_token_too() {
    let stub = EtcdStub::start().await;
    stub.enable_auth("root", "secret");
    let mut config = config(vec![endpoint(stub.address, false)]);
    config.credentials = credentials("root", "secret");
    let mut watch = Client::new(&config).watch(b"/a/", true).await.unwrap();
    assert!(watch.next().await.unwrap().unwrap().created);
}

// etcd clientv3 op.go getPrefix.
#[test]
fn prefix_end_increments_the_last_byte() {
    assert_eq!(prefix_end(b"/a/"), b"/a0");
    assert_eq!(prefix_end(&[b'a', 0xff]), b"b");
    assert_eq!(prefix_end(&[0xff, 0xff]), [0]);
    assert_eq!(prefix_end(b""), [0]);
}

#[test]
fn only_the_right_statuses_fail_over_or_refresh_the_token() {
    let status = |code, message: &str| Error::Status {
        code,
        message: message.into(),
    };
    assert!(status(Code::Unavailable, "").fails_over());
    assert!(!status(Code::InvalidArgument, "").fails_over());
    assert!(!Error::Stopped.fails_over());
    assert!(Error::Timeout.fails_over());
    assert!(status(Code::Unauthenticated, "etcdserver: invalid auth token").refreshes_token());
    assert!(
        status(
            Code::InvalidArgument,
            "etcdserver: revision of auth store is old"
        )
        .refreshes_token()
    );
    assert!(!status(Code::InvalidArgument, "other").refreshes_token());
}

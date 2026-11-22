use std::{net::SocketAddr, time::Duration};

use super::*;
use crate::etcd::{
    Endpoint,
    client::Timeouts,
    etcd_stub::{EtcdStub, Mode},
};
use pharos_server::grpc::Code;

const HOST: &str = r#"{"host":"1.2.3.4"}"#;

fn config(address: SocketAddr) -> Config {
    Config {
        zones: Vec::new(),
        fallthrough: Vec::new(),
        path_prefix: "skydns".into(),
        endpoints: vec![Endpoint {
            text: address.to_string(),
            host: address.ip().to_string(),
            port: address.port(),
            tls: false,
        }],
        tls: None,
        credentials: None,
        min_lease_ttl: 0,
        max_lease_ttl: 0,
        no_apex_fallback: false,
    }
}

fn limits() -> Limits {
    Limits {
        reconnect_min: Duration::from_millis(20),
        reconnect_max: Duration::from_millis(100),
        ..Limits::default()
    }
}

fn view_with(stub: &EtcdStub, limits: Limits, timeouts: Timeouts) -> View {
    let config = config(stub.address);
    View::with(&config, Client::with_timeouts(&config, timeouts), limits)
}

fn view(stub: &EtcdStub) -> View {
    view_with(stub, limits(), Timeouts::default())
}

/// A view whose watch is established.
async fn ready(stub: &EtcdStub) -> View {
    let view = view(stub);
    wait_for_health(&view, true).await;
    view
}

async fn wait_for_health(view: &View, healthy: bool) {
    // A Query starts the watch.
    let _ = view.get("/none", false).await;
    for _ in 0..400 {
        if view.is_healthy() == healthy {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the view did not become healthy = {healthy}");
}

fn services(records: &CachedRecords) -> Vec<&Service> {
    records
        .records
        .iter()
        .map(|record| match record {
            Record::Service(service) => service,
            Record::Invalid { key, error } => panic!("{key}: {error}"),
        })
        .collect()
}

/// Poll until `get` of `path` has the answer `expected`, at most for `bound`.
async fn settles(view: &View, path: &str, expected: impl Fn(&Outcome) -> bool, bound: Duration) {
    let started = tokio::time::Instant::now();
    loop {
        let outcome = view.get(path, false).await;
        if expected(&outcome) {
            return;
        }
        assert!(started.elapsed() < bound, "still {outcome:?}");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go get: a read of one key is one Get.
#[tokio::test]
async fn an_exact_read_parses_the_service() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/org/example/www", HOST);
    let records = view(&stub)
        .get("/skydns/org/example/www", false)
        .await
        .unwrap();
    let service = services(&records)[0];
    assert_eq!(service.host, "1.2.3.4");
    assert_eq!(service.key, "/skydns/org/example/www");
    // CoreDNS v1.15.0 plugin/etcd/etcd.go loopNodes: priority 10 and TTL 300 when nothing sets them.
    assert_eq!((service.priority, service.ttl), (10, 300));
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go get: a recursive read lists the keys under `path/`.
#[tokio::test]
async fn a_recursive_read_lists_the_keys_below() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/org/example/a", HOST);
    stub.put("/skydns/org/example/b", HOST);
    stub.put("/skydns/org/example2/c", HOST);
    let records = view(&stub).get("/skydns/org/example", true).await.unwrap();
    let keys: Vec<_> = records.records.iter().map(Record::key).collect();
    assert_eq!(keys, ["/skydns/org/example/a", "/skydns/org/example/b"]);
    assert_eq!(stub.calls("Range"), 1);
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go get: with no keys below, a recursive read gets the key itself.
#[tokio::test]
async fn a_recursive_read_falls_back_to_the_key_itself() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/org/example/www", HOST);
    let records = view(&stub)
        .get("/skydns/org/example/www", true)
        .await
        .unwrap();
    assert_eq!(records.records.len(), 1);
    assert_eq!(stub.calls("Range"), 2);
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go get: a trailing slash of the path is dropped for the key itself.
#[tokio::test]
async fn a_recursive_read_of_a_path_with_a_slash_falls_back_without_it() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/org/example", HOST);
    let records = view(&stub).get("/skydns/org/example/", true).await.unwrap();
    assert_eq!(records.records[0].key(), "/skydns/org/example");
}

#[tokio::test]
async fn nothing_found_is_key_not_found() {
    let stub = EtcdStub::start().await;
    let view = view(&stub);
    assert_eq!(
        view.get("/skydns/none", false).await.unwrap_err(),
        Error::KeyNotFound
    );
    assert_eq!(
        view.get("/skydns/none", true).await.unwrap_err(),
        Error::KeyNotFound
    );
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go loopNodes: a value that is not a service is an error, but only for the key that holds it.
#[tokio::test]
async fn an_invalid_value_is_a_record_of_its_own() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/org/example/a", HOST);
    stub.put("/skydns/org/example/b", "{not json");
    let records = view(&stub).get("/skydns/org/example", true).await.unwrap();
    assert!(matches!(&records.records[0], Record::Service(_)));
    match &records.records[1] {
        Record::Invalid { key, error } => {
            assert_eq!(key, "/skydns/org/example/b");
            assert!(error.starts_with("/skydns/org/example/b: "), "{error}");
        }
        other => panic!("{other:?}"),
    }
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go TTL.
#[tokio::test]
async fn a_lease_bounds_the_ttl() {
    let stub = EtcdStub::start().await;
    stub.set_lease(1, 100);
    stub.set_lease(2, 5);
    stub.set_lease(3, 1_000_000);
    stub.put_lease("/skydns/z/a", HOST, 1);
    stub.put_lease("/skydns/z/b", r#"{"host":"h","ttl":20}"#, 1);
    stub.put_lease("/skydns/z/c", HOST, 2);
    stub.put_lease("/skydns/z/d", HOST, 3);
    stub.put_lease("/skydns/z/e", HOST, 9);
    stub.put("/skydns/z/f", r#"{"host":"h","ttl":7}"#);
    let records = view(&stub).get("/skydns/z", true).await.unwrap();
    let ttls: Vec<_> = services(&records).iter().map(|s| s.ttl).collect();
    // lease 100; the service's 20 beats it; lease 5 is raised to 30; 1000000 is cut to 86400; an expired lease is ignored; no lease.
    assert_eq!(ttls, [100, 20, 30, 86_400, 300, 7]);
    // One lookup per lease, not per key.
    assert_eq!(stub.calls("LeaseTimeToLive"), 4);
}

#[test]
fn record_ttl_follows_coredns() {
    // (lease TTL, service TTL, min, max) -> TTL
    let cases = [
        (None, 0, 0, 0, 300),
        (None, 9, 0, 0, 9),
        (Some(-1), 9, 0, 0, 9),
        (Some(0), 0, 0, 0, 300),
        (Some(100), 0, 0, 0, 100),
        (Some(100), 50, 0, 0, 50),
        (Some(40), 50, 0, 0, 40),
        (Some(10), 0, 0, 0, 30),
        (Some(10), 0, 15, 0, 15),
        (Some(1000), 0, 0, 500, 500),
        // CoreDNS v1.15.0 plugin/etcd/etcd.go TTL: `else if` keeps the minimum when it exceeds the maximum.
        (Some(10), 0, 200, 100, 200),
        (Some(150), 0, 200, 100, 200),
        (Some(250), 0, 200, 100, 100),
    ];
    for (lease, service, min, max, expected) in cases {
        assert_eq!(
            record_ttl(lease, service, min, max),
            expected,
            "{lease:?} {service} {min} {max}"
        );
    }
}

// The view serves reads from etcd until the watch is established.
#[tokio::test]
async fn reads_before_the_watch_is_established_go_to_etcd() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/k", HOST);
    let view = view(&stub);
    stub.set_mode(Mode::Hang);
    // The watch hangs on creation, so the view stays unhealthy.
    for _ in 0..3 {
        let _ = tokio::time::timeout(Duration::from_millis(30), view.get("/skydns/k", false)).await;
    }
    assert!(!view.is_healthy());
    assert_eq!(stub.calls("Range"), 3);
    assert!(view.is_empty());
}

#[tokio::test]
async fn a_healthy_view_reads_etcd_once_for_repeated_queries() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/k", HOST);
    let view = ready(&stub).await;
    let before = stub.calls("Range");
    let first = view.get("/skydns/k", false).await.unwrap();
    let second = view.get("/skydns/k", false).await.unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(stub.calls("Range") - before, 1);
}

// A key that does not exist is held too: a name that does not exist is the common Query.
#[tokio::test]
async fn a_missing_key_is_held() {
    let stub = EtcdStub::start().await;
    let view = ready(&stub).await;
    let before = stub.calls("Range");
    for _ in 0..3 {
        assert_eq!(
            view.get("/skydns/gone", false).await.unwrap_err(),
            Error::KeyNotFound
        );
    }
    assert_eq!(stub.calls("Range") - before, 1);
}

// The same path read exactly and recursively are two entries.
#[tokio::test]
async fn exact_and_recursive_reads_are_held_apart() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/k", HOST);
    stub.put("/skydns/k/child", HOST);
    let view = ready(&stub).await;
    assert_eq!(view.get("/skydns/k", false).await.unwrap().records.len(), 1);
    assert_eq!(view.get("/skydns/k", true).await.unwrap().records.len(), 1);
    assert_eq!(view.len(), 2);
}

// etcd v3 rpc.proto Watch: a put or delete under the prefix is an event, and the view forgets.
#[tokio::test]
async fn a_put_or_delete_is_visible_within_a_bound() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/k", HOST);
    let view = ready(&stub).await;
    view.get("/skydns/k", false).await.unwrap();
    stub.put("/skydns/k", r#"{"host":"5.6.7.8"}"#);
    let bound = Duration::from_millis(500);
    settles(
        &view,
        "/skydns/k",
        |outcome| matches!(outcome, Ok(records) if services(records)[0].host == "5.6.7.8"),
        bound,
    )
    .await;
    stub.delete("/skydns/k");
    settles(
        &view,
        "/skydns/k",
        |outcome| matches!(outcome, Err(Error::KeyNotFound)),
        bound,
    )
    .await;
    stub.put("/skydns/k", HOST);
    settles(&view, "/skydns/k", Result::is_ok, bound).await;
}

#[tokio::test]
async fn a_key_that_was_missing_appears() {
    let stub = EtcdStub::start().await;
    let view = ready(&stub).await;
    assert!(view.get("/skydns/new", false).await.is_err());
    stub.put("/skydns/new", HOST);
    settles(
        &view,
        "/skydns/new",
        Result::is_ok,
        Duration::from_millis(500),
    )
    .await;
}

// A recursive entry sees a new child.
#[tokio::test]
async fn a_new_child_joins_a_recursive_entry() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/z/a", HOST);
    let view = ready(&stub).await;
    assert_eq!(view.get("/skydns/z", true).await.unwrap().records.len(), 1);
    stub.put("/skydns/z/b", HOST);
    let started = tokio::time::Instant::now();
    while view.get("/skydns/z", true).await.unwrap().records.len() != 2 {
        assert!(started.elapsed() < Duration::from_millis(500));
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

// A read that is in flight when an event arrives is answered, but is not held: it may predate the write.
#[tokio::test]
async fn a_read_that_races_an_event_is_not_held() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/k", HOST);
    let view = Arc::new(ready(&stub).await);
    stub.delay_range(Duration::from_millis(300));
    let reader = {
        let view = view.clone();
        tokio::spawn(async move { view.get("/skydns/k", false).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    stub.put("/skydns/k", r#"{"host":"5.6.7.8"}"#);
    let old = reader.await.unwrap().unwrap();
    assert_eq!(services(&old)[0].host, "1.2.3.4");
    stub.delay_range(Duration::ZERO);
    assert!(view.is_empty(), "the stale read was held");
    let current = view.get("/skydns/k", false).await.unwrap();
    assert_eq!(services(&current)[0].host, "5.6.7.8");
}

// Concurrent misses of one key make one read.
#[tokio::test]
async fn concurrent_misses_share_one_read() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/k", HOST);
    let view = Arc::new(ready(&stub).await);
    let before = stub.calls("Range");
    stub.delay_range(Duration::from_millis(150));
    let readers: Vec<_> = (0..8)
        .map(|_| {
            let view = view.clone();
            tokio::spawn(async move { view.get("/skydns/k", false).await })
        })
        .collect();
    for reader in readers {
        assert_eq!(reader.await.unwrap().unwrap().records.len(), 1);
    }
    assert_eq!(stub.calls("Range") - before, 1);
    assert!(view.inner.inflight.lock().unwrap().is_empty());
}

// An entry is read again after its maximum age: a lease TTL is sampled when it is filled.
#[tokio::test]
async fn an_entry_expires_after_its_maximum_age() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/k", HOST);
    let view = view_with(
        &stub,
        Limits {
            max_age: Duration::from_millis(150),
            ..limits()
        },
        Timeouts::default(),
    );
    wait_for_health(&view, true).await;
    view.get("/skydns/k", false).await.unwrap();
    let after_fill = stub.calls("Range");
    view.get("/skydns/k", false).await.unwrap();
    assert_eq!(stub.calls("Range"), after_fill);
    tokio::time::sleep(Duration::from_millis(200)).await;
    view.get("/skydns/k", false).await.unwrap();
    assert_eq!(stub.calls("Range"), after_fill + 1);
}

#[tokio::test]
async fn the_view_holds_at_most_its_entries() {
    let stub = EtcdStub::start().await;
    for index in 0..10 {
        stub.put(&format!("/skydns/k{index}"), HOST);
    }
    let view = view_with(
        &stub,
        Limits {
            max_entries: 3,
            ..limits()
        },
        Timeouts::default(),
    );
    wait_for_health(&view, true).await;
    for index in 0..10 {
        view.get(&format!("/skydns/k{index}"), false).await.unwrap();
        assert!(view.len() <= 3, "{} entries", view.len());
    }
    assert!(!view.is_empty());
}

#[tokio::test]
async fn the_view_holds_at_most_its_bytes_and_skips_a_huge_entry() {
    let stub = EtcdStub::start().await;
    let value = format!(r#"{{"host":"{}"}}"#, "h".repeat(200));
    for index in 0..10 {
        stub.put(&format!("/skydns/k{index}"), &value);
    }
    for name in ["a", "b", "c"] {
        stub.put(&format!("/skydns/big/{name}"), &value);
    }
    let view = view_with(
        &stub,
        Limits {
            max_bytes: 1000,
            max_entry_bytes: 400,
            ..limits()
        },
        Timeouts::default(),
    );
    wait_for_health(&view, true).await;
    // Three keys of about 230 bytes are over the 400 an entry may hold: served, not held.
    assert_eq!(
        view.get("/skydns/big", true).await.unwrap().records.len(),
        3
    );
    assert!(view.is_empty());
    for index in 0..10 {
        view.get(&format!("/skydns/k{index}"), false).await.unwrap();
        let cache = view.inner.cache.read().unwrap();
        assert!(cache.bytes <= 1000, "{} bytes", cache.bytes);
    }
}

// The watch is gone: reads go to etcd, so nothing older than a write is served.
#[tokio::test]
async fn a_lost_watch_bypasses_the_view_until_it_is_back() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/k", HOST);
    let view = ready(&stub).await;
    view.get("/skydns/k", false).await.unwrap();
    stub.fail_watch(true);
    stub.drop_connections();
    wait_for_health(&view, false).await;
    assert!(view.is_empty());
    stub.put("/skydns/k", r#"{"host":"5.6.7.8"}"#);
    let before = stub.calls("Range");
    for _ in 0..3 {
        let records = view.get("/skydns/k", false).await.unwrap();
        assert_eq!(services(&records)[0].host, "5.6.7.8");
    }
    assert_eq!(stub.calls("Range") - before, 3);
    assert!(view.is_empty());
    stub.fail_watch(false);
    wait_for_health(&view, true).await;
    let before = stub.calls("Range");
    view.get("/skydns/k", false).await.unwrap();
    view.get("/skydns/k", false).await.unwrap();
    assert_eq!(stub.calls("Range") - before, 1);
}

// A write while the watch is down is seen by the first read after it comes back.
#[tokio::test]
async fn a_write_during_an_outage_is_not_lost() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/k", HOST);
    let view = ready(&stub).await;
    view.get("/skydns/k", false).await.unwrap();
    stub.fail_watch(true);
    stub.drop_connections();
    wait_for_health(&view, false).await;
    stub.put("/skydns/k", r#"{"host":"9.9.9.9"}"#);
    stub.fail_watch(false);
    wait_for_health(&view, true).await;
    let records = view.get("/skydns/k", false).await.unwrap();
    assert_eq!(services(&records)[0].host, "9.9.9.9");
}

// An error is not held, so the next Query tries etcd again.
#[tokio::test]
async fn an_error_is_not_held() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/k", HOST);
    let view = ready(&stub).await;
    stub.set_mode(Mode::Fail(Code::Internal));
    let error = view.get("/skydns/k", false).await.unwrap_err();
    assert!(
        matches!(error, Error::Client(client::Error::Status { .. })),
        "{error}"
    );
    stub.set_mode(Mode::Normal);
    assert!(view.get("/skydns/k", false).await.is_ok());
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go etcdTimeout: a hung etcd is an error after the timeout.
#[tokio::test]
async fn a_hung_etcd_is_a_timeout_error() {
    let stub = EtcdStub::start().await;
    stub.set_mode(Mode::Hang);
    let view = view_with(
        &stub,
        limits(),
        Timeouts {
            call: Duration::from_millis(300),
            backoff: Duration::from_millis(100),
        },
    );
    let started = tokio::time::Instant::now();
    let error = view.get("/skydns/k", false).await.unwrap_err();
    assert_eq!(error, Error::Client(client::Error::Timeout));
    assert!(started.elapsed() >= Duration::from_millis(290));
    assert!(started.elapsed() < Duration::from_secs(2));
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go OnShutdown: closing the client ends the watch.
#[tokio::test]
async fn stop_ends_the_watch_and_refuses_reads() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/k", HOST);
    let view = ready(&stub).await;
    assert_eq!(stub.watchers(), 1);
    view.stop();
    assert!(!view.is_healthy());
    assert_eq!(
        view.get("/skydns/k", false).await.unwrap_err(),
        Error::Client(client::Error::Stopped)
    );
    for _ in 0..100 {
        if stub.watchers() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the watcher outlived the view");
}

// The watch covers the keys under the Directive's path and nothing else.
#[tokio::test]
async fn a_write_outside_the_path_keeps_the_view() {
    let stub = EtcdStub::start().await;
    stub.put("/skydns/k", HOST);
    let view = ready(&stub).await;
    view.get("/skydns/k", false).await.unwrap();
    stub.put("/other/k", "x");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(view.len(), 1);
}

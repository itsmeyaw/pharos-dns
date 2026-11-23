use std::sync::atomic::AtomicBool;

use super::*;
use crate::nomad::{
    client::Options,
    stub::{Reply, Stub},
};

fn health(addresses: &[&str], interval: Duration) -> Arc<Health> {
    let addresses: Vec<String> = addresses.iter().map(|a| (*a).to_owned()).collect();
    let client = Arc::new(Client::new(&addresses, Options::default()).unwrap());
    Health::with_interval(client, interval)
}

async fn wait_for(health: &Health, expected: bool) {
    for _ in 0..500 {
        if health.ready() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("readiness never became {expected}");
}

async fn run(lifecycle: &Lifecycle, phase: Phase) {
    lifecycle.run(phase).await.unwrap();
}

// CoreDNS v1.15.0 plugin/nomad/setup.go getClient: one client is never probed.
#[tokio::test]
async fn a_single_address_is_always_ready() {
    let health = health(&["http://127.0.0.1:1"], Duration::from_secs(1));
    assert!(health.ready());
    let mut lifecycle = Lifecycle::default();
    health.register(&mut lifecycle);
    run(&lifecycle, Phase::Startup).await;
    assert!(health.task.lock().unwrap().is_none());
    assert!(health.ready());
}

// Hook order of the hooks above: Startup returns before any probe finishes.
#[tokio::test]
async fn startup_does_not_wait_for_nomad() {
    let stub = Stub::default();
    let hung = stub
        .tcp(|_| Reply {
            stall: true,
            ..Reply::ok("{}")
        })
        .await;
    let health = health(&[&hung, &hung], Duration::from_secs(1));
    let mut lifecycle = Lifecycle::default();
    health.register(&mut lifecycle);
    tokio::time::timeout(Duration::from_secs(1), run(&lifecycle, Phase::Startup))
        .await
        .expect("Startup must not wait for the probe");
    assert!(!health.ready());
    run(&lifecycle, Phase::Shutdown).await;
}

// CoreDNS v1.15.0 plugin/nomad/ready.go Ready: ready exactly when one address answers `/v1/agent/self`.
#[tokio::test]
async fn several_addresses_are_ready_while_one_answers() {
    let up = Arc::new(AtomicBool::new(true));
    let stub = Stub::default();
    let live = {
        let up = Arc::clone(&up);
        stub.tcp(move |head| {
            assert!(head.starts_with("GET /v1/agent/self "), "{head}");
            if up.load(Ordering::SeqCst) {
                Reply::ok(r#"{"config":{}}"#)
            } else {
                Reply {
                    status: 500,
                    ..Reply::ok("")
                }
            }
        })
        .await
    };
    let dead = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let health = health(&[&dead, &live], Duration::from_millis(20));
    assert!(!health.ready(), "not ready before the first probe");
    let mut lifecycle = Lifecycle::default();
    health.register(&mut lifecycle);
    run(&lifecycle, Phase::Startup).await;
    wait_for(&health, true).await;
    up.store(false, Ordering::SeqCst);
    wait_for(&health, false).await;
    up.store(true, Ordering::SeqCst);
    wait_for(&health, true).await;
}

#[tokio::test]
async fn a_body_that_is_not_json_is_not_an_answer() {
    let stub = Stub::default();
    let garbage = stub.tcp(|_| Reply::ok("<html>")).await;
    let health = health(&[&garbage, &garbage], Duration::from_millis(20));
    let mut lifecycle = Lifecycle::default();
    health.register(&mut lifecycle);
    run(&lifecycle, Phase::Startup).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!health.ready());
    run(&lifecycle, Phase::Shutdown).await;
}

#[tokio::test]
async fn shutdown_stops_the_probe() {
    let stub = Stub::default();
    let live = stub.tcp(|_| Reply::ok("{}")).await;
    let health = health(&[&live, &live], Duration::from_millis(10));
    let mut lifecycle = Lifecycle::default();
    health.register(&mut lifecycle);
    run(&lifecycle, Phase::Startup).await;
    wait_for(&health, true).await;
    run(&lifecycle, Phase::Shutdown).await;
    tokio::task::yield_now().await;
    let seen = stub.heads.lock().unwrap().len();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(stub.heads.lock().unwrap().len(), seen);
    assert!(health.task.lock().unwrap().is_none());
}

// A second Startup (RestartFailed after a failed reload) replaces the old task instead of leaking it.
#[tokio::test]
async fn starting_twice_keeps_one_probe() {
    let stub = Stub::default();
    let live = stub.tcp(|_| Reply::ok("{}")).await;
    let health = health(&[&live, &live], Duration::from_secs(60));
    health.start();
    health.start();
    wait_for(&health, true).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Each task probed once and one endpoint answered; the aborted one may or may not have got that far.
    assert!(stub.heads.lock().unwrap().len() <= 2);
    health.stop();
}

#![forbid(unsafe_code)]

use pharos_server::{http::HealthProbe, metrics::Registry};
use tokio::io::AsyncReadExt;

// Derived from CoreDNS v1.15.0 plugin/health/overloaded_test.go.
#[tokio::test]
async fn cancelling_an_in_flight_probe_does_not_record_a_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let registry = Registry::default();
    registry.enable_health_metrics();
    let probe = HealthProbe::start(
        &listener.local_addr().unwrap().to_string(),
        registry.clone(),
    );
    let (mut stream, _) =
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
    let mut request = [0; 1024];
    assert!(stream.read(&mut request).await.unwrap() > 0);
    drop(probe);
    tokio::task::yield_now().await;
    let mut metrics = String::new();
    registry.encode(&mut metrics);
    assert!(
        metrics.contains("pharos_health_request_duration_seconds_count 0"),
        "{metrics}"
    );
    assert!(
        metrics.contains("pharos_health_request_failures_total 0"),
        "{metrics}"
    );
}

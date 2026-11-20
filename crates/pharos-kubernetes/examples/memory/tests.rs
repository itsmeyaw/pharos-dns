use super::{api_response, endpoint_ready, live_heap_bytes};
use http_body_util::BodyExt;

#[tokio::test]
async fn version_and_discovery_are_valid_kubernetes_responses() {
    for (path, expected) in [
        ("/version", "gitVersion"),
        ("/api", "APIVersions"),
        ("/apis", "APIGroupList"),
        ("/api/v1", "APIResourceList"),
        ("/apis/discovery.k8s.io/v1", "APIResourceList"),
    ] {
        let response = api_response(path, None);
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(&body).unwrap().contains(expected));
    }
    assert_eq!(api_response("/unknown", None).status(), 404);
}

#[tokio::test]
async fn watch_list_contains_resources_and_end_bookmark() {
    let mut body = api_response(
        "/api/v1/services",
        Some("watch=true&sendInitialEvents=true"),
    )
    .into_body();
    let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
    let text = std::str::from_utf8(&frame).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("\"type\":\"ADDED\""))
            .count(),
        10_000
    );
    assert!(text.contains("k8s.io/initial-events-end"));
    let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert_eq!(first["object"]["kind"], "Service");
    assert_eq!(
        last["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"],
        "true"
    );
}

#[tokio::test]
async fn endpoint_list_has_three_addresses_per_service() {
    let response = api_response("/apis/discovery.k8s.io/v1/endpointslices", None);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let slices = list["items"].as_array().unwrap();
    assert_eq!(slices.len(), 10_000);
    assert_eq!(
        slices
            .iter()
            .map(|slice| slice["endpoints"].as_array().unwrap().len())
            .sum::<usize>(),
        30_000
    );
}

#[test]
fn live_heap_does_not_double_count_reallocations() {
    let stats = stats_alloc::Stats {
        bytes_allocated: 200,
        bytes_deallocated: 50,
        bytes_reallocated: -20,
        ..Default::default()
    };
    assert_eq!(live_heap_bytes(stats), 150);
}

#[test]
fn unready_fraction_matches_requested_percentage() {
    for percent in [10, 50] {
        let unready = (0..100)
            .filter(|index| !endpoint_ready(*index, percent))
            .count();
        assert_eq!(unready, percent);
    }
}

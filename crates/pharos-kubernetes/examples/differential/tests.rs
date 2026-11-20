use super::api_response;
use http_body_util::BodyExt;
use serde_json::Value;

#[tokio::test]
async fn fixture_binds_the_requested_port() {
    let port = super::test_support::free_port();
    let listener = super::bind_api(port).await.unwrap();
    assert_eq!(listener.local_addr().unwrap().port(), port);
}

async fn list(path: &str, query: Option<&str>) -> Value {
    let response = api_response(path, query);
    assert_eq!(response.status(), 200);
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

fn names(list: &Value) -> Vec<&str> {
    list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["metadata"]["name"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn multicluster_discovery_and_fixtures_are_available() {
    let imports = list("/apis/multicluster.x-k8s.io/v1alpha1/serviceimports", None).await;
    assert_eq!(names(&imports), ["web", "headless"]);
    let slices = list(
        "/apis/discovery.k8s.io/v1/endpointslices",
        Some("labelSelector=multicluster.kubernetes.io%2Fservice-name"),
    )
    .await;
    assert_eq!(names(&slices), ["mc-web", "mc-headless"]);
    for path in [
        "/apis/multicluster.x-k8s.io",
        "/apis/multicluster.x-k8s.io/v1alpha1",
    ] {
        assert_eq!(api_response(path, None).status(), 200);
    }
}

#[tokio::test]
async fn list_filters_label_field_and_namespaced_paths() {
    let services = "/api/v1/services";
    assert_eq!(
        names(&list(services, Some("labelSelector=app%3Dweb")).await),
        ["web", "test", "hidden"]
    );
    assert_eq!(
        names(
            &list(
                services,
                Some("labelSelector=app%20in%20%28web%2Cdb%29%2Ctier%21%3Dhidden")
            )
            .await
        ),
        ["web", "test", "dual"]
    );
    assert_eq!(
        names(&list(services, Some("labelSelector=%21app")).await),
        ["headless", "alias"]
    );
    assert_eq!(
        names(&list(services, Some("labelSelector=app%20notin%20%28web%29")).await),
        ["dual", "headless", "alias"]
    );
    assert_eq!(
        names(&list("/api/v1/namespaces", Some("labelSelector=team%3Ddns")).await),
        ["default"]
    );
    assert_eq!(
        names(&list("/api/v1/namespaces/other/services", None).await),
        ["hidden"]
    );
    assert_eq!(names(&list("/api/v1/pods", Some("fieldSelector=status.phase%21%3DSucceeded%2Cstatus.phase%21%3DFailed%2Cstatus.phase%21%3DUnknown")).await), ["web-pod", "loopback-pod", "other-pod"]);
    assert_eq!(
        names(
            &list(
                "/api/v1/pods",
                Some("fieldSelector=metadata.namespace%3Ddefault%2Cstatus.podIP%3D10.2.0.5")
            )
            .await
        ),
        ["web-pod"]
    );
    assert_eq!(
        api_response(services, Some("labelSelector=app%20in%20%28")).status(),
        400
    );
    assert_eq!(
        api_response(services, Some("fieldSelector=unsupported%3Dx")).status(),
        400
    );
}

#[tokio::test]
async fn initial_watch_filters_and_ends_with_bookmark() {
    let mut body = api_response(
        "/api/v1/services",
        Some("watch=true&sendInitialEvents=true&labelSelector=app%3Dweb"),
    )
    .into_body();
    let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
    let events: Vec<Value> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0]["object"]["metadata"]["name"], "web");
    assert_eq!(events[1]["object"]["metadata"]["name"], "test");
    assert_eq!(events[2]["object"]["metadata"]["name"], "hidden");
    assert_eq!(events[3]["type"], "BOOKMARK");
    assert_eq!(
        events[3]["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"],
        "true"
    );
}

#[tokio::test]
async fn normal_watch_stays_open_and_does_not_replay() {
    let mut body =
        api_response("/api/v1/services", Some("watch=true&resourceVersion=1")).into_body();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), body.frame())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn endpoint_slice_has_distinct_and_unset_zones() {
    let slices = list("/apis/discovery.k8s.io/v1/endpointslices", None).await;
    let endpoints = slices["items"][0]["endpoints"].as_array().unwrap();
    assert_eq!(endpoints[0]["zone"], "us-west-2a");
    assert_eq!(endpoints[1]["zone"], "corp.example.com");
    assert!(endpoints[2].get("zone").is_none());
    assert!(slices["items"].as_array().unwrap().iter().any(|slice| {
        slice["metadata"]["labels"]["kubernetes.io/service-name"] == "web"
            && slice["endpoints"][0]["conditions"]["ready"] == true
    }));
}

#[tokio::test]
async fn pod_status_includes_both_pod_ip_forms() {
    let pods = list("/api/v1/pods", None).await;
    for pod in pods["items"].as_array().unwrap() {
        assert_eq!(pod["status"]["podIP"], pod["status"]["podIPs"][0]["ip"]);
    }
}

#[test]
fn discovery_and_unknown_paths() {
    for path in [
        "/version",
        "/api",
        "/apis",
        "/api/v1",
        "/apis/discovery.k8s.io/v1",
    ] {
        assert_eq!(api_response(path, None).status(), 200);
    }
    assert_eq!(api_response("/unknown", None).status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_http_server_serves_filtered_lists() {
    use std::io::{Read, Write};

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", super::test_support::free_port()))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = super::api::serve(listener, super::api_path_exists, api_response).await;
    });
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    stream.write_all(b"GET /api/v1/namespaces?labelSelector=team%3Ddns HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(headers.contains("200 OK"));
    let list: Value = serde_json::from_str(body).unwrap();
    assert_eq!(names(&list), ["default"]);

    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(
            b"POST /api/v1/services HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
        "{response}"
    );
    assert!(response.contains("allow: GET, HEAD\r\n"), "{response}");

    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(b"POST /unknown HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "{response}"
    );

    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(
            b"HEAD /api/v1/services HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.ends_with("\r\n\r\n"), "{response}");
    server.abort();
}

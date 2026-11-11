//! Small Kubernetes API used by the differential scenarios.

#![forbid(unsafe_code)]

#[path = "support/api.rs"]
mod api;

use std::{collections::HashMap, convert::Infallible, io::Write as _, path::Path};

use api::{Body, full};
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyExt, StreamBody};
use hyper::{Response, body::Frame};
use serde_json::{Value, json};
use tokio::net::TcpListener;

fn resources(name: &str) -> Option<(&'static str, &'static str, Vec<Value>)> {
    let result = match name {
        "services" => (
            "v1",
            "Service",
            vec![
                json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"web","namespace":"default","resourceVersion":"1","uid":"web","labels":{"app":"web"}},"spec":{"type":"ClusterIP","clusterIP":"10.96.0.10","clusterIPs":["10.96.0.10"],"ports":[{"name":"http","protocol":"TCP","port":80}]}}),
                json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"dual","namespace":"default","resourceVersion":"1","uid":"dual","labels":{"app":"db"}},"spec":{"type":"ClusterIP","clusterIP":"10.96.0.11","clusterIPs":["10.96.0.11","fd00::11"],"ipFamilies":["IPv4","IPv6"],"ports":[{"name":"http","protocol":"TCP","port":80}]}}),
                json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"headless","namespace":"default","resourceVersion":"1","uid":"headless"},"spec":{"type":"ClusterIP","clusterIP":"None","clusterIPs":["None"],"ports":[{"name":"http","protocol":"TCP","port":8080}]}}),
                json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"alias","namespace":"default","resourceVersion":"1","uid":"alias"},"spec":{"type":"ExternalName","externalName":"target.example.test"}}),
                json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"hidden","namespace":"other","resourceVersion":"1","uid":"hidden","labels":{"app":"web","tier":"hidden"}},"spec":{"type":"ClusterIP","clusterIP":"10.96.0.12","clusterIPs":["10.96.0.12"]}}),
            ],
        ),
        "pods" => (
            "v1",
            "Pod",
            vec![
                json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"web-pod","namespace":"default","resourceVersion":"1","uid":"web-pod","labels":{"app":"web"}},"spec":{"containers":[]},"status":{"phase":"Running","podIP":"10.2.0.5","podIPs":[{"ip":"10.2.0.5"}]}}),
                json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"other-pod","namespace":"other","resourceVersion":"1","uid":"other-pod","labels":{"app":"web"}},"spec":{"containers":[]},"status":{"phase":"Running","podIP":"10.2.0.6","podIPs":[{"ip":"10.2.0.6"}]}}),
                json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"finished","namespace":"default","resourceVersion":"1","uid":"finished","labels":{"app":"web"}},"spec":{"containers":[]},"status":{"phase":"Succeeded","podIP":"10.2.0.7","podIPs":[{"ip":"10.2.0.7"}]}}),
            ],
        ),
        "namespaces" => (
            "v1",
            "Namespace",
            vec![
                json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"default","resourceVersion":"1","uid":"default","labels":{"team":"dns"}}}),
                json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"other","resourceVersion":"1","uid":"other","labels":{"team":"other"}}}),
            ],
        ),
        "endpointslices" => (
            "discovery.k8s.io/v1",
            "EndpointSlice",
            vec![
                json!({"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice","metadata":{"name":"headless-1","namespace":"default","resourceVersion":"1","uid":"headless-1","labels":{"kubernetes.io/service-name":"headless"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":8080}],"endpoints":[
                    {"addresses":["10.2.0.5"],"hostname":"named","zone":"us-west-2a","conditions":{"ready":true},"targetRef":{"kind":"Pod","name":"web-pod","namespace":"default"}},
                    {"addresses":["10.2.0.8"],"zone":"corp.example.com","conditions":{"ready":true},"targetRef":{"kind":"Pod","name":"backend-pod","namespace":"default"}},
                    {"addresses":["10.2.0.9"],"conditions":{"ready":true}}
                ]}),
                json!({"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice","metadata":{"name":"web-1","namespace":"default","resourceVersion":"1","uid":"web-1","labels":{"kubernetes.io/service-name":"web","app":"web"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":80}],"endpoints":[{"addresses":["10.2.0.10"],"conditions":{"ready":true}}]}),
            ],
        ),
        _ => return None,
    };
    Some(result)
}

#[derive(Debug)]
enum Operator {
    In(Vec<String>),
    NotIn(Vec<String>),
    Exists,
    Missing,
}

#[derive(Debug)]
struct Requirement {
    key: String,
    op: Operator,
}

fn parse_selector(input: &str, fields: bool) -> Result<Vec<Requirement>, ()> {
    let mut parts = Vec::new();
    let (mut start, mut depth) = (0, 0usize);
    for (index, byte) in input.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => depth = depth.checked_sub(1).ok_or(())?,
            b',' if depth == 0 => {
                parts.push(input[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(());
    }
    if !input.is_empty() {
        parts.push(input[start..].trim());
    }
    parts
        .into_iter()
        .map(|part| {
            let set = part
                .split_once(" notin ")
                .map(|(key, value)| (key, value, true))
                .or_else(|| {
                    part.split_once(" in ")
                        .map(|(key, value)| (key, value, false))
                });
            let (key, op) = if let Some((key, values, negate)) = set {
                if fields {
                    return Err(());
                }
                let values = values
                    .trim()
                    .strip_prefix('(')
                    .and_then(|s| s.strip_suffix(')'))
                    .ok_or(())?;
                let values: Vec<String> = values
                    .split(',')
                    .map(|value| value.trim().to_owned())
                    .collect();
                if values.iter().any(String::is_empty) {
                    return Err(());
                }
                (
                    key.trim(),
                    if negate {
                        Operator::NotIn(values)
                    } else {
                        Operator::In(values)
                    },
                )
            } else if let Some((key, value)) = part.split_once("!=") {
                (key.trim(), Operator::NotIn(vec![value.trim().to_owned()]))
            } else if let Some((key, value)) =
                part.split_once("==").or_else(|| part.split_once('='))
            {
                (key.trim(), Operator::In(vec![value.trim().to_owned()]))
            } else if !fields {
                if let Some(key) = part.strip_prefix('!') {
                    (key, Operator::Missing)
                } else {
                    (part, Operator::Exists)
                }
            } else {
                return Err(());
            };
            if key.is_empty()
                || key
                    .chars()
                    .any(|c| c.is_whitespace() || "!(),=".contains(c))
            {
                return Err(());
            }
            if fields
                && !matches!(
                    key,
                    "metadata.name"
                        | "metadata.namespace"
                        | "status.phase"
                        | "status.podIP"
                        | "spec.nodeName"
                )
            {
                return Err(());
            }
            Ok(Requirement {
                key: key.to_owned(),
                op,
            })
        })
        .collect()
}

fn matches_selector(item: &Value, requirements: &[Requirement], fields: bool) -> bool {
    requirements.iter().all(|requirement| {
        let value = if fields {
            requirement
                .key
                .split('.')
                .fold(item, |value, part| &value[part])
                .as_str()
        } else {
            item["metadata"]["labels"][requirement.key.as_str()].as_str()
        };
        match &requirement.op {
            Operator::In(values) => value.is_some_and(|value| values.iter().any(|v| v == value)),
            Operator::NotIn(values) => value.is_none_or(|value| values.iter().all(|v| v != value)),
            Operator::Exists => value.is_some(),
            Operator::Missing => value.is_none(),
        }
    })
}

fn decode(input: &str) -> Result<String, ()> {
    let bytes = input.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let hex = bytes.get(index + 1..index + 3).ok_or(())?;
                result.push(
                    u8::from_str_radix(std::str::from_utf8(hex).map_err(|_| ())?, 16)
                        .map_err(|_| ())?,
                );
                index += 3;
            }
            b'+' => {
                result.push(b' ');
                index += 1;
            }
            byte => {
                result.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(result).map_err(|_| ())
}

fn query_params(query: &str) -> Result<HashMap<String, String>, ()> {
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            Ok((decode(key)?, decode(value)?))
        })
        .collect()
}

fn resource_path(path: &str) -> Option<(&str, Option<&str>)> {
    let (prefix, resource) = if let Some(path) = path.strip_prefix("/api/v1/") {
        (false, path)
    } else {
        (true, path.strip_prefix("/apis/discovery.k8s.io/v1/")?)
    };
    let parts: Vec<_> = resource.split('/').collect();
    let (name, namespace) = match parts.as_slice() {
        [name] => (*name, None),
        ["namespaces", namespace, name] if *name != "namespaces" => (*name, Some(*namespace)),
        _ => return None,
    };
    if (prefix && name == "endpointslices")
        || (!prefix && matches!(name, "services" | "pods" | "namespaces"))
    {
        Some((name, namespace))
    } else {
        None
    }
}

fn discovery(path: &str) -> Option<Value> {
    let group = json!({"name":"discovery.k8s.io","versions":[{"groupVersion":"discovery.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"discovery.k8s.io/v1","version":"v1"}});
    Some(match path {
        "/version" => json!({"major":"1","minor":"37","gitVersion":"v1.37.0"}),
        "/api" => json!({"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}),
        "/apis" => json!({"kind":"APIGroupList","apiVersion":"v1","groups":[group]}),
        "/apis/discovery.k8s.io" => {
            json!({"kind":"APIGroup","apiVersion":"v1","name":group["name"],"versions":group["versions"],"preferredVersion":group["preferredVersion"]})
        }
        "/api/v1" | "/apis/discovery.k8s.io/v1" => {
            let names: &[&str] = if path == "/api/v1" {
                &["services", "pods", "namespaces"]
            } else {
                &["endpointslices"]
            };
            let entries: Vec<_> = names.iter().map(|name| json!({"name":name,"namespaced":*name != "namespaces","kind":resources(name).unwrap().1,"verbs":["get","list","watch"]})).collect();
            json!({"kind":"APIResourceList","apiVersion":"v1","groupVersion":if path == "/api/v1" {"v1"} else {"discovery.k8s.io/v1"},"resources":entries})
        }
        _ => return None,
    })
}

fn response(status: u16, body: Body) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body)
        .unwrap()
}

fn api_response(path: &str, query: Option<&str>) -> Response<Body> {
    let Some((name, namespace)) = resource_path(path) else {
        return match discovery(path) {
            Some(body) => response(200, full(body.to_string())),
            None => response(
                404,
                full(
                    json!({"apiVersion":"v1","kind":"Status","reason":"NotFound","code":404})
                        .to_string(),
                ),
            ),
        };
    };
    let parsed = (|| {
        let query = query_params(query.unwrap_or_default())?;
        let labels = parse_selector(query.get("labelSelector").map_or("", String::as_str), false)?;
        let fields = parse_selector(query.get("fieldSelector").map_or("", String::as_str), true)?;
        Ok::<_, ()>((query, labels, fields))
    })();
    let Ok((query, labels, fields)) = parsed else {
        return response(
            400,
            full(
                json!({"apiVersion":"v1","kind":"Status","reason":"BadRequest","code":400})
                    .to_string(),
            ),
        );
    };
    let (api, kind, objects) = resources(name).unwrap();
    let objects: Vec<_> = objects
        .into_iter()
        .filter(|item| {
            namespace.is_none_or(|ns| item["metadata"]["namespace"].as_str() == Some(ns))
                && matches_selector(item, &labels, false)
                && matches_selector(item, &fields, true)
        })
        .collect();
    if query.get("watch").is_none_or(|watch| watch != "true") {
        return response(200, full(json!({"apiVersion":api,"kind":format!("{kind}List"),"metadata":{"resourceVersion":"1"},"items":objects}).to_string()));
    }
    let initial = query
        .get("sendInitialEvents")
        .is_some_and(|initial| initial == "true");
    let mut events = String::new();
    if initial {
        for object in objects {
            events.push_str(&format!("{}\n", json!({"type":"ADDED","object":object})));
        }
        events.push_str(&format!("{}\n", json!({"type":"BOOKMARK","object":{"apiVersion":api,"kind":kind,"metadata":{"resourceVersion":"1","annotations":{"k8s.io/initial-events-end":"true"}}}})));
    }
    // shortcut: fixtures never mutate; watches stay open until the API process exits.
    let first = futures::stream::iter(
        initial.then(|| Ok::<_, Infallible>(Frame::data(Bytes::from(events)))),
    );
    response(
        200,
        BodyExt::boxed(StreamBody::new(first.chain(futures::stream::pending()))),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: differential <kubeconfig>")?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let config = json!({"apiVersion":"v1","kind":"Config","clusters":[{"name":"fixture","cluster":{"server":url}}],"contexts":[{"name":"fixture","context":{"cluster":"fixture","user":"fixture"}}],"current-context":"fixture","users":[{"name":"fixture","user":{}}]});
    let path = Path::new(&path);
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)?;
    serde_json::to_writer(&mut file, &config)?;
    file.flush()?;
    std::fs::rename(temporary, path)?;
    api::serve(listener, api_response).await
}

#[cfg(test)]
mod tests {
    use super::api_response;
    use http_body_util::BodyExt;
    use serde_json::Value;

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
    async fn list_filters_label_field_and_namespaced_paths() {
        let services = "/api/v1/services";
        assert_eq!(
            names(&list(services, Some("labelSelector=app%3Dweb")).await),
            ["web", "hidden"]
        );
        assert_eq!(
            names(
                &list(
                    services,
                    Some("labelSelector=app%20in%20%28web%2Cdb%29%2Ctier%21%3Dhidden")
                )
                .await
            ),
            ["web", "dual"]
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
        assert_eq!(names(&list("/api/v1/pods", Some("fieldSelector=status.phase%21%3DSucceeded%2Cstatus.phase%21%3DFailed%2Cstatus.phase%21%3DUnknown")).await), ["web-pod", "other-pod"]);
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
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["object"]["metadata"]["name"], "web");
        assert_eq!(events[1]["object"]["metadata"]["name"], "hidden");
        assert_eq!(events[2]["type"], "BOOKMARK");
        assert_eq!(
            events[2]["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"],
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

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = super::api::serve(listener, api_response).await;
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
        server.abort();
    }
}

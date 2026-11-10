//! Measure the real watcher and store against a synthetic API server.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::{
    Request, Response,
    body::{Frame, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use pharos_kubernetes::{Controller, WatchConfig};
use std::{convert::Infallible, fmt::Write, time::Duration};
use tokio::net::TcpListener;

fn list(path: &str) -> String {
    let (api, kind) = match path {
        "/api/v1/services" => ("v1", "ServiceList"),
        "/apis/discovery.k8s.io/v1/endpointslices" => ("discovery.k8s.io/v1", "EndpointSliceList"),
        _ => ("v1", "NamespaceList"),
    };
    let mut json = format!(
        r#"{{"apiVersion":"{api}","kind":"{kind}","metadata":{{"resourceVersion":"1"}},"items":["#
    );
    for i in 0..10_000 {
        if kind == "NamespaceList" {
            break;
        }
        if i != 0 {
            json.push(',');
        }
        if kind == "ServiceList" {
            write!(json, r#"{{"metadata":{{"name":"svc{i}","namespace":"bench"}},"spec":{{"clusterIP":"10.{}.{}.{}","ports":[{{"port":80}}]}}}}"#, i / 65536, i / 256 % 256, i % 256).unwrap();
        } else {
            write!(json, r#"{{"metadata":{{"name":"slice{i}","namespace":"bench","labels":{{"kubernetes.io/service-name":"svc{i}"}}}},"addressType":"IPv4","endpoints":["#).unwrap();
            for offset in 0..3 {
                if offset != 0 {
                    json.push(',');
                }
                let address = i * 3 + offset;
                write!(
                    json,
                    r#"{{"addresses":["192.{}.{}.{}"]}}"#,
                    address / 65536,
                    address / 256 % 256,
                    address % 256
                )
                .unwrap();
            }
            json.push_str("]}");
        }
    }
    if kind == "NamespaceList" {
        json.push_str(r#"{"metadata":{"name":"bench"}}"#);
    }
    json.push_str("]}");
    json
}

fn rss_kib() -> Result<u64, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status")?;
        let rss = status
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .ok_or("VmRSS missing")?;
        return Ok(rss
            .split_whitespace()
            .next()
            .ok_or("VmRSS empty")?
            .parse()?);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()?;
        if !output.status.success() {
            return Err("ps failed".into());
        }
        Ok(std::str::from_utf8(&output.stdout)?.trim().parse()?)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|request: Request<Incoming>| async move {
                    let body: BoxBody<Bytes, Infallible> = if request
                        .uri()
                        .query()
                        .is_some_and(|query| query.contains("watch=true"))
                    {
                        let stream = futures::stream::pending::<Result<Frame<Bytes>, Infallible>>();
                        StreamBody::new(stream).boxed()
                    } else {
                        Full::new(Bytes::from(list(request.uri().path()))).boxed()
                    };
                    Ok::<_, Infallible>(Response::new(body))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    let client = kube::Client::try_from(kube::Config::new(url.parse()?))?;
    let before = rss_kib()?;
    let mut controller = Controller::start(client, WatchConfig::default());
    tokio::time::timeout(Duration::from_secs(60), async {
        while !controller.has_synced() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let counts = controller.store().with_read(|index| index.counts());
    assert_eq!(counts, (10_000, 10_000, 30_000, 0, 1));
    let after = rss_kib()?;
    println!(
        "RSS before: {before} KiB; after: {after} KiB; delta: {} KiB",
        after as i64 - before as i64
    );
    println!(
        "services: {}; slices: {}; endpoints: {}; pods: {}; namespaces: {}",
        counts.0, counts.1, counts.2, counts.3, counts.4
    );
    controller.stop().await;
    server.abort();
    Ok(())
}

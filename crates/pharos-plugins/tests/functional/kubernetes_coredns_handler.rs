#![forbid(unsafe_code)]
#![cfg(feature = "plugin-kubernetes")]

use crate::support;

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Record, Type};
use pharos_server::{Handler, Phase, Protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// APIConnServeTest in CoreDNS handler_test.go: services, endpoint slices, pod and namespaces.
const SERVICES: &str = r#"[
 {"metadata":{"name":"kubedns","namespace":"kube-system"},"spec":{"clusterIP":"10.0.0.10","ports":[{"name":"dns","protocol":"UDP","port":53}]}},
 {"metadata":{"name":"svc1","namespace":"testns"},"spec":{"clusterIP":"10.0.0.1","ports":[{"name":"http","protocol":"TCP","port":80}]}},
 {"metadata":{"name":"svcempty","namespace":"testns"},"spec":{"clusterIP":"10.0.0.1","ports":[{"name":"http","protocol":"TCP","port":80}]}},
 {"metadata":{"name":"svc6","namespace":"testns"},"spec":{"clusterIP":"1234:abcd::1","ports":[{"name":"http","protocol":"TCP","port":80}]}},
 {"metadata":{"name":"hdls1","namespace":"testns"},"spec":{"clusterIP":"None"}},
 {"metadata":{"name":"hdlsprtls","namespace":"testns"},"spec":{"clusterIP":"None"}},
 {"metadata":{"name":"external","namespace":"testns"},"spec":{"type":"ExternalName","externalName":"ext.interwebs.test","ports":[{"name":"http","protocol":"TCP","port":80}]}},
 {"metadata":{"name":"external-to-service","namespace":"testns"},"spec":{"type":"ExternalName","externalName":"svc1.testns.svc.cluster.local.","ports":[{"name":"http","protocol":"TCP","port":80}]}},
 {"metadata":{"name":"svc1","namespace":"unexposedns"},"spec":{"clusterIP":"10.0.0.2","ports":[{"name":"http","protocol":"TCP","port":80}]}},
 {"metadata":{"name":"svc-dual-stack","namespace":"testns"},"spec":{"clusterIPs":["10.0.0.3","10::3"],"ports":[{"name":"http","protocol":"TCP","port":80}]}}
]"#;
const ENDPOINTS: &str = r#"[
 {"metadata":{"name":"kubedns","namespace":"kube-system","labels":{"kubernetes.io/service-name":"kubedns"}},"addressType":"IPv4","ports":[{"name":"dns","protocol":"UDP","port":53}],"endpoints":[{"addresses":["172.0.0.100"]}]},
 {"metadata":{"name":"svc1-slice1","namespace":"testns","labels":{"kubernetes.io/service-name":"svc1"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":80}],"endpoints":[{"addresses":["172.0.0.1"],"hostname":"ep1a"}]},
 {"metadata":{"name":"svcempty-slice1","namespace":"testns","labels":{"kubernetes.io/service-name":"svcempty"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":80}],"endpoints":[]},
 {"metadata":{"name":"hdls1-v4","namespace":"testns","labels":{"kubernetes.io/service-name":"hdls1"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":80}],"endpoints":[{"addresses":["172.0.0.2"]},{"addresses":["172.0.0.3"]},{"addresses":["172.0.0.4"],"hostname":"dup-name"},{"addresses":["172.0.0.5"],"hostname":"dup-name"}]},
 {"metadata":{"name":"hdls1-v6","namespace":"testns","labels":{"kubernetes.io/service-name":"hdls1"}},"addressType":"IPv6","ports":[{"name":"http","protocol":"TCP","port":80}],"endpoints":[{"addresses":["5678:abcd::1"]},{"addresses":["5678:abcd::2"]}]},
 {"metadata":{"name":"hdlsprtls-slice1","namespace":"testns","labels":{"kubernetes.io/service-name":"hdlsprtls"}},"addressType":"IPv4","endpoints":[{"addresses":["172.0.0.20"]}]}
]"#;
const PODS: &str = r#"[{"metadata":{"name":"foo","namespace":"podns","labels":{"app.kubernetes.io/name":"foo","bar":"baz"}},"status":{"podIPs":[{"ip":"10.240.0.1"}]}}]"#;
const NAMESPACES: &str = r#"[{"metadata":{"name":"testns"}},{"metadata":{"name":"podns"}},{"metadata":{"name":"svcns"}},{"metadata":{"name":"kube-system"}},{"metadata":{"name":"unexposedns"}}]"#;
const IMPORTS: &str = r#"[{"apiVersion":"multicluster.x-k8s.io/v1alpha1","kind":"ServiceImport","metadata":{"name":"svc1","namespace":"testns"},"spec":{"type":"ClusterSetIP","ips":["10.0.0.1"],"ports":[{"name":"http","protocol":"TCP","port":80}]}},{"apiVersion":"multicluster.x-k8s.io/v1alpha1","kind":"ServiceImport","metadata":{"name":"hdls1","namespace":"testns"},"spec":{"type":"Headless"}}]"#;
const MC_ENDPOINTS: &str = r#"[{"metadata":{"name":"mc1","namespace":"testns","labels":{"multicluster.kubernetes.io/service-name":"hdls1","multicluster.kubernetes.io/source-cluster":"cluster1"}},"addressType":"IPv4","ports":[{"name":"http","protocol":"TCP","port":80}],"endpoints":[{"addresses":["172.0.0.2"]}]}]"#;

async fn api(
    hold_endpoints: bool,
) -> (
    String,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", support::free_port()))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (gate, _) = tokio::sync::watch::channel(!hold_endpoints);
    let receiver = gate.subscribe();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut receiver = receiver.clone();
            tokio::spawn(async move {
                let mut request = [0; 8192];
                let n = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                if request.contains("watch=true") {
                    if socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").await.is_ok() {
                        let _ = socket.read(&mut request.into_owned().into_bytes()).await;
                    }
                    return;
                }
                let (kind, items) = if request.contains("/serviceimports") {
                    ("ServiceImportList", IMPORTS)
                } else if request.contains("/api/v1/services") {
                    ("ServiceList", SERVICES)
                } else if request.contains("/endpointslices") {
                    while !*receiver.borrow_and_update() {
                        if receiver.changed().await.is_err() {
                            return;
                        }
                    }
                    (
                        "EndpointSliceList",
                        if request.contains("multicluster.kubernetes.io") {
                            MC_ENDPOINTS
                        } else {
                            ENDPOINTS
                        },
                    )
                } else if request.contains("/api/v1/pods") {
                    ("PodList", PODS)
                } else {
                    ("NamespaceList", NAMESPACES)
                };
                let body = format!(
                    r#"{{"apiVersion":"v1","kind":"{kind}","metadata":{{"resourceVersion":"1"}},"items":{items}}}"#
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (format!("http://{address}"), gate, task)
}

#[cfg(feature = "plugin-autopath")]
#[test]
fn autopath_uses_verified_client_pod_namespace() {
    crate::on_plugin_stack(autopath_verified_client_pod_namespace);
}

#[cfg(feature = "plugin-autopath")]
async fn autopath_verified_client_pod_namespace() {
    let (endpoint, _, task) = api(false).await;
    let config = format!(
        ".:53 {{\n autopath @kubernetes\n kubernetes cluster.local {{\n endpoint {endpoint}\n pods verified\n startup_timeout 3s\n }}\n}}"
    );
    let (mut listeners, lifecycle) =
        servers(configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap())
            .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = listeners.drain().next().unwrap();
    let name: Name = "svc1.testns.podns.svc.cluster.local.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut b = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(
                &wire,
                "10.240.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
        pharos_server::Action::Respond
    );
    let msg = Message::parse(&response).unwrap();
    assert_eq!(msg.rcode(), Rcode::NOERROR);
    let Rdata::Cname(target) = msg.answers().next().unwrap().data().unwrap() else {
        panic!("expected CNAME")
    };
    assert_eq!(target.to_string(), "svc1.testns.svc.cluster.local.");
    lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

// Derived from CoreDNS v1.15.0 plugin/kubernetes/metadata_test.go TestMetadataPodsVerified.
#[cfg(all(feature = "plugin-metadata", feature = "plugin-whoami"))]
#[tokio::test]
async fn verified_client_pod_metadata_is_collected_outside_kubernetes_domains() {
    use pharos_server::{Context, Metadata, Transport};
    let (endpoint, _, task) = api(false).await;
    let text = format!(
        ". {{\n metadata\n kubernetes cluster.local {{\n endpoint {endpoint}\n pods verified\n startup_timeout 3s\n }}\n whoami\n}}"
    );
    let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives())
        .unwrap()
        .remove(0)
        .config;
    chain.lifecycle.run(Phase::Startup).await.unwrap();
    let name: Name = "example.com.".parse().unwrap();
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 18];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "10.240.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &root,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    chain.serve(&mut cx).await;
    assert_eq!(
        cx.metadata.get("kubernetes/client-namespace"),
        Some("podns")
    );
    assert_eq!(cx.metadata.get("kubernetes/client-pod-name"), Some("foo"));
    assert_eq!(
        cx.metadata
            .get("kubernetes/client-label/app.kubernetes.io/name"),
        Some("foo")
    );
    assert_eq!(cx.metadata.get("kubernetes/client-label/bar"), Some("baz"));
    chain.lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}

#[derive(Clone)]
struct Case {
    id: &'static str,
    name: &'static str,
    kind: Type,
    code: Rcode,
    answer: Vec<String>,
    authority: Vec<String>,
    extra: Vec<String>,
}

fn rr(name: &str, ttl: u32, kind: &str, data: &str) -> String {
    format!("{name} {ttl} {kind} {data}")
}
fn soa(zone: &str) -> String {
    // CoreDNS's test helper ignores SOA serial; compare the live serial separately.
    rr(
        zone,
        5,
        "SOA",
        &format!("ns.dns.{zone} hostmaster.{zone} <serial> 7200 1800 86400 5"),
    )
}
fn row(
    id: &'static str,
    name: &'static str,
    kind: Type,
    code: Rcode,
    answer: Vec<String>,
    authority: Vec<String>,
    extra: Vec<String>,
) -> Case {
    Case {
        id,
        name,
        kind,
        code,
        answer,
        authority,
        extra,
    }
}
fn positive(id: &'static str, name: &'static str, kind: Type, data: &[&str]) -> Case {
    let typ = if kind == Type::A {
        "A"
    } else if kind == Type::AAAA {
        "AAAA"
    } else {
        "CNAME"
    };
    row(
        id,
        name,
        kind,
        Rcode::NOERROR,
        data.iter().map(|d| rr(name, 5, typ, d)).collect(),
        vec![],
        vec![],
    )
}
fn negative(id: &'static str, name: &'static str, kind: Type, code: Rcode, zone: &str) -> Case {
    row(id, name, kind, code, vec![], vec![soa(zone)], vec![])
}
fn srv(id: &'static str, name: &'static str, target: &str, weight: u16, ip: &str) -> Case {
    row(
        id,
        name,
        Type::SRV,
        Rcode::NOERROR,
        vec![rr(name, 5, "SRV", &format!("0 {weight} 80 {target}"))],
        vec![],
        vec![rr(
            target,
            5,
            if ip.contains(':') { "AAAA" } else { "A" },
            ip,
        )],
    )
}

fn record(record: Record<'_>, expected_serial: Option<u32>) -> String {
    assert_eq!(record.class, Class::IN);
    let (kind, data) = match record.data().unwrap() {
        Rdata::A(ip) => ("A", ip.to_string()),
        Rdata::Aaaa(ip) => ("AAAA", ip.to_string()),
        Rdata::Cname(target) => ("CNAME", target.to_string()),
        Rdata::Ns(target) => ("NS", target.to_string()),
        Rdata::Txt(data) => ("TXT", String::from_utf8(data[1..].to_vec()).unwrap()),
        Rdata::Srv {
            priority,
            weight,
            port,
            target,
        } => ("SRV", format!("{priority} {weight} {port} {target}")),
        Rdata::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            assert!(
                serial == 0 || serial > 1_000_000_000,
                "invalid live SOA serial {serial}"
            );
            if let Some(expected) = expected_serial {
                assert_eq!(serial, expected, "SOA serial changed");
            }
            (
                "SOA",
                format!("{mname} {rname} <serial> {refresh} {retry} {expire} {minimum}"),
            )
        }
        other => panic!("unexpected RDATA {other:?}"),
    };
    rr(&record.name.to_string(), record.ttl, kind, &data)
}

async fn run_group(options: &str, cases: Vec<Case>, synced: bool) {
    let options = options.to_owned();
    crate::on_plugin_stack(move || run_group_on_stack(options, cases, synced));
}

async fn run_group_on_stack(options: String, cases: Vec<Case>, synced: bool) {
    let (endpoint, gate, api_task) = api(!synced).await;
    let text = format!(
        ".:53 {{\n bind 127.0.0.1\n kubernetes cluster.local {{\n  endpoint {endpoint}\n  startup_timeout 3s\n  {options}\n }}\n}}"
    );
    let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let lifecycle = blocks[0].config.lifecycle.clone();
    let startup = if synced {
        lifecycle.run(Phase::Startup).await.unwrap();
        None
    } else {
        let lifecycle = lifecycle.clone();
        Some(tokio::spawn(async move {
            lifecycle.run(Phase::Startup).await.unwrap()
        }))
    };
    let (servers, _) = servers(blocks).unwrap();
    let server = servers.values().next().unwrap();
    let serial = if synced {
        let zone: Name = "cluster.local.".parse().unwrap();
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
        builder
            .question(
                NameRef::parse(zone.as_wire(), 0).unwrap(),
                Type::SOA,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        let mut wire = Vec::with_capacity(4096);
        server
            .handle(
                &query,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Tcp,
                &mut wire,
            )
            .await;
        let msg = Message::parse(&wire).unwrap();
        let Rdata::Soa { serial, .. } = msg.answers().next().unwrap().data().unwrap() else {
            panic!("missing SOA")
        };
        assert!(serial == 0 || serial > 1_000_000_000);
        Some(serial)
    } else {
        None
    };
    let mut errors = Vec::new();
    for case in cases {
        let name: Name = case.name.parse().unwrap();
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
        builder
            .question(
                NameRef::parse(name.as_wire(), 0).unwrap(),
                case.kind,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        let mut wire = Vec::with_capacity(4096);
        server
            .handle(
                &query,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Tcp,
                &mut wire,
            )
            .await;
        let message =
            Message::parse(&wire).unwrap_or_else(|e| panic!("{} {}: {e:?}", case.id, case.name));
        assert!(!message.tc(), "{} unexpected truncation", case.id);
        let mut previous = Vec::new();
        for rr in message.answers() {
            if let Ok(Rdata::Cname(target)) = rr.data() {
                assert!(
                    !previous.contains(&target.to_string()),
                    "{} CNAME after target",
                    case.id
                );
            }
            previous.push(rr.name.to_string());
        }
        let mut answer: Vec<_> = message.answers().map(|rr| record(rr, serial)).collect();
        let mut authority: Vec<_> = message.authorities().map(|rr| record(rr, serial)).collect();
        let mut extra: Vec<_> = message.additionals().map(|rr| record(rr, serial)).collect();
        let mut expected = (case.answer, case.authority, case.extra);
        answer.sort();
        authority.sort();
        extra.sort();
        expected.0.sort();
        expected.1.sort();
        expected.2.sort();
        if (message.rcode(), &answer, &authority, &extra)
            != (case.code, &expected.0, &expected.1, &expected.2)
        {
            errors.push(format!(
                "{} {} {:?}\n  expected {:?} {:?}\n  actual   {:?} {:?}",
                case.id,
                case.name,
                case.kind,
                case.code,
                expected,
                message.rcode(),
                (answer, authority, extra)
            ));
        }
    }
    if let Some(startup) = startup {
        gate.send(true).unwrap();
        startup.await.unwrap();
    }
    lifecycle.run(Phase::Shutdown).await.unwrap();
    api_task.abort();
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[tokio::test]
async fn multicluster_answers_service_and_cluster_qualified_endpoint() {
    let zone = "cluster.local.";
    run_group(
        "multicluster cluster.local",
        vec![
            positive(
                "import",
                "svc1.testns.svc.cluster.local.",
                Type::A,
                &["10.0.0.1"],
            ),
            positive(
                "headless",
                "hdls1.testns.svc.cluster.local.",
                Type::A,
                &["172.0.0.2"],
            ),
            positive(
                "endpoint",
                "172-0-0-2.cluster1.hdls1.testns.svc.cluster.local.",
                Type::A,
                &["172.0.0.2"],
            ),
            srv(
                "headless srv",
                "_http._tcp.hdls1.testns.svc.cluster.local.",
                "172-0-0-2.cluster1.hdls1.testns.svc.cluster.local.",
                100,
                "172.0.0.2",
            ),
            srv(
                "import srv",
                "_http._tcp.svc1.testns.svc.cluster.local.",
                "svc1.testns.svc.cluster.local.",
                100,
                "10.0.0.1",
            ),
            negative(
                "missing cluster",
                "172-0-0-2.hdls1.testns.svc.cluster.local.",
                Type::A,
                Rcode::NXDOMAIN,
                zone,
            ),
            negative(
                "no ipv6",
                "svc1.testns.svc.cluster.local.",
                Type::AAAA,
                Rcode::NOERROR,
                zone,
            ),
        ],
        true,
    )
    .await;
}

// One-based row IDs map to CoreDNS v1.15.0 tables:
// 1. common = handler_test.go commonDnsTestCases (1-34).
// 2. regular = handler_test.go dnsTestCases (1-11).
// 3. namespace = handler_test.go nsTestCases (1-2).
// 4. not-synced = handler_test.go notSyncedTestCases (1).
// 5. case = handler_case_test.go dnsPreserveCaseCases (1-4).
// 6. empty = handler_ignore_emptyservice_test.go dnsEmptyServiceTestCases (1-2).
// 7. disabled = handler_pod_disabled_test.go podModeDisabledCases (1-2).
// 8. insecure = handler_pod_insecure_test.go podModeInsecureCases (1-7).
// 9. verified = handler_pod_verified_test.go podModeVerifiedCases (1-5).
// 10. apex = kubernetes_apex_test.go kubeApexCases (1-6).
#[tokio::test]
async fn handler_common_and_regular() {
    let zone = "cluster.local.";
    let a = Rcode::NOERROR;
    let nx = Rcode::NXDOMAIN;
    let svc1 = "svc1.testns.svc.cluster.local.";
    let empty = "svcempty.testns.svc.cluster.local.";
    let svc6 = "svc6.testns.svc.cluster.local.";
    let head = "hdls1.testns.svc.cluster.local.";
    let dual = "svc-dual-stack.testns.svc.cluster.local.";
    let ext = "external.testns.svc.cluster.local.";
    let mut cases = vec![
        positive("common 1", svc1, Type::A, &["10.0.0.1"]),
        positive("common 2", empty, Type::A, &["10.0.0.1"]),
        srv("common 3", svc1, svc1, 100, "10.0.0.1"),
        srv("common 4", empty, empty, 100, "10.0.0.1"),
        srv("common 5", svc6, svc6, 100, "1234:abcd::1"),
        srv(
            "common 6",
            "_http._tcp.svc1.testns.svc.cluster.local.",
            svc1,
            100,
            "10.0.0.1",
        ),
        srv(
            "common 7",
            "_http._tcp.svcempty.testns.svc.cluster.local.",
            empty,
            100,
            "10.0.0.1",
        ),
        positive(
            "common 8",
            head,
            Type::A,
            &["172.0.0.2", "172.0.0.3", "172.0.0.4", "172.0.0.5"],
        ),
        positive(
            "common 9",
            "hdlsprtls.testns.svc.cluster.local.",
            Type::A,
            &["172.0.0.20"],
        ),
        negative("common 10", svc1, Type::AAAA, a, zone),
        negative(
            "common 11",
            "svc0.testns.svc.cluster.local.",
            Type::AAAA,
            nx,
            zone,
        ),
        negative(
            "common 12",
            "svc0.testns.svc.cluster.local.",
            Type::A,
            nx,
            zone,
        ),
        negative(
            "common 13",
            "svc0.svc-nons.svc.cluster.local.",
            Type::A,
            nx,
            zone,
        ),
        row(
            "common 14",
            "dns-version.cluster.local.",
            Type::TXT,
            a,
            vec![rr("dns-version.cluster.local.", 28800, "TXT", "1.1.0")],
            vec![],
            vec![],
        ),
        negative("common 15", svc1, Type::TXT, a, zone),
        negative(
            "common 16",
            "svc0.svc-nons.svc.cluster.local.",
            Type::TXT,
            nx,
            zone,
        ),
        negative(
            "common 17",
            "bogusendpoint.hdls1.testns.svc.cluster.local.",
            Type::A,
            nx,
            zone,
        ),
        negative(
            "common 18",
            "bogusendpoint.svc0.testns.svc.cluster.local.",
            Type::A,
            nx,
            zone,
        ),
        positive("common 19", svc6, Type::AAAA, &["1234:abcd::1"]),
        srv(
            "common 20",
            "_http._tcp.svc6.testns.svc.cluster.local.",
            svc6,
            100,
            "1234:abcd::1",
        ),
        positive(
            "common 21",
            head,
            Type::AAAA,
            &["5678:abcd::1", "5678:abcd::2"],
        ),
        negative("common 22", "svc.cluster.local.", Type::A, a, zone),
        negative("common 23", "pod.cluster.local.", Type::A, a, zone),
        negative("common 24", "testns.svc.cluster.local.", Type::A, a, zone),
        negative("common 25", "svc.cluster.local.", Type::NS, a, zone),
        negative("common 26", "testns.svc.cluster.local.", Type::NS, a, zone),
        negative("common 27", "foo.cluster.local.", Type::NS, nx, zone),
        negative("common 28", "foo.svc.cluster.local.", Type::NS, nx, zone),
        positive("common 29", dual, Type::A, &["10.0.0.3"]),
        positive("common 30", dual, Type::AAAA, &["10::3"]),
        row(
            "common 31",
            dual,
            Type::SRV,
            a,
            vec![rr(dual, 5, "SRV", &format!("0 50 80 {dual}"))],
            vec![],
            vec![rr(dual, 5, "A", "10.0.0.3"), rr(dual, 5, "AAAA", "10::3")],
        ),
        negative("common 32", svc1, Type::SOA, a, zone),
        negative(
            "common 33",
            "endpoint.external.testns.svc.cluster.local.",
            Type::CNAME,
            nx,
            zone,
        ),
        negative(
            "common 34",
            "subdomain.subdomain.external.testns.svc.cluster.local.",
            Type::CNAME,
            nx,
            zone,
        ),
    ];
    let q = "_http._tcp.hdls1.testns.svc.cluster.local.";
    let targets = [
        ("172-0-0-2.hdls1.testns.svc.cluster.local.", "172.0.0.2"),
        ("172-0-0-3.hdls1.testns.svc.cluster.local.", "172.0.0.3"),
        (
            "5678-abcd--1.hdls1.testns.svc.cluster.local.",
            "5678:abcd::1",
        ),
        (
            "5678-abcd--2.hdls1.testns.svc.cluster.local.",
            "5678:abcd::2",
        ),
        ("dup-name.hdls1.testns.svc.cluster.local.", "172.0.0.4"),
        ("dup-name.hdls1.testns.svc.cluster.local.", "172.0.0.5"),
    ];
    let mut answers: Vec<_> = targets
        .iter()
        .map(|(target, _)| rr(q, 5, "SRV", &format!("0 16 80 {target}")))
        .collect();
    answers.sort();
    answers.dedup();
    let extra = targets
        .iter()
        .map(|(target, ip)| rr(target, 5, if ip.contains(':') { "AAAA" } else { "A" }, ip))
        .collect();
    cases.extend([
        row("regular 1", q, Type::SRV, a, answers, vec![], extra),
        positive(
            "regular 2",
            head,
            Type::A,
            &["172.0.0.2", "172.0.0.3", "172.0.0.4", "172.0.0.5"],
        ),
        positive(
            "regular 3",
            "5678-abcd--2.hdls1.testns.svc.cluster.local.",
            Type::AAAA,
            &["5678:abcd::2"],
        ),
        positive(
            "regular 4",
            "5678-abcd--1.hdls1.testns.svc.cluster.local.",
            Type::AAAA,
            &["5678:abcd::1"],
        ),
        positive(
            "regular 5",
            "172-0-0-20.hdlsprtls.testns.svc.cluster.local.",
            Type::A,
            &["172.0.0.20"],
        ),
        positive(
            "regular 6",
            "172-0-0-2.hdls1.testns.svc.cluster.local.",
            Type::A,
            &["172.0.0.2"],
        ),
        positive(
            "regular 7",
            "172-0-0-3.hdls1.testns.svc.cluster.local.",
            Type::A,
            &["172.0.0.3"],
        ),
        positive(
            "regular 8",
            "dup-name.hdls1.testns.svc.cluster.local.",
            Type::A,
            &["172.0.0.4", "172.0.0.5"],
        ),
        positive("regular 9", ext, Type::CNAME, &["ext.interwebs.test."]),
        row(
            "regular 11",
            "external-to-service.testns.svc.cluster.local.",
            Type::A,
            a,
            vec![
                rr(
                    "external-to-service.testns.svc.cluster.local.",
                    5,
                    "CNAME",
                    svc1,
                ),
                rr(svc1, 5, "A", "10.0.0.1"),
            ],
            vec![],
            vec![],
        ),
    ]);
    run_group("namespaces testns", cases, true).await;
}

#[tokio::test]
async fn handler_case_and_ignore_empty() {
    let z = "cluster.local.";
    let cases = vec![
        negative(
            "case 1",
            "not-a-service.testns.svc.ClUsTeR.lOcAl.",
            Type::A,
            Rcode::NXDOMAIN,
            "ClUsTeR.lOcAl.",
        ),
        positive(
            "case 2",
            "SvC1.TeStNs.SvC.cLuStEr.LoCaL.",
            Type::A,
            &["10.0.0.1"],
        ),
        srv(
            "case 3",
            "_HtTp._TcP.sVc1.TeStNs.SvC.cLuStEr.LoCaL.",
            "svc1.testns.svc.cLuStEr.LoCaL.",
            100,
            "10.0.0.1",
        ),
        row(
            "case 4",
            "Cluster.local.",
            Type::SOA,
            Rcode::NOERROR,
            vec![soa("Cluster.local.")],
            vec![],
            vec![],
        ),
        negative(
            "empty 1",
            "svcempty.testns.svc.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            z,
        ),
        positive(
            "empty 2",
            "external.testns.svc.cluster.local.",
            Type::CNAME,
            &["ext.interwebs.test."],
        ),
    ];
    run_group("ignore empty_service", cases, true).await;
}

#[tokio::test]
async fn handler_pod_disabled() {
    run_group(
        "pods disabled",
        vec![
            negative(
                "disabled 1",
                "10-240-0-1.podns.pod.cluster.local.",
                Type::A,
                Rcode::NXDOMAIN,
                "cluster.local.",
            ),
            negative(
                "disabled 2",
                "172-0-0-2.podns.pod.cluster.local.",
                Type::A,
                Rcode::NXDOMAIN,
                "cluster.local.",
            ),
        ],
        true,
    )
    .await;
}

#[tokio::test]
async fn handler_pod_insecure() {
    let z = "cluster.local.";
    let cases = vec![
        positive(
            "insecure 1",
            "10-240-0-1.podns.pod.cluster.local.",
            Type::A,
            &["10.240.0.1"],
        ),
        positive(
            "insecure 2",
            "172-0-0-2.podns.pod.cluster.local.",
            Type::A,
            &["172.0.0.2"],
        ),
        negative(
            "insecure 3",
            "blah.podns.pod.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            z,
        ),
        negative(
            "insecure 4",
            "blah.podns.pod.cluster.local.",
            Type::AAAA,
            Rcode::NXDOMAIN,
            z,
        ),
        negative(
            "insecure 5",
            "blah.podns.pod.cluster.local.",
            Type::HINFO,
            Rcode::NXDOMAIN,
            z,
        ),
        negative(
            "insecure 6",
            "blah.pod-nons.pod.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            z,
        ),
        negative(
            "insecure 7",
            "podns.pod.cluster.local.",
            Type::A,
            Rcode::NOERROR,
            z,
        ),
    ];
    // The upstream helper ignores SOA minimum; the live backend uses its default TTL of 5.
    run_group("pods insecure", cases, true).await;
}

#[tokio::test]
async fn handler_pod_verified() {
    let z = "cluster.local.";
    run_group(
        "pods verified",
        vec![
            positive(
                "verified 1",
                "10-240-0-1.podns.pod.cluster.local.",
                Type::A,
                &["10.240.0.1"],
            ),
            negative(
                "verified 2",
                "podns.pod.cluster.local.",
                Type::A,
                Rcode::NOERROR,
                z,
            ),
            negative(
                "verified 3",
                "svcns.svc.cluster.local.",
                Type::A,
                Rcode::NOERROR,
                z,
            ),
            negative(
                "verified 4",
                "pod-nons.pod.cluster.local.",
                Type::A,
                Rcode::NXDOMAIN,
                z,
            ),
            negative(
                "verified 5",
                "172-0-0-2.podns.pod.cluster.local.",
                Type::A,
                Rcode::NXDOMAIN,
                z,
            ),
        ],
        true,
    )
    .await;
}

#[tokio::test]
async fn handler_apex() {
    let z = "cluster.local.";
    run_group(
        "",
        vec![
            row(
                "apex 1",
                z,
                Type::SOA,
                Rcode::NOERROR,
                vec![soa(z)],
                vec![],
                vec![],
            ),
            negative("apex 2", z, Type::HINFO, Rcode::NOERROR, z),
            // The Go test injects loopback directly; a real loopback bind is filtered.
            negative("apex 3 bound loopback", z, Type::NS, Rcode::NOERROR, z),
            negative("apex 4", z, Type::A, Rcode::NOERROR, z),
            negative("apex 5", z, Type::AAAA, Rcode::NOERROR, z),
            negative("apex 6", z, Type::SRV, Rcode::NOERROR, z),
        ],
        true,
    )
    .await;
}

#[tokio::test]
async fn handler_namespace() {
    let cases = vec![
        positive(
            "namespace 1",
            "svc1.testns.svc.cluster.local.",
            Type::A,
            &["10.0.0.1"],
        ),
        negative(
            "namespace 2",
            "svc1.nsnoexist.svc.cluster.local.",
            Type::A,
            Rcode::NXDOMAIN,
            "cluster.local.",
        ),
    ];
    // The upstream namespace test ignores its comparison result; the live default TTL is 5.
    run_group("", cases, true).await;
}

#[tokio::test]
async fn handler_not_synced() {
    run_group(
        "namespaces testns",
        vec![negative(
            "not-synced 1",
            "svc0.testns.svc.cluster.local.",
            Type::A,
            Rcode::SERVFAIL,
            "cluster.local.",
        )],
        false,
    )
    .await;
}

enum TruncatedRoute {
    Kubernetes(Box<Chain>),
    Target,
}

impl pharos_server::Chain for TruncatedRoute {
    async fn serve(&self, cx: &mut pharos_server::Context<'_, '_>) -> pharos_server::Outcome {
        match self {
            Self::Kubernetes(chain) => chain.serve(cx).await,
            Self::Target => {
                let q = cx.query.questions().next().unwrap();
                let mut builder =
                    MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8600).unwrap();
                builder.question(q.name, q.qtype, q.qclass).unwrap();
                builder
                    .record(
                        pharos_proto::Section::Answer,
                        q.name,
                        Type::A,
                        Class::IN,
                        5,
                        &[1, 2, 3, 4],
                    )
                    .unwrap();
                let _ = builder.finish();
                pharos_server::Outcome::Response
            }
        }
    }
    fn is_empty(&self) -> bool {
        false
    }
}

// handler_test.go dnsTestCases row 10: the synthetic upstream returns a truncated A response.
#[test]
fn handler_external_truncated_upstream() {
    crate::on_plugin_stack(external_truncated_upstream);
}

async fn external_truncated_upstream() {
    let (endpoint, _, api_task) = api(false).await;
    let text = format!(
        ".:53 {{\n kubernetes cluster.local {{\n  endpoint {endpoint}\n  namespaces testns\n  startup_timeout 3s\n }}\n}}"
    );
    let mut blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let chain = blocks.remove(0).config;
    let lifecycle = chain.lifecycle.clone();
    lifecycle.run(Phase::Startup).await.unwrap();
    let key = pharos_server::ListenerKey {
        transport: pharos_server::Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = pharos_server::Router::default();
    router.add(
        key,
        ".".parse().unwrap(),
        Some(TruncatedRoute::Kubernetes(Box::new(chain))),
        vec![],
    );
    router.add(
        key,
        "ext.interwebs.test.".parse().unwrap(),
        Some(TruncatedRoute::Target),
        vec![],
    );
    let server = pharos_server::Server::new(router, key);
    let name: Name = "external.testns.svc.cluster.local.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut wire = Vec::with_capacity(512);
    server
        .handle(
            &query,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut wire,
        )
        .await;
    let response = Message::parse(&wire).unwrap();
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.tc(), "regular 10 must preserve truncation");
    assert_eq!(response.authority_count(), 0);
    assert_eq!(response.additional_count(), 0);
    let answers: Vec<_> = response.answers().map(|rr| record(rr, None)).collect();
    assert_eq!(
        answers,
        [
            rr(
                "external.testns.svc.cluster.local.",
                5,
                "CNAME",
                "ext.interwebs.test."
            ),
            rr("ext.interwebs.test.", 5, "A", "1.2.3.4"),
        ]
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
    api_task.abort();
}

// Skipped upstream executions: TestMultiClusterServeDNS common rows 1-34 and
// multiclusterDnsTestCases rows 1-9: multicluster.

#![forbid(unsafe_code)]
#![cfg(all(
    feature = "plugin-metadata",
    feature = "plugin-kubernetes",
    feature = "plugin-log"
))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Context, Metadata, Protocol, Transport};

// Derived from CoreDNS v1.15.0 plugin/metadata/metadata_test.go TestLabelFormat.
#[test]
fn coredns_label_format() {
    for (label, valid) in [
        ("plugin/LABEL", true),
        ("p/LABEL", true),
        ("plugin/L", true),
        ("PLUGIN/LABEL/SUB-LABEL", true),
        ("LABEL", false),
        ("plugin.LABEL", false),
        ("/NO-PLUGIN-NOT-ACCEPTED", false),
        ("ONLY-PLUGIN-NOT-ACCEPTED/", false),
        ("/", false),
        ("//", false),
    ] {
        assert_eq!(pharos_plugins::metadata::is_label(label), valid, "{label}");
    }
}

// Derived from CoreDNS v1.15.0 plugin/kubernetes/metadata_test.go.
#[tokio::test]
async fn kubernetes_metadata_is_collected_before_the_chain() {
    let blocks = parse("Corefile", ". {\n metadata\n kubernetes cluster.local clusterset.local {\n multicluster clusterset.local\n}\n}").unwrap();
    let chain = configure::<Chain>(&blocks, directives()).unwrap();
    for (name, fields) in [
        (
            "10-240-0-1.podns.pod.cluster.local.",
            vec![
                ("kind", "pod"),
                ("service", "10-240-0-1"),
                ("namespace", "podns"),
            ],
        ),
        (
            // Kubernetes DNS spec 1.1.0 §2.3.1: Service DNS names use <service>.<ns>.svc.<zone>.
            "s.ns.svc.cluster.local.",
            vec![("kind", "svc"), ("service", "s"), ("namespace", "ns")],
        ),
        (
            // KEP-1645 §Design Details > ClusterSet Service Behavior Expectations > DNS: Endpoint.
            "ep.c1.s.ns.svc.clusterset.local.",
            vec![
                ("cluster", "c1"),
                ("endpoint", "ep"),
                ("service", "s"),
                ("namespace", "ns"),
            ],
        ),
        (
            // Kubernetes DNS spec 1.1.0 §2.3.2: _<port>._<proto>.<service>.<ns>.svc.<zone>.
            "_http._tcp.s.ns.svc.cluster.local.",
            vec![
                ("port-name", "http"),
                ("protocol", "tcp"),
                ("service", "s"),
                ("namespace", "ns"),
                ("kind", "svc"),
                ("endpoint", ""),
            ],
        ),
        (
            "ep.s.ns.svc.cluster.local.",
            vec![("endpoint", "ep"), ("service", "s")],
        ),
        (
            "foo.bar.notapod.cluster.local.",
            vec![("parse-error", "invalid query name")],
        ),
    ] {
        let qname: Name = name.parse().unwrap();
        let domain: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
        builder
            .question(
                NameRef::parse(qname.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 18];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        chain[0].config.serve(&mut cx).await;
        for (label, value) in fields {
            assert_eq!(
                cx.metadata.get(&format!("kubernetes/{label}")),
                Some(value),
                "{name}"
            );
        }
    }
}

#[tokio::test]
async fn collector_scope_and_log_metadata_follow_the_directive() {
    for (directive, name, kubernetes, logged) in [
        (
            "metadata cluster.local",
            "s.ns.svc.cluster.local.",
            Some("s"),
            true,
        ),
        (
            "metadata example.org",
            "s.ns.svc.cluster.local.",
            None,
            true,
        ),
        ("", "s.ns.svc.cluster.local.", None, false),
    ] {
        let config = format!(". {{\n {directive}\n log\n kubernetes cluster.local\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &config).unwrap(), directives()).unwrap();
        let qname: Name = name.parse().unwrap();
        let domain: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
        builder
            .question(
                NameRef::parse(qname.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 18];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        chain[0].config.serve(&mut cx).await;
        assert_eq!(
            cx.metadata.get("kubernetes/service"),
            kubernetes,
            "{directive}"
        );
        assert_eq!(cx.metadata.get("log/type").is_some(), logged, "{directive}");
        let mut output = String::new();
        pharos_plugins::log_format::Format::compile("{/kubernetes/service} {/log/type}").format(
            &mut output,
            &cx,
            pharos_server::Outcome::Response,
            std::time::Duration::ZERO,
        );
        assert_eq!(
            output,
            match (kubernetes, logged) {
                (Some(_), true) => "s SERVERERROR",
                (None, true) => "- SERVERERROR",
                (None, false) => "- -",
                _ => unreachable!(),
            }
        );
    }
}

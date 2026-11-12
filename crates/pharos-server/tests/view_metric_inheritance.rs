#![forbid(unsafe_code)]

use std::sync::Arc;

use pharos_proto::{Message, Name, Rcode, Type};
use pharos_server::{
    Chain, Context, Handler, ListenerKey, Outcome, Protocol, Router, Server, Transport,
};
struct View {
    name: &'static str,
    has_view: bool,
    accepts: bool,
    writer: bool,
}

impl Chain for View {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        if self.writer {
            assert!(
                cx.metadata
                    .insert(pharos_server::metrics::WRITER_METADATA, "test")
            );
        }
        Outcome::Unanswered(Rcode::REFUSED)
    }
    fn is_empty(&self) -> bool {
        false
    }
    fn has_view(&self) -> bool {
        self.has_view
    }
    fn view_name(&self) -> &str {
        self.name
    }
    fn matches_view(&self, _: &Context<'_, '_>) -> bool {
        self.accepts
    }
    fn visit_enabled(&self, visit: &mut dyn FnMut(&'static str)) {
        visit("test");
    }
}

fn key() -> ListenerKey {
    ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    }
}

fn add(
    router: &mut Router<View>,
    domain: &str,
    name: &'static str,
    has_view: bool,
    accepts: bool,
    writer: bool,
) {
    router.add(
        key(),
        domain.parse().unwrap(),
        Some(View {
            name,
            has_view,
            accepts,
            writer,
        }),
        vec![],
    );
}

fn query(name: &str, qtype: Type) -> Vec<u8> {
    let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    wire.extend_from_slice(name.parse::<Name>().unwrap().as_wire());
    wire.extend_from_slice(&qtype.0.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire
}

#[tokio::test(flavor = "current_thread")]
async fn ds_metric_view_follows_last_matching_nonempty_candidate() {
    for writer in [false, true] {
        for parent_has_view in [false, true] {
            for incremental in [false, true] {
                let mut router = Router::default();
                add(&mut router, "example.org.", "child", true, true, false);
                if !incremental {
                    add(&mut router, "org.", "", parent_has_view, true, writer);
                }
                let mut server = Server::new(router, key());
                if incremental {
                    add(
                        Arc::get_mut(&mut server.router).unwrap(),
                        "org.",
                        "",
                        parent_has_view,
                        true,
                        writer,
                    );
                }
                let wire = query("example.org.", Type::DS);
                let mut response = Vec::with_capacity(512);
                server
                    .handle(
                        &wire,
                        "127.0.0.1:1234".parse().unwrap(),
                        Protocol::Udp,
                        &mut response,
                    )
                    .await;
                assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
                let mut metrics = String::new();
                server.metrics().encode(&mut metrics);
                assert!(metrics.contains("pharos_dns_requests_total{family=\"1\",proto=\"udp\",server=\"dns://127.0.0.1:53\",type=\"DS\",view=\"child\",zone=\"org.\"} 1\n"), "{metrics}");
                let plugin = if writer { "test" } else { "" };
                assert!(metrics.contains(&format!("pharos_dns_responses_total{{plugin=\"{plugin}\",rcode=\"REFUSED\",server=\"dns://127.0.0.1:53\",view=\"child\",zone=\"org.\"}} 1\n")), "{metrics}");
            }
        }
    }
}

#[tokio::test]
async fn named_parent_overrides_child_and_rejected_child_does_not_inherit() {
    for (parent, child_accepted, expected) in [("parent", true, "parent"), ("", false, "")] {
        let mut router = Router::default();
        add(
            &mut router,
            "example.org.",
            "child",
            true,
            child_accepted,
            false,
        );
        add(&mut router, "org.", parent, !parent.is_empty(), true, true);
        let server = Server::new(router, key());
        server
            .handle(
                &query("example.org.", Type::DS),
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut Vec::new(),
            )
            .await;
        let mut metrics = String::new();
        server.metrics().encode(&mut metrics);
        assert!(metrics.contains(&format!("plugin=\"test\",rcode=\"REFUSED\",server=\"dns://127.0.0.1:53\",view=\"{expected}\",zone=\"org.\"}} 1\n")), "{metrics}");
    }
}

#[tokio::test]
async fn metrics_select_the_inherited_view_for_each_query() {
    let mut router = Router::default();
    add(&mut router, "deep.example.org.", "deep", true, true, false);
    add(&mut router, "example.org.", "shallow", true, false, false);
    add(&mut router, "other.org.", "other", true, true, false);
    add(&mut router, "org.", "", false, true, true);
    let server = Server::new(router, key());
    let peer = "127.0.0.1:1234".parse().unwrap();
    server
        .handle(
            &query("deep.example.org.", Type::DS),
            peer,
            Protocol::Udp,
            &mut Vec::new(),
        )
        .await;
    server
        .handle(
            &query("example.org.", Type::DS),
            peer,
            Protocol::Udp,
            &mut Vec::new(),
        )
        .await;
    server
        .handle(
            &query("other.org.", Type::DS),
            peer,
            Protocol::Udp,
            &mut Vec::new(),
        )
        .await;
    server
        .handle(
            &query("deep.example.org.", Type::A),
            peer,
            Protocol::Udp,
            &mut Vec::new(),
        )
        .await;
    let mut metrics = String::new();
    server.metrics().encode(&mut metrics);
    for view in ["deep", "other", ""] {
        assert!(metrics.contains(&format!("plugin=\"test\",rcode=\"REFUSED\",server=\"dns://127.0.0.1:53\",view=\"{view}\",zone=\"org.\"}} 1\n")), "{metrics}");
    }
    assert!(metrics.contains("plugin=\"\",rcode=\"REFUSED\",server=\"dns://127.0.0.1:53\",view=\"deep\",zone=\"deep.example.org.\"} 1\n"), "{metrics}");
}

#[test]
fn legacy_root_ds_uses_first_matching_block() {
    let mut router = Router::default();
    router.add(key(), ".".parse().unwrap(), Some("first"), vec![]);
    router.add(key(), ".".parse().unwrap(), Some("last"), vec![]);
    let wire = query(".", Type::DS);
    let block = router
        .route(
            &key(),
            Message::parse(&wire).unwrap(),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
        )
        .unwrap();
    assert_eq!(block.chain(), Some(&"first"));
}

#[tokio::test]
async fn ds_empty_parent_uses_last_accepted_name_not_rejected_or_empty_views() {
    let mut router = Router::default();
    add(&mut router, "deep.example.org.", "first", true, true, false);
    add(&mut router, "example.org.", "second", true, true, false);
    add(&mut router, "org.", "rejected", true, false, false);
    add(&mut router, "org.", "", true, true, true);
    let server = Server::new(router, key());
    server
        .handle(
            &query("deep.example.org.", Type::DS),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut Vec::new(),
        )
        .await;
    let mut metrics = String::new();
    server.metrics().encode(&mut metrics);
    assert!(metrics.contains("plugin=\"test\",rcode=\"REFUSED\",server=\"dns://127.0.0.1:53\",view=\"second\",zone=\"org.\"} 1\n"), "{metrics}");
}

#[tokio::test]
async fn root_ds_inherits_and_incremental_child_updates_existing_parent() {
    for domain in [".", "org."] {
        let mut router = Router::default();
        add(&mut router, domain, "", false, true, true);
        let mut server = Server::new(router, key());
        let child = if domain == "." { "." } else { "example.org." };
        // For equal domains the named candidate must be added before the parent.
        if domain == "." {
            let mut router = Router::default();
            add(&mut router, ".", "child", true, true, false);
            add(&mut router, ".", "", false, true, true);
            server = Server::new(router, key());
        } else {
            add(
                Arc::get_mut(&mut server.router).unwrap(),
                child,
                "child",
                true,
                true,
                false,
            );
        }
        server
            .handle(
                &query(child, Type::DS),
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut Vec::new(),
            )
            .await;
        let mut metrics = String::new();
        server.metrics().encode(&mut metrics);
        assert!(metrics.contains(&format!("plugin=\"test\",rcode=\"REFUSED\",server=\"dns://127.0.0.1:53\",view=\"child\",zone=\"{domain}\"}} 1\n")), "{metrics}");
    }
}

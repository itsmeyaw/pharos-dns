#![forbid(unsafe_code)]

use std::{net::SocketAddr, sync::Arc};

use pharos_proto::{Message, Name, Rcode, Type};
use pharos_server::{
    Chain, Context, Handler, ListenerKey, Outcome, Protocol, Router, Server, Transport, ViewFilter,
};

struct View {
    name: &'static str,
    collector: Option<&'static str>,
    expected: Option<&'static str>,
    accepts: bool,
    result: Rcode,
    shed: bool,
}

impl Chain for View {
    async fn serve(&self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Unanswered(self.result)
    }

    async fn serve_with_collected_metadata(&self, cx: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(cx.metadata.get("test/value"), self.expected);
        Outcome::Unanswered(self.result)
    }

    fn is_empty(&self) -> bool {
        false
    }
    fn has_metadata_collector(&self) -> bool {
        self.collector.is_some()
    }
    fn collect_metadata(&self, cx: &mut Context<'_, '_>) {
        if let Some(value) = self.collector {
            assert!(cx.metadata.insert("test/value", value));
            if value == "child" {
                assert!(cx.metadata.insert("test/old", "old"));
            } else if value == "parent" {
                assert_eq!(cx.metadata.get("test/old"), None);
            }
        }
    }
    fn matches_view(&self, cx: &Context<'_, '_>) -> bool {
        assert_eq!(
            cx.metadata.get("test/value"),
            self.collector.or(self.expected)
        );
        self.accepts
    }
    fn has_view(&self) -> bool {
        true
    }
    fn view_name(&self) -> &str {
        self.name
    }
    fn shed_enabled(&self) -> bool {
        self.shed
    }
    fn parallel_query(&self, _: &Message<'_>) -> Option<tokio::sync::watch::Receiver<bool>> {
        self.shed.then(|| tokio::sync::watch::channel(false).1)
    }
}

#[test]
fn view_name_does_not_replace_source_and_has_no_size_limit() {
    struct Source;
    impl pharos_server::MetadataSource for Source {
        fn get(&self, label: &str) -> Option<&str> {
            (label == "kubernetes/namespace").then_some("default")
        }
    }
    let mut slots = [None; 2];
    let mut metadata = pharos_server::Metadata::new(&mut slots);
    let name: Arc<str> = "x".repeat(2048).into();
    metadata.set_source(Arc::new(Source));
    metadata.set_view_name(Arc::clone(&name));
    assert_eq!(metadata.get("view/name"), Some(name.as_ref()));
    assert_eq!(metadata.get("kubernetes/namespace"), Some("default"));
    assert!(metadata.insert("view/name", "override"));
    assert_eq!(metadata.get("view/name"), Some("override"));
}

#[tokio::test]
async fn no_view_keeps_existing_response_bytes_and_never_calls_view_hooks() {
    struct Plain;
    impl Chain for Plain {
        async fn serve(&self, _: &mut Context<'_, '_>) -> Outcome {
            Outcome::Unanswered(Rcode::REFUSED)
        }
        fn is_empty(&self) -> bool {
            false
        }
        fn has_metadata_collector(&self) -> bool {
            panic!("unexpected collector check")
        }
        fn matches_view(&self, _: &Context<'_, '_>) -> bool {
            panic!("unexpected view check")
        }
        async fn serve_with_collected_metadata(&self, _: &mut Context<'_, '_>) -> Outcome {
            panic!("unexpected collected serve")
        }
    }
    let mut router = Router::default();
    router.add(key(), ".".parse().unwrap(), Some(Plain), vec![]);
    let server = Server::new(router, key());
    let request = query("example.org.", Type::A);
    let mut expected = request.clone();
    expected[2] = 0x81;
    expected[3] = 0x05;
    let mut response = Vec::new();
    server
        .handle(
            &request,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    assert_eq!(response, expected);
}

#[tokio::test]
async fn self_lookup_uses_view_routing() {
    struct Lookup {
        name: &'static str,
        accepts: bool,
        lookup: bool,
    }
    impl Chain for Lookup {
        async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
            if self.lookup {
                let answer = cx
                    .self_lookup(&"target.other.".parse().unwrap(), Type::A)
                    .await
                    .unwrap();
                assert_eq!(Message::parse(&answer).unwrap().rcode(), Rcode::SERVFAIL);
                Outcome::Unanswered(Rcode::REFUSED)
            } else {
                Outcome::Unanswered(if self.accepts {
                    Rcode::SERVFAIL
                } else {
                    Rcode::REFUSED
                })
            }
        }
        fn is_empty(&self) -> bool {
            false
        }
        fn view_name(&self) -> &str {
            self.name
        }
        fn has_view(&self) -> bool {
            true
        }
        fn matches_view(&self, _: &Context<'_, '_>) -> bool {
            self.accepts
        }
    }
    let mut router = Router::default();
    for (domain, chain) in [
        (
            "example.org.",
            Lookup {
                name: "source",
                accepts: true,
                lookup: true,
            },
        ),
        (
            "other.",
            Lookup {
                name: "reject",
                accepts: false,
                lookup: false,
            },
        ),
        (
            "other.",
            Lookup {
                name: "target",
                accepts: true,
                lookup: false,
            },
        ),
    ] {
        router.add(key(), domain.parse().unwrap(), Some(chain), vec![]);
    }
    let server = Server::new(router, key());
    let mut response = Vec::new();
    server
        .handle(
            &query("example.org.", Type::A),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
}

fn key() -> ListenerKey {
    ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    }
}

fn query(name: &str, qtype: Type) -> Vec<u8> {
    let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    wire.extend_from_slice(name.parse::<Name>().unwrap().as_wire());
    wire.extend_from_slice(&qtype.0.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire
}

fn view(
    name: &'static str,
    collector: Option<&'static str>,
    expected: Option<&'static str>,
    accepts: bool,
    result: Rcode,
    shed: bool,
) -> Arc<View> {
    Arc::new(View {
        name,
        collector,
        expected,
        accepts,
        result,
        shed,
    })
}

fn add(router: &mut Router<Arc<View>>, domain: &str, chain: Arc<View>, filters: Vec<ViewFilter>) {
    router.add(key(), domain.parse().unwrap(), Some(chain), filters);
}

fn reject(_: &Message<'_>, _: SocketAddr, _: Protocol) -> bool {
    false
}

#[tokio::test]
async fn metadata_is_collected_before_legacy_filters_and_survives_missing_collector() {
    let mut router = Router::default();
    add(
        &mut router,
        "example.org.",
        view(
            "filtered",
            Some("retained"),
            None,
            true,
            Rcode::SERVFAIL,
            false,
        ),
        vec![reject],
    );
    add(
        &mut router,
        "example.org.",
        view(
            "selected",
            None,
            Some("retained"),
            true,
            Rcode::REFUSED,
            true,
        ),
        vec![],
    );
    let server = Server::new(router, key());
    let peer = "127.0.0.1:1234".parse().unwrap();
    let mut response = Vec::new();
    server
        .handle(
            &query("example.org.", Type::A),
            peer,
            Protocol::Tcp,
            &mut response,
        )
        .await;
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
    let mut metrics = String::new();
    server.metrics().encode(&mut metrics);
    assert!(
        metrics.contains("view=\"selected\",zone=\"example.org.\"} 1"),
        "{metrics}"
    );
    assert!(server.shed_query(&query("example.org.", Type::A), peer));
    assert!(
        server
            .parallel_query(&query("example.org.", Type::HINFO), peer)
            .is_some()
    );
}

#[tokio::test]
async fn empty_named_view_still_filters_when_added_after_server_creation() {
    let mut server = Server::new(Router::default(), key());
    let router = Arc::get_mut(&mut server.router).unwrap();
    add(
        router,
        "example.org.",
        view("", None, None, false, Rcode::SERVFAIL, false),
        vec![],
    );
    let mut response = Vec::new();
    server
        .handle(
            &query("example.org.", Type::A),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
}

#[tokio::test]
async fn ds_uses_last_matching_handler_but_metadata_from_later_rejected_collector() {
    let mut router = Router::default();
    add(
        &mut router,
        "example.org.",
        view(
            "child",
            Some("child"),
            Some("child"),
            true,
            Rcode::SERVFAIL,
            false,
        ),
        vec![],
    );
    add(
        &mut router,
        "org.",
        view(
            "parent",
            Some("parent"),
            Some("later"),
            true,
            Rcode::REFUSED,
            false,
        ),
        vec![],
    );
    add(
        &mut router,
        "org.",
        view(
            "later",
            Some("later"),
            Some("later"),
            false,
            Rcode::SERVFAIL,
            false,
        ),
        vec![],
    );
    let server = Server::new(router, key());
    let mut response = Vec::new();
    server
        .handle(
            &query("example.org.", Type::DS),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
}

#[tokio::test]
async fn root_ds_uses_last_matching_view() {
    let mut router = Router::default();
    add(
        &mut router,
        ".",
        view("first", None, None, true, Rcode::SERVFAIL, false),
        vec![],
    );
    add(
        &mut router,
        ".",
        view("last", None, None, true, Rcode::REFUSED, false),
        vec![],
    );
    let server = Server::new(router, key());
    let mut response = Vec::new();
    server
        .handle(
            &query(".", Type::DS),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
}

#[tokio::test]
async fn view_without_collector_does_not_enable_metadata() {
    struct NoCollector;
    impl Chain for NoCollector {
        async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
            assert!(!cx.metadata.enabled());
            Outcome::Unanswered(Rcode::REFUSED)
        }
        fn is_empty(&self) -> bool {
            false
        }
        fn has_view(&self) -> bool {
            true
        }
        fn matches_view(&self, cx: &Context<'_, '_>) -> bool {
            assert!(!cx.metadata.enabled());
            true
        }
    }
    let mut router = Router::default();
    router.add(key(), ".".parse().unwrap(), Some(NoCollector), vec![]);
    let server = Server::new(router, key());
    let mut response = Vec::new();
    server
        .handle(
            &query("example.org.", Type::A),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response,
        )
        .await;
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
}

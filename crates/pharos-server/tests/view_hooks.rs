#![forbid(unsafe_code)]

use std::{net::SocketAddr, sync::Arc};

use pharos_proto::{Message, Name, Rcode, Type};
use pharos_server::{Chain, Context, Handler, ListenerKey, Outcome, Protocol, Router, Server, Transport};

struct View {
    name: &'static str,
    accepts: bool,
    shed: bool,
}

impl Chain for View {
    async fn serve(&self, cx: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(cx.metadata.get("test/view"), Some(self.name));
        Outcome::Unanswered(if self.shed { Rcode::SERVFAIL } else { Rcode::REFUSED })
    }

    fn is_empty(&self) -> bool { false }

    fn collect_metadata(&self, cx: &mut Context<'_, '_>) {
        assert!(cx.metadata.insert("test/view", self.name));
    }

    fn matches_view(&self, cx: &Context<'_, '_>) -> bool {
        assert_eq!(cx.metadata.get("test/view"), Some(self.name));
        assert_eq!(cx.local, "127.0.0.1:53".parse().unwrap());
        assert_eq!(cx.client, "127.0.0.1:1234".parse().unwrap());
        assert!(matches!(cx.protocol, Protocol::Udp | Protocol::Tcp));
        self.accepts
    }

    fn view_name(&self) -> &str { self.name }

    fn shed_enabled(&self) -> bool { self.shed }

    fn parallel_query(&self, _: &Message<'_>) -> Option<tokio::sync::watch::Receiver<bool>> {
        self.shed.then(|| tokio::sync::watch::channel(false).1)
    }
}

fn query(name: &str, qtype: Type) -> Vec<u8> {
    let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    wire.extend_from_slice(name.parse::<Name>().unwrap().as_wire());
    wire.extend_from_slice(&qtype.0.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire
}

fn server() -> Server<Arc<View>> {
    let key = ListenerKey { transport: Transport::Dns, address: "127.0.0.1:53".parse().unwrap() };
    let mut router = Router::default();
    for (domain, name, accepts, shed) in [
        ("example.org.", "rejected", false, false),
        ("example.org.", "selected", true, true),
        ("example.org.", "later", true, false),
        ("org.", "parent", true, false),
        ("org.", "rejected-parent", false, true),
    ] {
        router.add(key, domain.parse().unwrap(), Some(Arc::new(View { name, accepts, shed })), vec![]);
    }
    Server::new(router, key)
}

#[tokio::test]
async fn selected_view_retains_metadata_and_records_its_name() {
    let server = server();
    let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let mut response = Vec::new();
    server.handle(&query("example.org.", Type::A), peer, Protocol::Tcp, &mut response).await;
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::SERVFAIL);
    let mut metrics = String::new();
    server.metrics().encode(&mut metrics);
    assert!(metrics.contains("view=\"selected\",zone=\"example.org.\"} 1"), "{metrics}");
}

#[tokio::test]
async fn ds_preserves_selected_parent_metadata_after_rejected_candidate() {
    let server = server();
    let mut response = Vec::new();
    server.handle(&query("example.org.", Type::DS), "127.0.0.1:1234".parse().unwrap(), Protocol::Udp, &mut response).await;
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
    let mut metrics = String::new();
    server.metrics().encode(&mut metrics);
    assert!(metrics.contains("view=\"parent\",zone=\"org.\"} 1"), "{metrics}");
}

#[test]
fn shed_and_parallel_dispatch_use_selected_view() {
    let server = server();
    let peer = "127.0.0.1:1234".parse().unwrap();
    assert!(server.shed_query(&query("example.org.", Type::A), peer));
    assert!(server.parallel_query(&query("example.org.", Type::HINFO), peer).is_some());
}

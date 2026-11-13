#![forbid(unsafe_code)]

use pharos_server::{
    Action, Chain, Context, Error, Handler, ListenerKey, Outcome, Protocol, Router, Server,
    Transport,
};
use std::sync::Arc;

struct Broken;

struct Panicking {
    zones: pharos_server::metrics::DynamicZones,
}

impl Chain for Panicking {
    async fn serve(&self, _: &mut Context<'_, '_>) -> Outcome {
        panic!("test panic")
    }

    fn is_empty(&self) -> bool {
        false
    }

    fn dynamic_metric_zones(&self) -> Option<&pharos_server::metrics::DynamicZones> {
        Some(&self.zones)
    }
}

#[tokio::test]
async fn dynamic_zones_keep_panic_in_dropped_metrics() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let zones = pharos_server::metrics::DynamicZones::default();
    zones.publish(vec!["example.org.".parse().unwrap()]);
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(Panicking { zones }), vec![]);
    let mut server = Server::new(router, key);
    server.logger = |_| {};
    let query = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\x03org\0\0\x01\0\x01";
    assert_eq!(
        server
            .handle(
                query,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut Vec::with_capacity(512)
            )
            .await,
        Action::Respond
    );
    let mut text = String::new();
    server.metrics().encode(&mut text);
    assert!(
        text.contains("type=\"A\",view=\"\",zone=\"dropped\"} 1"),
        "{text}"
    );
    assert!(
        !text.contains("type=\"A\",view=\"\",zone=\"example.org.\"} 1"),
        "{text}"
    );
}

impl Chain for Broken {
    async fn serve(&self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Error(Error::InvalidQuery)
    }

    fn is_empty(&self) -> bool {
        false
    }
}

#[tokio::test]
async fn server_records_query_and_unanswered_response() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut router = Router::default();
    router.add(key, ".".parse().unwrap(), Some(Broken), vec![]);
    let mut server = Server::new(router, key);
    server.logger = |_| {};
    let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 13, 0, 1];
    let mut response = Vec::with_capacity(512);
    assert_eq!(
        server
            .handle(
                &query,
                "127.0.0.1:1234".parse().unwrap(),
                Protocol::Udp,
                &mut response
            )
            .await,
        Action::Respond
    );
    let mut text = String::new();
    server.metrics().encode(&mut text);
    assert!(text.contains("pharos_dns_requests_total{family=\"1\",proto=\"udp\",server=\"dns://127.0.0.1:53\",type=\"other\",view=\"\",zone=\".\"} 1\n"), "{text}");
    assert!(text.contains("pharos_dns_responses_total{plugin=\"\",rcode=\"SERVFAIL\",server=\"dns://127.0.0.1:53\",view=\"\",zone=\".\"} 1\n"), "{text}");
    assert!(text.contains("pharos_dns_response_size_bytes_sum{proto=\"udp\",server=\"dns://127.0.0.1:53\",view=\"\",zone=\".\"} 0\n"), "{text}");
}

#[tokio::test]
async fn blocks_added_after_server_creation_record_metrics() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut server = Server::new(Router::default(), key);
    server.logger = |_| {};
    Arc::get_mut(&mut server.router)
        .unwrap()
        .add(key, ".".parse().unwrap(), Some(Broken), vec![]);
    let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
    server
        .handle(
            &query,
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut Vec::with_capacity(512),
        )
        .await;
    let mut text = String::new();
    server.metrics().encode(&mut text);
    assert!(text.contains("zone=\".\"} 1"), "{text}");
}

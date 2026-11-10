#![forbid(unsafe_code)]

use pharos_server::{
    Action, Chain, Context, Error, Handler, ListenerKey, Outcome, Protocol, Router, Server,
    Transport,
};

struct Broken;

impl Chain for Broken {
    async fn serve(&self, _: &mut Context<'_>) -> Outcome {
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
    server
        .router
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

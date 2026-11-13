use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
use stats_alloc::INSTRUMENTED_SYSTEM;

#[tokio::test]
async fn sign_adds_no_query_allocations() {
    if crate::run_isolated("sign_allocations::sign_adds_no_query_allocations") {
        return;
    }
    let blocks = parse("Corefile", ". {\n sign missing.zone\n whoami\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let domain: Name = ".".parse().unwrap();
    let wire = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
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
    assert_eq!(configured[0].config.serve(&mut cx).await, Outcome::Response);
    let before = INSTRUMENTED_SYSTEM.stats();
    for _ in 0..100 {
        assert_eq!(configured[0].config.serve(&mut cx).await, Outcome::Response);
    }
    let after = INSTRUMENTED_SYSTEM.stats();
    assert_eq!(
        (
            after.allocations - before.allocations,
            after.reallocations - before.reallocations
        ),
        (0, 0)
    );
}

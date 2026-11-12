#![cfg(all(feature = "plugin-tsig", feature = "plugin-whoami"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name, TsigAlgorithm, TsigKey};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region};
use std::{
    future::Future,
    task::{Context as TaskContext, Poll, Waker},
};

#[test]
fn tsig_verification_and_signing_do_not_allocate() {
    if crate::run_isolated("tsig::cases::tsig_verification_and_signing_do_not_allocate") {
        return;
    }
    let blocks = parse(
        "Corefile",
        ". {\n tsig {\n secret key. c2VjcmV0\n }\n whoami\n}",
    )
    .unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let key = TsigKey::new("key.".parse().unwrap(), TsigAlgorithm::Sha256, b"secret");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut wire = Vec::with_capacity(512);
    wire.extend_from_slice(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1]);
    key.sign(&mut wire, now, 300, None).unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
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
    let region = Region::new(&INSTRUMENTED_SYSTEM);
    let result = {
        let mut future = std::pin::pin!(configured[0].config.serve(&mut cx));
        future
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()))
    };
    let signing = cx.metadata.take_tsig_signing();
    let action = pharos_server::finish_outcome_signed(
        Message::parse(&wire).unwrap(),
        Protocol::Udp,
        Outcome::Response,
        &mut response,
        signing,
        |_| panic!("finalization failed"),
    );
    let stats = region.change();
    assert_eq!(result, Poll::Ready(Outcome::Response));
    assert_eq!(action, pharos_server::Action::Respond);
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
}

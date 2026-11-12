#![cfg(all(feature = "plugin-dnssec", feature = "plugin-whoami"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::{Action, Handler, Protocol};

#[tokio::test(flavor = "current_thread")]
async fn no_do_and_warmed_signature_hits_do_not_allocate() {
    if crate::run_isolated("dnssec::cases::no_do_and_warmed_signature_hits_do_not_allocate") {
        return;
    }
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl:0 {{\n dnssec {{\n key file {base}\n }}\n whoami\n}}");
    let (mut servers, _) =
        servers(configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap())
            .unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let unsigned = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x03www\x04miek\x02nl\0\0\x01\0\x01";
    let dnskey = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x04miek\x02nl\0\0\x30\0\x01";
    let signed = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\x01\x03www\x04miek\x02nl\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\x80\0\0\0";
    let peer = "127.0.0.1:1001".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    for query in [unsigned.as_slice(), dnskey.as_slice(), signed.as_slice()] {
        assert_eq!(
            server
                .handle(query, peer, Protocol::Udp, &mut response)
                .await,
            Action::Respond
        );
        if query == signed {
            let message = pharos_proto::Message::parse(&response).unwrap();
            assert!(
                message
                    .additionals()
                    .any(|rr| rr.rtype == pharos_proto::Type::RRSIG)
            );
        }
        let before = crate::GLOBAL.stats();
        for _ in 0..100 {
            assert_eq!(
                server
                    .handle(query, peer, Protocol::Udp, &mut response)
                    .await,
                Action::Respond
            );
        }
        let after = crate::GLOBAL.stats();
        assert_eq!(after.allocations - before.allocations, 0);
        assert_eq!(after.reallocations - before.reallocations, 0);
    }
}

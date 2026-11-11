#![forbid(unsafe_code)]
#![cfg(feature = "plugin-multisocket")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// CoreDNS v1.15.0 plugin/multisocket/multisocket_test.go.
#[test]
fn setup_accepts_socket_counts_and_rejects_invalid_directives() {
    for (input, expected) in [
        ("multisocket", None),
        ("multisocket 2", Some(2)),
        ("multisocket 1024", Some(1024)),
        (" multisocket 1", Some(1)),
    ] {
        let blocks = parse("Corefile", &format!(".:53 {{\n{input}\n}}")).unwrap();
        let configured = configure::<Chain>(&blocks, directives()).unwrap();
        assert_eq!(configured[0].config.multisocket, Some(expected));
    }
    for input in [
        "multisocket text",
        "multisocket 0",
        "multisocket -1",
        "multisocket 1025",
        "multisocket 2 2",
        "multisocket 2 {\n block\n}",
        "multisocket 2\n multisocket 3",
    ] {
        let blocks = parse("Corefile", &format!(".:53 {{\n{input}\n}}")).unwrap();
        assert!(
            configure::<Chain>(&blocks, directives()).is_err(),
            "{input}"
        );
    }
}

#[test]
fn first_server_block_sets_each_listeners_count() {
    let input = "first.example:1053 {\n multisocket 3\n whoami\n}\nsecond.example:1053 {\n multisocket 5\n whoami\n}\nthird.example:1054 {\n multisocket 2\n whoami\n}";
    let blocks = parse("Corefile", input).unwrap();
    let (servers, _) =
        pharos_plugins::servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    for (key, server) in servers {
        assert_eq!(
            server.udp_workers,
            if key.address.port() == 1053 { 3 } else { 2 }
        );
    }
}

#[test]
fn first_block_without_multisocket_keeps_the_default_count() {
    struct DefaultWorkers;
    impl pharos_server::Handler for DefaultWorkers {
        async fn handle(
            &self,
            _: &[u8],
            _: std::net::SocketAddr,
            _: pharos_server::Protocol,
            _: &mut Vec<u8>,
        ) -> pharos_server::Action {
            pharos_server::Action::Drop
        }
    }
    let default = parse("Corefile", "first.example:1053 {\n whoami\n}").unwrap();
    let (default, _) =
        pharos_plugins::servers(configure::<Chain>(&default, directives()).unwrap()).unwrap();
    let expected = default.values().next().unwrap().udp_workers;
    assert_eq!(
        expected,
        pharos_server::Handler::udp_workers(&DefaultWorkers)
    );
    let shared = parse(
        "Corefile",
        "first.example:1053 {\n whoami\n}\nsecond.example:1053 {\n multisocket 1024\n whoami\n}",
    )
    .unwrap();
    let (shared, _) =
        pharos_plugins::servers(configure::<Chain>(&shared, directives()).unwrap()).unwrap();
    assert_eq!(shared.values().next().unwrap().udp_workers, expected);
    let explicit = parse("Corefile", "first.example:1053 {\n multisocket\n whoami\n}").unwrap();
    let (explicit, _) =
        pharos_plugins::servers(configure::<Chain>(&explicit, directives()).unwrap()).unwrap();
    assert_eq!(explicit.values().next().unwrap().udp_workers, expected);
}

#![recursion_limit = "512"]
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

#![forbid(unsafe_code)]
#![cfg(feature = "plugin-shed")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

#[test]
fn coredns_shed_setup_cases() {
    for (directive, valid) in [
        ("shed", true),
        ("shed extra", false),
        ("shed {\n depth 10\n}", false),
        ("shed\n shed", false),
    ] {
        let text = format!(".:53 {{\n{directive}\n}}");
        assert_eq!(
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).is_ok(),
            valid,
            "{directive}"
        );
    }
    for transport in ["tls", "grpc", "https", "quic"] {
        let text = format!("{transport}://.:53 {{\n shed\n}}");
        assert!(
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).is_err(),
            "{transport}"
        );
    }
}

#[cfg(feature = "plugin-whoami")]
#[test]
fn shared_listener_sheds_only_matching_blocks() {
    use pharos_server::Handler;
    let text = "one.example:53 {\n shed\n whoami\n}\ntwo.example:53 {\n whoami\n}";
    let blocks = configure::<Chain>(&parse("Corefile", text).unwrap(), directives()).unwrap();
    let (servers, _) = pharos_plugins::servers(blocks).unwrap();
    let server = servers.values().next().unwrap();
    assert!(server.shed_metrics().is_some());
    let peer = "127.0.0.1:1234".parse().unwrap();
    for (name, expected) in [("one.example.", true), ("two.example.", false)] {
        let name: pharos_proto::Name = name.parse().unwrap();
        let mut wire = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        wire.extend_from_slice(name.as_wire());
        wire.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(server.shed_query(&wire, peer), expected);
    }
}

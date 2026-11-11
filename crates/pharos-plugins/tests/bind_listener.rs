#![forbid(unsafe_code)]
#![recursion_limit = "512"]
#![cfg(feature = "plugin-bind")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};

fn configure_input(
    input: &str,
) -> Result<Vec<pharos_corefile::BlockContext<Chain>>, pharos_corefile::Error> {
    configure(&parse("Corefile", input)?, directives())
}

#[test]
fn specific_listeners_are_distinct_and_duplicates_rejected() {
    let blocks =
        configure_input(".:1053 {\n bind 127.0.0.1\n}\n.:1053 {\n bind 127.0.0.2\n}").unwrap();
    let (servers, _) = servers(blocks).unwrap();
    assert_eq!(servers.len(), 2);
    for address in ["127.0.0.1:1053", "127.0.0.2:1053"] {
        assert!(
            servers
                .keys()
                .any(|key| key.address == address.parse().unwrap())
        );
    }
    for second in ["bind 127.0.0.1", ""] {
        assert!(
            configure_input(&format!(
                ".:1053 {{\n bind 127.0.0.1\n}}\n.:1053 {{\n {second}\n}}"
            ))
            .is_err()
        );
    }
    assert!(configure_input(".:1053 {\n}\n.:1053 {\n bind 127.0.0.1\n}").is_err());
    assert!(configure_input("example.org:1053 {\n}\nother.org:1053 {\n bind 127.0.0.1\n}").is_ok());
}

#[test]
fn scoped_ipv6_listener_resolves_interface_index() {
    let interface = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };
    let mut blocks = configure_input(".:1053 {\n bind ::1\n}").unwrap();
    blocks[0].listen_addresses = vec![format!("fe80::1%{interface}")];
    let (servers, _) = servers(blocks).unwrap();
    let address = servers.keys().next().unwrap().address;
    assert!(matches!(address, std::net::SocketAddr::V6(address) if address.scope_id() != 0));
}

#[test]
fn ipv4_mapped_ipv6_address_uses_ipv4_listener() {
    let blocks = configure_input(".:1053 {\n bind ::ffff:127.0.0.1\n}").unwrap();
    let (servers, _) = servers(blocks).unwrap();
    assert_eq!(
        servers.keys().next().unwrap().address,
        "127.0.0.1:1053".parse().unwrap()
    );
}

#[cfg(all(feature = "plugin-prometheus", feature = "plugin-whoami"))]
#[test]
fn metrics_use_specific_listener_address() {
    let blocks = configure_input(".:1053 {\n bind 127.0.0.1\n prometheus\n whoami\n}").unwrap();
    let (servers, _) = servers(blocks).unwrap();
    let mut text = String::new();
    servers.values().next().unwrap().metrics().encode(&mut text);
    assert!(text.contains("server=\"dns://127.0.0.1:1053\""), "{text}");
}

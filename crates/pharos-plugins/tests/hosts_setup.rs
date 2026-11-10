#![forbid(unsafe_code)]
#![cfg(feature = "plugin-hosts")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

fn accepts(directive: &str) -> bool {
    let text = format!(".:53 {{\n{directive}\n}}");
    parse("Corefile", &text)
        .and_then(|blocks| configure::<Chain>(&blocks, directives()))
        .is_ok()
}

#[test]
fn accepts_coredns_hosts_setup_cases() {
    for text in [
        "hosts",
        "hosts /tmp",
        "hosts /etc/hosts miek.nl. pun.gent.",
        "hosts /etc/hosts miek.nl 10.0.0.9/8 {\n fallthrough\n}",
        "hosts highly_unlikely_to_exist_hosts_file example.org {\n 10.0.0.1 example.org\n fallthrough\n}",
        "hosts /etc/coredns/NodeHosts {\n ttl 60\n reload 15s\n fallthrough\n}",
        "hosts {\n no_reverse\n ttl 65535 ignored\n reload 0\n fallthrough example.org\n fallthrough_unsupported\n}",
    ] {
        assert!(accepts(text), "rejected {text}");
    }
}

#[test]
fn rejects_coredns_invalid_hosts_setup_cases() {
    for text in [
        "hosts\n hosts",
        "hosts {\n fallthrough\n 10.0.0.1 example.org\n}",
        "hosts {\n ttl\n}",
        "hosts {\n ttl 0\n}",
        "hosts {\n ttl 65536\n}",
        "hosts {\n reload -1s\n}",
        "hosts {\n reload 1s extra\n}",
        "hosts {\n fallthrough_unsupported\n}",
        "hosts {\n fallthrough\n fallthrough_unsupported extra\n}",
    ] {
        assert!(!accepts(text), "accepted {text}");
    }
}

#[test]
fn setup_keeps_defaults_domains_and_nodehosts_options() {
    let text = "example.org:53 {\n hosts NodeHosts {\n ttl 60\n reload 15s\n fallthrough\n }\n}";
    let blocks = parse("/etc/coredns/Corefile", text).unwrap();
    let blocks = configure::<Chain>(&blocks, directives()).unwrap();
    let hosts = blocks[0].config.hosts.as_ref().unwrap();
    assert_eq!(hosts.path, std::path::Path::new("/etc/coredns/NodeHosts"));
    assert_eq!(hosts.domains, ["example.org."]);
    assert_eq!(hosts.ttl, 60);
    assert_eq!(hosts.reload, std::time::Duration::from_secs(15));
    assert!(hosts.auto_reverse);
    assert!(hosts.fallthrough.through("anything.example."));

    let blocks = parse("Corefile", ".:53 {\n hosts\n}").unwrap();
    let blocks = configure::<Chain>(&blocks, directives()).unwrap();
    let hosts = blocks[0].config.hosts.as_ref().unwrap();
    assert_eq!(hosts.path, std::path::Path::new("/etc/hosts"));
    assert_eq!(hosts.ttl, 3600);
    assert_eq!(hosts.reload, std::time::Duration::from_secs(5));
    assert!(!hosts.fallthrough.through("example.org."));
}

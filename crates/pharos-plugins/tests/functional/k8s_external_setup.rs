#![cfg(feature = "plugin-k8s-external")]

use pharos_corefile::{Cursor, parse};
use pharos_plugins::k8s_external::setup::{Config, parse as parse_setup};

fn config(text: &str) -> Result<Config, pharos_corefile::Error> {
    let blocks = parse("Corefile", &format!(".:53 {{\n{text}\n}}"))?;
    let tokens = &blocks[0].directives["k8s_external"];
    parse_setup(&mut Cursor::new("Corefile", tokens), &["."])
}

#[test]
fn coredns_setup_defaults_and_options() {
    let defaults = config("k8s_external").unwrap();
    assert_eq!(defaults.zones, ["."]);
    assert_eq!(defaults.apex, "dns");
    assert_eq!(defaults.ttl, 5);
    assert!(!defaults.headless);

    let custom = config("k8s_external example.org {\n apex testdns\n ttl 30\n headless\n fallthrough ip6.arpa in-addr.arpa\n}").unwrap();
    assert_eq!(custom.zones, ["example.org."]);
    assert_eq!(custom.apex, "testdns");
    assert_eq!(custom.ttl, 30);
    assert!(custom.headless);
    assert_eq!(custom.fallthrough.domains, ["ip6.arpa.", "in-addr.arpa."]);
}

#[test]
fn coredns_setup_rejects_bad_options() {
    for option in ["ttl", "ttl -1", "ttl 3601", "ttl nope", "apex", "unknown"] {
        assert!(
            config(&format!("k8s_external example.org {{\n {option}\n}}")).is_err(),
            "{option}"
        );
    }
    assert!(
        config("k8s_external example.org {\n ttl 0 extra\n apex dns extra\n headless extra\n}")
            .is_ok()
    );
}

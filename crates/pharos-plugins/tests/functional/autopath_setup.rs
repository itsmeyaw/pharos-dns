#![forbid(unsafe_code)]
#![cfg(feature = "plugin-autopath")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/autopath/setup_test.go.
#[test]
fn coredns_autopath_setup_cases() {
    let file = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/autopath-resolv.conf"
    );
    for (directive, valid) in [
        ("autopath @kubernetes".to_owned(), true),
        ("autopath example.org @kubernetes".to_owned(), true),
        ("autopath 10.0.0.0/8 @kubernetes".to_owned(), true),
        (format!("autopath {file}"), true),
        ("autopath kubernetes".to_owned(), false),
        ("autopath".to_owned(), false),
        ("autopath \"\"".to_owned(), false),
    ] {
        let text = format!(".:53 {{\n {directive}\n}}");
        let blocks = parse("Corefile", &text).unwrap();
        assert_eq!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            valid,
            "{directive}"
        );
    }
}

// CoreDNS setup resolves @providers after all Plugins have initialized.
#[cfg(feature = "plugin-whoami")]
#[test]
fn autopath_provider_must_implement_autopather_if_present() {
    for (provider, valid) in [
        ("@missing", true),
        ("@kubernetes", true),
        ("@whoami", false),
    ] {
        let text = format!(".:53 {{\n autopath {provider}\n whoami\n}}");
        let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
        assert_eq!(pharos_plugins::servers(blocks).is_ok(), valid, "{provider}");
    }
}

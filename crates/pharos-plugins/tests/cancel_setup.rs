#![forbid(unsafe_code)]
#![cfg(feature = "plugin-cancel")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

#[test]
fn coredns_cancel_setup_cases() {
    for directive in ["cancel", "cancel 5s", "cancel 1h30m", "cancel 1ms"] {
        let text = format!(".:53 {{\n{directive}\n}}");
        assert!(
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).is_ok(),
            "{directive}"
        );
    }
    for directive in [
        "cancel 5",
        "cancel -1s",
        "cancel 0",
        "cancel 0s",
        "cancel 1s extra",
    ] {
        let text = format!(".:53 {{\n{directive}\n}}");
        assert!(
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).is_err(),
            "{directive}"
        );
    }
}

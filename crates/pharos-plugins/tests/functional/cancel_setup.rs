#![forbid(unsafe_code)]
#![cfg(feature = "plugin-cancel")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

#[test]
fn coredns_cancel_setup_cases() {
    for directive in [
        "cancel",
        "cancel 5s",
        "cancel 1h30m",
        "cancel 1ms",
        "cancel 2s\ncancel 3s",
    ] {
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

#[test]
fn repeated_cancel_uses_last_timeout() {
    let text = ".:53 {\n cancel 2s\n cancel 3s\n}";
    let blocks = configure::<Chain>(&parse("Corefile", text).unwrap(), directives()).unwrap();
    assert_eq!(
        blocks[0].config.cancel.as_ref().unwrap().timeout,
        std::time::Duration::from_secs(3)
    );
}

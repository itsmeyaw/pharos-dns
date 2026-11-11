#![forbid(unsafe_code)]
#![cfg(feature = "plugin-debug")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};

#[test]
fn coredns_debug_setup_cases() {
    for (directive, valid) in [("debug", true), ("debug\ndebug", true), ("debug off", false)] {
        let text = format!(".:53 {{\n{directive}\n}}");
        assert_eq!(
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).is_ok(),
            valid,
            "{directive}"
        );
    }
}

#[test]
#[cfg(all(feature = "plugin-whoami", feature = "plugin-errors"))]
fn debug_in_one_block_disables_recovery_for_all_listeners() {
    let text = "one.example:1053 {\n debug\n whoami\n}\ntwo.example:1054 {\n errors\n whoami\n}";
    let blocks = configure::<Chain>(&parse("Corefile", text).unwrap(), directives()).unwrap();
    let (servers, _) = servers(blocks).unwrap();
    assert_eq!(servers.len(), 2);
    assert!(servers.values().all(|server| server.debug));
}

#[test]
fn coredns_hexdump_vector() {
    let wire = b"\x00\x0a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x07example\x05local\x00\x00\x01\x00\x01\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00";
    assert_eq!(
        pharos_plugins::debug::hexdump(wire),
        "debug: 000000 00 0a 01 00 00 01 00 00 00 00 00 01 07 65 78 61\ndebug: 000010 6d 70 6c 65 05 6c 6f 63 61 6c 00 00 01 00 01 00\ndebug: 000020 00 29 10 00 00 00 80 00 00 00\ndebug: 00002a"
    );
}

#[test]
fn debug_logging_is_enabled_only_after_startup() {
    if std::env::var_os("PHAROS_DEBUG_TEST").is_some() {
        pharos_plugins::debug::log_message("before", &[1]);
        let blocks =
            configure::<Chain>(&parse("Corefile", ". {\n debug\n}").unwrap(), directives())
                .unwrap();
        let (_, lifecycle) = servers(blocks).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(lifecycle.run(pharos_server::Phase::Started))
            .unwrap();
        pharos_plugins::debug::log_message("after", &[1]);
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "debug_logging_is_enabled_only_after_startup",
            "--nocapture",
        ])
        .env("PHAROS_DEBUG_TEST", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("before"), "{stdout}");
    assert!(
        stdout.contains("DEBUG debug: after\ndebug: 000000 01\ndebug: 000001"),
        "{stdout}"
    );
}

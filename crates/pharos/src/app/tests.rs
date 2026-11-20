use std::{cell::RefCell, io};

use super::{corefile_hash, digest_hex, interval, shutdown};

#[tokio::test]
async fn retired_handlers_have_a_deadline_and_accept_shutdown_signals() {
    use pharos_server::{ListenerKey, Transport};
    use std::{sync::Arc, time::Duration};
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let handler = Arc::new(());
    let retired = vec![pharos_server::RetiredHandler {
        key,
        handler: Arc::clone(&handler),
        shutdown: None,
    }];
    let result =
        super::drain_retired(&retired, Duration::from_millis(10), std::future::pending()).await;
    assert_eq!(result, None);
    let result = super::drain_retired(&retired, Duration::from_secs(5), async {
        super::StopSignal::Interrupt
    })
    .await;
    assert_eq!(result, Some(super::StopSignal::Interrupt));
}

#[test]
fn startup_domains_render_bound_ipv6_addresses() {
    let (_, _, domains, _, _, _) = super::prepare(
        &crate::Options::default(),
        "Corefile",
        ".:1053 {\n bind ::1\n whoami\n}",
        &pharos_server::metrics::Registry::default(),
    )
    .unwrap();
    let (address, names) = domains.first_key_value().unwrap();
    let names: Vec<_> = names.iter().map(String::as_str).collect();
    assert_eq!(
        pharos_server::startup_domains("", address, &names),
        ".:1053 on ::1\n"
    );
}

#[test]
fn unicode_corefile_key_routes_raw_utf8_query_name() {
    // RFC 4343 §2.1: normalized Corefile keys must be parseable ASCII presentation names.
    let (servers, _, domains, _, _, _) = super::prepare(
        &crate::Options::default(),
        "Corefile",
        "MÜNICH.example:1053 {\nwhoami\n}",
        &pharos_server::metrics::Registry::default(),
    )
    .unwrap();
    assert_eq!(
        domains.values().next().unwrap(),
        &[r"m\195\188nich.example.".to_owned()]
    );
    let (_, server) = servers.iter().next().unwrap();
    let wire = [
        0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'm', 0xc3, 0xbc, b'n', b'i', b'c', b'h', 7, b'e',
        b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1,
    ];
    assert!(
        server
            .router
            .route(
                &server.key,
                pharos_proto::Message::parse(&wire).unwrap(),
                "127.0.0.1:1234".parse().unwrap(),
                pharos_server::Protocol::Udp,
            )
            .is_some()
    );
}

#[test]
fn hash_preserves_line_boundaries_that_change_directive_arguments() {
    let same_line = pharos_corefile::parse(
        "Corefile",
        ". {\n errors {\n consolidate 3s pattern warning\n }\n}",
    )
    .unwrap();
    let new_line = pharos_corefile::parse(
        "Corefile",
        ". {\n errors {\n consolidate 3s pattern\n warning\n }\n}",
    )
    .unwrap();
    assert_ne!(corefile_hash(&same_line), corefile_hash(&new_line));
    assert!(
        pharos_corefile::configure::<pharos_plugins::Chain>(
            &same_line,
            pharos_plugins::directives()
        )
        .is_ok()
    );
    assert!(
        pharos_corefile::configure::<pharos_plugins::Chain>(
            &new_line,
            pharos_plugins::directives()
        )
        .is_err()
    );
}

#[test]
fn sha512_and_jitter_match_reload_contract() {
    assert_eq!(
        digest_hex(aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA512,
            b"abc"
        )),
        concat!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
    );
    let config = pharos_plugins::reload::Reload {
        interval: std::time::Duration::from_secs(10),
        jitter: std::time::Duration::from_secs(4),
    };
    for _ in 0..100 {
        let duration = interval(config);
        assert!(duration >= std::time::Duration::from_secs(8));
        assert!(duration < std::time::Duration::from_secs(12));
    }
}

#[tokio::test]
async fn shutdown_hooks_run_before_pidfile_removal_and_listener_stop() {
    for (terminate, hook_fails, stop_fails, expected) in [
        (true, false, false, 0),
        (true, true, false, 4),
        (true, false, true, 3),
        (true, true, true, 3),
        (false, false, true, 0),
        (false, true, true, 4),
    ] {
        let steps = RefCell::new(Vec::new());
        let hooks = async {
            steps.borrow_mut().push("hooks");
            if hook_fails {
                Err(io::Error::other("hook"))
            } else {
                Ok(())
            }
        };
        let remove = || steps.borrow_mut().push("pidfile");
        let stop = async {
            steps.borrow_mut().push("stop");
            if stop_fails {
                Err(io::Error::other("stop"))
            } else {
                Ok(())
            }
        };
        assert_eq!(shutdown(terminate, hooks, remove, stop).await, expected);
        assert_eq!(*steps.borrow(), ["hooks", "pidfile", "stop"]);
    }
}

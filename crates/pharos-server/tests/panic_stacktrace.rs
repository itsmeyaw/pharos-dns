#![forbid(unsafe_code)]

use pharos_server::{
    Chain, Context, Handler, ListenerKey, Outcome, Protocol, Router, Server, Transport,
};
use std::{process::Command, sync::Arc};

struct PanicChain(bool);

impl Chain for PanicChain {
    async fn serve(&self, _: &mut Context<'_>) -> Outcome {
        panic_at_origin()
    }
    fn is_empty(&self) -> bool {
        false
    }
    fn stacktrace(&self) -> bool {
        self.0
    }
}

#[inline(never)]
fn panic_at_origin() -> Outcome {
    panic!("stacktrace test panic")
}

#[test]
fn chain_stacktrace_is_forwarded_by_arc() {
    assert!(Arc::new(PanicChain(true)).stacktrace());
    assert!(!Arc::new(PanicChain(false)).stacktrace());
}

struct CaughtPanic;
impl Chain for CaughtPanic {
    async fn serve(&self, _: &mut Context<'_>) -> Outcome {
        let _ = std::panic::catch_unwind(panic_at_origin);
        Outcome::Drop
    }
    fn is_empty(&self) -> bool {
        false
    }
    fn stacktrace(&self) -> bool {
        true
    }
}

#[test]
fn internally_caught_panics_do_not_produce_stacktrace_logs() {
    if std::env::var_os("PHAROS_TEST_CAUGHT").is_some() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let key = ListenerKey {
                transport: Transport::Dns,
                address: "127.0.0.1:53".parse().unwrap(),
            };
            let mut router = Router::default();
            router.add(key, ".".parse().unwrap(), Some(CaughtPanic), vec![]);
            let server = Server::new(router, key);
            let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
            assert_eq!(
                server
                    .handle(
                        &query,
                        "127.0.0.1:1234".parse().unwrap(),
                        Protocol::Udp,
                        &mut Vec::with_capacity(512)
                    )
                    .await,
                pharos_server::Action::Drop
            );
        });
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "internally_caught_panics_do_not_produce_stacktrace_logs",
            "--nocapture",
        ])
        .env("PHAROS_TEST_CAUGHT", "1")
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Plugin panic stacktrace"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("stacktrace test panic"));
}

#[test]
fn stacktrace_is_captured_at_panic_only_when_enabled() {
    if let Ok(mode) = std::env::var("PHAROS_TEST_STACKTRACE") {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let settings: &[bool] = match mode.as_str() {
                "mixed" => &[true, false],
                "off" => &[false],
                _ => &[true],
            };
            for &enabled in settings {
                let key = ListenerKey {
                    transport: Transport::Dns,
                    address: "127.0.0.1:53".parse().unwrap(),
                };
                let mut router = Router::default();
                router.add(
                    key,
                    ".".parse().unwrap(),
                    Some(Arc::new(PanicChain(enabled))),
                    vec![],
                );
                let mut server = Server::new(router, key);
                server.debug = mode == "debug";
                let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
                let task = tokio::spawn(async move {
                    server
                        .handle(
                            &query,
                            "127.0.0.1:1234".parse().unwrap(),
                            Protocol::Udp,
                            &mut Vec::with_capacity(512),
                        )
                        .await
                });
                let result = task.await;
                assert_eq!(result.is_err(), mode == "debug");
            }
        });
        return;
    }
    for mode in ["on", "off", "debug", "mixed"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "stacktrace_is_captured_at_panic_only_when_enabled",
                "--nocapture",
            ])
            .env("PHAROS_TEST_STACKTRACE", mode)
            .env("RUST_BACKTRACE", "0")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout.matches("Plugin panic stacktrace").count(),
            usize::from(mode == "on" || mode == "mixed"),
            "{stdout}"
        );
        assert_eq!(
            stdout.contains("panic_at_origin"),
            mode == "on" || mode == "mixed",
            "{stdout}"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("stacktrace test panic"));
    }
}

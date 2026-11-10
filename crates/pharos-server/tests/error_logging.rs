#![forbid(unsafe_code)]

use pharos_proto::{Message, Rcode};
use pharos_server::{
    Action, Chain, Context, Error, Handler, ListenerKey, Outcome, Protocol, Router, Server,
    Transport, logging::ERROR_LOGGED_METADATA,
};
use std::process::Command;
use std::sync::Mutex;

static LOGGED: Mutex<Vec<Error>> = Mutex::new(Vec::new());

struct Broken {
    marked: bool,
    panic: bool,
    response: bool,
    error: Error,
}

impl Chain for Broken {
    async fn serve(&self, cx: &mut Context<'_>) -> Outcome {
        if self.marked {
            for key in [
                "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14",
            ] {
                assert!(cx.metadata.insert(key, "used"));
            }
            assert!(cx.metadata.insert(ERROR_LOGGED_METADATA, "true"));
        }
        if self.panic {
            panic!("plugin panic");
        }
        if self.response {
            cx.response.extend_from_slice(&[0; 12]);
            return Outcome::Response;
        }
        Outcome::Error(self.error)
    }
    fn is_empty(&self) -> bool {
        false
    }
}

fn log(error: Error) {
    LOGGED.lock().unwrap().push(error);
}

#[tokio::test]
async fn suppresses_only_marked_plugin_error_not_panics_or_scrub_errors() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:53".parse().unwrap(),
    };
    let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, b'a', 0, 0, 1, 0, 1];
    wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    let peer = "127.0.0.1:1234".parse().unwrap();
    for (marked, panic, response, capacity, error, expected) in [
        (
            false,
            false,
            false,
            512,
            Error::NoNextPlugin,
            vec![Error::NoNextPlugin],
        ),
        (true, false, false, 512, Error::NoNextPlugin, vec![]),
        (
            true,
            false,
            false,
            19,
            Error::ResponseBufferTooSmall,
            vec![Error::ResponseBufferTooSmall],
        ),
        (
            true,
            true,
            false,
            512,
            Error::NoNextPlugin,
            vec![Error::PluginPanic],
        ),
        (
            true,
            false,
            true,
            0,
            Error::NoNextPlugin,
            vec![Error::ResponseBufferTooSmall],
        ),
    ] {
        LOGGED.lock().unwrap().clear();
        let mut router = Router::default();
        router.add(
            key,
            ".".parse().unwrap(),
            Some(Broken {
                marked,
                panic,
                response,
                error,
            }),
            vec![],
        );
        let mut server = Server::new(router, key);
        server.logger = log;
        let mut reply = Vec::with_capacity(capacity);
        assert_eq!(
            server.handle(&wire, peer, Protocol::Udp, &mut reply).await,
            Action::Respond
        );
        assert_eq!(*LOGGED.lock().unwrap(), expected);
        assert_eq!(Message::parse(&reply).unwrap().rcode(), Rcode::SERVFAIL);
    }
}

#[test]
fn default_logger_only_reports_panics_and_scrub_errors() {
    if let Ok(mode) = std::env::var("PHAROS_TEST_DEFAULT_LOGGER") {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let key = ListenerKey {
                transport: Transport::Dns,
                address: "127.0.0.1:53".parse().unwrap(),
            };
            let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, b'a', 0, 0, 1, 0, 1];
            wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
            let mut router = Router::default();
            router.add(
                key,
                ".".parse().unwrap(),
                Some(Broken {
                    marked: false,
                    panic: mode == "panic",
                    response: false,
                    error: Error::NoNextPlugin,
                }),
                vec![],
            );
            let server = Server::new(router, key);
            let mut response = Vec::with_capacity(if mode == "scrub" { 19 } else { 512 });
            assert_eq!(
                server
                    .handle(
                        &wire,
                        "127.0.0.1:1234".parse().unwrap(),
                        Protocol::Udp,
                        &mut response
                    )
                    .await,
                Action::Respond
            );
        });
        return;
    }
    for (mode, expected) in [
        ("ordinary", None),
        ("scrub", Some("Response buffer too small")),
        ("panic", Some("plugin panicked")),
    ] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "default_logger_only_reports_panics_and_scrub_errors",
                "--nocapture",
            ])
            .env("PHAROS_TEST_DEFAULT_LOGGER", mode)
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
            stdout.matches("Plugin error:").count(),
            usize::from(expected.is_some()),
            "{stdout}"
        );
        if let Some(expected) = expected {
            assert!(stdout.contains(expected), "{stdout}");
        }
    }
}

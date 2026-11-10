#![cfg(feature = "plugin-errors")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Error, Metadata, Next, Outcome, Phase, Plugin, Protocol, Transport};

struct Answer(Outcome);
impl Next for Answer {
    async fn run(self, _: &mut Context<'_>) -> Outcome {
        self.0
    }
}

// Derived from CoreDNS v1.15.0 plugin/errors/errors_test.go.
#[test]
fn errors_are_logged_and_consolidated() {
    for (case, expected, absent) in [
        (
            "normal",
            " ERROR errors: 2 example.org. A: no next plugin found",
            "errors like",
        ),
        ("success", "", " errors: "),
        (
            "consolidate",
            " WARNING errors: 3 errors like '^no next' occurred in last 2s",
            "example.org.",
        ),
        (
            "show_first",
            " INFO errors: 2 example.org. A: no next plugin found",
            "errors like",
        ),
        (
            "show_many",
            " INFO errors: 3 errors like '^no next' occurred in last 2s",
            " WARNING errors: ",
        ),
        (
            "timer",
            " ERROR errors: 3 errors like '^no next' occurred in last 20ms",
            "example.org.",
        ),
        (
            "first_match",
            " WARNING errors: 3 errors like '^no next' occurred in last 2s",
            " INFO errors: ",
        ),
        (
            "unmatched",
            " ERROR errors: 2 example.org. A: no next plugin found",
            "errors like",
        ),
        (
            "debug",
            " DEBUG errors: 3 errors like '^no next' occurred in last 2s",
            "example.org.",
        ),
        (
            "explicit_error",
            " ERROR errors: 3 errors like '^no next' occurred in last 2s",
            "example.org.",
        ),
        (
            "stopped",
            " WARNING errors: 2 example.org. A: no next plugin found",
            "errors like",
        ),
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "errors_probe", "--nocapture"])
            .env("PHAROS_ERRORS_TEST", case)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains(expected), "{case}: {stdout}");
        assert!(!stdout.contains(absent), "{case}: {stdout}");
    }
}

#[tokio::test]
async fn errors_probe() {
    let Ok(case) = std::env::var("PHAROS_ERRORS_TEST") else {
        return;
    };
    let rule = match case.as_str() {
        "consolidate" => "errors {\n consolidate 2s \"^no next\" warning\n}",
        "show_first" | "show_many" => "errors {\n consolidate 2s \"^no next\" info show_first\n}",
        "timer" => "errors {\n consolidate 20ms \"^no next\"\n}",
        "first_match" => {
            "errors {\n consolidate 2s \"^no next\" warning\n consolidate 2s .* info\n}"
        }
        "unmatched" => "errors {\n consolidate 2s ^other warning\n}",
        "debug" => "errors {\n consolidate 2s \"^no next\" debug\n}",
        "explicit_error" => "errors {\n consolidate 2s \"^no next\" error\n}",
        "stopped" => "errors {\n consolidate 2s \"^no next\" warning\n}",
        _ => "errors",
    };
    let blocks = parse("Corefile", &format!(". {{\n{rule}\n}} ")).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let domain: Name = ".".parse().unwrap();
    let query = b"\x00\x01\x01\x00\x00\x01\0\0\0\0\0\0\x07example\x03org\0\0\x01\0\x01";
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 4];
    let mut cx = Context {
        query: Message::parse(query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let outcome = if case == "success" {
        Outcome::Response
    } else {
        Outcome::Error(Error::NoNextPlugin)
    };
    if case == "stopped" {
        configured[0]
            .config
            .lifecycle
            .run(Phase::Shutdown)
            .await
            .unwrap();
    }
    let count = if matches!(
        case.as_str(),
        "consolidate" | "show_many" | "timer" | "first_match" | "debug" | "explicit_error"
    ) {
        3
    } else {
        1
    };
    for _ in 0..count {
        assert_eq!(
            configured[0]
                .config
                .errors
                .as_ref()
                .unwrap()
                .serve(&mut cx, Answer(outcome))
                .await,
            outcome
        );
    }
    if case == "timer" {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    configured[0]
        .config
        .lifecycle
        .run(Phase::Shutdown)
        .await
        .unwrap();
}

#![cfg(feature = "plugin-errors")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Error, Metadata, Next, Outcome, Phase, Plugin, Protocol, Transport};
use std::io::{BufRead, Write};

struct Answer(Outcome);
impl Next for Answer {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
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
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "errors::errors_outcomes::errors_probe",
                "--nocapture",
            ])
            .env("PHAROS_ERRORS_TEST", case);
        let (status, stdout) = if case == "timer" {
            let mut child = command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let (sent, received) = std::sync::mpsc::channel();
            let reader = std::thread::spawn(move || {
                let mut output = String::new();
                for line in std::io::BufReader::new(stdout).lines() {
                    let line = line.unwrap();
                    if line
                        .contains(" ERROR errors: 3 errors like '^no next' occurred in last 20ms")
                    {
                        let _ = sent.send(());
                    }
                    output.push_str(&line);
                    output.push('\n');
                }
                output
            });
            if received
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_err()
            {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "timer did not flush before shutdown: {}",
                    reader.join().unwrap()
                );
            }
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"continue\n")
                .unwrap();
            let status = child.wait().unwrap();
            (status, reader.join().unwrap())
        } else {
            let output = command.output().unwrap();
            (output.status, String::from_utf8(output.stdout).unwrap())
        };
        assert!(status.success(), "{case}: {status}");
        assert!(stdout.contains(expected), "{case}: {stdout}");
        assert!(!stdout.contains(absent), "{case}: {stdout}");
    }
}

#[tokio::test]
async fn errors_probe() {
    let Ok(case) = std::env::var("PHAROS_ERRORS_TEST") else {
        return;
    };
    pharos_server::logging::set_debug_enabled(case == "debug");
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
                .serve(&mut cx, Answer(outcome.clone()))
                .await,
            outcome
        );
    }
    if case == "timer" {
        tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            assert_eq!(line, "continue\n");
        })
        .await
        .unwrap();
    }
    configured[0]
        .config
        .lifecycle
        .run(Phase::Shutdown)
        .await
        .unwrap();
}

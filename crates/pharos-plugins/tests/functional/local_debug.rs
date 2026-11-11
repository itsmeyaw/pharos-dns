#![forbid(unsafe_code)]
#![cfg(feature = "plugin-local")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport, logging};

#[tokio::test]
async fn localhost_interception_supports_debug_logging() {
    if std::env::var_os("PHAROS_LOCAL_DEBUG_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "local::local_debug::localhost_interception_supports_debug_logging",
                "--nocapture",
            ])
            .env("PHAROS_LOCAL_DEBUG_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("DEBUG local: Intercepting localhost query for"),
            "{stdout}"
        );
        assert!(stdout.contains("a.localhost."), "{stdout}");
        assert!(stdout.contains("127.0.0.1"), "{stdout}");
        return;
    }
    let blocks = parse("Corefile", ". {\n local\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01a\x09localhost\0\0\x01\0\x01";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    logging::set_debug_enabled(true);
    assert!(logging::debug_enabled());
    assert_eq!(configured[0].config.serve(&mut cx).await, Outcome::Response);
    logging::set_debug_enabled(false);
}

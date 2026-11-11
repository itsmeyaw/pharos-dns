#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-forward", feature = "plugin-debug"))]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
use tokio::net::UdpSocket;

const QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";

#[tokio::main(flavor = "current_thread")]
async fn mismatch_with_debug() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
        wire[2] |= 0x80;
        wire[len - 3] = 28;
        socket.send_to(&wire[..len], peer).await.unwrap();
    });
    let text = format!(".:0 {{\n debug\n forward . {address}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let blocks = configure::<Chain>(&blocks, directives()).unwrap();
    let (_, lifecycle) = servers(blocks).unwrap();
    lifecycle.run(pharos_server::Phase::Started).await.unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(QUERY).unwrap(),
        client: "127.0.0.1:1000".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain.serve(&mut cx).await,
        Outcome::Unanswered(pharos_proto::Rcode::FORMERR)
    );
}

#[test]
fn wrong_reply_is_hexdumped_when_debug_is_on() {
    if std::env::var_os("PHAROS_DEBUG_TEST").is_some() {
        mismatch_with_debug();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "wrong_reply_is_hexdumped_when_debug_is_on",
            "--nocapture",
        ])
        .env("PHAROS_DEBUG_TEST", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{stdout}");
    assert!(
        stdout.contains(", www.example.com. 1\ndebug: 000000 "),
        "{stdout}"
    );
    assert!(stdout.contains("\ndebug: 000021\n"), "{stdout}");
}

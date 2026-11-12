#![cfg(feature = "plugin-log")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct Answer<'a>(Outcome, &'a [u8]);
impl Next for Answer<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        cx.response.extend_from_slice(self.1);
        self.0
    }
}

#[test]
fn classes_and_first_matching_rule_control_emission() {
    for (case, expected) in [
        ("denial", Some("DENIAL NXDOMAIN")),
        ("error", None),
        ("first", None),
        ("unmatched", Some("SECOND NXDOMAIN")),
        ("servfail-error", Some("ERROR SERVFAIL")),
        ("servfail-denial", None),
        ("servfail-default", Some("SERVFAIL")),
        ("refused-default", Some("REFUSED")),
        ("drop-default", Some(" - ")),
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "log::log_outcomes::class_filter_probe",
                "--nocapture",
            ])
            .env("PHAROS_LOG_TEST", case)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let entries: Vec<_> = stdout
            .lines()
            .filter(|line| line.contains(" INFO log: "))
            .collect();
        match expected {
            Some(value) => {
                assert_eq!(entries.len(), 1, "{stdout}");
                assert!(entries[0].contains(value), "{stdout}");
            }
            None => assert!(entries.is_empty(), "{stdout}"),
        }
    }
}

#[tokio::test]
async fn class_filter_probe() {
    let Ok(case) = std::env::var("PHAROS_LOG_TEST") else {
        return;
    };
    let rules = match case.as_str() {
        "denial" => "log example.org \"DENIAL {rcode}\" {\n class denial\n}",
        "error" => "log example.org \"ERROR {rcode}\" {\n class error\n}",
        "first" => "log example.org \"FIRST {rcode}\" {\n class error\n}\nlog . \"SECOND {rcode}\"",
        "unmatched" => "log elsewhere.test \"FIRST {rcode}\"\nlog . \"SECOND {rcode}\"",
        "servfail-error" => "log . \"ERROR {rcode}\" {\n class error\n}",
        "servfail-denial" => "log . \"DENIAL {rcode}\" {\n class denial\n}",
        "servfail-default" | "refused-default" | "drop-default" => "log",
        _ => panic!("unexpected case"),
    };
    let blocks = parse("Corefile", &format!(". {{\n{rules}\n}}")).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 4];
    let query = b"\x00\x01\x01\x00\x00\x01\0\0\0\0\0\0\x03www\x07example\x03org\0\0\x01\0\x01";
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
    let (outcome, wire): (Outcome, &[u8]) = match case.as_str() {
        "servfail-error" | "servfail-denial" | "servfail-default" => {
            (Outcome::Error(pharos_server::Error::NoNextPlugin), &[])
        }
        "refused-default" => (Outcome::Unanswered(Rcode::REFUSED), &[]),
        "drop-default" => (Outcome::Drop, &[]),
        _ => (Outcome::Response, b"\0\x01\x80\x03\0\0\0\0\0\0\0\0"),
    };
    assert_eq!(
        configured[0]
            .config
            .log
            .as_ref()
            .unwrap()
            .serve(&mut cx, Answer(outcome.clone(), wire),)
            .await,
        outcome
    );
}

#[tokio::test]
async fn expired_dnssec_signature_is_an_error_class() {
    let blocks = parse("Corefile", ". {\n log {\n class denial\n }\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let log = configured[0].config.log.as_ref().unwrap();
    let root = NameRef::parse(&[0], 0).unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x8000).unwrap();
    builder.reserve(11).unwrap();
    let mut signature = [0; 19];
    signature[11] = 1;
    builder
        .record(Section::Answer, root, Type::RRSIG, Class::IN, 0, &signature)
        .unwrap();
    let opt = [0, 0, 41, 2, 0, 0, 0, 0x80, 0, 0, 0];
    builder.finish_with_opt(&opt).unwrap();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 4];
    let mut cx = Context {
        query: Message::parse(&[0; 12]).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    log.serve(&mut cx, Answer(Outcome::Response, &wire)).await;
    assert_eq!(cx.metadata.get("log/type"), Some("OTHERERROR"));
    assert_eq!(cx.metadata.get("log/class"), Some("error"));
}

#[tokio::test]
async fn matching_rule_classifies_next_outcome_without_changing_it() {
    let blocks = parse("Corefile", ". {\n log example.org {\n class success\n }\n}").unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let log = configured[0].config.log.as_ref().unwrap();
    let domain: Name = ".".parse().unwrap();
    let query = b"\x00\x01\x01\x00\x00\x01\0\0\0\0\0\0\x03www\x07example\x03org\0\0\x01\0\x01";
    for (outcome, wire, kind, class) in [
        (Outcome::Drop, &b""[..], "OTHERERROR", "error"),
        (
            Outcome::Unanswered(Rcode::SERVFAIL),
            &b""[..],
            "SERVERERROR",
            "error",
        ),
        (
            Outcome::Response,
            &b"\0\x01\x80\x03\0\0\0\0\0\0\0\0"[..],
            "NXDOMAIN",
            "denial",
        ),
        (
            Outcome::Response,
            &b"\0\x01\x80\0\0\0\0\0\0\0\0\0"[..],
            "NOERROR",
            "success",
        ),
    ] {
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
        assert_eq!(
            log.serve(&mut cx, Answer(outcome.clone(), wire)).await,
            outcome
        );
        assert_eq!(cx.metadata.get("log/type"), Some(kind));
        assert_eq!(cx.metadata.get("log/class"), Some(class));
        assert_eq!(cx.response, wire);
    }
}

#![forbid(unsafe_code)]
#![cfg(feature = "plugin-log")]

use std::{alloc::System, time::Duration};

use pharos_plugins::log_format::{COMBINED_LOG_FORMAT, COMMON_LOG_FORMAT, Format};
use pharos_proto::{Message, Name, Rcode};
use pharos_server::{Context, Error, Metadata, Outcome, Protocol, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn render(format: &str, cx: &Context<'_, '_>, outcome: Outcome) -> String {
    let mut output = String::new();
    Format::compile(format).format(&mut output, cx, outcome, Duration::from_millis(125));
    output
}

#[test]
fn coredns_replacer_formats_requests_responses_and_metadata_without_allocating() {
    let _serial = crate::serial();
    // The request and response use the same question as CoreDNS's replacer tests.
    let query =
        b"\x04\x1d\x01\x30\x00\x01\x00\x00\x00\x00\x00\x00\x07Example\x03Org\x00\x00\x0d\x00\x01";
    let mut edns_query = query.to_vec();
    edns_query[10..12].copy_from_slice(&1_u16.to_be_bytes());
    edns_query.extend_from_slice(b"\x00\x00\x29\x10\x00\x00\x00\x80\x00\x00\x00");
    let no_questions = [0_u8; 12];
    let domain: Name = ".".parse().unwrap();
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&0x87f0_u16.to_be_bytes());
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    // Compressed owner and CNAME target exercise the uncompressed size.
    response.extend_from_slice(b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x00\x00\x02\xc0\x0c");
    let mut slots = [None; 2];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert("test/meta2", "two"));
    assert!(metadata.insert("test/meta3", "three"));
    let mut cx = Context {
        query: Message::parse(query).unwrap(),
        client: "10.240.0.1:40212".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata,
        response: &mut response,
        max_response_size: 512,
    };

    let compiled = Format::compile("{combined} {/test/meta2} {local}");
    let mut output = String::with_capacity(512);
    let region = Region::new(GLOBAL);
    compiled.format(
        &mut output,
        &cx,
        Outcome::Response,
        Duration::from_millis(125),
    );
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert!(output.ends_with("\"0\" two 127.0.0.1"));

    let labels = [
        ("{type}", "HINFO"),
        ("{name}", "example.org."),
        ("{class}", "IN"),
        ("{proto}", "udp"),
        ("{size}", "29"),
        ("{remote}", "10.240.0.1"),
        ("{port}", "40212"),
        ("{local}", "127.0.0.1"),
        ("{>id}", "1053"),
        ("{>opcode}", "0"),
        ("{>do}", "false"),
        ("{>bufsize}", "512"),
        ("{rcode}", "NOERROR"),
        ("{rsize}", "65"),
        ("{duration}", "0.125s"),
        ("{>rflags}", "qr,aa,tc,rd,ra,z,ad,cd"),
    ];
    for (label, expected) in labels {
        assert_eq!(render(label, &cx, Outcome::Response), expected, "{label}");
    }

    for (format, expected) in [
        ("", ""),
        ("A", "A"),
        ("A {A}", "A {A}"),
        ("{{remote}}", "{10.240.0.1}"),
        ("{ A {remote} A }", "{ A 10.240.0.1 A }"),
        ("{remote}}", "10.240.0.1}"),
        ("{{remote}", "{10.240.0.1"),
        ("Foo } {remote}", "Foo } 10.240.0.1"),
        ("{ Foo", "{ Foo"),
        ("} Foo", "} Foo"),
        ("{/test/meta2", "{/test/meta2"),
        ("{test/meta2} {/test/meta4}", "{test/meta2} -"),
        ("{/test/meta2} {/test/key4}", "two -"),
        ("{/test/meta2} {/test/meta3}", "two three"),
        (
            "A { {remote} {type} {/test/meta2} } B",
            "A { 10.240.0.1 HINFO two } B",
        ),
    ] {
        assert_eq!(render(format, &cx, Outcome::Response), expected, "{format}");
    }

    let common = "10.240.0.1:40212 - 1053 \"HINFO IN example.org. udp 29 false 512\" NOERROR qr,aa,tc,rd,ra,z,ad,cd 65 0.125s";
    assert_eq!(render(COMMON_LOG_FORMAT, &cx, Outcome::Response), common);
    assert_eq!(render("{common}", &cx, Outcome::Response), common);
    assert_eq!(
        render("{combined}", &cx, Outcome::Response),
        format!("{common} \"0\"")
    );
    assert_eq!(
        render(COMBINED_LOG_FORMAT, &cx, Outcome::Response),
        format!("{common} \"0\"")
    );

    let fields = "{rcode} {>rflags} {rsize} {duration}";
    assert_eq!(render(fields, &cx, Outcome::Drop), "- - 0 0.125s");
    assert_eq!(
        render(fields, &cx, Outcome::Unanswered(Rcode::NOERROR)),
        "- - 0 0.125s"
    );
    assert_eq!(
        render(fields, &cx, Outcome::Unanswered(Rcode::REFUSED)),
        "REFUSED qr,rd,cd 29 0.125s"
    );
    assert_eq!(
        render(fields, &cx, Outcome::Error(Error::NoNextPlugin)),
        "SERVFAIL qr,rd,cd 29 0.125s"
    );
    cx.response.clear();
    cx.response.extend_from_slice(&[1, 2, 3]);
    assert_eq!(render(fields, &cx, Outcome::Response), "- - 3 0.125s");

    cx.client = "[2001:db8::1]:53".parse().unwrap();
    cx.protocol = Protocol::Tcp;
    assert_eq!(
        render("{remote}:{port} {proto} {>bufsize}", &cx, Outcome::Drop),
        "[2001:db8::1]:53 tcp 65535"
    );

    cx.query = Message::parse(&edns_query).unwrap();
    cx.protocol = Protocol::Udp;
    assert_eq!(
        render("{>do} {>bufsize} {size}", &cx, Outcome::Drop),
        "true 4096 40"
    );
    assert_eq!(
        render("{rcode} {rsize}", &cx, Outcome::Unanswered(Rcode::SERVFAIL)),
        "SERVFAIL 40"
    );

    cx.query = Message::parse(&no_questions).unwrap();
    assert_eq!(render("{name}|{type}|{class}", &cx, Outcome::Drop), ".||");

    cx.query = Message::parse(query).unwrap();
    output.clear();
    let region = Region::new(GLOBAL);
    compiled.format(
        &mut output,
        &cx,
        Outcome::Unanswered(Rcode::REFUSED),
        Duration::from_millis(125),
    );
    let stats = region.change();
    assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    assert!(output.ends_with("\"0\" two 127.0.0.1"));
    output.clear();
    output.push_str("prefix: ");
    compiled.format(&mut output, &cx, Outcome::Drop, Duration::ZERO);
    assert!(output.starts_with("prefix: "));
    assert!(output.contains("0s"));
}

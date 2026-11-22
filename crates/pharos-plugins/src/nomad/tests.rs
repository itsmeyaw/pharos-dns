use std::time::Duration;

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Context, Error, Metadata, Next, Outcome, Plugin, Protocol, Transport};
use tokio::net::TcpListener;

use super::*;
use stub::{Reply as Canned, Stub};

struct NoNext;

impl Next for NoNext {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Error(Error::NoNextPlugin)
    }
}

// Plugin/nomad/nomad_test.go TestNomad: the registrations the fake Nomad servers return.
fn nomad_api(head: &str) -> Canned {
    let path = head.split(' ').nth(1).unwrap();
    let body = match path.split('?').next().unwrap() {
        "/v1/service/example" => {
            r#"[{"Address":"1.2.3.4","Namespace":"default","Port":23202,"ServiceName":"example"}]"#
        }
        "/v1/service/fakeipv6" => {
            r#"[{"Address":"1:2:3::4","Namespace":"default","Port":8000,"ServiceName":"fakeipv6"}]"#
        }
        "/v1/service/multi" => {
            r#"[{"Address":"1.2.3.4","Namespace":"default","Port":25395,"ServiceName":"multi"},{"Address":"1.2.3.5","Namespace":"default","Port":20888,"ServiceName":"multi"},{"Address":"1.2.3.6","Namespace":"default","Port":26292,"ServiceName":"multi"}]"#
        }
        "/v1/service/mixed" => {
            r#"[{"Address":"1.2.3.4","Port":1},{"Address":"1:2:3::4","Port":2},{"Address":"::ffff:1.2.3.5","Port":3}]"#
        }
        "/v1/service/badip" => r#"[{"Address":"1.2.3.4","Port":1},{"Address":"nope","Port":2}]"#,
        "/v1/service/nonexistent" => "[]",
        "/v1/service/null" => "null",
        _ => {
            return Canned {
                status: 404,
                ..Canned::ok("")
            };
        }
    };
    Canned::ok(body)
}

fn settings(addresses: Vec<String>) -> Settings {
    Settings {
        zone: "service.nomad".to_owned(),
        ttl: 30,
        filter: String::new(),
        token: None,
        addresses,
    }
}

async fn plugin() -> (Nomad, Stub) {
    let stub = Stub::default();
    let address = stub.tcp(nomad_api).await;
    (
        Nomad::new(settings(vec![address]), &|_| None).unwrap(),
        stub,
    )
}

fn query(name: &str, qtype: Type, qclass: Class) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0x1234, 0x0110).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, qclass)
        .unwrap();
    let _ = builder.finish();
    wire
}

async fn serve(nomad: &Nomad, wire: &[u8]) -> Result<Vec<u8>, Outcome> {
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    match nomad.serve(&mut cx, NoNext).await {
        Outcome::Response => Ok(response),
        other => Err(other),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Rendered {
    rcode: Rcode,
    flags: u16,
    answer: Vec<String>,
    authority: Vec<String>,
    extra: Vec<String>,
}

fn render(wire: &[u8]) -> Rendered {
    let message = Message::parse(wire).unwrap();
    let records = |records: pharos_proto::Records<'_>| {
        records
            .map(|record| {
                format!(
                    "{} {} {} {}",
                    record.name,
                    record.ttl,
                    record.rtype,
                    record.data().unwrap()
                )
            })
            .collect::<Vec<_>>()
    };
    Rendered {
        rcode: message.rcode(),
        flags: message.flags() & 0xfff0,
        answer: records(message.answers()),
        authority: records(message.authorities()),
        extra: records(message.additionals()),
    }
}

async fn ask(nomad: &Nomad, name: &str, qtype: Type) -> Rendered {
    render(&serve(nomad, &query(name, qtype, Class::IN)).await.unwrap())
}

// QR, AA, RD and CD: what CoreDNS `SetReply` and `Authoritative` produce for this query.
const FLAGS: u16 = 0x8000 | 0x0400 | 0x0100 | 0x0010;

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

// Plugin/nomad/nomad_test.go TestNomad cases.
#[tokio::test]
async fn a_record() {
    let (nomad, _) = plugin().await;
    let got = ask(&nomad, "example.default.service.nomad.", Type::A).await;
    assert_eq!(got.rcode, Rcode::NOERROR);
    assert_eq!(got.flags, FLAGS);
    assert_eq!(
        got.answer,
        strings(&["example.default.service.nomad. 30 A 1.2.3.4"])
    );
    assert!(got.authority.is_empty() && got.extra.is_empty());
}

#[tokio::test]
async fn aaaa_for_an_ipv4_service_is_empty() {
    let (nomad, _) = plugin().await;
    let got = ask(&nomad, "example.default.service.nomad.", Type::AAAA).await;
    assert_eq!((got.rcode, got.flags), (Rcode::NOERROR, FLAGS));
    assert!(got.answer.is_empty());
}

#[tokio::test]
async fn aaaa_record_and_empty_a_for_ipv6() {
    let (nomad, _) = plugin().await;
    let got = ask(&nomad, "fakeipv6.default.service.nomad.", Type::AAAA).await;
    assert_eq!(got.rcode, Rcode::NOERROR);
    assert_eq!(
        got.answer,
        strings(&["fakeipv6.default.service.nomad. 30 AAAA 1:2:3::4"])
    );
    let got = ask(&nomad, "fakeipv6.default.service.nomad.", Type::A).await;
    assert_eq!(got.rcode, Rcode::NOERROR);
    assert!(got.answer.is_empty());
}

#[tokio::test]
async fn several_registrations_keep_their_order() {
    let (nomad, _) = plugin().await;
    let got = ask(&nomad, "multi.default.service.nomad.", Type::A).await;
    assert_eq!(
        got.answer,
        strings(&[
            "multi.default.service.nomad. 30 A 1.2.3.4",
            "multi.default.service.nomad. 30 A 1.2.3.5",
            "multi.default.service.nomad. 30 A 1.2.3.6",
        ])
    );
}

// CoreDNS nomad.go handleResponseError: the SOA lands in the Answer section of an NXDOMAIN.
#[tokio::test]
async fn nonexistent_service_is_nxdomain_with_the_soa_in_the_answer() {
    let (nomad, _) = plugin().await;
    for name in ["nonexistent", "null"] {
        let got = ask(&nomad, &format!("{name}.default.service.nomad."), Type::A).await;
        assert_eq!(got.rcode, Rcode::NXDOMAIN);
        assert_eq!(got.flags, FLAGS);
        assert_eq!(
            got.answer,
            strings(&[&format!(
                "{name}.default.service.nomad. 30 SOA ns1.{name}.default.service.nomad. hostmaster.service.nomad. 0 3600 600 86400 30"
            )])
        );
        assert!(got.authority.is_empty());
    }
}

#[tokio::test]
async fn srv_record_with_the_address_in_additional() {
    let (nomad, _) = plugin().await;
    let got = ask(&nomad, "example.default.service.nomad.", Type::SRV).await;
    assert_eq!(got.rcode, Rcode::NOERROR);
    assert_eq!(
        got.answer,
        strings(&[
            "example.default.service.nomad. 30 SRV 10 10 23202 example.default.service.nomad."
        ])
    );
    assert_eq!(
        got.extra,
        strings(&["example.default.service.nomad. 30 A 1.2.3.4"])
    );
    let got = ask(&nomad, "fakeipv6.default.service.nomad.", Type::SRV).await;
    assert_eq!(
        got.extra,
        strings(&["fakeipv6.default.service.nomad. 30 AAAA 1:2:3::4"])
    );
}

// Go net.IP.To4: an IPv4-mapped address is IPv4 for A, AAAA and the SRV extra alike.
#[tokio::test]
async fn address_families_are_split_like_go() {
    let (nomad, _) = plugin().await;
    let a = ask(&nomad, "mixed.default.service.nomad.", Type::A).await;
    assert_eq!(
        a.answer,
        strings(&[
            "mixed.default.service.nomad. 30 A 1.2.3.4",
            "mixed.default.service.nomad. 30 A 1.2.3.5",
        ])
    );
    let aaaa = ask(&nomad, "mixed.default.service.nomad.", Type::AAAA).await;
    assert_eq!(
        aaaa.answer,
        strings(&["mixed.default.service.nomad. 30 AAAA 1:2:3::4"])
    );
    let srv = ask(&nomad, "mixed.default.service.nomad.", Type::SRV).await;
    assert_eq!(srv.answer.len(), 3);
    assert_eq!(
        srv.extra,
        strings(&[
            "mixed.default.service.nomad. 30 A 1.2.3.4",
            "mixed.default.service.nomad. 30 AAAA 1:2:3::4",
            "mixed.default.service.nomad. 30 A 1.2.3.5",
        ])
    );
}

// CoreDNS nomad.go addServiceResponses: an unusable address ends the loop; what was added stays, the Response is NXDOMAIN.
#[tokio::test]
async fn an_unparsable_address_turns_the_response_into_nxdomain() {
    let (nomad, _) = plugin().await;
    let got = ask(&nomad, "badip.default.service.nomad.", Type::A).await;
    assert_eq!(got.rcode, Rcode::NXDOMAIN);
    assert_eq!(got.answer.len(), 2);
    assert_eq!(got.answer[0], "badip.default.service.nomad. 30 A 1.2.3.4");
    assert!(got.answer[1].contains("SOA"));
}

#[tokio::test]
async fn an_unsupported_type_is_nxdomain_with_the_soa() {
    let (nomad, _) = plugin().await;
    let got = ask(&nomad, "example.default.service.nomad.", Type::TXT).await;
    assert_eq!(got.rcode, Rcode::NXDOMAIN);
    assert_eq!(got.answer.len(), 1);
    assert!(got.answer[0].contains("SOA"));
}

// CoreDNS nomad.go handleServiceLookupError: NOERROR, authoritative, nothing else.
#[tokio::test]
async fn a_failed_lookup_is_an_empty_noerror() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", dead.local_addr().unwrap());
    drop(dead);
    let nomad = Nomad::new(settings(vec![address]), &|_| None).unwrap();
    let got = ask(&nomad, "example.default.service.nomad.", Type::A).await;
    assert_eq!((got.rcode, got.flags), (Rcode::NOERROR, FLAGS));
    assert!(got.answer.is_empty() && got.authority.is_empty() && got.extra.is_empty());
}

#[tokio::test]
async fn failing_over_from_a_dead_server() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_address = format!("http://{}", dead.local_addr().unwrap());
    drop(dead);
    let stub = Stub::default();
    let live = stub.tcp(nomad_api).await;
    let nomad = Nomad::new(settings(vec![dead_address, live]), &|_| None).unwrap();
    let got = ask(&nomad, "example.default.service.nomad.", Type::A).await;
    assert_eq!(
        got.answer,
        strings(&["example.default.service.nomad. 30 A 1.2.3.4"])
    );
}

#[tokio::test]
async fn names_outside_the_zone_or_without_a_namespace_go_to_the_next_plugin() {
    let (nomad, stub) = plugin().await;
    for name in [
        "service.nomad.",
        "example.service.nomad.",
        "example.default.other.nomad.",
        "a.b.default.example.com.",
        "nomad.",
        ".",
    ] {
        let outcome = serve(&nomad, &query(name, Type::A, Class::IN))
            .await
            .unwrap_err();
        assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin), "{name}");
    }
    // A class other than IN is not Nomad data.
    let outcome = serve(
        &nomad,
        &query("example.default.service.nomad.", Type::A, Class::CH),
    )
    .await
    .unwrap_err();
    assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin));
    assert!(stub.heads.lock().unwrap().is_empty());
}

// CoreDNS nomad.go processQName: extra labels in front are ignored; `state.Name()` lower-cases.
#[tokio::test]
async fn service_and_namespace_come_from_the_first_two_labels_in_lower_case() {
    let (nomad, stub) = plugin().await;
    let got = ask(&nomad, "ExAmple.Default.Service.Nomad.", Type::A).await;
    assert_eq!(
        got.answer,
        strings(&["ExAmple.Default.Service.Nomad. 30 A 1.2.3.4"])
    );
    let got = ask(&nomad, "example.team.default.service.nomad.", Type::A).await;
    assert_eq!(got.rcode, Rcode::NOERROR);
    let heads = stub.heads.lock().unwrap();
    assert!(
        heads[0].starts_with("GET /v1/service/example?namespace=default "),
        "{}",
        heads[0]
    );
    assert!(
        heads[1].starts_with("GET /v1/service/example?namespace=team "),
        "{}",
        heads[1]
    );
}

#[tokio::test]
async fn the_filter_and_ttl_come_from_the_settings() {
    let stub = Stub::default();
    let address = stub.tcp(nomad_api).await;
    let nomad = Nomad::new(
        Settings {
            ttl: 5,
            filter: "Tags contains x".to_owned(),
            ..settings(vec![address])
        },
        &|_| None,
    )
    .unwrap();
    let got = ask(&nomad, "example.default.service.nomad.", Type::A).await;
    assert_eq!(
        got.answer,
        strings(&["example.default.service.nomad. 5 A 1.2.3.4"])
    );
    assert!(stub.heads.lock().unwrap()[0].contains("?filter=Tags+contains+x&namespace=default "));
}

#[tokio::test]
async fn query_labels_are_percent_encoded_in_the_request() {
    let (nomad, stub) = plugin().await;
    ask(&nomad, "a\\.b\\032c.d\\047e.service.nomad.", Type::A).await;
    let head = stub.heads.lock().unwrap()[0].clone();
    assert!(
        head.starts_with("GET /v1/service/a.b%20c?namespace=d%2Fe "),
        "{head}"
    );
}

// Zones: the default is `service.nomad`; a configured zone is the one trimmed, with or without the final dot.
#[tokio::test]
async fn a_configured_zone_is_the_suffix_that_is_trimmed() {
    let stub = Stub::default();
    let address = stub.tcp(nomad_api).await;
    for zone in ["corp.example", "corp.example."] {
        let nomad = Nomad::new(
            Settings {
                zone: zone.to_owned(),
                ..settings(vec![address.clone()])
            },
            &|_| None,
        )
        .unwrap();
        let got = ask(&nomad, "example.default.corp.example.", Type::A).await;
        assert_eq!(
            got.answer,
            strings(&["example.default.corp.example. 30 A 1.2.3.4"])
        );
        let outcome = serve(
            &nomad,
            &query("example.default.service.nomad.", Type::A, Class::IN),
        )
        .await
        .unwrap_err();
        assert_eq!(outcome, Outcome::Error(Error::NoNextPlugin));
    }
}

#[tokio::test]
async fn the_root_zone_trims_nothing() {
    let stub = Stub::default();
    let address = stub.tcp(nomad_api).await;
    let nomad = Nomad::new(
        Settings {
            zone: ".".to_owned(),
            ..settings(vec![address])
        },
        &|_| None,
    )
    .unwrap();
    let got = ask(&nomad, "example.default.", Type::A).await;
    assert_eq!(got.answer, strings(&["example.default. 30 A 1.2.3.4"]));
}

// RFC 1035 §2.3.4: names stop at 255 octets; `ns1.` makes the SOA name four longer than the query.
#[tokio::test]
async fn a_name_too_long_for_the_soa_is_a_plugin_error() {
    let (nomad, _) = plugin().await;
    // 252 octets on the wire, the most a Query name may have for the `ns1.` name to overflow.
    let extra = [
        "x".repeat(63),
        "y".repeat(63),
        "z".repeat(63),
        "w".repeat(24),
    ]
    .join(".");
    let wire = query(
        &format!("nonexistent.default.{extra}.service.nomad."),
        Type::A,
        Class::IN,
    );
    let outcome = serve(&nomad, &wire).await.unwrap_err();
    assert_eq!(outcome, Outcome::Error(Error::Internal));
}

#[test]
fn zone_that_cannot_hold_the_mailbox_is_rejected() {
    let zone = [
        "a".repeat(60),
        "b".repeat(60),
        "c".repeat(60),
        "d".repeat(60),
    ]
    .join(".");
    let error = Nomad::new(
        Settings {
            zone,
            ..settings(vec!["http://127.0.0.1:1".to_owned()])
        },
        &|_| None,
    )
    .unwrap_err();
    assert!(error.contains("invalid zone"), "{error}");
}

#[test]
fn the_address_defaults_to_nomad_addr_then_localhost() {
    let nomad = Nomad::new(settings(Vec::new()), &|name| {
        (name == "NOMAD_ADDR").then(|| "http://10.0.0.1:4646".to_owned())
    })
    .unwrap();
    assert_eq!(format!("{:?}", nomad.client), "Client { endpoints: 1, .. }");
    assert!(Nomad::new(settings(Vec::new()), &|_| None).is_ok());
    let error = Nomad::new(settings(Vec::new()), &|name| {
        (name == "NOMAD_ADDR").then(|| "not-a-url".to_owned())
    })
    .unwrap_err();
    assert!(error.contains("invalid address"), "{error}");
}

#[test]
fn debug_output_hides_the_token() {
    let nomad = Nomad::new(
        Settings {
            token: Some("s3cret".to_owned()),
            ..settings(vec!["http://127.0.0.1:1".to_owned()])
        },
        &|_| None,
    )
    .unwrap();
    assert!(!format!("{nomad:?}").contains("s3cret"));
    assert!(!format!("{:?}", settings(Vec::new())).contains("s3cret"));
    let with_token = Settings {
        token: Some("s3cret".to_owned()),
        ..settings(Vec::new())
    };
    assert!(!format!("{with_token:?}").contains("s3cret"));
}

#[tokio::test(start_paused = true)]
async fn a_hung_nomad_does_not_hang_the_query() {
    let stub = Stub::default();
    let address = stub
        .tcp(|_| Canned {
            stall: true,
            ..Canned::ok("")
        })
        .await;
    let nomad = Nomad::new(settings(vec![address]), &|_| None).unwrap();
    let wire = query("example.default.service.nomad.", Type::A, Class::IN);
    let got = tokio::time::timeout(Duration::from_secs(30), serve(&nomad, &wire))
        .await
        .expect("bounded by the client timeout")
        .unwrap();
    assert_eq!(render(&got).rcode, Rcode::NOERROR);
}

#![forbid(unsafe_code)]
#![cfg(feature = "plugin-nomad")]

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers_with_registry};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use pharos_server::{Action, Handler, Lifecycle, Phase, Protocol, metrics::Registry};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// What the stub Nomad answers one request with.
#[derive(Clone)]
struct Reply {
    status: u16,
    body: String,
    stall: bool,
}

impl Reply {
    fn ok(body: &str) -> Self {
        Self {
            status: 200,
            body: body.to_owned(),
            stall: false,
        }
    }

    fn status(status: u16, body: &str) -> Self {
        Self {
            status,
            ..Self::ok(body)
        }
    }

    fn stall() -> Self {
        Self {
            stall: true,
            ..Self::ok("")
        }
    }
}

/// A local HTTP/1.1 server that plays Nomad and records every request head.
struct Stub {
    address: String,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Stub {
    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }

    fn requests(&self) -> usize {
        self.heads.lock().unwrap().len()
    }
}

async fn stub(handler: impl Fn(&str) -> Reply + Send + Sync + 'static) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub = Stub {
        address: format!("http://{}", listener.local_addr().unwrap()),
        heads: Arc::default(),
    };
    let (heads, handler) = (stub.heads.clone(), Arc::new(handler));
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (heads, handler) = (heads.clone(), handler.clone());
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                loop {
                    while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                        let mut chunk = [0; 1024];
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                        }
                    }
                    let end = buffer.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    let head = String::from_utf8_lossy(&buffer.drain(..end).collect::<Vec<_>>())
                        .into_owned();
                    heads.lock().unwrap().push(head.clone());
                    let reply = handler(&head);
                    if reply.stall {
                        std::future::pending::<()>().await;
                    }
                    let wire = format!(
                        "HTTP/1.1 {} X\r\nContent-Length: {}\r\n\r\n{}",
                        reply.status,
                        reply.body.len(),
                        reply.body
                    );
                    if stream.write_all(wire.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    stub
}

/// An address nothing listens on.
async fn dead() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    format!("http://{}", listener.local_addr().unwrap())
}

// Plugin/nomad/nomad_test.go TestNomad: the registrations the fake Nomad servers return.
fn nomad_api(head: &str) -> Reply {
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
        // Nomad answers 200 and an empty list for a service it does not know.
        _ => "[]",
    };
    Reply::ok(body)
}

fn query(name: &str, qtype: Type) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 0x1234, 0x0100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
        .unwrap();
    let _ = builder.finish();
    wire
}

fn build(corefile: &str) -> std::io::Result<(impl Handler, Registry, Lifecycle)> {
    let blocks = parse("Corefile", corefile).unwrap();
    let registry = Registry::new("test", "test", "test");
    let (mut servers, lifecycle) = servers_with_registry(
        configure::<Chain>(&blocks, directives()).map_err(std::io::Error::other)?,
        registry.clone(),
    )?;
    Ok((servers.drain().next().unwrap().1, registry, lifecycle))
}

fn front(corefile: &str) -> (impl Handler, Registry, Lifecycle) {
    build(corefile).unwrap()
}

async fn ask_type(server: &impl Handler, name: &str, qtype: Type) -> Vec<u8> {
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        Box::pin(server.handle(
            &query(name, qtype),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response
        ))
        .await,
        Action::Respond
    );
    response
}

#[derive(Debug, PartialEq)]
struct Seen {
    rcode: Rcode,
    authoritative: bool,
    answer: Vec<String>,
    authority: Vec<String>,
    extra: Vec<String>,
}

fn render(wire: &[u8]) -> Seen {
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
    Seen {
        rcode: message.rcode(),
        authoritative: message.flags() & 0x0400 != 0,
        answer: records(message.answers()),
        authority: records(message.authorities()),
        extra: records(message.additionals()),
    }
}

async fn ask(server: &impl Handler, name: &str, qtype: Type) -> Seen {
    render(&ask_type(server, name, qtype).await)
}

fn nomad_block(address: &str, options: &str) -> String {
    format!(".:0 {{\n nomad {{\n address {address}\n{options}\n }}\n}}")
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

// The Corefile reaches the Plugin through the path the binary takes: parse, configure, servers.
#[tokio::test]
async fn a_corefile_with_every_property_builds_and_serves() {
    let nomad = stub(nomad_api).await;
    let (server, registry, lifecycle) = front(&format!(
        ".:0 {{\n nomad corp.nomad {{\n  address {}\n  filter \"Tags contains x\"\n  token s3cret\n  ttl 0\n }}\n}}",
        nomad.address
    ));
    let seen = ask(&server, "example.default.corp.nomad.", Type::A).await;
    assert_eq!(seen.rcode, Rcode::NOERROR);
    assert_eq!(
        seen.answer,
        strings(&["example.default.corp.nomad. 0 A 1.2.3.4"])
    );
    let head = nomad.heads().remove(0);
    assert!(
        head.starts_with(
            "GET /v1/service/example?filter=Tags+contains+x&namespace=default HTTP/1.1\r\n"
        ),
        "{head}"
    );
    assert!(
        head.to_lowercase()
            .contains("\r\nx-nomad-token: s3cret\r\n"),
        "{head}"
    );
    // The default zone is `service.nomad`; this Server Block serves `corp.nomad` only.
    assert!(
        ask(&server, "example.default.service.nomad.", Type::A)
            .await
            .answer
            .is_empty()
    );
    assert_eq!(nomad.requests(), 1);
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(
        text.contains(
            "pharos_nomad_success_requests_total{namespace=\"default\",server=\"dns://:0\"} 1"
        ),
        "{text}"
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn a_bare_nomad_directive_builds() {
    let (server, _, lifecycle) = front(".:0 {\n nomad\n}");
    // The default address (or `NOMAD_ADDR`) is used; whatever answers there, the Plugin answers too.
    let seen = ask(&server, "example.default.service.nomad.", Type::A).await;
    assert_eq!(seen.rcode, Rcode::NOERROR);
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

// CoreDNS v1.15.0 plugin/nomad/setup_test.go TestSetup, through `configure`.
#[test]
fn bad_nomad_directives_fail_the_build() {
    for corefile in [
        ".:0 {\n nomad {\n  fallthrough\n }\n}",
        ".:0 {\n nomad {\n  ttl 3601\n }\n}",
        ".:0 {\n nomad {\n  ttl -1\n }\n}",
        ".:0 {\n nomad {\n  address\n }\n}",
        ".:0 {\n nomad {\n  token a b\n }\n}",
        ".:0 {\n nomad {\n  address ftp://127.0.0.1\n }\n}",
        ".:0 {\n nomad\n nomad\n}",
    ] {
        assert!(build(corefile).is_err(), "{corefile}");
    }
}

// CoreDNS v1.15.0 plugin/nomad/nomad_test.go TestNomad: "A", "AAAA" and "SRV".
#[tokio::test]
async fn answers_a_aaaa_and_srv() {
    let nomad = stub(nomad_api).await;
    let (server, _, _) = front(&nomad_block(&nomad.address, ""));
    let a = ask(&server, "example.default.service.nomad.", Type::A).await;
    assert_eq!(a.rcode, Rcode::NOERROR);
    assert!(a.authoritative);
    assert_eq!(
        a.answer,
        strings(&["example.default.service.nomad. 30 A 1.2.3.4"])
    );
    let aaaa = ask(&server, "fakeipv6.default.service.nomad.", Type::AAAA).await;
    assert_eq!(
        aaaa.answer,
        strings(&["fakeipv6.default.service.nomad. 30 AAAA 1:2:3::4"])
    );
    let srv = ask(&server, "example.default.service.nomad.", Type::SRV).await;
    assert_eq!(
        srv.answer,
        strings(&[
            "example.default.service.nomad. 30 SRV 10 10 23202 example.default.service.nomad."
        ])
    );
    assert_eq!(
        srv.extra,
        strings(&["example.default.service.nomad. 30 A 1.2.3.4"])
    );
}

#[tokio::test]
async fn the_wrong_address_family_is_an_empty_noerror() {
    let nomad = stub(nomad_api).await;
    let (server, _, _) = front(&nomad_block(&nomad.address, ""));
    for (name, qtype) in [
        ("example.default.service.nomad.", Type::AAAA),
        ("fakeipv6.default.service.nomad.", Type::A),
    ] {
        let seen = ask(&server, name, qtype).await;
        assert_eq!(seen.rcode, Rcode::NOERROR, "{name}");
        assert!(seen.authoritative, "{name}");
        assert!(
            seen.answer.is_empty() && seen.authority.is_empty(),
            "{name}"
        );
    }
}

#[tokio::test]
async fn several_registrations_keep_their_order() {
    let nomad = stub(nomad_api).await;
    let (server, _, _) = front(&nomad_block(&nomad.address, ""));
    let seen = ask(&server, "multi.default.service.nomad.", Type::A).await;
    assert_eq!(
        seen.answer,
        strings(&[
            "multi.default.service.nomad. 30 A 1.2.3.4",
            "multi.default.service.nomad. 30 A 1.2.3.5",
            "multi.default.service.nomad. 30 A 1.2.3.6",
        ])
    );
    let srv = ask(&server, "multi.default.service.nomad.", Type::SRV).await;
    assert_eq!(srv.answer.len(), 3);
    assert_eq!(srv.extra.len(), 3);
}

// CoreDNS v1.15.0 plugin/nomad/nomad.go handleResponseError: NXDOMAIN with the SOA in the ANSWER section.
#[tokio::test]
async fn an_unknown_service_is_nxdomain_with_the_soa_in_the_answer() {
    let nomad = stub(nomad_api).await;
    let (server, _, _) = front(&nomad_block(&nomad.address, ""));
    for name in [
        "nonexistent.default.service.nomad.",
        "missing.default.service.nomad.",
    ] {
        let seen = ask(&server, name, Type::A).await;
        assert_eq!(seen.rcode, Rcode::NXDOMAIN, "{name}");
        assert!(seen.authoritative);
        assert_eq!(seen.answer.len(), 1, "{name}: {seen:?}");
        assert!(seen.answer[0].contains(" SOA "), "{seen:?}");
        assert!(seen.authority.is_empty());
    }
}

#[tokio::test]
async fn an_unsupported_type_is_nxdomain_with_the_soa() {
    let nomad = stub(nomad_api).await;
    let (server, _, _) = front(&nomad_block(&nomad.address, ""));
    for qtype in [Type::TXT, Type::MX, Type::NS, Type::CNAME] {
        let seen = ask(&server, "example.default.service.nomad.", qtype).await;
        assert_eq!(seen.rcode, Rcode::NXDOMAIN, "{qtype}");
        assert_eq!(seen.answer.len(), 1, "{qtype}");
        assert!(seen.answer[0].contains(" SOA "), "{qtype}");
    }
}

// The Query is not Nomad's: the Plugin hands it on and never calls Nomad.
#[tokio::test]
async fn names_outside_the_zone_never_reach_nomad() {
    let nomad = stub(nomad_api).await;
    let (server, _, _) = front(&nomad_block(&nomad.address, ""));
    for name in [
        "www.example.org.",
        "service.nomad.",
        "example.service.nomad.",
        "example.default.service.nomad.example.org.",
        ".",
    ] {
        let seen = ask(&server, name, Type::A).await;
        assert!(seen.answer.is_empty(), "{name}: {seen:?}");
        assert!(!seen.authoritative, "{name}: {seen:?}");
    }
    assert_eq!(nomad.requests(), 0);
}

// RFC 4343 §3: names compare case-insensitively; labels beyond service and namespace are ignored, as in CoreDNS.
#[tokio::test]
async fn names_are_case_insensitive_and_extra_labels_are_ignored() {
    let nomad = stub(nomad_api).await;
    let (server, _, _) = front(&nomad_block(&nomad.address, ""));
    let seen = ask(&server, "EXAMPLE.Default.Service.Nomad.", Type::A).await;
    assert_eq!(
        seen.answer,
        strings(&["EXAMPLE.Default.Service.Nomad. 30 A 1.2.3.4"])
    );
    assert!(nomad.heads()[0].starts_with("GET /v1/service/example?namespace=default "));
}

#[tokio::test]
async fn the_token_travels_in_a_header_and_never_in_the_url() {
    let nomad = stub(nomad_api).await;
    let (server, _, _) = front(&nomad_block(&nomad.address, " token tok-SECRET-123"));
    ask(&server, "example.default.service.nomad.", Type::A).await;
    let head = nomad.heads().remove(0);
    assert!(
        head.to_lowercase()
            .contains("\r\nx-nomad-token: tok-secret-123\r\n"),
        "{head}"
    );
    assert!(!head.lines().next().unwrap().contains("SECRET"), "{head}");
}

#[tokio::test]
async fn no_token_means_no_header() {
    let nomad = stub(nomad_api).await;
    let (server, _, _) = front(&nomad_block(&nomad.address, ""));
    ask(&server, "example.default.service.nomad.", Type::A).await;
    assert!(!nomad.heads()[0].to_lowercase().contains("x-nomad-token"));
}

// A hostile Nomad must not make the Plugin repeat the token it was given.
#[tokio::test]
async fn the_token_is_not_echoed_when_nomad_fails() {
    for reply in [
        Reply::status(403, "denied for tok-SECRET-123"),
        Reply::ok("tok-SECRET-123"),
        Reply::status(500, ""),
    ] {
        let nomad = stub(move |_| reply.clone()).await;
        let (server, _, _) = front(&nomad_block(&nomad.address, " token tok-SECRET-123"));
        let wire = ask_type(&server, "example.default.service.nomad.", Type::A).await;
        assert!(!String::from_utf8_lossy(&wire).contains("SECRET"));
        assert_eq!(render(&wire).rcode, Rcode::NOERROR);
    }
}

// Hashicorp nomad api v1.10.5 api/services.go Get: `url.PathEscape(name)` and `url.Values.Encode`.
#[tokio::test]
async fn hostile_labels_are_percent_encoded() {
    let nomad = stub(nomad_api).await;
    let (server, _, _) = front(&nomad_block(&nomad.address, ""));
    for (name, target) in [
        (
            "a/b.default.service.nomad.",
            "/v1/service/a%2Fb?namespace=default",
        ),
        (
            "a\\?b=c.default.service.nomad.",
            "/v1/service/a%3Fb=c?namespace=default",
        ),
        (
            "a\\#b.default.service.nomad.",
            "/v1/service/a%23b?namespace=default",
        ),
        (
            "a\\ b.default.service.nomad.",
            "/v1/service/a%20b?namespace=default",
        ),
        (
            "a\\%2e.default.service.nomad.",
            "/v1/service/a%252e?namespace=default",
        ),
        (
            "a\\255b.default.service.nomad.",
            "/v1/service/a%FFb?namespace=default",
        ),
        (
            "a\\010b.default.service.nomad.",
            "/v1/service/a%0Ab?namespace=default",
        ),
        (
            "svc.d\\&x\\=y.service.nomad.",
            "/v1/service/svc?namespace=d%26x%3Dy",
        ),
        (
            "svc.a\\ b\\;c.service.nomad.",
            "/v1/service/svc?namespace=a+b%3Bc",
        ),
        (
            "svc.n\\255.service.nomad.",
            "/v1/service/svc?namespace=n%FF",
        ),
    ] {
        ask(&server, name, Type::A).await;
        let head = nomad.heads().pop().unwrap();
        assert_eq!(
            head.lines().next().unwrap(),
            format!("GET {target} HTTP/1.1"),
            "{name}"
        );
        // One request head only: nothing was smuggled in as a header.
        assert_eq!(head.matches("\r\n\r\n").count(), 1, "{name}");
    }
}

#[tokio::test]
async fn ttl_and_filter_come_from_the_corefile() {
    let nomad = stub(nomad_api).await;
    let (server, _, _) = front(&nomad_block(&nomad.address, " ttl 0"));
    let seen = ask(&server, "example.default.service.nomad.", Type::A).await;
    assert_eq!(
        seen.answer,
        strings(&["example.default.service.nomad. 0 A 1.2.3.4"])
    );
    let (server, _, _) = front(&nomad_block(
        &nomad.address,
        " ttl 3600\n filter \"Tags contains canary\"",
    ));
    let seen = ask(&server, "example.default.service.nomad.", Type::A).await;
    assert_eq!(
        seen.answer,
        strings(&["example.default.service.nomad. 3600 A 1.2.3.4"])
    );
    let head = nomad.heads().pop().unwrap();
    assert!(
        head.starts_with("GET /v1/service/example?filter=Tags+contains+canary&namespace=default "),
        "{head}"
    );
}

// The SOA of the NXDOMAIN path carries the ttl too.
#[tokio::test]
async fn ttl_applies_to_the_soa() {
    let nomad = stub(nomad_api).await;
    let (server, _, _) = front(&nomad_block(&nomad.address, " ttl 0"));
    let seen = ask(&server, "nonexistent.default.service.nomad.", Type::A).await;
    assert!(seen.answer[0].contains(" 0 SOA "), "{seen:?}");
}

// CoreDNS v1.15.0 plugin/nomad/nomad.go handleServiceLookupError: a lookup failure is an empty authoritative NOERROR.
#[tokio::test]
async fn nomad_down_is_a_fast_empty_noerror() {
    let (server, registry, _) = front(&nomad_block(&dead().await, ""));
    let start = Instant::now();
    let seen = ask(&server, "example.default.service.nomad.", Type::A).await;
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(seen.rcode, Rcode::NOERROR);
    assert!(seen.authoritative);
    assert!(seen.answer.is_empty() && seen.authority.is_empty() && seen.extra.is_empty());
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(
        text.contains(
            "pharos_nomad_failed_requests_total{namespace=\"default\",server=\"dns://:0\"} 1"
        ),
        "{text}"
    );
    assert!(
        !text.contains("pharos_nomad_success_requests_total"),
        "{text}"
    );
}

#[tokio::test]
async fn a_nomad_error_status_is_an_empty_noerror() {
    for status in [403, 404, 429, 500, 503] {
        let nomad = stub(move |_| Reply::status(status, "[]")).await;
        let (server, _, _) = front(&nomad_block(&nomad.address, ""));
        let seen = ask(&server, "example.default.service.nomad.", Type::A).await;
        assert_eq!(seen.rcode, Rcode::NOERROR, "{status}");
        assert!(seen.answer.is_empty(), "{status}");
    }
}

// The request ends after 5 seconds whatever Nomad does; paused time keeps the test instant.
#[tokio::test(start_paused = true)]
async fn a_slow_nomad_is_cut_off_by_the_timeout() {
    let nomad = stub(|_| Reply::stall()).await;
    let (server, registry, _) = front(&nomad_block(&nomad.address, ""));
    let start = tokio::time::Instant::now();
    let seen = ask(&server, "example.default.service.nomad.", Type::A).await;
    let waited = start.elapsed();
    assert!(
        waited >= Duration::from_secs(5) && waited < Duration::from_secs(6),
        "{waited:?}"
    );
    assert_eq!(seen.rcode, Rcode::NOERROR);
    assert!(seen.answer.is_empty());
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(
        text.contains("pharos_nomad_failed_requests_total"),
        "{text}"
    );
}

// CoreDNS v1.15.0 plugin/nomad/nomad_test.go TestNomad: the next address answers when the first is dead.
#[tokio::test]
async fn failover_moves_to_the_next_address_and_stays_there() {
    let live = stub(nomad_api).await;
    let dead = dead().await;
    let broken = stub(|_| Reply::status(500, "")).await;
    let (server, _, _) = front(&format!(
        ".:0 {{\n nomad {{\n address {dead} {} {}\n }}\n}}",
        broken.address, live.address
    ));
    for _ in 0..3 {
        let seen = ask(&server, "example.default.service.nomad.", Type::A).await;
        assert_eq!(
            seen.answer,
            strings(&["example.default.service.nomad. 30 A 1.2.3.4"])
        );
    }
    // The broken endpoint was tried once; later Queries start at the live one.
    assert_eq!(broken.requests(), 1);
    assert_eq!(live.requests(), 3);
}

#[tokio::test]
async fn every_address_failing_is_an_empty_noerror() {
    let broken = stub(|_| Reply::status(500, "")).await;
    let (server, _, _) = front(&format!(
        ".:0 {{\n nomad {{\n address {}\n address {}\n }}\n}}",
        dead().await,
        broken.address
    ));
    let seen = ask(&server, "example.default.service.nomad.", Type::A).await;
    assert_eq!(seen.rcode, Rcode::NOERROR);
    assert!(seen.answer.is_empty());
}

#[tokio::test]
async fn metrics_count_answers_failures_and_the_namespace() {
    let nomad = stub(nomad_api).await;
    let (server, registry, _) = front(&nomad_block(&nomad.address, ""));
    ask(&server, "example.default.service.nomad.", Type::A).await;
    ask(&server, "multi.default.service.nomad.", Type::SRV).await;
    ask(&server, "nonexistent.default.service.nomad.", Type::A).await;
    ask(&server, "example.prod.service.nomad.", Type::TXT).await;
    ask(&server, "www.example.org.", Type::A).await;
    let mut text = String::new();
    registry.encode(&mut text);
    let lines = text
        .lines()
        .filter(|line| line.starts_with("pharos_nomad_"))
        .collect::<Vec<_>>();
    assert_eq!(
        lines,
        [
            "pharos_nomad_success_requests_total{namespace=\"default\",server=\"dns://:0\"} 2",
            "pharos_nomad_failed_requests_total{namespace=\"default\",server=\"dns://:0\"} 1",
            "pharos_nomad_failed_requests_total{namespace=\"prod\",server=\"dns://:0\"} 1",
        ]
    );
}

// The namespace label comes from the Query name, so its cardinality is bounded.
#[tokio::test]
async fn namespace_labels_are_bounded_under_a_flood_of_names() {
    let nomad = stub(nomad_api).await;
    let (server, registry, _) = front(&nomad_block(&nomad.address, ""));
    for index in 0..150 {
        ask(
            &server,
            &format!("example.ns{index}.service.nomad."),
            Type::A,
        )
        .await;
    }
    let mut text = String::new();
    registry.encode(&mut text);
    let series = text
        .lines()
        .filter(|line| line.starts_with("pharos_nomad_success_requests_total{"))
        .count();
    assert_eq!(series, 65, "{text}");
    assert!(
        text.contains("namespace=\"_other\",server=\"dns://:0\"} 86"),
        "{text}"
    );
}

// Startup never waits for Nomad.
#[tokio::test]
async fn startup_does_not_wait_for_nomad() {
    let hung = stub(|_| Reply::stall()).await;
    let (_, _, lifecycle) = front(&format!(
        ".:0 {{\n nomad {{\n  address {} {}\n }}\n}}",
        hung.address, hung.address
    ));
    tokio::time::timeout(Duration::from_secs(1), lifecycle.run(Phase::Startup))
        .await
        .expect("Startup must not wait for Nomad")
        .unwrap();
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

// CoreDNS v1.15.0 plugin/nomad/ready.go: one address is always ready; several need one that answers.
#[cfg(feature = "plugin-ready")]
mod ready {
    use super::*;

    async fn status(address: std::net::SocketAddr) -> String {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    fn free_address() -> std::net::SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    #[tokio::test]
    async fn a_single_address_is_ready_at_once() {
        let ready = free_address();
        let (_, _, lifecycle) = front(&format!(
            ".:0 {{\n ready {ready}\n nomad {{\n  address {}\n }}\n}}",
            dead().await
        ));
        lifecycle.run(Phase::Startup).await.unwrap();
        let response = status(ready).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        lifecycle.run(Phase::Shutdown).await.unwrap();
    }

    #[tokio::test]
    async fn several_dead_addresses_are_not_ready() {
        let ready = free_address();
        let (_, _, lifecycle) = front(&format!(
            ".:0 {{\n ready {ready}\n nomad {{\n  address {} {}\n }}\n}}",
            dead().await,
            dead().await
        ));
        lifecycle.run(Phase::Startup).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let response = status(ready).await;
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        assert!(response.contains("nomad"), "{response}");
        lifecycle.run(Phase::Shutdown).await.unwrap();
    }

    #[tokio::test]
    async fn one_live_address_among_several_is_ready() {
        let live = stub(|_| Reply::ok("{}")).await;
        let ready = free_address();
        let (_, _, lifecycle) = front(&format!(
            ".:0 {{\n ready {ready}\n nomad {{\n  address {} {}\n }}\n}}",
            dead().await,
            live.address
        ));
        lifecycle.run(Phase::Startup).await.unwrap();
        let mut response = String::new();
        for _ in 0..200 {
            response = status(ready).await;
            if response.starts_with("HTTP/1.1 200") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            live.heads()[0].starts_with("GET /v1/agent/self "),
            "{:?}",
            live.heads()
        );
        lifecycle.run(Phase::Shutdown).await.unwrap();
    }
}

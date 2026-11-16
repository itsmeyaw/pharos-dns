use super::*;
use pharos_proto::zone::ZoneParser;

struct TestNext;

impl pharos_server::Next for TestNext {
    fn run(
        self,
        _: &mut pharos_server::Context<'_, '_>,
    ) -> impl std::future::Future<Output = pharos_server::Outcome> + Send {
        std::future::ready(pharos_server::Outcome::Unanswered(Rcode::SERVFAIL))
    }
}

fn catalog_records(text: &str) -> (Name, Vec<pharos_proto::zone::ZoneRecord>) {
    let origin: Name = "catalog.example.".parse().unwrap();
    let records = ZoneParser::new(text.as_bytes(), origin.clone(), "catalog")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    (origin, records)
}

#[test]
fn coredns_catalog_requires_version_and_unique_members() {
    let header = "@ 60 IN SOA ns. hostmaster. 1 10 10 100 60\n@ 60 IN NS ns.\n";
    for invalid in [
        "a.zones 60 IN PTR example.org.\n",
        "version 60 IN TXT \"1\"\n",
        "version 60 IN TXT \"2\"\nversion 60 IN TXT \"2\"\n",
        "version 60 IN TXT \"2\"\na.zones 60 IN PTR example.org.\nb.zones 60 IN PTR example.org.\n",
        "version 60 IN TXT \"2\"\na.zones 60 IN PTR example.org.\na.zones 60 IN PTR other.example.\n",
        "version 60 IN TXT \"2\"\na.zones 60 IN PTR example.org.\ncoo.a.zones 60 IN PTR one.example.\ncoo.a.zones 60 IN PTR two.example.\n",
        "version 60 IN TXT \"2\"\ncoo.orphan.zones 60 IN PTR one.example.\ncoo.orphan.zones 60 IN PTR two.example.\n",
        "version 60 IN TXT \"2\"\na.zones 60 CH PTR example.org.\n",
    ] {
        let (origin, records) = catalog_records(&format!("{header}{invalid}"));
        assert!(catalog::parse(&origin, &records).is_err(), "{invalid}");
    }
    let (origin, records) = catalog_records(&format!(
        "{header}@ 60 IN SOA ns. hostmaster. 2 10 10 100 60\nversion 60 IN TXT \"2\"\n"
    ));
    assert!(catalog::parse(&origin, &records).is_err());
    let (origin, records) = catalog_records(&format!(
        "{header}version 60 IN TXT \"2\"\na.zones 60 IN PTR example.org.\ncoo.a.zones 60 IN PTR other.catalog.example.\n"
    ));
    let parsed = catalog::parse(&origin, &records).unwrap();
    assert_eq!(parsed.members.len(), 1);
    assert_eq!(parsed.members[0].zone.to_string(), "example.org.");
    assert_eq!(
        parsed.members[0].coo.as_ref().unwrap().to_string(),
        "other.catalog.example."
    );
}

#[test]
fn coredns_catalog_sorts_members_and_groups() {
    let (origin, records) = catalog_records(
        "@ 60 IN SOA ns. hostmaster. 1 10 10 100 60\n@ 60 IN NS ns.\nversion 60 IN TXT \"2\"\nb.zones 60 IN PTR Example.NET.\na.zones 60 IN PTR example.com.\ngroup.a.zones 60 IN TXT \"unsigned\"\ngroup.a.zones 60 IN TXT \"operator-default\"\n",
    );
    let catalog = catalog::parse(&origin, &records).unwrap();
    assert_eq!(catalog.members[0].zone.to_string(), "example.com.");
    assert_eq!(catalog.members[1].zone.to_string(), "example.net.");
    assert_eq!(
        catalog.members[0].groups,
        [b"operator-default".to_vec(), b"unsigned".to_vec()]
    );
}

#[test]
fn coredns_serial_comparison_wraps() {
    use crate::serial::serial_at_least;
    assert!(serial_at_least(0, u32::MAX));
    assert!(!serial_at_least(u32::MAX, 0));
    assert!(!serial_at_least(4_000_000_000, 12_345));
    assert!(!serial_at_least(7, 9));
}

#[test]
fn coredns_notify_checks_ip_spelling_and_scope() {
    let loopback = "[::1]:1234".parse().unwrap();
    assert!(update::primary_matches("[::1]:53", loopback));
    assert_eq!(
        update::primary_address("[::1]:5353", loopback),
        Some("[::1]:5353".parse().unwrap())
    );
    assert!(!update::primary_matches("[0:0:0:0:0:0:0:1]:53", loopback));
    // Index 1 names the first interface (lo0 or lo) on the supported hosts.
    let name = nix::net::if_::if_indextoname(1).unwrap();
    let name = name.to_str().unwrap();
    let scoped = std::net::SocketAddrV6::new("fe80::1".parse().unwrap(), 1234, 0, 1).into();
    assert!(update::primary_matches(
        &format!("[fe80::1%{name}]:53"),
        scoped
    ));
    assert!(update::primary_matches("[fe80::1%1]:53", scoped));
    assert!(!update::primary_matches("[fe80::1%2]:53", scoped));
    assert!(!update::primary_matches("[fe80::1]:53", scoped));
}

fn soa_rdata(serial: u32) -> Vec<u8> {
    let mut soa = vec![0, 0];
    for value in [serial, 3600, 1, 3600, 60] {
        soa.extend_from_slice(&value.to_be_bytes());
    }
    soa
}

/// Serve one AXFR: opening SOA, `extra` records, closing SOA.
async fn serve_axfr(
    listener: tokio::net::TcpListener,
    serial: u32,
    extra: impl FnOnce(&mut pharos_proto::MessageBuilder<'_>, NameRef<'_>),
) {
    let (socket, _) = listener.accept().await.unwrap();
    serve_axfr_on(socket, serial, extra).await;
}

async fn serve_axfr_on(
    mut socket: tokio::net::TcpStream,
    serial: u32,
    extra: impl FnOnce(&mut pharos_proto::MessageBuilder<'_>, NameRef<'_>),
) {
    use pharos_proto::{Message, MessageBuilder, Section};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let length = socket.read_u16().await.unwrap();
    let mut input = vec![0; usize::from(length)];
    socket.read_exact(&mut input).await.unwrap();
    let query = Message::parse(&input).unwrap();
    let q = query.questions().next().unwrap();
    let mut output = Vec::new();
    let mut builder = MessageBuilder::new(&mut output, 65535, query.id(), 0x8400).unwrap();
    builder.question(q.name, q.qtype, q.qclass).unwrap();
    let soa = soa_rdata(serial);
    builder
        .record(Section::Answer, q.name, Type::SOA, Class::IN, 60, &soa)
        .unwrap();
    // RFC 1034 §4.2.1 / RFC 1035 §5.2: a zone needs an apex NS RRset to be loadable.
    builder
        .record(
            Section::Answer,
            q.name,
            Type::NS,
            Class::IN,
            60,
            b"\x02ns\x07example\x03org\x00",
        )
        .unwrap();
    extra(&mut builder, q.name);
    builder
        .record(Section::Answer, q.name, Type::SOA, Class::IN, 60, &soa)
        .unwrap();
    let _ = builder.finish();
    socket.write_u16(output.len() as u16).await.unwrap();
    socket.write_all(&output).await.unwrap();
}

fn plain_zone(from: std::net::SocketAddr) -> SecondaryZone {
    SecondaryZone::new(ZoneConfig {
        limits: Default::default(),
        apex: "example.org.".parse().unwrap(),
        from: vec![from.to_string()],
        catalog: None,
    })
}

#[tokio::test]
async fn secondary_axfr_stores_compressed_rdata_names_uncompressed() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let zone = plain_zone(listener.local_addr().unwrap());
    let primary = tokio::spawn(serve_axfr(listener, 1, |builder, apex| {
        // The target compresses against the Question name.
        builder
            .record_with(
                pharos_proto::Section::Answer,
                apex,
                Type::NS,
                Class::IN,
                60,
                |writer| writer.write_name(apex),
            )
            .unwrap();
    }));
    let (shared, _, _) = catalog_shared();
    update::transfer(&shared, &zone).await.unwrap();
    primary.await.unwrap();
    let snapshot = zone.current.load_full().unwrap();
    assert!(
        snapshot
            .records()
            .iter()
            .any(|record| record.rtype == Type::NS && record.rdata == zone.config.apex.as_wire())
    );
}

#[test]
fn secondary_setup_applies_transfer_limits() {
    let corefile = "example.org:53 {\n secondary {\n transfer from 127.0.0.1\n max_records 10\n max_bytes 4096\n }\n}";
    let blocks = pharos_corefile::parse("Corefile", corefile).unwrap();
    let configured =
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
    let secondary = configured[0].config.secondary.as_ref().unwrap();
    let limits = secondary.shared.zones.load()[0].config.limits;
    assert_eq!((limits.max_records, limits.max_bytes), (10, 4096));
}

#[tokio::test]
async fn secondary_serializes_transfers_and_never_publishes_an_older_serial() {
    use std::sync::atomic::AtomicUsize;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let zone = Arc::new(plain_zone(listener.local_addr().unwrap()));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let primary = {
        let (active, peak) = (Arc::clone(&active), Arc::clone(&peak));
        tokio::spawn(async move {
            let mut handlers = Vec::new();
            // The first connection offers the newer serial; the second an older one.
            for serial in [5, 3] {
                let (socket, _) = listener.accept().await.unwrap();
                let (active, peak) = (Arc::clone(&active), Arc::clone(&peak));
                handlers.push(tokio::spawn(async move {
                    peak.fetch_max(active.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    serve_axfr_on(socket, serial, |_, _| {}).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                }));
            }
            for handler in handlers {
                handler.await.unwrap();
            }
        })
    };
    let (shared, _, _) = catalog_shared();
    let (first, second) = tokio::join!(
        update::transfer(&shared, &zone),
        update::transfer(&shared, &zone)
    );
    first.unwrap();
    second.unwrap();
    primary.await.unwrap();
    assert_eq!(peak.load(Ordering::SeqCst), 1);
    assert_eq!(zone.current.load_full().unwrap().serial(), Some(5));
}

#[tokio::test]
async fn failed_notify_check_enters_retry_instead_of_waiting_for_refresh() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let zone = Arc::new(plain_zone(address));
    let (shared, _, _) = catalog_shared();
    let task = tokio::spawn(update::run(shared, Arc::clone(&zone)));
    let (socket, _) = listener.accept().await.unwrap();
    // REFRESH is 3600 s and RETRY 1 s: only the NOTIFY failure can cause a second check soon.
    serve_axfr_on(socket, 1, |_, _| {}).await;
    while zone.current.load().is_none() {
        tokio::task::yield_now().await;
    }
    *zone.notify_source.lock().unwrap() = Some(address);
    zone.notify.notify_one();
    // The NOTIFY SOA check fails when the primary drops the connection.
    drop(listener.accept().await.unwrap());
    tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
        .await
        .expect("failed NOTIFY did not trigger a RETRY check")
        .unwrap();
    task.abort();
}

#[test]
fn unknown_notify_logging_is_rate_limited_per_zone() {
    assert!(log_unknown_notify(0));
    assert!(!log_unknown_notify(1));
    assert!(!log_unknown_notify(1023));
    assert!(log_unknown_notify(1024));
}

#[test]
fn notify_with_extra_questions_is_acknowledged() {
    use pharos_proto::{Message, MessageBuilder};
    use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
    let zone = plain_zone("127.0.0.1:53".parse().unwrap());
    let apex = NameRef::parse(zone.config.apex.as_wire(), 0).unwrap();
    let mut request = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut request, 512, 7, 0x2400).unwrap();
    builder.question(apex, Type::SOA, Class::IN).unwrap();
    builder.question(apex, Type::NS, Class::IN).unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&request).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &zone.config.apex,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(handle_notify(&zone, &mut cx), Outcome::Response);
}

#[tokio::test]
async fn secondary_rejects_axfr_over_record_cap_and_keeps_no_zone() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut zone = plain_zone(listener.local_addr().unwrap());
    zone.config.limits.max_records = 2;
    let primary = tokio::spawn(serve_axfr(listener, 1, |builder, apex| {
        for _ in 0..3 {
            builder
                .record(
                    pharos_proto::Section::Answer,
                    apex,
                    Type::A,
                    Class::IN,
                    60,
                    &[192, 0, 2, 1],
                )
                .unwrap();
        }
    }));
    let (shared, _, _) = catalog_shared();
    let error = update::transfer(&shared, &zone).await.unwrap_err();
    primary.await.unwrap();
    assert!(error.to_string().contains("max_records"), "{error}");
    assert!(zone.current.load().is_none());
}

#[tokio::test]
async fn secondary_rejects_axfr_over_byte_cap_and_keeps_no_zone() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut zone = plain_zone(listener.local_addr().unwrap());
    zone.config.limits.max_bytes = 40;
    let primary = tokio::spawn(serve_axfr(listener, 1, |builder, apex| {
        builder
            .record(
                pharos_proto::Section::Answer,
                apex,
                Type::TXT,
                Class::IN,
                60,
                &[30; 31],
            )
            .unwrap();
    }));
    let (shared, _, _) = catalog_shared();
    let error = update::transfer(&shared, &zone).await.unwrap_err();
    primary.await.unwrap();
    assert!(error.to_string().contains("max_bytes"), "{error}");
    assert!(zone.current.load().is_none());
}

#[tokio::test]
async fn secondary_axfr_has_a_total_deadline() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut zone = plain_zone(listener.local_addr().unwrap());
    zone.config.limits.timeout = std::time::Duration::from_millis(100);
    let primary = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Read the query, then stay silent: only the total deadline ends this before the 5 s frame deadline.
        let length = socket.read_u16().await.unwrap();
        let mut input = vec![0; usize::from(length)];
        socket.read_exact(&mut input).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });
    let (shared, _, _) = catalog_shared();
    let started = std::time::Instant::now();
    let error = update::transfer(&shared, &zone).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    primary.abort();
}

#[tokio::test]
async fn secondary_validates_axfr_apex_ns_and_deduplicates_records() {
    use pharos_proto::{Class, Message, MessageBuilder, Section};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn primary(listener: tokio::net::TcpListener, mode: u8) {
        let (mut socket, _) = listener.accept().await.unwrap();
        let length = socket.read_u16().await.unwrap();
        let mut input = vec![0; usize::from(length)];
        socket.read_exact(&mut input).await.unwrap();
        let query = Message::parse(&input).unwrap();
        let q = query.questions().next().unwrap();
        let mut output = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut output, 512, query.id(), 0x8400).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        let mut soa = vec![0, 0];
        for value in [250u32, 1, 1, 10, 60] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        builder
            .record(Section::Answer, q.name, Type::SOA, Class::IN, 60, &soa)
            .unwrap();
        if mode != 0 && mode != 3 {
            builder
                .record(
                    Section::Answer,
                    q.name,
                    Type::NS,
                    Class::IN,
                    60,
                    "ns.example.org.".parse::<Name>().unwrap().as_wire(),
                )
                .unwrap();
        }
        let owner: Name = if mode == 1 {
            "good.example.org."
        } else {
            "evil.example.org."
        }
        .parse()
        .unwrap();
        builder
            .record(
                Section::Answer,
                NameRef::parse(owner.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
                60,
                &[192, 0, 2, 1],
            )
            .unwrap();
        if mode == 1 {
            builder
                .record(
                    Section::Answer,
                    NameRef::parse(owner.as_wire(), 0).unwrap(),
                    Type::A,
                    Class::IN,
                    60,
                    &[192, 0, 2, 1],
                )
                .unwrap();
        }
        if mode == 2 {
            builder
                .record(
                    Section::Answer,
                    q.name,
                    Type::NSEC3PARAM,
                    Class::IN,
                    60,
                    &[1, 0, 0, 0, 0],
                )
                .unwrap();
        }
        if mode != 0 {
            builder
                .record(Section::Answer, q.name, Type::SOA, Class::IN, 60, &soa)
                .unwrap();
        }
        let _ = builder.finish();
        socket.write_u16(output.len() as u16).await.unwrap();
        socket.write_all(&output).await.unwrap();
    }
    for mode in [0, 2] {
        let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let from = vec![
            first.local_addr().unwrap().to_string(),
            second.local_addr().unwrap().to_string(),
        ];
        let first = tokio::spawn(primary(first, mode));
        let second = tokio::spawn(primary(second, 1));
        let (shared, _, _) = catalog_shared();
        let zone = SecondaryZone::new(ZoneConfig {
            limits: Default::default(),
            apex: "example.org.".parse().unwrap(),
            from,
            catalog: None,
        });
        update::transfer(&shared, &zone).await.unwrap();
        first.await.unwrap();
        second.await.unwrap();
        let snapshot = zone.current.load_full().unwrap();
        let good: Name = "good.example.org.".parse().unwrap();
        let evil: Name = "evil.example.org.".parse().unwrap();
        assert_eq!(
            snapshot
                .rrset(NameRef::parse(good.as_wire(), 0).unwrap(), Type::A)
                .count(),
            1
        );
        assert_eq!(
            snapshot
                .rrset(NameRef::parse(evil.as_wire(), 0).unwrap(), Type::A)
                .count(),
            0
        );
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let from = listener.local_addr().unwrap().to_string();
    let primary = tokio::spawn(primary(listener, 3));
    let (shared, _, _) = catalog_shared();
    let missing_ns = SecondaryZone::new(ZoneConfig {
        apex: "example.org.".parse().unwrap(),
        from: vec![from],
        catalog: None,
        limits: Default::default(),
    });
    let error = update::transfer(&shared, &missing_ns).await.unwrap_err();
    assert!(error.to_string().contains("Zone apex has no NS record"));
    assert!(
        error
            .to_string()
            .contains("add an NS RRset at the Zone apex")
    );
    assert!(missing_ns.current.load_full().is_none());
    primary.await.unwrap();
}

#[tokio::test]
async fn secondary_soa_check_matches_response_id_and_question() {
    use pharos_proto::{Message, MessageBuilder, Section};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for (wrong_id, wrong_question) in [
            (false, false),
            (false, false),
            (false, false),
            (true, false),
            (false, true),
        ] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let length = socket.read_u16().await.unwrap();
            let mut query = vec![0; usize::from(length)];
            socket.read_exact(&mut query).await.unwrap();
            let query = Message::parse(&query).unwrap();
            let question = query.questions().next().unwrap();
            let mut output = Vec::with_capacity(512);
            let mut builder = MessageBuilder::new(
                &mut output,
                512,
                query.id().wrapping_add(u16::from(wrong_id)),
                0x8400,
            )
            .unwrap();
            let other: Name = "other.example.".parse().unwrap();
            let name = if wrong_question {
                NameRef::parse(other.as_wire(), 0).unwrap()
            } else {
                question.name
            };
            builder
                .question(name, question.qtype, question.qclass)
                .unwrap();
            let mut soa = vec![0, 0];
            for value in [250u32, 0, 0, 0, 0] {
                soa.extend_from_slice(&value.to_be_bytes());
            }
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::SOA,
                    Class::IN,
                    60,
                    &soa,
                )
                .unwrap();
            let _ = builder.finish();
            socket.write_u16(output.len() as u16).await.unwrap();
            socket.write_all(&output).await.unwrap();
        }
    });
    let zone = SecondaryZone::new(ZoneConfig {
        limits: Default::default(),
        apex: "example.org.".parse().unwrap(),
        from: vec![address.to_string()],
        catalog: None,
    });
    assert!(update::should_transfer(&zone).await.unwrap().is_some());
    for serial in [249, 250] {
        let text = format!("@ 60 IN SOA ns. hostmaster. {serial} 0 0 0 0\n@ 60 IN NS ns.\n");
        let records = ZoneParser::new(text.as_bytes(), zone.config.apex.clone(), "test")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        zone.current.store(Some(Arc::new(
            crate::zone::Zone::from_records(zone.config.apex.clone(), records).unwrap(),
        )));
        assert_eq!(
            update::should_transfer(&zone).await.unwrap().is_some(),
            serial == 249
        );
    }
    assert!(update::should_transfer(&zone).await.is_err());
    assert!(update::should_transfer(&zone).await.is_err());
    server.await.unwrap();
}

#[tokio::test]
async fn secondary_reuses_soa_connection_for_axfr() {
    use pharos_proto::{Message, MessageBuilder, Section};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let primary = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut query_wire = vec![0; usize::from(socket.read_u16().await.unwrap())];
        socket.read_exact(&mut query_wire).await.unwrap();
        let query = Message::parse(&query_wire).unwrap();
        let question = query.questions().next().unwrap();
        assert_eq!(question.qtype, Type::SOA);

        let mut response_wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut response_wire, 512, query.id(), 0x8400).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::SOA,
                Class::IN,
                60,
                &soa_rdata(2),
            )
            .unwrap();
        let _ = builder.finish();
        socket
            .write_u16(response_wire.len() as u16)
            .await
            .unwrap();
        socket.write_all(&response_wire).await.unwrap();

        let mut query_wire = vec![0; usize::from(socket.read_u16().await.unwrap())];
        socket.read_exact(&mut query_wire).await.unwrap();
        let query = Message::parse(&query_wire).unwrap();
        let question = query.questions().next().unwrap();
        assert_eq!(question.qtype, Type::AXFR);

        let mut response_wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut response_wire, 512, query.id(), 0x8400).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        for rtype in [Type::SOA, Type::NS, Type::SOA] {
            let rdata = if rtype == Type::NS {
                b"\x02ns\x07example\x03org\x00".as_slice()
            } else {
                &soa_rdata(2)
            };
            builder
                .record(Section::Answer, question.name, rtype, Class::IN, 60, rdata)
                .unwrap();
        }
        let _ = builder.finish();
        socket
            .write_u16(response_wire.len() as u16)
            .await
            .unwrap();
        socket.write_all(&response_wire).await.unwrap();
    });

    let zone = plain_zone(address);
    let (shared, _, _) = catalog_shared();
    let (primary_address, socket) = update::should_transfer(&zone)
        .await
        .unwrap()
        .unwrap();
    update::transfer_on_connection(&shared, &zone, primary_address, socket)
        .await
        .unwrap();
    primary.await.unwrap();
}

#[tokio::test]
async fn notify_refresh_queries_the_sending_primary() {
    use pharos_proto::{Message, MessageBuilder, Section};
    use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let source = listener.local_addr().unwrap();
    let primary = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let len = socket.read_u16().await.unwrap();
        let mut query = vec![0; usize::from(len)];
        socket.read_exact(&mut query).await.unwrap();
        let query = Message::parse(&query).unwrap();
        let question = query.questions().next().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, query.id(), 0x8400).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        let mut soa = vec![0, 0];
        for value in [2u32, 10, 10, 100, 60] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        builder
            .record(
                Section::Answer,
                question.name,
                Type::SOA,
                Class::IN,
                60,
                &soa,
            )
            .unwrap();
        let _ = builder.finish();
        socket.write_u16(wire.len() as u16).await.unwrap();
        socket.write_all(&wire).await.unwrap();
    });
    let zone = SecondaryZone::new(ZoneConfig {
        limits: Default::default(),
        apex: "example.org.".parse().unwrap(),
        from: vec![source.to_string()],
        catalog: None,
    });
    let mut request = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut request, 512, 7, 0x2400).unwrap();
    builder
        .question(
            NameRef::parse(zone.config.apex.as_wire(), 0).unwrap(),
            Type::SOA,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&request).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &zone.config.apex,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(handle_notify(&zone, &mut cx), Outcome::Response);
    let target = zone.notify_source.lock().unwrap().take().unwrap();
    assert_eq!(target, source);
    assert!(update::should_transfer_from(&zone, target)
        .await
        .unwrap()
        .is_some());
    primary.await.unwrap();
}

#[tokio::test]
async fn coredns_notify_accepts_only_known_primary() {
    use pharos_proto::{Message, MessageBuilder};
    use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
    let corefile = "example.org:53 {\n secondary {\n transfer from 127.0.0.1:15353\n }\n}";
    let blocks = pharos_corefile::parse("Corefile", corefile).unwrap();
    let configured =
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
    let secondary = configured[0].config.secondary.as_ref().unwrap();
    let apex: Name = "example.org.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 7, 0x2400).unwrap();
    builder
        .question(
            NameRef::parse(apex.as_wire(), 0).unwrap(),
            Type::SOA,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.2:1000".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &apex,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        secondary.serve_with(&mut cx, TestNext, true).await,
        Outcome::Drop
    );
    assert_eq!(
        secondary.shared.zones.load()[0]
            .unknown_notify
            .load(Ordering::Relaxed),
        1
    );
    cx.client = "127.0.0.1:1000".parse().unwrap();
    assert_eq!(
        secondary.serve_with(&mut cx, TestNext, true).await,
        Outcome::Response
    );
    cx.protocol = Protocol::Tcp;
    cx.max_response_size = 65535;
    assert_eq!(
        secondary.serve_with(&mut cx, TestNext, true).await,
        Outcome::Response
    );
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.id(), 7);
    assert_eq!(response.opcode(), Opcode::NOTIFY);
    assert!(response.aa());
    let zone = &secondary.shared.zones.load()[0];
    assert_eq!(
        *zone.notify_source.lock().unwrap(),
        Some("127.0.0.1:15353".parse().unwrap())
    );
    tokio::time::timeout(std::time::Duration::from_millis(10), zone.notify.notified())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), zone.notify.notified())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn secondary_ignores_malformed_notify_and_non_soa_question() {
    use pharos_proto::{Message, MessageBuilder};
    use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
    let corefile = "example.org:53 {\n secondary {\n transfer from 127.0.0.1:15353\n }\n}";
    let blocks = pharos_corefile::parse("Corefile", corefile).unwrap();
    let configured =
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
    let secondary = configured[0].config.secondary.as_ref().unwrap();
    let apex: Name = "example.org.".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    for (flags, qtype, qclass, qname, client, outcome) in [
        (
            0x2500,
            Type::SOA,
            Class::IN,
            apex.clone(),
            "127.0.0.1:1000".parse().unwrap(),
            Outcome::Drop,
        ),
        (
            0x2500,
            Type::SOA,
            Class::IN,
            apex.clone(),
            "127.0.0.2:1000".parse().unwrap(),
            Outcome::Drop,
        ),
        (
            0x2000,
            Type::SOA,
            Class::IN,
            apex.clone(),
            "127.0.0.1:1000".parse().unwrap(),
            Outcome::Drop,
        ),
        (
            0x2400,
            Type::A,
            Class::IN,
            apex.clone(),
            "127.0.0.1:1000".parse().unwrap(),
            Outcome::Drop,
        ),
        (
            0x2400,
            Type::SOA,
            Class::CH,
            apex.clone(),
            "127.0.0.1:1000".parse().unwrap(),
            Outcome::Drop,
        ),
        (
            0xa400,
            Type::SOA,
            Class::IN,
            apex.clone(),
            "127.0.0.1:1000".parse().unwrap(),
            Outcome::Drop,
        ),
        (
            0x2400,
            Type::SOA,
            Class::IN,
            "child.example.org.".parse().unwrap(),
            "127.0.0.1:1000".parse().unwrap(),
            Outcome::Drop,
        ),
    ] {
        let mut query = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut query, 512, 7, flags).unwrap();
        builder
            .question(NameRef::parse(qname.as_wire(), 0).unwrap(), qtype, qclass)
            .unwrap();
        let _ = builder.finish();
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client,
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &apex,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(secondary.serve_with(&mut cx, TestNext, true).await, outcome);
    }
    let mut query = Vec::with_capacity(512);
    let builder = MessageBuilder::new(&mut query, 512, 7, 0x2400).unwrap();
    let _ = builder.finish();
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1000".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &apex,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        secondary.serve_with(&mut cx, TestNext, true).await,
        Outcome::Drop
    );
    let zone = &secondary.shared.zones.load()[0];
    assert!(zone.notify_source.lock().unwrap().is_none());
}

#[test]
fn zero_soa_timers_use_one_second_floor() {
    let zone = SecondaryZone::new(ZoneConfig {
        limits: Default::default(),
        apex: "example.org.".parse().unwrap(),
        from: vec![],
        catalog: None,
    });
    let records = ZoneParser::new(
        "@ 60 IN SOA ns. hostmaster. 1 0 0 0 0\n@ 60 IN NS ns.\n".as_bytes(),
        zone.config.apex.clone(),
        "test",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    zone.current.store(Some(Arc::new(
        crate::zone::Zone::from_records(zone.config.apex.clone(), records).unwrap(),
    )));
    assert_eq!(
        update::timers(&zone),
        (
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1)
        )
    );
}

#[tokio::test]
async fn failed_refresh_expires_the_zone() {
    use pharos_proto::{Message, MessageBuilder, Section};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (release_recovery, wait_for_recovery) = tokio::sync::oneshot::channel();
    let primary = tokio::spawn(async move {
        let mut wait_for_recovery = Some(wait_for_recovery);
        for attempt in 0..3 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let len = socket.read_u16().await.unwrap();
            let mut query = vec![0; usize::from(len)];
            socket.read_exact(&mut query).await.unwrap();
            let query = Message::parse(&query).unwrap();
            let question = query.questions().next().unwrap();
            let mut response = Vec::with_capacity(512);
            let flags = if attempt == 1 { 0x8405 } else { 0x8400 };
            let mut builder = MessageBuilder::new(&mut response, 512, query.id(), flags).unwrap();
            builder
                .question(question.name, question.qtype, question.qclass)
                .unwrap();
            if attempt != 1 {
                if attempt == 2 {
                    wait_for_recovery.take().unwrap().await.unwrap();
                }
                let mut soa = vec![0, 0];
                for value in [1u32, 1, 3, 1, 0] {
                    soa.extend_from_slice(&value.to_be_bytes());
                }
                let count = 2;
                for index in 0..count {
                    if index + 1 == count {
                        builder
                            .record(
                                Section::Answer,
                                question.name,
                                Type::NS,
                                Class::IN,
                                60,
                                "ns.example.org.".parse::<Name>().unwrap().as_wire(),
                            )
                            .unwrap();
                    }
                    builder
                        .record(
                            Section::Answer,
                            question.name,
                            Type::SOA,
                            Class::IN,
                            60,
                            &soa,
                        )
                        .unwrap();
                }
            }
            let _ = builder.finish();
            socket.write_u16(response.len() as u16).await.unwrap();
            socket.write_all(&response).await.unwrap();
        }
    });
    let (shared, _, _) = catalog_shared();
    let zone = Arc::new(SecondaryZone::new(ZoneConfig {
        limits: Default::default(),
        apex: "example.org.".parse().unwrap(),
        from: vec![address.to_string()],
        catalog: None,
    }));
    let task = tokio::spawn(update::run(shared, Arc::clone(&zone)));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while zone.current.load().is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "initial transfer did not publish a zone"
        );
        tokio::task::yield_now().await;
    }
    while !zone.expired.load(Ordering::Relaxed) {
        assert!(
            std::time::Instant::now() < deadline,
            "zone did not expire after a failed refresh"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    release_recovery.send(()).unwrap();
    while zone.expired.load(Ordering::Relaxed) {
        assert!(
            std::time::Instant::now() < deadline,
            "zone stayed expired after a successful unchanged SOA check"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), primary)
        .await
        .expect("primary did not finish")
        .unwrap();
    assert!(zone.current.load().is_some());
    task.abort();
    let _ = task.await;
}

fn catalog_shared() -> (Arc<Shared>, Arc<SecondaryZone>, Arc<SecondaryZone>) {
    let source = |apex: &str| {
        Arc::new(SecondaryZone::new(ZoneConfig {
            limits: Default::default(),
            apex: apex.parse().unwrap(),
            from: vec!["127.0.0.1:1".into()],
            catalog: Some(vec![".".parse().unwrap()]),
        }))
    };
    let old = source("old.catalog.example.");
    let new = source("new.catalog.example.");
    let shared = Arc::new(Shared {
        zones: arc_swap::ArcSwap::from_pointee(vec![Arc::clone(&old), Arc::clone(&new)]),
        tasks: Mutex::new(Vec::new()),
        running: AtomicBool::new(true),
        catalogs: Mutex::new(catalog::State::default()),
        #[cfg(feature = "plugin-transfer")]
        notifier: crate::zone::ZoneNotifier::default(),
    });
    (shared, old, new)
}

fn catalog_for(origin: &Name, member_id: Option<&str>, coo: Option<&str>) -> catalog::Catalog {
    let mut text =
        "@ 60 IN SOA ns. hostmaster. 1 10 10 100 60\n@ 60 IN NS ns.\nversion 60 IN TXT \"2\"\n"
            .to_owned();
    if let Some(id) = member_id {
        text.push_str(&format!("{id}.zones 60 IN PTR example.org.\n"));
        if let Some(coo) = coo {
            text.push_str(&format!("coo.{id}.zones 60 IN PTR {coo}\n"));
        }
    }
    let records = ZoneParser::new(text.as_bytes(), origin.clone(), "catalog")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    catalog::parse(origin, &records).unwrap()
}

#[tokio::test]
async fn coredns_catalog_adds_and_removes_member_zones() {
    let (shared, old, _) = catalog_shared();
    catalog::apply(
        &shared,
        &old,
        catalog_for(&old.config.apex, Some("a"), None),
    );
    assert!(
        shared
            .zones
            .load()
            .iter()
            .any(|zone| zone.config.apex.to_string() == "example.org.")
    );
    catalog::apply(&shared, &old, catalog_for(&old.config.apex, None, None));
    assert!(
        !shared
            .zones
            .load()
            .iter()
            .any(|zone| zone.config.apex.to_string() == "example.org.")
    );
    for task in shared.tasks.lock().unwrap().drain(..) {
        task.abort();
    }
}

#[tokio::test]
async fn coredns_catalog_ownership_requires_coo_and_preserves_same_id() {
    let (shared, old, new) = catalog_shared();
    catalog::apply(
        &shared,
        &old,
        catalog_for(&old.config.apex, Some("a"), None),
    );
    let member = shared
        .zones
        .load()
        .iter()
        .find(|zone| zone.config.apex.to_string() == "example.org.")
        .unwrap()
        .clone();
    let records = ZoneParser::new(
        "@ 60 IN SOA ns. hostmaster. 7 10 10 100 60\n@ 60 IN NS ns.\n".as_bytes(),
        member.config.apex.clone(),
        "member",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    member.current.store(Some(Arc::new(
        crate::zone::Zone::from_records(member.config.apex.clone(), records).unwrap(),
    )));
    catalog::apply(
        &shared,
        &new,
        catalog_for(&new.config.apex, Some("a"), None),
    );
    assert!(Arc::ptr_eq(
        &member,
        shared
            .zones
            .load()
            .iter()
            .find(|zone| zone.config.apex == member.config.apex)
            .unwrap()
    ));
    catalog::apply(
        &shared,
        &old,
        catalog_for(&old.config.apex, Some("a"), Some("new.catalog.example.")),
    );
    catalog::apply(
        &shared,
        &new,
        catalog_for(&new.config.apex, Some("a"), None),
    );
    let migrated = shared
        .zones
        .load()
        .iter()
        .find(|zone| zone.config.apex == member.config.apex)
        .unwrap()
        .clone();
    assert!(!Arc::ptr_eq(&member, &migrated));
    assert_eq!(migrated.current.load().as_ref().unwrap().serial(), Some(7));
    for task in shared.tasks.lock().unwrap().drain(..) {
        task.abort();
    }
}

#[tokio::test]
async fn coredns_catalog_id_change_resets_zone_and_restrictions_reject_members() {
    let (shared, old, _) = catalog_shared();
    catalog::apply(
        &shared,
        &old,
        catalog_for(&old.config.apex, Some("a"), None),
    );
    let first = shared
        .zones
        .load()
        .iter()
        .find(|zone| zone.config.apex.to_string() == "example.org.")
        .unwrap()
        .clone();
    let records = ZoneParser::new(
        "@ 60 IN SOA ns. hostmaster. 7 10 10 100 60\n@ 60 IN NS ns.\n".as_bytes(),
        first.config.apex.clone(),
        "member",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    first.current.store(Some(Arc::new(
        crate::zone::Zone::from_records(first.config.apex.clone(), records).unwrap(),
    )));
    catalog::apply(
        &shared,
        &old,
        catalog_for(&old.config.apex, Some("b"), None),
    );
    let changed = shared
        .zones
        .load()
        .iter()
        .find(|zone| zone.config.apex == first.config.apex)
        .unwrap()
        .clone();
    assert!(!Arc::ptr_eq(&first, &changed));
    assert!(changed.current.load().is_none());
    let restricted = SecondaryZone::new(ZoneConfig {
        limits: Default::default(),
        apex: old.config.apex.clone(),
        from: old.config.from.clone(),
        catalog: Some(vec!["other.example.".parse().unwrap()]),
    });
    catalog::apply(
        &shared,
        &restricted,
        catalog_for(&restricted.config.apex, Some("b"), None),
    );
    assert!(
        !shared
            .zones
            .load()
            .iter()
            .any(|zone| zone.config.apex == first.config.apex)
    );
    for task in shared.tasks.lock().unwrap().drain(..) {
        task.abort();
    }
}

#[tokio::test]
async fn stopped_secondary_cannot_spawn_catalog_member_tasks() {
    let (shared, old, _) = catalog_shared();
    shared.running.store(false, Ordering::Relaxed);
    catalog::apply(
        &shared,
        &old,
        catalog_for(&old.config.apex, Some("a"), None),
    );
    assert!(shared.tasks.lock().unwrap().is_empty());
    assert!(
        !shared
            .zones
            .load()
            .iter()
            .any(|zone| zone.config.apex.to_string() == "example.org.")
    );
}

#[tokio::test]
async fn catalog_migration_respects_restrictions_and_changed_identity() {
    let (shared, old, new) = catalog_shared();
    catalog::apply(
        &shared,
        &old,
        catalog_for(&old.config.apex, Some("a"), Some("new.catalog.example.")),
    );
    let first = shared
        .zones
        .load()
        .iter()
        .find(|zone| zone.config.apex.to_string() == "example.org.")
        .unwrap()
        .clone();
    let records = ZoneParser::new(
        "@ 60 IN SOA ns. hostmaster. 7 10 10 100 60\n@ 60 IN NS ns.\n".as_bytes(),
        first.config.apex.clone(),
        "member",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    first.current.store(Some(Arc::new(
        crate::zone::Zone::from_records(first.config.apex.clone(), records).unwrap(),
    )));
    let restricted = SecondaryZone::new(ZoneConfig {
        limits: Default::default(),
        apex: new.config.apex.clone(),
        from: new.config.from.clone(),
        catalog: Some(vec!["other.example.".parse().unwrap()]),
    });
    catalog::apply(
        &shared,
        &restricted,
        catalog_for(&new.config.apex, Some("b"), None),
    );
    assert!(Arc::ptr_eq(
        &first,
        shared
            .zones
            .load()
            .iter()
            .find(|zone| zone.config.apex == first.config.apex)
            .unwrap()
    ));
    catalog::apply(
        &shared,
        &new,
        catalog_for(&new.config.apex, Some("b"), None),
    );
    let migrated = shared
        .zones
        .load()
        .iter()
        .find(|zone| zone.config.apex == first.config.apex)
        .unwrap()
        .clone();
    assert!(!Arc::ptr_eq(&first, &migrated));
    assert!(migrated.current.load().is_none());
    for task in shared.tasks.lock().unwrap().drain(..) {
        task.abort();
    }
}

#[tokio::test]
async fn broken_catalog_cannot_authorize_member_migration() {
    let (shared, old, new) = catalog_shared();
    catalog::apply(
        &shared,
        &old,
        catalog_for(&old.config.apex, Some("a"), Some("new.catalog.example.")),
    );
    let member = shared
        .zones
        .load()
        .iter()
        .find(|zone| zone.config.apex.to_string() == "example.org.")
        .unwrap()
        .clone();
    catalog::invalidate(&shared, &old);
    catalog::apply(
        &shared,
        &new,
        catalog_for(&new.config.apex, Some("a"), None),
    );
    assert!(Arc::ptr_eq(
        &member,
        shared
            .zones
            .load()
            .iter()
            .find(|zone| zone.config.apex == member.config.apex)
            .unwrap()
    ));
    for task in shared.tasks.lock().unwrap().drain(..) {
        task.abort();
    }
}

#[tokio::test]
async fn empty_catalog_scope_rejects_all_members() {
    let (shared, old, _) = catalog_shared();
    let restricted = SecondaryZone::new(ZoneConfig {
        limits: Default::default(),
        apex: old.config.apex.clone(),
        from: old.config.from.clone(),
        catalog: Some(Vec::new()),
    });
    catalog::apply(
        &shared,
        &restricted,
        catalog_for(&restricted.config.apex, Some("a"), None),
    );
    assert!(
        shared
            .zones
            .load()
            .iter()
            .all(|zone| zone.config.apex != "example.org.".parse().unwrap())
    );
}

#[tokio::test]
async fn secondary_shutdown_cancels_initial_transfer_retry() {
    let blocks = pharos_corefile::parse(
        "Corefile",
        "example.org:53 {\n secondary {\n transfer from 127.0.0.1:1\n }\n}",
    )
    .unwrap();
    let configured =
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
    let chain = &configured[0].config;
    chain
        .lifecycle
        .run(pharos_server::Phase::Startup)
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        chain.lifecycle.run(pharos_server::Phase::Shutdown),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        chain
            .secondary
            .as_ref()
            .unwrap()
            .shared
            .tasks
            .lock()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn invalid_catalog_transfer_retains_zone_but_regular_zone_accepts_it() {
    use pharos_proto::{Message, MessageBuilder, Section};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for catalog in [true, false] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let primary = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let len = socket.read_u16().await.unwrap();
            let mut input = vec![0; usize::from(len)];
            socket.read_exact(&mut input).await.unwrap();
            let query = Message::parse(&input).unwrap();
            let question = query.questions().next().unwrap();
            let mut wire = Vec::with_capacity(512);
            let mut builder = MessageBuilder::new(&mut wire, 512, query.id(), 0x8400).unwrap();
            builder
                .question(question.name, question.qtype, question.qclass)
                .unwrap();
            let mut soa = vec![0, 0];
            for value in [2u32, 10, 10, 100, 60] {
                soa.extend_from_slice(&value.to_be_bytes());
            }
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::SOA,
                    Class::IN,
                    60,
                    &soa,
                )
                .unwrap();
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::NS,
                    Class::IN,
                    60,
                    &[0],
                )
                .unwrap();
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::SOA,
                    Class::IN,
                    60,
                    &soa,
                )
                .unwrap();
            let _ = builder.finish();
            socket.write_u16(wire.len() as u16).await.unwrap();
            socket.write_all(&wire).await.unwrap();
        });
        let (shared, _, _) = catalog_shared();
        let zone = SecondaryZone::new(ZoneConfig {
            limits: Default::default(),
            apex: "catalog.example.".parse().unwrap(),
            from: vec![address.to_string()],
            catalog: catalog.then(Vec::new),
        });
        let records = ZoneParser::new(
            "@ 60 IN SOA ns. hostmaster. 1 10 10 100 60\n@ 60 IN NS ns.\n".as_bytes(),
            zone.config.apex.clone(),
            "original",
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        zone.current.store(Some(Arc::new(
            crate::zone::Zone::from_records(zone.config.apex.clone(), records).unwrap(),
        )));
        assert_eq!(update::transfer(&shared, &zone).await.is_err(), catalog);
        assert_eq!(
            zone.current.load_full().unwrap().serial(),
            Some(if catalog { 1 } else { 2 })
        );
        primary.await.unwrap();
    }
}

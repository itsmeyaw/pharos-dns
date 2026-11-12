use super::*;
use pharos_proto::zone::ZoneParser;

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
        "version 60 IN TXT \"2\"\na.zones 60 CH PTR example.org.\n",
    ] {
        let (origin, records) = catalog_records(&format!("{header}{invalid}"));
        assert!(catalog::parse(&origin, &records).is_err(), "{invalid}");
    }
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
    assert!(!update::serial_less(0, u32::MAX));
    assert!(update::serial_less(u32::MAX, 0));
    assert!(update::serial_less(4_000_000_000, 12_345));
    assert!(update::serial_less(7, 9));
}

#[tokio::test]
async fn coredns_failed_primary_does_not_merge_partial_records() {
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
}

#[tokio::test]
async fn coredns_should_transfer_checks_soa_serial_and_response_id() {
    use pharos_proto::{Message, MessageBuilder, Section};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for wrong_id in [false, false, false, true] {
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
            builder
                .question(question.name, question.qtype, question.qclass)
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
        apex: "example.org.".parse().unwrap(),
        from: vec![address.to_string()],
        catalog: None,
    });
    assert!(update::should_transfer(&zone).await.unwrap());
    for serial in [249, 250] {
        let text = format!("@ 60 IN SOA ns. hostmaster. {serial} 0 0 0 0\n");
        let records = ZoneParser::new(text.as_bytes(), zone.config.apex.clone(), "test")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        zone.current.store(Some(Arc::new(
            crate::zone::Zone::from_records(zone.config.apex.clone(), records).unwrap(),
        )));
        assert_eq!(update::should_transfer(&zone).await.unwrap(), serial == 249);
    }
    assert!(update::should_transfer(&zone).await.is_err());
    server.await.unwrap();
}

#[tokio::test]
async fn coredns_notify_accepts_only_known_primary() {
    use pharos_proto::{Message, MessageBuilder};
    use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
    let corefile = "example.org:53 {\n secondary {\n transfer from 127.0.0.1\n }\n}";
    let blocks = pharos_corefile::parse("Corefile", corefile).unwrap();
    let configured =
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
    let chain = &configured[0].config;
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
    assert_eq!(chain.serve(&mut cx).await, Outcome::Drop);
    cx.client = "127.0.0.1:1000".parse().unwrap();
    assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    cx.protocol = Protocol::Tcp;
    cx.max_response_size = 65535;
    assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.id(), 7);
    assert!(response.aa());
    let zone = &chain.secondary.as_ref().unwrap().shared.zones.load()[0];
    assert_eq!(zone.notify_pending.load(Ordering::Relaxed), 2);
    tokio::time::timeout(std::time::Duration::from_millis(10), zone.notify.notified())
        .await
        .unwrap();
}

#[test]
fn coredns_zero_soa_timers_use_one_second() {
    let zone = SecondaryZone::new(ZoneConfig {
        apex: "example.org.".parse().unwrap(),
        from: vec![],
        catalog: None,
    });
    let records = ZoneParser::new(
        "@ 60 IN SOA ns. hostmaster. 1 0 0 0 0\n".as_bytes(),
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
    let primary = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let len = socket.read_u16().await.unwrap();
        let mut query = vec![0; usize::from(len)];
        socket.read_exact(&mut query).await.unwrap();
        let query = Message::parse(&query).unwrap();
        let question = query.questions().next().unwrap();
        let mut response = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut response, 512, query.id(), 0x8400).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        let mut soa = vec![0, 0];
        for value in [1u32, 1, 1, 1, 0] {
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
                Type::SOA,
                Class::IN,
                60,
                &soa,
            )
            .unwrap();
        let _ = builder.finish();
        socket.write_u16(response.len() as u16).await.unwrap();
        socket.write_all(&response).await.unwrap();
    });
    let (shared, _, _) = catalog_shared();
    let zone = Arc::new(SecondaryZone::new(ZoneConfig {
        apex: "example.org.".parse().unwrap(),
        from: vec![address.to_string()],
        catalog: None,
    }));
    let task = tokio::spawn(update::run(shared, Arc::clone(&zone)));
    primary.await.unwrap();
    while zone.current.load().is_none() {
        tokio::task::yield_now().await;
    }
    tokio::time::pause();
    for _ in 0..30 {
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        if zone.expired.load(Ordering::Relaxed) {
            break;
        }
    }
    assert!(zone.current.load().is_some());
    assert!(zone.expired.load(Ordering::Relaxed));
    task.abort();
    let _ = task.await;
}

fn catalog_shared() -> (Arc<Shared>, Arc<SecondaryZone>, Arc<SecondaryZone>) {
    let source = |apex: &str, catalog| {
        Arc::new(SecondaryZone::new(ZoneConfig {
            apex: apex.parse().unwrap(),
            from: vec!["127.0.0.1:1".into()],
            catalog,
        }))
    };
    let old = source("old.catalog.example.", Some(vec![]));
    let new = source("new.catalog.example.", Some(vec![]));
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
        "@ 60 IN SOA ns. hostmaster. 7 10 10 100 60\n".as_bytes(),
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
        "@ 60 IN SOA ns. hostmaster. 7 10 10 100 60\n".as_bytes(),
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

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
    async fn primary(listener: tokio::net::TcpListener, complete: bool) {
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
        let owner: Name = if complete {
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
        if complete {
            builder
                .record(Section::Answer, q.name, Type::SOA, Class::IN, 60, &soa)
                .unwrap();
        }
        let _ = builder.finish();
        socket.write_u16(output.len() as u16).await.unwrap();
        socket.write_all(&output).await.unwrap();
    }
    let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let from = vec![
        first.local_addr().unwrap().to_string(),
        second.local_addr().unwrap().to_string(),
    ];
    let first = tokio::spawn(primary(first, false));
    let second = tokio::spawn(primary(second, true));
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

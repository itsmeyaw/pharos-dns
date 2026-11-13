use super::*;

#[test]
fn update_builds_a_new_snapshot_without_mutating_the_old_one() {
    let apex: Name = "example.org.".parse().unwrap();
    let original = Zone::load(apex.clone(), Path::new("tests/fixtures/file/example.zone")).unwrap();
    let owner: Name = "new.example.org.".parse().unwrap();
    let update = pharos_proto::zone::ZoneRecord {
        owner: owner.clone(),
        class: Class::IN,
        rtype: Type::A,
        ttl: 60,
        rdata: vec![192, 0, 2, 99],
    };
    let (candidate, changed) = original.apply_updates(&[update]).unwrap();
    let owner = NameRef::parse(owner.as_wire(), 0).unwrap();
    assert!(changed);
    assert_eq!(original.rrset(owner, Type::A).count(), 0);
    assert_eq!(candidate.rrset(owner, Type::A).count(), 1);
    assert_eq!(
        candidate.serial(),
        original.serial().map(|serial| serial + 1)
    );
}

#[test]
fn update_delete_matches_case_insensitive_domain_rdata() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\nwww 60 IN CNAME target.example.org.\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "test")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let zone = Zone::from_records(apex, records).unwrap();
    let target: Name = "TARGET.Example.Org.".parse().unwrap();
    let owner: Name = "WWW.EXAMPLE.ORG.".parse().unwrap();
    let update = pharos_proto::zone::ZoneRecord {
        owner: owner.clone(),
        class: Class::NONE,
        rtype: Type::CNAME,
        ttl: 0,
        rdata: target.as_wire().to_vec(),
    };
    let (candidate, changed) = zone.apply_updates(&[update]).unwrap();
    assert!(changed);
    assert_eq!(
        candidate
            .rrset(NameRef::parse(owner.as_wire(), 0).unwrap(), Type::CNAME)
            .count(),
        0
    );
}

#[test]
fn update_protects_apex_and_applies_ordered_cname_changes() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 4294967295 2 3 4 5\n@ 60 IN NS ns.example.org.\nwww 60 IN A 192.0.2.1\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "test")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let original = Zone::from_records(apex.clone(), records).unwrap();
    let owner: Name = "www.example.org.".parse().unwrap();
    let target: Name = "target.example.org.".parse().unwrap();
    let cname = pharos_proto::zone::ZoneRecord {
        owner: owner.clone(),
        class: Class::IN,
        rtype: Type::CNAME,
        ttl: 60,
        rdata: target.as_wire().to_vec(),
    };
    let (unchanged, changed) = original
        .apply_updates(std::slice::from_ref(&cname))
        .unwrap();
    assert!(!changed);
    assert_eq!(unchanged.serial(), Some(u32::MAX));
    let delete = pharos_proto::zone::ZoneRecord {
        owner: owner.clone(),
        class: Class::ANY,
        rtype: Type::A,
        ttl: 0,
        rdata: Vec::new(),
    };
    let apex_delete = pharos_proto::zone::ZoneRecord {
        owner: apex.clone(),
        class: Class::ANY,
        rtype: Type::ANY,
        ttl: 0,
        rdata: Vec::new(),
    };
    let (updated, changed) = original
        .apply_updates(&[delete, cname, apex_delete])
        .unwrap();
    assert!(changed);
    assert_eq!(updated.serial(), Some(1));
    assert_eq!(
        updated
            .rrset(NameRef::parse(owner.as_wire(), 0).unwrap(), Type::CNAME)
            .count(),
        1
    );
    assert_eq!(
        updated
            .rrset(NameRef::parse(apex.as_wire(), 0).unwrap(), Type::NS)
            .count(),
        1
    );
}

#[test]
fn update_replaces_multiple_existing_cnames_with_one() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\nwww 60 IN CNAME a.example.org.\nwww 60 IN CNAME b.example.org.\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "test")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let zone = Zone::from_records(apex, records).unwrap();
    let existing = zone
        .records()
        .iter()
        .find(|rr| rr.rtype == Type::CNAME)
        .unwrap()
        .clone();
    let owner = existing.owner.clone();
    let (candidate, changed) = zone.apply_updates(&[existing]).unwrap();
    assert!(changed);
    assert_eq!(
        candidate
            .rrset(NameRef::parse(owner.as_wire(), 0).unwrap(), Type::CNAME)
            .count(),
        1
    );
}

#[test]
fn shared_zone_snapshot_retains_previous_generation() {
    let apex: Name = "example.org.".parse().unwrap();
    let path = Path::new("tests/fixtures/file/example.zone");
    let original = Arc::new(crate::zone::Zone::load(apex.clone(), path).unwrap());
    let holder = crate::zone::ZoneHolder::from(Some(Arc::clone(&original)));
    let snapshot = holder.load_full().unwrap();
    holder.store(None);
    assert_eq!(snapshot.apex(), &apex);
    assert!(holder.load_full().is_none());
}

#[cfg(feature = "plugin-transfer")]
#[test]
fn shared_zone_exposes_transfer_stream() {
    let apex: Name = "example.org.".parse().unwrap();
    let zone =
        Arc::new(Zone::load(apex.clone(), Path::new("tests/fixtures/file/example.zone")).unwrap());
    let request = crate::transfer::TransferRequest {
        zone: NameRef::parse(apex.as_wire(), 0).unwrap(),
        qtype: Type::AXFR,
        qclass: Class::IN,
        serial: 0,
        id: 1,
        flags: 0,
        protocol: Protocol::Tcp,
    };
    assert!(zone.transfer(request).is_ok());
}

#[test]
fn records_construct_a_reusable_zone_with_indexed_names_and_types() {
    let apex: Name = "example.org.".parse().unwrap();
    let parser = ZoneParser::new(
        include_str!("../../tests/fixtures/file/example.zone").as_bytes(),
        apex.clone(),
        "example.zone",
    );
    let records = parser.collect::<Result<Vec<_>, _>>().unwrap();
    let zone = Zone::from_records(apex.clone(), records).unwrap();
    assert_eq!(zone.apex(), &apex);
    let name: Name = "WWW.Example.Org.".parse().unwrap();
    let name = NameRef::parse(name.as_wire(), 0).unwrap();
    let answers = zone.rrset(name, Type::A).collect::<Vec<_>>();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].rdata, [192, 0, 2, 1]);
    let ent: Name = "empty.example.org.".parse().unwrap();
    assert!(zone.exists(ent.as_wire()));
    assert!(!zone.exact(ent.as_wire()));
    let cut: Name = "host.child.example.org.".parse().unwrap();
    assert_eq!(
        zone.cut(cut.as_wire(), Type::A).unwrap().owner.to_string(),
        "child.example.org."
    );
}

#[test]
fn predecessor_uses_nearest_tree_name_not_nearest_nsec() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 3600 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 3600 IN NSEC a.example.org. SOA NSEC\na 60 IN A 192.0.2.1\nc 60 IN NSEC example.org. NSEC\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "test")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let zone = Zone::from_records(apex, records).unwrap();
    let name: Name = "b.example.org.".parse().unwrap();
    assert!(zone.previous_nsec(name.as_wire()).is_none());
    let name: Name = "z.example.org.".parse().unwrap();
    assert_eq!(
        zone.previous_nsec(name.as_wire())
            .unwrap()
            .owner
            .to_string(),
        "c.example.org."
    );
}

#[tokio::test]
async fn zone_lookup_is_reusable_without_file_plugin() {
    struct DropNext;
    impl Next for DropNext {
        async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
            Outcome::Drop
        }
    }
    let apex: Name = "example.org.".parse().unwrap();
    let records = ZoneParser::new(
        include_str!("../../tests/fixtures/file/example.zone").as_bytes(),
        apex.clone(),
        "test",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let zone = Zone::from_records(apex.clone(), records).unwrap();
    let name: Name = "www.example.org.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut context = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: pharos_server::Transport::Dns,
        protocol: Protocol::Udp,
        domain: &apex,
        metadata: pharos_server::Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        zone.lookup(&mut context, DropNext, &[]).await,
        Outcome::Response
    );
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 1]
    );
}

#[tokio::test]
async fn unavailable_self_lookup_keeps_cname_in_servfail() {
    struct DropNext;
    impl Next for DropNext {
        async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
            Outcome::Drop
        }
    }
    let apex: Name = "example.org.".parse().unwrap();
    let records = ZoneParser::new(
        include_str!("../../tests/fixtures/file/example.zone").as_bytes(),
        apex.clone(),
        "test",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let zone = Zone::from_records(apex.clone(), records).unwrap();
    let name: Name = "external.example.org.".parse().unwrap();
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: pharos_server::Transport::Dns,
        protocol: Protocol::Udp,
        domain: &apex,
        metadata: pharos_server::Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(zone.lookup(&mut cx, DropNext, &[]).await, Outcome::Response);
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.rcode(), Rcode::SERVFAIL);
    assert_eq!(response.answers().next().unwrap().rtype, Type::CNAME);
}

#[tokio::test]
async fn signed_empty_nonterminal_includes_predecessor_nsec() {
    struct DropNext;
    impl Next for DropNext {
        async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
            Outcome::Drop
        }
    }
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 3600 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 3600 IN NS ns.example.org.\n@ 3600 IN NSEC a.example.org. SOA NS NSEC\na 60 IN A 192.0.2.1\na 60 IN NSEC leaf.empty.example.org. A NSEC\nleaf.empty 60 IN A 192.0.2.2\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "test")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let zone = Zone::from_records(apex.clone(), records).unwrap();
    let name: Name = "empty.example.org.".parse().unwrap();
    let mut query = Vec::with_capacity(1232);
    let mut builder = MessageBuilder::new(&mut query, 1232, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    builder
        .record(
            Section::Additional,
            NameRef::parse(&[0], 0).unwrap(),
            Type::OPT,
            Class(1232),
            0x8000,
            &[],
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: pharos_server::Transport::Dns,
        protocol: Protocol::Udp,
        domain: &apex,
        metadata: pharos_server::Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    assert_eq!(zone.lookup(&mut cx, DropNext, &[]).await, Outcome::Response);
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let denial = response
        .authorities()
        .find(|rr| rr.rtype == Type::NSEC)
        .unwrap();
    assert_eq!(denial.name.to_string(), "a.example.org.");
}

#[tokio::test]
async fn nxdomain_below_empty_nonterminal_uses_coredns_closest_encloser() {
    struct DropNext;
    impl Next for DropNext {
        async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
            Outcome::Drop
        }
    }
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 3600 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 3600 IN NS ns.example.org.\n@ 3600 IN NSEC *.example.org. SOA NS NSEC\n*.example.org. 60 IN TXT \"wild\"\n*.example.org. 60 IN NSEC a.example.org. TXT NSEC\na 60 IN A 192.0.2.1\na 60 IN NSEC leaf.empty.example.org. A NSEC\nleaf.empty 60 IN A 192.0.2.2\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "test")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let zone = Zone::from_records(apex.clone(), records).unwrap();
    let name: Name = "x.empty.example.org.".parse().unwrap();
    let mut query = Vec::with_capacity(1232);
    let mut builder = MessageBuilder::new(&mut query, 1232, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    builder
        .record(
            Section::Additional,
            NameRef::parse(&[0], 0).unwrap(),
            Type::OPT,
            Class(1232),
            0x8000,
            &[],
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [None; 8];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: pharos_server::Transport::Dns,
        protocol: Protocol::Udp,
        domain: &apex,
        metadata: pharos_server::Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    assert_eq!(zone.lookup(&mut cx, DropNext, &[]).await, Outcome::Response);
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    assert_eq!(
        response
            .authorities()
            .filter(|rr| rr.rtype == Type::NSEC)
            .map(|rr| rr.name.to_string())
            .collect::<Vec<_>>(),
        ["*.example.org."]
    );
}

#[test]
fn multiple_soa_records_keep_last_like_coredns() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 3600 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 3600 IN SOA ns.example.org. hostmaster.example.org. 2 2 3 4 5\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "test")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let zone = Zone::from_records(apex.clone(), records).unwrap();
    assert_eq!(zone.serial(), Some(2));
    assert_eq!(
        zone.rrset(NameRef::parse(apex.as_wire(), 0).unwrap(), Type::SOA)
            .count(),
        1
    );
}

#[test]
fn zero_serial_is_rejected_at_file_setup_like_coredns() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-zero-serial.zone");
    let original = include_str!("../../tests/fixtures/file/example.zone");
    std::fs::write(&path, original.replace(" 1 7200", " 0 7200")).unwrap();
    let corefile = format!("example.org:53 {{\n file {}\n}}", path.display());
    let blocks = pharos_corefile::parse("Corefile", &corefile).unwrap();
    assert!(pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).is_err());
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn negative_reload_fails_startup_instead_of_disabling_reload() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let corefile = format!("example.org:53 {{\n file {path} {{\n reload -1s\n }}\n}}");
    let blocks = pharos_corefile::parse("Corefile", &corefile).unwrap();
    let configured =
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
    assert!(
        configured[0]
            .config
            .lifecycle
            .run(pharos_server::Phase::Startup)
            .await
            .is_err()
    );
}

// Derived from CoreDNS plugin/file/reload_test.go.
#[test]
fn serial_reload_retains_old_zone_on_unchanged_or_invalid_data() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-serial-reload-test.zone");
    let original = include_str!("../../tests/fixtures/file/example.zone");
    std::fs::write(&path, original).unwrap();
    let apex: Name = "example.org.".parse().unwrap();
    let loaded = Loaded {
        apex: apex.clone(),
        path: path.clone(),
        current: arc_swap::ArcSwapOption::from(Some(Arc::new(Zone::load(apex, &path).unwrap()))),
        interval: Duration::from_secs(1),
        negative_interval: false,
        by_mtime: false,
        modified: Mutex::new(None),
        reload_gate: Mutex::new(()),
    };
    std::fs::write(&path, original.replace("192.0.2.1", "192.0.2.9")).unwrap();
    assert!(!loaded.reload());
    assert_eq!(loaded.current.load().as_ref().unwrap().serial(), Some(1));
    std::fs::write(&path, "invalid zone").unwrap();
    assert!(!loaded.reload());
    assert_eq!(loaded.current.load().as_ref().unwrap().serial(), Some(1));
    std::fs::write(&path, original.replace(" 1 7200", " 2 7200")).unwrap();
    assert!(loaded.reload());
    assert_eq!(loaded.current.load().as_ref().unwrap().serial(), Some(2));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn mtime_reload_accepts_unchanged_serial() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-mtime-reload-test.zone");
    let original = include_str!("../../tests/fixtures/file/example.zone");
    std::fs::write(&path, original).unwrap();
    let apex: Name = "example.org.".parse().unwrap();
    let loaded = Loaded {
        apex: apex.clone(),
        path: path.clone(),
        current: arc_swap::ArcSwapOption::from(Some(Arc::new(Zone::load(apex, &path).unwrap()))),
        interval: Duration::from_secs(1),
        negative_interval: false,
        by_mtime: true,
        modified: Mutex::new(Some(SystemTime::UNIX_EPOCH)),
        reload_gate: Mutex::new(()),
    };
    assert!(loaded.reload());
    assert!(!loaded.reload());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn reload_uses_path_mtime_sampled_before_open() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-stat-race.zone");
    let replacement =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-stat-race-new.zone");
    let original = include_str!("../../tests/fixtures/file/example.zone");
    let old_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let observed_time = old_time + Duration::from_secs(10);
    let new_time = observed_time + Duration::from_secs(10);
    std::fs::write(&path, original).unwrap();
    let apex: Name = "example.org.".parse().unwrap();
    let loaded = Loaded {
        apex: apex.clone(),
        path: path.clone(),
        current: arc_swap::ArcSwapOption::from(Some(Arc::new(Zone::load(apex, &path).unwrap()))),
        interval: Duration::from_secs(1),
        negative_interval: false,
        by_mtime: true,
        modified: Mutex::new(Some(old_time)),
        reload_gate: Mutex::new(()),
    };
    std::fs::File::open(&path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(observed_time))
        .unwrap();
    std::fs::write(&replacement, original.replace(" 1 7200", " 2 7200")).unwrap();
    std::fs::File::open(&replacement)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(new_time))
        .unwrap();
    assert!(loaded.reload_with_open(|path| {
        std::fs::rename(&replacement, path)?;
        std::fs::File::open(path)
    }));
    assert_eq!(loaded.current.load().as_ref().unwrap().serial(), Some(2));
    assert_eq!(*loaded.modified.lock().unwrap(), Some(observed_time));
    assert!(loaded.reload());
    assert_eq!(*loaded.modified.lock().unwrap(), Some(new_time));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn mtime_reload_keeps_previous_zone_and_timestamp_on_errors() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-mtime-errors.zone");
    let original = include_str!("../../tests/fixtures/file/example.zone");
    let old_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let changed_time = old_time + Duration::from_secs(10);
    std::fs::write(&path, original).unwrap();
    let apex: Name = "example.org.".parse().unwrap();
    let loaded = Loaded {
        apex: apex.clone(),
        path: path.clone(),
        current: arc_swap::ArcSwapOption::from(Some(Arc::new(Zone::load(apex, &path).unwrap()))),
        interval: Duration::from_secs(1),
        negative_interval: false,
        by_mtime: true,
        modified: Mutex::new(Some(old_time)),
        reload_gate: Mutex::new(()),
    };
    std::fs::File::open(&path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(old_time))
        .unwrap();
    assert!(!loaded.reload_with_open(|_| panic!("unchanged mtime must not open the file")));
    std::fs::write(&path, "invalid zone").unwrap();
    std::fs::File::open(&path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(changed_time))
        .unwrap();
    assert!(!loaded.reload());
    assert_eq!(*loaded.modified.lock().unwrap(), Some(old_time));
    assert_eq!(loaded.current.load().as_ref().unwrap().serial(), Some(1));
    assert!(
        !loaded
            .reload_with_open(|_| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)))
    );
    assert_eq!(*loaded.modified.lock().unwrap(), Some(old_time));
    assert_eq!(loaded.current.load().as_ref().unwrap().serial(), Some(1));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn reload_gate_prevents_overlapping_blocking_reload_generations() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-concurrent-reload.zone");
    let original = include_str!("../../tests/fixtures/file/example.zone");
    std::fs::write(&path, original).unwrap();
    let apex: Name = "example.org.".parse().unwrap();
    let loaded = Arc::new(Loaded {
        apex: apex.clone(),
        path: path.clone(),
        current: arc_swap::ArcSwapOption::from(Some(Arc::new(Zone::load(apex, &path).unwrap()))),
        interval: Duration::from_secs(1),
        negative_interval: false,
        by_mtime: false,
        modified: Mutex::new(None),
        reload_gate: Mutex::new(()),
    });
    let gate = loaded.reload_gate.lock().unwrap();
    std::fs::write(&path, original.replace(" 1 7200", " 2 7200")).unwrap();
    let (ready, started) = std::sync::mpsc::channel();
    let reader = Arc::clone(&loaded);
    let worker = std::thread::spawn(move || {
        ready.send(()).unwrap();
        reader.reload()
    });
    started.recv().unwrap();
    std::fs::write(&path, original.replace(" 1 7200", " 3 7200")).unwrap();
    drop(gate);
    assert!(worker.join().unwrap());
    assert_eq!(loaded.current.load().as_ref().unwrap().serial(), Some(3));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn parse_opened_file_keeps_its_version_after_path_replacement() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-opened-version.zone");
    let replacement =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-opened-replacement.zone");
    let original = include_str!("../../tests/fixtures/file/example.zone");
    std::fs::write(&path, original).unwrap();
    let old_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let new_time = old_time + Duration::from_secs(10);
    std::fs::File::open(&path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(old_time))
        .unwrap();
    let opened = std::fs::File::open(&path).unwrap();
    std::fs::write(&replacement, original.replace(" 1 7200", " 2 7200")).unwrap();
    std::fs::File::open(&replacement)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(new_time))
        .unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    assert_eq!(opened.metadata().unwrap().modified().unwrap(), old_time);
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        new_time
    );
    let zone = Zone::load_opened("example.org.".parse().unwrap(), &path, opened).unwrap();
    assert_eq!(zone.serial(), Some(1));
    assert_eq!(
        Zone::load("example.org.".parse().unwrap(), &path)
            .unwrap()
            .serial(),
        Some(2)
    );
    std::fs::remove_file(path).unwrap();
}

// Derived from CoreDNS TestFileParseReloadByMtimeUsesOpenedFileMtime.
#[test]
fn setup_uses_opened_file_snapshot_before_path_replacement() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-setup-snapshot.zone");
    let replacement =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-setup-snapshot-new.zone");
    let original = include_str!("../../tests/fixtures/file/example.zone");
    let old_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let new_time = old_time + Duration::from_secs(10);
    std::fs::write(&path, original).unwrap();
    std::fs::File::open(&path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(old_time))
        .unwrap();
    std::fs::write(&replacement, original.replace(" 1 7200", " 2 7200")).unwrap();
    std::fs::File::open(&replacement)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(new_time))
        .unwrap();
    let config = format!(
        "example.org:53 {{\n file {} {{\n reload_by_mtime\n }}\n}}",
        path.display()
    );
    let blocks = pharos_corefile::parse("Corefile", &config).unwrap();
    let tokens = &blocks[0].directives["file"];
    let mut cursor = Cursor::new("Corefile", tokens);
    let file = File::parse_with_reader(
        &mut cursor,
        &["example.org."],
        None,
        |apex, path, reader| {
            std::fs::rename(&replacement, path).map_err(|error| error.to_string())?;
            Zone::load_reader_with_serial(apex, path, BufReader::new(reader), Some(0))
        },
    )
    .unwrap();
    let zone = &file.zones[0];
    assert_eq!(zone.current.load().as_ref().unwrap().serial(), Some(1));
    assert_eq!(*zone.modified.lock().unwrap(), Some(old_time));
    assert!(zone.reload());
    assert_eq!(zone.current.load().as_ref().unwrap().serial(), Some(2));
    assert_eq!(*zone.modified.lock().unwrap(), Some(new_time));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn repeated_file_options_replace_fallthrough_and_duplicate_zones() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/example.zone"
    );
    let config = format!(
        ".:53 {{\n file {path} example.org {{\n fallthrough example.org\n reload 5s\n }}\n file {path} example.org {{\n fallthrough example.net\n }}\n}}"
    );
    let blocks = pharos_corefile::parse("Corefile", &config).unwrap();
    let configured =
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
    let file = configured[0].config.file.as_ref().unwrap();
    assert_eq!(file.zones.len(), 1);
    assert_eq!(file.zones[0].interval, Duration::from_secs(5));
    assert_eq!(
        file.fallthrough,
        vec!["example.net.".parse::<Name>().unwrap()]
    );
}

#[test]
fn setup_parses_opened_zone_before_options() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-setup-order.zone");
    std::fs::write(&path, "invalid zone\n").unwrap();
    let config = format!(
        "example.org:53 {{\n file {} {{\n unknown_option\n }}\n}}",
        path.display()
    );
    let blocks = pharos_corefile::parse("Corefile", &config).unwrap();
    let error =
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap_err();
    assert!(error.message.contains("invalid record header"), "{error}");
    std::fs::remove_file(path).unwrap();
}

// Derived from CoreDNS TestFileParseReloadByMtimeRecoversLaterZoneAfterMissingFile.
#[test]
fn sticky_open_error_leaves_later_zone_mtime_unset_for_recovery() {
    let missing = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../target/file-missing-{}.zone",
        std::process::id()
    ));
    assert!(!missing.exists());
    let existing = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/file/external.zone"
    );
    let config = format!(
        ".:53 {{\n file {} example.org {{\n reload 10ms\n reload_by_mtime\n }}\n file {existing} external.test {{\n reload 10ms\n reload_by_mtime\n }}\n}}",
        missing.display()
    );
    let blocks = pharos_corefile::parse("Corefile", &config).unwrap();
    let configured =
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
    let file = configured[0].config.file.as_ref().unwrap();
    let zone = file
        .zones
        .iter()
        .find(|zone| zone.apex.to_string() == "external.test.")
        .unwrap();
    assert!(zone.current.load().is_none());
    assert_eq!(*zone.modified.lock().unwrap(), None);
    assert!(zone.reload());
    assert_eq!(zone.current.load().as_ref().unwrap().serial(), Some(1));
}

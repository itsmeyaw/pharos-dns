use super::*;

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
        by_mtime: false,
        modified: Mutex::new(None),
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
        by_mtime: true,
        modified: Mutex::new(Some(SystemTime::UNIX_EPOCH)),
    };
    assert!(loaded.reload());
    assert!(!loaded.reload());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn parse_opened_file_keeps_its_version_after_path_replacement() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-opened-version.zone");
    let replacement =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-opened-replacement.zone");
    let original = include_str!("../../tests/fixtures/file/example.zone");
    std::fs::write(&path, original).unwrap();
    let opened = std::fs::File::open(&path).unwrap();
    std::fs::write(&replacement, original.replace(" 1 7200", " 2 7200")).unwrap();
    std::fs::rename(&replacement, &path).unwrap();
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

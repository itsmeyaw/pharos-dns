use super::*;

struct DropNext;

impl Next for DropNext {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        Outcome::Drop
    }
}

async fn zone_response(
    zone: &Zone,
    name: &Name,
    kind: Type,
    class: Class,
    dnssec: bool,
) -> (Outcome, Vec<u8>) {
    let mut query = Vec::with_capacity(1232);
    let mut builder = MessageBuilder::new(&mut query, 1232, 1, 0).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, class)
        .unwrap();
    if dnssec {
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
    }
    let _ = builder.finish();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [None; 8];
    let mut context = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: pharos_server::Transport::Dns,
        protocol: Protocol::Udp,
        domain: zone.apex(),
        metadata: pharos_server::Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    let outcome = zone.lookup(&mut context, DropNext, &[]).await;
    drop(context);
    (outcome, response)
}

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
fn update_matches_legacy_name_bearing_record_data() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\n";
    let mut records = ZoneParser::new(text.as_bytes(), apex.clone(), "test")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let owner: Name = "mailbox.example.org.".parse().unwrap();
    let lower: Name = "target.example.org.".parse().unwrap();
    let upper: Name = "TARGET.EXAMPLE.ORG.".parse().unwrap();
    records.push(pharos_proto::zone::ZoneRecord {
        owner: owner.clone(),
        rtype: Type::MB,
        class: Class::IN,
        ttl: 60,
        rdata: lower.as_wire().to_vec(),
    });
    let zone = Zone::from_records(apex, records).unwrap();
    let remove = pharos_proto::zone::ZoneRecord {
        owner: owner.clone(),
        rtype: Type::MB,
        class: Class::NONE,
        ttl: 0,
        rdata: upper.as_wire().to_vec(),
    };
    let (updated, changed) = zone.apply_updates(&[remove]).unwrap();
    assert!(changed);
    assert_eq!(
        updated
            .rrset(NameRef::parse(owner.as_wire(), 0).unwrap(), Type::MB)
            .count(),
        0
    );
}

#[test]
fn update_accepts_empty_name_rdata_without_changing_file_validation() {
    let apex: Name = "example.org.".parse().unwrap();
    let original = Zone::load(apex.clone(), Path::new("tests/fixtures/file/example.zone")).unwrap();
    let record = pharos_proto::zone::ZoneRecord {
        owner: "empty.example.org.".parse().unwrap(),
        rtype: Type::CNAME,
        class: Class::IN,
        ttl: 60,
        rdata: Vec::new(),
    };
    let (candidate, changed) = original
        .apply_updates(std::slice::from_ref(&record))
        .unwrap();
    assert!(changed);
    assert!(
        candidate
            .records()
            .iter()
            .any(|rr| rr.owner == record.owner && rr.rdata.is_empty())
    );
    let mut records = original.records().to_vec();
    records.push(record);
    assert!(Zone::from_records(apex, records).is_err());
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
fn static_zone_rejects_multiple_cname_targets() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\nwww 60 IN CNAME a.example.org.\nwww 60 IN CNAME b.example.org.\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "test")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(Zone::from_records(apex, records).is_err());
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
    let query_name: Name = "EXAMPLE.ORG.".parse().unwrap();
    let request = crate::transfer::TransferRequest {
        zone: NameRef::parse(query_name.as_wire(), 0).unwrap(),
        qtype: Type::AXFR,
        qclass: Class::IN,
        serial: 0,
        id: 1,
        flags: 0x0110,
        protocol: Protocol::Tcp,
    };
    let mut stream = zone.clone().transfer(request).unwrap();
    let mut response = Vec::with_capacity(65535);
    assert!(stream.next(&mut response).unwrap());
    let message = Message::parse(&response).unwrap();
    assert_eq!(
        message.questions().next().unwrap().name.to_string(),
        "EXAMPLE.ORG."
    );
    assert_eq!(message.flags() & 0x0110, 0x0100);
    let wrong_class = crate::transfer::TransferRequest {
        zone: NameRef::parse(apex.as_wire(), 0).unwrap(),
        qtype: Type::AXFR,
        qclass: Class(3),
        serial: 0,
        id: 1,
        flags: 0,
        protocol: Protocol::Tcp,
    };
    assert!(zone.transfer(wrong_class).is_err());
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
fn zone_preserves_case_and_normalizes_duplicate_rrsets() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 3600 IN SOA Ns.Example.Org. Host.Example.Org. 1 2 3 4 60\n@ 300 IN NS Ns.Example.Org.\n@ 60 IN NS ns.example.org.\nWWW.Example.Org. 300 IN A 192.0.2.1\nwww.example.org. 60 IN A 192.0.2.1\nWwW.Example.Org. 120 IN A 192.0.2.2\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "case.zone")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let zone = Zone::from_records(apex.clone(), records).unwrap();
    let first = zone
        .records()
        .iter()
        .find(|rr| rr.rtype == Type::A)
        .unwrap();
    assert_eq!(first.owner.to_string(), "WWW.Example.Org.");
    let soa = zone
        .records()
        .iter()
        .find(|rr| rr.rtype == Type::SOA)
        .unwrap();
    let rdata = NameRef::parse(&soa.rdata, 0).unwrap();
    assert_eq!(rdata.to_string(), "Ns.Example.Org.");
    let rname = NameRef::parse(&soa.rdata, rdata.wire_len()).unwrap();
    assert_eq!(rname.to_string(), "Host.Example.Org.");
    let ns = zone
        .rrset(NameRef::parse(apex.as_wire(), 0).unwrap(), Type::NS)
        .collect::<Vec<_>>();
    assert_eq!(ns.len(), 1);
    assert_eq!(
        NameRef::parse(&ns[0].rdata, 0).unwrap().to_string(),
        "Ns.Example.Org."
    );
    assert_eq!(ns[0].ttl, 60);
    let owner = NameRef::parse(first.owner.as_wire(), 0).unwrap();
    let answers = zone.rrset(owner, Type::A).collect::<Vec<_>>();
    assert_eq!(answers.len(), 2);
    assert!(answers.iter().all(|rr| rr.ttl == 60));
}

#[test]
fn signatures_keep_ttl_of_their_covered_rrset() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 3600 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 3600 IN NS ns.example.org.\n@ 3600 IN RRSIG NS 8 2 3600 20300101000000 20200101000000 12345 example.org. AQID\n@ 60 IN A 192.0.2.1\n@ 60 IN RRSIG A 8 2 60 20300101000000 20200101000000 12345 example.org. AQID\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "rrsig-ttl.zone")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let zone = Zone::from_records(apex, records).unwrap();
    let signatures = zone
        .records()
        .iter()
        .filter(|rr| rr.rtype == Type::RRSIG)
        .map(|rr| (u16::from_be_bytes([rr.rdata[0], rr.rdata[1]]), rr.ttl))
        .collect::<Vec<_>>();
    assert!(signatures.contains(&(Type::NS.0, 3600)));
    assert!(signatures.contains(&(Type::A.0, 60)));
}

#[test]
fn duplicate_cname_targets_compare_case_insensitively_without_rewriting_case() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\nalias.example.org. 300 IN CNAME TARGET.example.org.\nalias.example.org. 60 IN CNAME target.EXAMPLE.org.\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "cname-case.zone")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let zone = Zone::from_records(apex, records).unwrap();
    let owner: Name = "alias.example.org.".parse().unwrap();
    let cname = zone.rrset(NameRef::parse(owner.as_wire(), 0).unwrap(), Type::CNAME);
    let cname = cname.collect::<Vec<_>>();
    assert_eq!(cname.len(), 1);
    assert_eq!(
        NameRef::parse(&cname[0].rdata, 0).unwrap().to_string(),
        "TARGET.example.org."
    );
    assert_eq!(cname[0].ttl, 60);
}

#[test]
fn zone_rejects_mixed_classes_and_cname_coexistence() {
    let apex: Name = "example.org.".parse().unwrap();
    let records = ZoneParser::new(
        &b"@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\n"[..],
        apex.clone(),
        "class.zone",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let mut mixed = records.clone();
    mixed.push(pharos_proto::zone::ZoneRecord {
        owner: "host.example.org.".parse().unwrap(),
        class: Class(3),
        rtype: Type::A,
        ttl: 60,
        rdata: [192, 0, 2, 1].into(),
    });
    assert!(Zone::from_records(apex.clone(), mixed).is_err());

    let mut conflict = records;
    conflict.extend(
        ZoneParser::new(
            &b"alias.example.org. 60 IN CNAME target.example.org.\nalias.example.org. 60 IN A 192.0.2.1\n"[..],
            apex.clone(),
            "cname.zone",
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap(),
    );
    assert!(Zone::from_records(apex, conflict).is_err());
}

#[test]
fn zone_rejects_mixed_svcb_modes() {
    let apex: Name = "example.org.".parse().unwrap();
    let base = || {
        ZoneParser::new(
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\n"
                .as_bytes(),
            apex.clone(),
            "special.zone",
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    };
    let owner: Name = "svc.example.org.".parse().unwrap();
    let mut svcb = base();
    svcb.extend([
        pharos_proto::zone::ZoneRecord {
            owner: owner.clone(),
            class: Class::IN,
            rtype: Type::SVCB,
            ttl: 60,
            rdata: [0, 0, 0].into(),
        },
        pharos_proto::zone::ZoneRecord {
            owner,
            class: Class::IN,
            rtype: Type::SVCB,
            ttl: 60,
            rdata: [0, 1, 0].into(),
        },
        pharos_proto::zone::ZoneRecord {
            owner: "svc.example.org.".parse().unwrap(),
            class: Class::IN,
            rtype: Type::A,
            ttl: 60,
            rdata: [192, 0, 2, 1].into(),
        },
    ]);
    let zone = Zone::from_records(apex, svcb).unwrap();
    let owner: Name = "svc.example.org.".parse().unwrap();
    let bindings = zone.rrset(NameRef::parse(owner.as_wire(), 0).unwrap(), Type::SVCB);
    let bindings = bindings.collect::<Vec<_>>();
    assert_eq!(bindings.len(), 1);
    assert_eq!(&bindings[0].rdata[..2], &[0, 0]);

    let (outcome, response) = zone_response(&zone, &owner, Type::SVCB, Class::IN, true).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(Message::parse(&response).unwrap().additional_count(), 0);
}

#[test]
fn zone_rejects_alias_targets_and_wildcard_dname() {
    let apex: Name = "example.org.".parse().unwrap();
    for record in [
        "mail.example.org. 60 IN MX 10 alias.example.org.",
        "delegated.example.org. 60 IN NS alias.example.org.",
        "1.2.0.192.in-addr.arpa. 60 IN PTR alias.example.org.",
    ] {
        let text = format!(
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\nalias.example.org. 60 IN CNAME target.example.org.\n{record}\n"
        );
        let records = ZoneParser::new(text.as_bytes(), apex.clone(), "alias-target.zone")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(Zone::from_records(apex.clone(), records).is_err());
    }
    let text = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\n*.example.org. 60 IN DNAME target.example.org.\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "wildcard-dname.zone")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(Zone::from_records(apex, records).is_err());

    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\nd.example.org. 60 IN DNAME target.example.org.\nchild.d.example.org. 60 IN A 192.0.2.1\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "dname-descendant.zone")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(Zone::from_records(apex, records).is_err());
}

#[tokio::test]
async fn apex_nodata_uses_negative_ttl_and_class_any_clears_aa() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 3600 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 30\n@ 3600 IN NS ns.example.org.\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "negative.zone")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let zone = Zone::from_records(apex.clone(), records).unwrap();
    let (outcome, response) = zone_response(&zone, &apex, Type::A, Class::IN, false).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().count(), 0);
    assert_eq!(response.authorities().next().unwrap().ttl, 30);

    let (outcome, response) = zone_response(&zone, &apex, Type::A, Class::ANY, false).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(Message::parse(&response).unwrap().flags() & 0x0400, 0);

    let (outcome, _) = zone_response(&zone, &apex, Type::A, Class(3), false).await;
    assert_eq!(outcome, Outcome::Drop);
}

#[tokio::test]
async fn empty_nonterminal_blocks_ancestor_wildcard() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\n*.example.org. 60 IN A 192.0.2.1\nleaf.empty.example.org. 60 IN A 192.0.2.2\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "ent.zone")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let zone = Zone::from_records(apex, records).unwrap();
    let ent: Name = "empty.example.org.".parse().unwrap();
    let (outcome, response) = zone_response(&zone, &ent, Type::A, Class::IN, false).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().count(), 0);
}

#[tokio::test]
async fn legacy_and_modern_service_targets_get_required_additional_records() {
    let apex: Name = "example.org.".parse().unwrap();
    let mut records = ZoneParser::new(
        "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\n"
            .as_bytes(),
        apex.clone(),
        "additional.zone",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let host: Name = "host.example.org.".parse().unwrap();
    let service: Name = "service.example.org.".parse().unwrap();
    records.extend([
        pharos_proto::zone::ZoneRecord {
            owner: host.clone(),
            class: Class::IN,
            rtype: Type::A,
            ttl: 60,
            rdata: [192, 0, 2, 10].into(),
        },
        pharos_proto::zone::ZoneRecord {
            owner: host.clone(),
            class: Class::IN,
            rtype: Type::AAAA,
            ttl: 60,
            rdata: [0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10].into(),
        },
        pharos_proto::zone::ZoneRecord {
            owner: host.clone(),
            class: Class::IN,
            rtype: Type::X25,
            ttl: 60,
            rdata: vec![1],
        },
        pharos_proto::zone::ZoneRecord {
            owner: host.clone(),
            class: Class::IN,
            rtype: Type::ISDN,
            ttl: 60,
            rdata: vec![2],
        },
    ]);
    let mut host_rdata = vec![0, 1];
    host_rdata.extend_from_slice(host.as_wire());
    for (owner, rtype) in [
        ("afsdb.example.org.", Type::AFSDB),
        ("rt.example.org.", Type::RT),
        ("kx.example.org.", Type::KX),
    ] {
        records.push(pharos_proto::zone::ZoneRecord {
            owner: owner.parse().unwrap(),
            class: Class::IN,
            rtype,
            ttl: 60,
            rdata: host_rdata.clone(),
        });
    }
    records.extend([
        pharos_proto::zone::ZoneRecord {
            owner: service.clone(),
            class: Class::IN,
            rtype: Type::SVCB,
            ttl: 60,
            rdata: vec![0, 1, 0, 0, 1, 3, 2, b'h', b'2'],
        },
        pharos_proto::zone::ZoneRecord {
            owner: service.clone(),
            class: Class::IN,
            rtype: Type::A,
            ttl: 60,
            rdata: [192, 0, 2, 11].into(),
        },
    ]);
    let zone = Zone::from_records(apex, records).unwrap();
    for (owner, kind, expected_target) in [
        ("afsdb.example.org.", Type::AFSDB, host.clone()),
        ("rt.example.org.", Type::RT, host.clone()),
        ("kx.example.org.", Type::KX, host.clone()),
        ("service.example.org.", Type::SVCB, service.clone()),
    ] {
        let owner: Name = owner.parse().unwrap();
        let (outcome, response) = zone_response(&zone, &owner, kind, Class::IN, false).await;
        assert_eq!(outcome, Outcome::Response);
        let additional = Message::parse(&response)
            .unwrap()
            .additionals()
            .filter(|rr| rr.name.to_string() == expected_target.to_string())
            .map(|rr| rr.rtype)
            .collect::<Vec<_>>();
        assert!(additional.contains(&Type::A));
        match kind {
            Type::RT => {
                assert!(additional.contains(&Type::X25));
                assert!(additional.contains(&Type::ISDN));
            }
            Type::KX => assert!(additional.contains(&Type::AAAA)),
            _ => {}
        }
    }
}

#[tokio::test]
async fn referral_includes_available_sibling_nameserver_glue() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\nchild.example.org. 60 IN NS ns.sibling.example.org.\nns.sibling.example.org. 60 IN A 192.0.2.53\n";
    let records = ZoneParser::new(text.as_bytes(), apex.clone(), "sibling.zone")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let zone = Zone::from_records(apex, records).unwrap();
    let query: Name = "www.child.example.org.".parse().unwrap();
    let (outcome, response) = zone_response(&zone, &query, Type::A, Class::IN, false).await;
    assert_eq!(outcome, Outcome::Response);
    assert!(
        Message::parse(&response)
            .unwrap()
            .additionals()
            .any(|rr| { rr.name.to_string() == "ns.sibling.example.org." && rr.rtype == Type::A })
    );
}

#[tokio::test]
async fn overlong_dname_substitution_returns_yxdomain_with_dname() {
    let apex: Name = "example.org.".parse().unwrap();
    let mut records = ZoneParser::new(
        "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\n"
            .as_bytes(),
        apex.clone(),
        "dname.zone",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let owner: Name = "d.example.org.".parse().unwrap();
    let target: Name = format!("{}.{}.", "t".repeat(63), "u".repeat(30))
        .parse()
        .unwrap();
    records.push(pharos_proto::zone::ZoneRecord {
        owner,
        class: Class::IN,
        rtype: Type::DNAME,
        ttl: 60,
        rdata: target.as_wire().to_vec(),
    });
    let zone = Zone::from_records(apex, records).unwrap();
    let long = "a".repeat(63);
    let query: Name = format!("{long}.{long}.{long}.d.example.org.")
        .parse()
        .unwrap();
    let (outcome, response) = zone_response(&zone, &query, Type::A, Class::IN, false).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&response).unwrap();
    assert_eq!(response.rcode(), Rcode::YXDOMAIN);
    assert!(response.answers().any(|rr| rr.rtype == Type::DNAME));
    assert!(!response.answers().any(|rr| rr.rtype == Type::CNAME));
}

#[tokio::test]
async fn wildcard_cname_signature_uses_expanded_owner() {
    let apex: Name = "example.org.".parse().unwrap();
    let mut records = ZoneParser::new(
        "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\n*.example.org. 60 IN CNAME target.example.org.\n"
            .as_bytes(),
        apex.clone(),
        "wildcard-cname.zone",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    records.push(pharos_proto::zone::ZoneRecord {
        owner: "*.example.org.".parse().unwrap(),
        class: Class::IN,
        rtype: Type::RRSIG,
        ttl: 60,
        rdata: [Type::CNAME.0.to_be_bytes().as_slice(), &[0; 16]].concat(),
    });
    let zone = Zone::from_records(apex, records).unwrap();
    let query: Name = "www.example.org.".parse().unwrap();
    let (outcome, response) = zone_response(&zone, &query, Type::A, Class::IN, true).await;
    assert_eq!(outcome, Outcome::Response);
    assert!(
        Message::parse(&response)
            .unwrap()
            .answers()
            .any(|rr| { rr.rtype == Type::RRSIG && rr.name.to_string() == "www.example.org." })
    );
}

#[tokio::test]
async fn wildcard_nsec_is_not_synthesized_at_expanded_owner() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\n*.example.org. 60 IN A 192.0.2.1\n*.example.org. 60 IN NSEC a.example.org. A NSEC RRSIG\n";
    let mut records = ZoneParser::new(text.as_bytes(), apex.clone(), "wildcard-nsec.zone")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut signature = Type::NSEC.0.to_be_bytes().to_vec();
    signature.extend_from_slice(&[0; 16]);
    records.push(pharos_proto::zone::ZoneRecord {
        owner: "*.example.org.".parse().unwrap(),
        class: Class::IN,
        rtype: Type::RRSIG,
        ttl: 60,
        rdata: signature,
    });
    let zone = Zone::from_records(apex, records).unwrap();
    let query: Name = "www.example.org.".parse().unwrap();
    let (outcome, response) = zone_response(&zone, &query, Type::NSEC, Class::IN, true).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&response).unwrap();
    assert!(!response.answers().any(|rr| rr.rtype == Type::NSEC));
}

#[tokio::test]
async fn dnssec_referral_without_ds_includes_nsec_and_signature() {
    let apex: Name = "example.org.".parse().unwrap();
    let mut records = ZoneParser::new(
        "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 60 IN NS ns.example.org.\nchild.example.org. 60 IN NS ns.child.example.org.\nchild.example.org. 60 IN NSEC z.example.org. NS NSEC RRSIG\n"
            .as_bytes(),
        apex.clone(),
        "referral.zone",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let mut signature = Type::NSEC.0.to_be_bytes().to_vec();
    signature.extend_from_slice(&[0; 16]);
    records.push(pharos_proto::zone::ZoneRecord {
        owner: "child.example.org.".parse().unwrap(),
        class: Class::IN,
        rtype: Type::RRSIG,
        ttl: 60,
        rdata: signature,
    });
    let zone = Zone::from_records(apex, records).unwrap();
    let query: Name = "host.child.example.org.".parse().unwrap();
    let (outcome, response) = zone_response(&zone, &query, Type::A, Class::IN, true).await;
    assert_eq!(outcome, Outcome::Response);
    let response = Message::parse(&response).unwrap();
    assert!(
        response
            .authorities()
            .any(|rr| { rr.rtype == Type::NSEC && rr.name.to_string() == "child.example.org." })
    );
    assert!(
        response
            .authorities()
            .any(|rr| { rr.rtype == Type::RRSIG && rr.name.to_string() == "child.example.org." })
    );
}

#[test]
fn predecessor_uses_nearest_tree_name_not_nearest_nsec() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 3600 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 3600 IN NS ns.example.org.\n@ 3600 IN NSEC a.example.org. SOA NS NSEC\na 60 IN A 192.0.2.1\nc 60 IN NSEC example.org. NSEC\n";
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
async fn nxdomain_below_empty_nonterminal_uses_ent_as_closest_encloser() {
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
        ["a.example.org."]
    );
}

#[test]
fn zone_file_rejects_multiple_soa_records() {
    let apex: Name = "example.org.".parse().unwrap();
    let text = "@ 3600 IN SOA ns.example.org. hostmaster.example.org. 1 2 3 4 5\n@ 3600 IN SOA ns.example.org. hostmaster.example.org. 2 2 3 4 5\n@ 3600 IN NS ns.example.org.\n";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/multiple-soa.zone");
    std::fs::write(&path, text).unwrap();
    assert!(Zone::load(apex, &path).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn zero_serial_is_valid_at_file_setup() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/file-zero-serial.zone");
    let original = include_str!("../../tests/fixtures/file/example.zone");
    std::fs::write(&path, original.replace(" 1 7200", " 0 7200")).unwrap();
    let corefile = format!("example.org:53 {{\n file {}\n}}", path.display());
    let blocks = pharos_corefile::parse("Corefile", &corefile).unwrap();
    assert!(pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).is_ok());
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

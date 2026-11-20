use super::{acquire, validate};
use crate::dynupdate::setup;
use pharos_corefile::{Cursor, lex};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn validates_without_creating_and_shares_hardlinked_store() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("seed"), "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n").unwrap();
    let text = "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}";
    let tokens = lex("Corefile", text);
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    validate(&config).unwrap();
    assert!(!dir.join("db").exists());
    let first = acquire(&config).unwrap();
    assert_eq!(
        std::fs::metadata(dir.join("db"))
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    assert_eq!(first.current.load().serial(), Some(1));
    assert_eq!(
        first
            .db
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .get(super::ORIGIN_KEY),
        Some(&b"example.org."[..])
    );
    let before = std::fs::read(dir.join("db")).unwrap();
    std::fs::remove_file(dir.join("seed")).unwrap();
    assert_eq!(validate(&config).unwrap().serial(), Some(1));
    assert_eq!(std::fs::read(dir.join("db")).unwrap(), before);
    std::fs::hard_link(dir.join("db"), dir.join("alias")).unwrap();
    let alias_text = "dynupdate {\nfile seed\ndatabase alias\nallow key.example.org. * A\n}";
    let tokens = lex("Corefile", alias_text);
    let alias_config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let second = acquire(&alias_config).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    // An UPDATE through one name is read through the other: both are the same inode.
    let added = pharos_proto::zone::ZoneRecord {
        owner: "linked.example.org.".parse().unwrap(),
        rtype: pharos_proto::Type::A,
        class: pharos_proto::Class::IN,
        ttl: 60,
        rdata: vec![192, 0, 2, 9],
    };
    let key: pharos_proto::Name = "key.example.org.".parse().unwrap();
    first
        .transact(&config, &key, &[], std::slice::from_ref(&added))
        .unwrap();
    let seen = validate(&alias_config).unwrap();
    assert!(
        seen.records()
            .iter()
            .any(|record| record.owner == added.owner)
    );
    drop(first);
    drop(second);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_database_with_noncanonical_origin_instead_of_seed_fallback() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-origin-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let text = "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}";
    let tokens = lex("Corefile", text);
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let shared = acquire(&config).unwrap();
    {
        let mut db = shared.db.lock().unwrap();
        db.as_mut()
            .unwrap()
            .commit(&[pharos_kv::Op::Put(
                super::ORIGIN_KEY.to_vec(),
                b"EXAMPLE.ORG.".to_vec(),
            )])
            .unwrap();
    }
    drop(shared);
    assert!(validate(&config).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_durable_database_missing_apex_ns_with_repair_guidance() {
    use pharos_proto::Type;

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-no-apex-ns-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let shared = acquire(&config).unwrap();
    let database = dir.join("db").canonicalize().unwrap();
    let removed = shared
        .current
        .load()
        .records()
        .iter()
        .filter(|record| record.rtype == Type::NS)
        .map(|record| pharos_kv::Op::Delete(super::record_key(record).unwrap()))
        .collect::<Vec<_>>();
    shared
        .db
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .commit(&removed)
        .unwrap();
    drop(shared);

    let error = validate(&config).err().unwrap().to_string();
    assert!(error.contains("Zone apex has no NS record"), "{error}");
    assert!(
        error.contains("add an NS RRset at the Zone apex"),
        "{error}"
    );
    assert!(error.contains(&database.display().to_string()), "{error}");
    assert!(
        error.contains("restore/UPDATE NS on previous build"),
        "{error}"
    );
    assert!(error.contains("recreate DB from corrected seed"), "{error}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn concurrent_prerequisites_apply_to_the_committed_snapshot() {
    use pharos_proto::{Class, Name, Rcode, Type, zone::ZoneRecord};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-race-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let text = "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}";
    let tokens = lex("Corefile", text);
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let shared = acquire(&config).unwrap();
    let key: Name = "key.example.org.".parse().unwrap();
    let owner: Name = "host.example.org.".parse().unwrap();
    let prereq = ZoneRecord {
        owner: owner.clone(),
        rtype: Type::A,
        class: Class::NONE,
        ttl: 0,
        rdata: Vec::new(),
    };
    let update = ZoneRecord {
        owner,
        rtype: Type::A,
        class: Class::IN,
        ttl: 60,
        rdata: vec![192, 0, 2, 1],
    };
    let results = std::thread::scope(|scope| {
        let threads = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    shared
                        .transact(
                            &config,
                            &key,
                            std::slice::from_ref(&prereq),
                            std::slice::from_ref(&update),
                        )
                        .unwrap()
                        .0
                })
            })
            .collect::<Vec<_>>();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results
            .iter()
            .filter(|rcode| **rcode == Rcode::NOERROR)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|rcode| **rcode == Rcode::YXRRSET)
            .count(),
        7
    );
    assert_eq!(shared.current.load().serial(), Some(2));
    drop(shared);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failed_durable_commit_does_not_publish_candidate() {
    use pharos_proto::{Class, Name, Type, zone::ZoneRecord};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-failed-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let original = acquire(&config).unwrap();
    let snapshot = original.current.load_full();
    drop(original);
    let db = pharos_kv::Db::open_read_only(std::fs::File::open(dir.join("db")).unwrap()).unwrap();
    let shared = super::Shared {
        current: arc_swap::ArcSwap::from(Arc::clone(&snapshot)),
        db: std::sync::Mutex::new(Some(db)),
        compact_due: std::sync::atomic::AtomicBool::new(false),
    };
    let key: Name = "key.example.org.".parse().unwrap();
    let update = ZoneRecord {
        owner: "new.example.org.".parse().unwrap(),
        rtype: Type::A,
        class: Class::IN,
        ttl: 60,
        rdata: vec![192, 0, 2, 1],
    };
    assert!(shared.transact(&config, &key, &[], &[update]).is_err());
    assert!(Arc::ptr_eq(&snapshot, &shared.current.load_full()));
    assert_eq!(shared.current.load().serial(), Some(1));
    drop(shared);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn corrupt_and_truncated_database_never_falls_back_to_seed() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-corrupt-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let shared = acquire(&config).unwrap();
    drop(shared);
    let path = dir.join("db");
    let valid = std::fs::read(&path).unwrap();
    let mut bad_checksum = valid.clone();
    bad_checksum[40] ^= 1;
    bad_checksum[4096 + 40] ^= 1;
    for damaged in [bad_checksum, valid[..79].to_vec()] {
        std::fs::write(&path, &damaged).unwrap();
        assert!(validate(&config).is_err());
        assert!(acquire(&config).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), damaged);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn large_zone_survives_restart_without_seed() {
    use pharos_proto::{Class, Name, NameRef, Rcode, Type, zone::ZoneRecord};
    use std::fmt::Write;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-large-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    let mut seed = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n@ 60 IN NS ns.example.org.\n".to_owned();
    for index in 0..400 {
        writeln!(seed, "large-{index} 60 IN TXT \"{}\"", "a".repeat(200)).unwrap();
    }
    std::fs::write(dir.join("seed"), seed).unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let shared = acquire(&config).unwrap();
    let key: Name = "key.example.org.".parse().unwrap();
    let owner: Name = "saved.example.org.".parse().unwrap();
    let update = ZoneRecord {
        owner: owner.clone(),
        rtype: Type::A,
        class: Class::IN,
        ttl: 60,
        rdata: vec![192, 0, 2, 10],
    };
    assert_eq!(
        shared.transact(&config, &key, &[], &[update]).unwrap().0,
        Rcode::NOERROR
    );
    assert!(
        shared
            .db
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .iter()
            .map(|(key, _)| key.len())
            .sum::<usize>()
            > 65535
    );
    drop(shared);
    std::fs::remove_file(dir.join("seed")).unwrap();
    assert_eq!(validate(&config).unwrap().serial(), Some(11));
    let restarted = acquire(&config).unwrap();
    let snapshot = restarted.current.load_full();
    assert_eq!(
        snapshot
            .rrset(NameRef::parse(owner.as_wire(), 0).unwrap(), Type::A)
            .count(),
        1
    );
    assert_eq!(snapshot.records().len(), 403);
    drop(snapshot);
    drop(restarted);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn overlapping_reloads_serialize_distinct_updates() {
    use pharos_proto::{Class, Name, Rcode, Type, zone::ZoneRecord};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-reload-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let old = acquire(&config).unwrap();
    let new = acquire(&config).unwrap();
    assert!(Arc::ptr_eq(&old, &new));
    let key: Name = "key.example.org.".parse().unwrap();
    std::thread::scope(|scope| {
        let threads = (0..16)
            .map(|index| {
                let shared = if index % 2 == 0 { &old } else { &new };
                let config = &config;
                let key = &key;
                scope.spawn(move || {
                    let record = ZoneRecord {
                        owner: format!("host-{index}.example.org.").parse().unwrap(),
                        rtype: Type::A,
                        class: Class::IN,
                        ttl: 60,
                        rdata: vec![192, 0, 2, index + 1],
                    };
                    assert_eq!(
                        shared.transact(config, key, &[], &[record]).unwrap().0,
                        Rcode::NOERROR
                    );
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
    });
    assert_eq!(new.current.load().serial(), Some(26));
    assert_eq!(new.current.load().records().len(), 18);
    drop(old);
    assert_eq!(new.current.load().serial(), Some(26));
    drop(new);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn coredns_update_limits_are_atomic_in_both_modes() {
    use pharos_proto::{Class, Name, Rcode, Type, zone::ZoneRecord};
    for durable in [false, true] {
        for limit in ["records", "bytes", "updates"] {
            let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target")
                .join(format!(
                    "pharos-dynamic-limit-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(
                    dir.join("seed"),
                    "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
                )
                .unwrap();
            let database = if durable { "database db\n" } else { "" };
            let text = format!("dynupdate {{\nfile seed\n{database}allow key.example.org. * A\n}}");
            let tokens = lex("Corefile", &text);
            let mut config = setup::parse(
                &mut Cursor::new("Corefile", &tokens),
                &["example.org"],
                Some(&dir),
            )
            .unwrap();
            let shared = if durable {
                acquire(&config).unwrap()
            } else {
                Arc::new(super::Shared::memory(validate(&config).unwrap()))
            };
            let before = shared.current.load_full();
            match limit {
                "records" => config.max_records = before.records().len(),
                "bytes" => config.max_bytes = super::wire::encode(before.records()).unwrap().len(),
                _ => config.max_update_records = 1,
            }
            let key: Name = "key.example.org.".parse().unwrap();
            let updates = ["first.example.org.", "second.example.org."].map(|owner| ZoneRecord {
                owner: owner.parse().unwrap(),
                rtype: Type::A,
                class: Class::IN,
                ttl: 60,
                rdata: vec![192, 0, 2, 1],
            });
            assert_eq!(
                shared.transact(&config, &key, &[], &updates).unwrap().0,
                Rcode::REFUSED,
                "{durable} {limit}"
            );
            assert!(Arc::ptr_eq(&before, &shared.current.load_full()));
            assert_eq!(shared.current.load().serial(), Some(10));
            drop(before);
            drop(shared);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[test]
fn key_and_prerequisite_checks_precede_update_prescan() {
    use pharos_proto::{Class, Name, Rcode, Type, zone::ZoneRecord};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-order-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let shared = super::Shared::memory(validate(&config).unwrap());
    let missing = ZoneRecord {
        owner: "missing.example.org.".parse().unwrap(),
        rtype: Type::A,
        class: Class::ANY,
        ttl: 0,
        rdata: Vec::new(),
    };
    let outside = ZoneRecord {
        owner: "outside.test.".parse().unwrap(),
        rtype: Type::A,
        class: Class::IN,
        ttl: 60,
        rdata: vec![192, 0, 2, 1],
    };
    let known: Name = "key.example.org.".parse().unwrap();
    let unknown: Name = "other.example.org.".parse().unwrap();
    assert_eq!(
        shared
            .transact(
                &config,
                &unknown,
                std::slice::from_ref(&missing),
                std::slice::from_ref(&outside)
            )
            .unwrap()
            .0,
        Rcode::REFUSED
    );
    assert_eq!(
        shared
            .transact(&config, &known, &[missing], &[outside])
            .unwrap()
            .0,
        Rcode::NXRRSET
    );
    assert_eq!(shared.current.load().serial(), Some(10));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn closed_store_entries_are_reclaimed_on_next_open() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-registry-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let first_text = "dynupdate {\nfile seed\ndatabase first\nallow key.example.org. * A\n}";
    let tokens = lex("Corefile", first_text);
    let first_config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let first = acquire(&first_config).unwrap();
    let identity = super::identity(&std::fs::metadata(dir.join("first")).unwrap());
    drop(first);
    let second_text = "dynupdate {\nfile seed\ndatabase second\nallow key.example.org. * A\n}";
    let tokens = lex("Corefile", second_text);
    let second_config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let second = acquire(&second_config).unwrap();
    assert!(!super::registry().lock().unwrap().contains_key(&identity));
    drop(second);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn acknowledged_update_survives_abrupt_process_exit() {
    use pharos_proto::{Class, Name, NameRef, Rcode, Type, zone::ZoneRecord};
    const ENV: &str = "PHAROS_DYNUPDATE_EXIT_DIRECTORY";
    if let Some(dir) = std::env::var_os(ENV) {
        let dir = std::path::PathBuf::from(dir);
        let tokens = lex(
            "Corefile",
            "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
        );
        let config = setup::parse(
            &mut Cursor::new("Corefile", &tokens),
            &["example.org"],
            Some(&dir),
        )
        .unwrap();
        let shared = acquire(&config).unwrap();
        let key: Name = "key.example.org.".parse().unwrap();
        let update = ZoneRecord {
            owner: "saved.example.org.".parse().unwrap(),
            rtype: Type::A,
            class: Class::IN,
            ttl: 60,
            rdata: vec![192, 0, 2, 77],
        };
        assert_eq!(
            shared.transact(&config, &key, &[], &[update]).unwrap().0,
            Rcode::NOERROR
        );
        std::process::exit(73);
    }
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-exit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "dynupdate::store::tests::acknowledged_update_survives_abrupt_process_exit",
        ])
        .env(ENV, &dir)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    std::fs::remove_file(dir.join("seed")).unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let zone = validate(&config).unwrap();
    let owner: Name = "saved.example.org.".parse().unwrap();
    assert_eq!(zone.serial(), Some(11));
    assert_eq!(
        zone.rrset(NameRef::parse(owner.as_wire(), 0).unwrap(), Type::A)
            .next()
            .unwrap()
            .rdata,
        [192, 0, 2, 77]
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(feature = "plugin-transfer")]
#[test]
fn transfer_snapshots_remain_consistent_during_updates() {
    use crate::transfer::TransferRequest;
    use pharos_proto::{Class, Message, Name, NameRef, Rcode, Rdata, Type, zone::ZoneRecord};
    use pharos_server::Protocol;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-snapshot-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("seed"), "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n@ 60 IN NS ns.example.org.\n").unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let shared = acquire(&config).unwrap();
    let key: Name = "key.example.org.".parse().unwrap();
    let barrier = std::sync::Barrier::new(5);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let shared = &shared;
            let barrier = &barrier;
            scope.spawn(move || {
                let apex: Name = "example.org.".parse().unwrap();
                barrier.wait();
                for _ in 0..40 {
                    let snapshot = shared.current.load_full();
                    let mut stream = snapshot
                        .transfer(TransferRequest {
                            zone: NameRef::parse(apex.as_wire(), 0).unwrap(),
                            serial: 0,
                            id: 1,
                            flags: 0,
                            protocol: Protocol::Tcp,
                            qtype: Type::AXFR,
                            qclass: Class::IN,
                        })
                        .unwrap();
                    let mut wire = Vec::with_capacity(65535);
                    let mut serials = Vec::new();
                    let mut count = 0;
                    while stream.next(&mut wire).unwrap() {
                        let message = Message::parse(&wire).unwrap();
                        for rr in message.answers() {
                            count += 1;
                            if let Ok(Rdata::Soa { serial, .. }) = rr.data() {
                                serials.push(serial);
                            }
                        }
                    }
                    assert_eq!(serials.len(), 2);
                    assert_eq!(serials[0], serials[1]);
                    assert_eq!(serials[0] as usize - 10, count - 3);
                }
            });
        }
        barrier.wait();
        for index in 0..20 {
            let record = ZoneRecord {
                owner: format!("host-{index}.example.org.").parse().unwrap(),
                rtype: Type::A,
                class: Class::IN,
                ttl: 60,
                rdata: vec![192, 0, 2, index + 1],
            };
            assert_eq!(
                shared.transact(&config, &key, &[], &[record]).unwrap().0,
                Rcode::NOERROR
            );
        }
    });
    drop(shared);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn read_only_validation_releases_lock_and_preserves_database() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-validate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    drop(acquire(&config).unwrap());
    std::fs::remove_file(dir.join("seed")).unwrap();
    let before = std::fs::read(dir.join("db")).unwrap();
    assert_eq!(validate(&config).unwrap().serial(), Some(1));
    assert_eq!(std::fs::read(dir.join("db")).unwrap(), before);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join("db"))
        .unwrap();
    file.try_lock().unwrap();
    drop(file);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn seed_file_and_hardlink_cannot_be_database() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-seed-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    let seed = dir.join("seed");
    std::fs::write(
            &seed,
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    std::fs::hard_link(&seed, dir.join("alias")).unwrap();
    let before = std::fs::read(&seed).unwrap();
    for database in ["seed", "alias"] {
        let text =
            format!("dynupdate {{\nfile seed\ndatabase {database}\nallow key.example.org. * A\n}}");
        let tokens = lex("Corefile", &text);
        let config = setup::parse(
            &mut Cursor::new("Corefile", &tokens),
            &["example.org"],
            Some(&dir),
        )
        .unwrap();
        assert!(validate(&config).is_err());
        assert!(acquire(&config).is_err());
        assert_eq!(std::fs::read(&seed).unwrap(), before);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn empty_cname_survives_database_restart() {
    use pharos_proto::{Class, Name, Rcode, Type, zone::ZoneRecord};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-empty-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * CNAME\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let shared = acquire(&config).unwrap();
    let key: Name = "key.example.org.".parse().unwrap();
    let record = ZoneRecord {
        owner: "empty.example.org.".parse().unwrap(),
        rtype: Type::CNAME,
        class: Class::IN,
        ttl: 60,
        rdata: Vec::new(),
    };
    assert_eq!(
        shared.transact(&config, &key, &[], &[record]).unwrap().0,
        Rcode::NOERROR
    );
    drop(shared);
    std::fs::remove_file(dir.join("seed")).unwrap();
    let zone = validate(&config).unwrap();
    assert!(
        zone.records()
            .iter()
            .any(|rr| rr.rtype == Type::CNAME && rr.rdata.is_empty())
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn coredns_explicit_any_permission_only_allows_delete_all() {
    use pharos_proto::{Class, Name, Rcode, Type, zone::ZoneRecord};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-any-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("seed"), "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n@ 60 IN NS ns.example.org.\nwww 60 IN A 192.0.2.1\n").unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\nallow key.example.org. www.example.org. ANY\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let shared = super::Shared::memory(validate(&config).unwrap());
    let key: Name = "key.example.org.".parse().unwrap();
    let owner: Name = "www.example.org.".parse().unwrap();
    let delete = ZoneRecord {
        owner: owner.clone(),
        rtype: Type::ANY,
        class: Class::ANY,
        ttl: 0,
        rdata: Vec::new(),
    };
    assert_eq!(
        shared.transact(&config, &key, &[], &[delete]).unwrap().0,
        Rcode::NOERROR
    );
    assert!(
        !shared
            .current
            .load()
            .records()
            .iter()
            .any(|rr| rr.owner == owner)
    );
    let add = ZoneRecord {
        owner,
        rtype: Type::A,
        class: Class::IN,
        ttl: 60,
        rdata: vec![192, 0, 2, 20],
    };
    assert_eq!(
        shared.transact(&config, &key, &[], &[add]).unwrap().0,
        Rcode::REFUSED
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn coredns_rejects_invalid_database_contents_and_limits() {
    use pharos_proto::{Class, Type, zone::ZoneRecord};
    for case in [
        "wrong-zone",
        "unknown-format",
        "truncated-records",
        "invalid-zone",
        "records",
        "bytes",
    ] {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "pharos-dynamic-invalid-db-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("seed"), "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n@ 60 IN NS ns.example.org.\n").unwrap();
        let tokens = lex(
            "Corefile",
            "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
        );
        let mut config = setup::parse(
            &mut Cursor::new("Corefile", &tokens),
            &["example.org"],
            Some(&dir),
        )
        .unwrap();
        let shared = acquire(&config).unwrap();
        if matches!(case, "wrong-zone" | "truncated-records" | "invalid-zone") {
            let mut guard = shared.db.lock().unwrap();
            let db = guard.as_mut().unwrap();
            let invalid_rr = ZoneRecord {
                owner: "outside.test.".parse().unwrap(),
                rtype: Type::A,
                class: Class::IN,
                ttl: 60,
                rdata: vec![192, 0, 2, 1],
            };
            let op = match case {
                "wrong-zone" => {
                    pharos_kv::Op::Put(super::ORIGIN_KEY.to_vec(), b"other.example.".to_vec())
                }
                "truncated-records" => pharos_kv::Op::Put(vec![b'r', 0xff, 1], Vec::new()),
                _ => pharos_kv::Op::Put(super::record_key(&invalid_rr).unwrap(), Vec::new()),
            };
            db.commit(&[op]).unwrap();
        }
        drop(shared);
        if case == "unknown-format" {
            let path = dir.join("db");
            std::fs::write(&path, []).unwrap();
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap();
            drop(
                pharos_kv::Db::create(file, &[pharos_kv::Op::Put(b"x".to_vec(), Vec::new())])
                    .unwrap(),
            );
        }
        if case == "records" {
            config.max_records = 1;
        }
        if case == "bytes" {
            config.max_bytes = 1;
        }
        let before = std::fs::read(dir.join("db")).unwrap();
        assert!(validate(&config).is_err(), "{case}");
        assert!(acquire(&config).is_err(), "{case}");
        assert_eq!(std::fs::read(dir.join("db")).unwrap(), before, "{case}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn exclusive_bbolt_lock_times_out_and_releases() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-lock-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    drop(acquire(&config).unwrap());
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join("db"))
        .unwrap();
    file.try_lock().unwrap();
    let start = std::time::Instant::now();
    assert!(acquire(&config).is_err());
    assert!(start.elapsed() >= std::time::Duration::from_millis(900));
    drop(file);
    assert!(acquire(&config).is_ok());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn database_created_between_stat_and_open_is_not_overwritten() {
    use pharos_proto::{Class, Type, zone::ZoneRecord};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-create-race-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let seed = validate(&config).unwrap();
    let update = ZoneRecord {
        owner: "saved.example.org.".parse().unwrap(),
        rtype: Type::A,
        class: Class::IN,
        ttl: 60,
        rdata: vec![192, 0, 2, 10],
    };
    let (updated, _) = seed.apply_updates(&[update]).unwrap();
    let shared = super::acquire_with(&config, || {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join("db"))
            .unwrap();
        pharos_kv::Db::create(
            file,
            &super::zone_ops(&config.origin, updated.records()).unwrap(),
        )
        .unwrap();
    })
    .unwrap();
    assert_eq!(shared.current.load().serial(), Some(2));
    drop(shared);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejected_update_section_never_partially_changes_zone() {
    use pharos_proto::{Class, Name, Rcode, Type, zone::ZoneRecord};
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-atomic-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\nallow key.example.org. * *\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    let shared = super::Shared::memory(validate(&config).unwrap());
    let before = shared.current.load_full();
    let key: Name = "key.example.org.".parse().unwrap();
    let valid = ZoneRecord {
        owner: "new.example.org.".parse().unwrap(),
        rtype: Type::A,
        class: Class::IN,
        ttl: 60,
        rdata: vec![192, 0, 2, 10],
    };
    let outside = ZoneRecord {
        owner: "outside.test.".parse().unwrap(),
        rtype: Type::A,
        class: Class::IN,
        ttl: 60,
        rdata: vec![192, 0, 2, 11],
    };
    let malformed = ZoneRecord {
        owner: "new.example.org.".parse().unwrap(),
        rtype: Type::A,
        class: Class::ANY,
        ttl: 1,
        rdata: Vec::new(),
    };
    for (invalid, expected) in [(outside, Rcode::NOTZONE), (malformed, Rcode::FORMERR)] {
        assert_eq!(
            shared
                .transact(&config, &key, &[], &[valid.clone(), invalid])
                .unwrap()
                .0,
            expected
        );
        assert!(Arc::ptr_eq(&before, &shared.current.load_full()));
        assert_eq!(shared.current.load().serial(), Some(10));
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn initializes_missing_database_through_symlink() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-symlink-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    std::os::unix::fs::symlink("actual", dir.join("alias")).unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase alias\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    assert_eq!(validate(&config).unwrap().serial(), Some(1));
    assert!(!dir.join("actual").exists());
    let shared = acquire(&config).unwrap();
    assert_eq!(shared.current.load().serial(), Some(1));
    assert!(dir.join("actual").exists());
    assert!(
        std::fs::symlink_metadata(dir.join("alias"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    drop(shared);
    std::fs::remove_dir_all(dir).unwrap();
}

// RFC 2181 §5.2: an RRset is unordered, and the store hands records back in key order.
fn record_set(records: &[pharos_proto::zone::ZoneRecord]) -> std::collections::BTreeSet<Vec<u8>> {
    records
        .iter()
        .map(|r| super::record_key(r).unwrap())
        .collect()
}

fn bbolt_fixture_config(tag: &str) -> (std::path::PathBuf, crate::dynupdate::setup::Config) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-dynamic-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
            dir.join("seed"),
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n@ 60 IN NS ns.example.org.\n",
        )
        .unwrap();
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/dynupdate/coredns.db"
        ),
        dir.join("db"),
    )
    .unwrap();
    let tokens = lex(
        "Corefile",
        "dynupdate {\nfile seed\ndatabase db\nallow key.example.org. * A\n}",
    );
    let config = setup::parse(
        &mut Cursor::new("Corefile", &tokens),
        &["example.org"],
        Some(&dir),
    )
    .unwrap();
    (dir, config)
}

#[test]
fn bbolt_database_is_converted_on_first_open_and_kept_as_backup() {
    use pharos_proto::{Class, Name, Rcode, Type, zone::ZoneRecord};
    let (dir, config) = bbolt_fixture_config("import");
    let original = std::fs::read(dir.join("db")).unwrap();
    // `pharos check` reads the bbolt file without converting it.
    let checked = validate(&config).unwrap();
    assert_eq!(std::fs::read(dir.join("db")).unwrap(), original);
    assert!(!dir.join("db.bbolt.bak").exists());
    let shared = acquire(&config).unwrap();
    assert_eq!(
        record_set(shared.current.load().records()),
        record_set(checked.records())
    );
    assert_eq!(std::fs::read(dir.join("db.bbolt.bak")).unwrap(), original);
    let converted = std::fs::File::open(dir.join("db")).unwrap();
    assert!(pharos_kv::Db::looks_like_database(&converted).unwrap());
    let key: Name = "key.example.org.".parse().unwrap();
    let update = ZoneRecord {
        owner: "after-import.example.org.".parse().unwrap(),
        rtype: Type::A,
        class: Class::IN,
        ttl: 60,
        rdata: vec![192, 0, 2, 77],
    };
    assert_eq!(
        shared.transact(&config, &key, &[], &[update]).unwrap().0,
        Rcode::NOERROR
    );
    let expected = shared.current.load().records().to_vec();
    drop(shared);
    assert_eq!(
        record_set(validate(&config).unwrap().records()),
        record_set(&expected)
    );
    assert_eq!(
        record_set(acquire(&config).unwrap().current.load().records()),
        record_set(&expected)
    );
    assert_eq!(std::fs::read(dir.join("db.bbolt.bak")).unwrap(), original);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn interrupted_creation_is_initialised_again_from_the_seed() {
    let (dir, config) = bbolt_fixture_config("interrupted");
    std::fs::write(dir.join("db"), vec![0u8; 100_000]).unwrap();
    let shared = acquire(&config).unwrap();
    assert_eq!(shared.current.load().serial(), Some(1));
    drop(shared);
    let file = std::fs::File::open(dir.join("db")).unwrap();
    assert!(pharos_kv::Db::looks_like_database(&file).unwrap());
    assert!(!dir.join("db.bbolt.bak").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn empty_database_is_initialised_again_from_the_seed() {
    let (dir, config) = bbolt_fixture_config("interrupted-empty");
    std::fs::write(dir.join("db"), b"").unwrap();
    let shared = acquire(&config).unwrap();
    assert_eq!(shared.current.load().serial(), Some(1));
    drop(shared);
    let file = std::fs::File::open(dir.join("db")).unwrap();
    assert!(pharos_kv::Db::looks_like_database(&file).unwrap());
    assert!(!dir.join("db.bbolt.bak").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn existing_backup_blocks_conversion_and_leaves_the_database_alone() {
    let (dir, config) = bbolt_fixture_config("import-backup");
    std::fs::write(dir.join("db.bbolt.bak"), b"someone else's file").unwrap();
    let original = std::fs::read(dir.join("db")).unwrap();
    assert!(acquire(&config).is_err());
    assert_eq!(std::fs::read(dir.join("db")).unwrap(), original);
    assert_eq!(
        std::fs::read(dir.join("db.bbolt.bak")).unwrap(),
        b"someone else's file"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn conversion_resumes_after_a_crash_between_backup_and_replace() {
    let (dir, config) = bbolt_fixture_config("import-resume");
    std::fs::hard_link(dir.join("db"), dir.join("db.bbolt.bak")).unwrap();
    std::fs::write(dir.join("db.import"), b"half-written leftover").unwrap();
    assert!(acquire(&config).is_ok());
    let converted = std::fs::File::open(dir.join("db")).unwrap();
    assert!(pharos_kv::Db::looks_like_database(&converted).unwrap());
    assert!(!dir.join("db.import").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn conversion_replaces_the_symlink_target_not_the_symlink() {
    let (dir, config) = bbolt_fixture_config("import-link");
    std::fs::rename(dir.join("db"), dir.join("real")).unwrap();
    std::os::unix::fs::symlink("real", dir.join("db")).unwrap();
    drop(acquire(&config).unwrap());
    assert!(
        std::fs::symlink_metadata(dir.join("db"))
            .unwrap()
            .is_symlink()
    );
    let converted = std::fs::File::open(dir.join("real")).unwrap();
    assert!(pharos_kv::Db::looks_like_database(&converted).unwrap());
    assert!(dir.join("real.bbolt.bak").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

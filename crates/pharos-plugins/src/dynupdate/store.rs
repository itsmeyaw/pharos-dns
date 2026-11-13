use super::{bbolt, setup::Config, update::build_zone, wire};
use crate::zone::Zone;
use arc_swap::ArcSwap;
use pharos_proto::{
    Name, Rcode,
    zone::{ZoneParser, ZoneRecord},
};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, BufReader, ErrorKind},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};

type Identity = (u64, u64);
type Registry = Mutex<HashMap<Identity, Weak<Shared>>>;
static STORES: OnceLock<Registry> = OnceLock::new();

pub(super) struct Shared {
    pub(super) current: ArcSwap<Zone>,
    pub(super) db: Mutex<Option<bbolt::Store>>,
}

impl Shared {
    pub(super) fn memory(zone: Arc<Zone>) -> Self {
        Self {
            current: ArcSwap::from(zone),
            db: Mutex::new(None),
        }
    }

    // RFC 2136 §3.2: serialize prerequisites with the durable UPDATE they guard.
    pub(super) fn transact(
        &self,
        config: &Config,
        key: &Name,
        prereqs: &[ZoneRecord],
        updates: &[ZoneRecord],
    ) -> io::Result<(Rcode, bool)> {
        if !config.configured_key(key)
            || prereqs
                .len()
                .checked_add(updates.len())
                .is_none_or(|count| count > config.max_update_records)
        {
            return Ok((Rcode::REFUSED, false));
        }
        let mut db = self.db.lock().map_err(invalid)?;
        let zone = self.current.load_full();
        let code = super::update::prerequisites(&zone, prereqs);
        if code != Rcode::NOERROR {
            return Ok((code, false));
        }
        if updates
            .iter()
            .any(|rr| !config.allows(key, &rr.owner, rr.rtype))
        {
            return Ok((Rcode::REFUSED, false));
        }
        let code = super::update::validate_updates(&zone, updates);
        if code != Rcode::NOERROR {
            return Ok((code, false));
        }
        let (candidate, changed) = zone.apply_updates(updates).map_err(invalid)?;
        if !changed {
            return Ok((Rcode::NOERROR, false));
        }
        if check_limits(&candidate, config).is_err() {
            return Ok((Rcode::REFUSED, false));
        }
        if let Some(db) = db.as_mut() {
            db.commit(
                config.origin.canonical().as_bytes(),
                &wire::encode(candidate.records())?,
            )?;
        }
        self.current.store(Arc::new(candidate));
        Ok((Rcode::NOERROR, true))
    }
}

fn registry() -> &'static Registry {
    STORES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, error.to_string())
}

fn identity(meta: &std::fs::Metadata) -> Identity {
    (meta.dev(), meta.ino())
}

// bbolt v1.5.0 bolt_unix.go:17-45: acquire a shared or exclusive advisory lock with a one-second timeout.
fn lock(file: &File, shared: bool) -> io::Result<()> {
    let start = Instant::now();
    loop {
        let result = if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        };
        match result {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < Duration::from_secs(1) => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(ErrorKind::WouldBlock, "bbolt lock timeout"));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
    }
}

fn check_limits(zone: &Zone, config: &Config) -> io::Result<()> {
    let bytes = zone.records().iter().try_fold(0usize, |total, rr| {
        total
            .checked_add(rr.owner.as_wire().len())?
            .checked_add(10)?
            .checked_add(rr.rdata.len())
    });
    if zone.records().len() > config.max_records || bytes.is_none_or(|size| size > config.max_bytes)
    {
        return Err(invalid("Zone exceeds configured limits"));
    }
    Ok(())
}

fn seed(config: &Config) -> io::Result<Zone> {
    let file = File::open(&config.seed)?;
    let mut parser = ZoneParser::new(
        BufReader::new(file),
        config.origin.clone(),
        config.seed.to_string_lossy(),
    );
    parser.set_include_allowed(true);
    let mut records = Vec::new();
    let mut remaining = config.max_bytes;
    for record in parser {
        let record = record.map_err(invalid)?;
        let size = record
            .owner
            .as_wire()
            .len()
            .checked_add(10)
            .and_then(|n| n.checked_add(record.rdata.len()))
            .ok_or_else(|| invalid("Zone exceeds max_bytes"))?;
        remaining = remaining
            .checked_sub(size)
            .ok_or_else(|| invalid("Zone exceeds max_bytes"))?;
        if records.len() == config.max_records {
            return Err(invalid("Zone exceeds max_records"));
        }
        records.push(record);
    }
    build_zone(
        config.origin.clone(),
        records,
        config.max_records,
        config.max_bytes,
    )
    .map_err(invalid)
}

fn load(db: &bbolt::Store, config: &Config) -> io::Result<Zone> {
    let (origin, records) = db.read()?;
    if origin != config.origin.canonical().as_bytes() {
        return Err(invalid("database belongs to another Zone"));
    }
    let records = wire::decode(&records, config.max_records, config.max_bytes)?;
    build_zone(
        config.origin.clone(),
        records,
        config.max_records,
        config.max_bytes,
    )
    .map_err(invalid)
}

// CoreDNS plugin/dynupdate/store.go:44-71: overlapping instances share a store by file identity.
pub(super) fn validate(config: &Config) -> io::Result<Arc<Zone>> {
    let Some(path) = &config.database else {
        return seed(config).map(Arc::new);
    };
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return seed(config).map(Arc::new),
        Err(error) => return Err(error),
    };
    if std::fs::metadata(&config.seed).is_ok_and(|seed| identity(&seed) == identity(&metadata)) {
        return Err(invalid("database and seed are the same file"));
    }
    if let Some(shared) = registry()
        .lock()
        .map_err(invalid)?
        .get(&identity(&metadata))
        .and_then(Weak::upgrade)
    {
        let zone = shared.current.load_full();
        if zone.apex() != &config.origin {
            return Err(invalid("database belongs to another Zone"));
        }
        check_limits(&zone, config)?;
        return Ok(zone);
    }
    let file = File::open(path)?;
    lock(&file, true)?;
    load(&bbolt::Store::open_limited(file, config.max_bytes)?, config).map(Arc::new)
}

pub(super) fn acquire(config: &Config) -> io::Result<Arc<Shared>> {
    let path = config
        .database
        .as_ref()
        .ok_or_else(|| invalid("database required"))?;
    let mut stores = registry().lock().map_err(invalid)?;
    stores.retain(|_, store| store.strong_count() != 0);
    let existed = match std::fs::metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    let initial = if existed { None } else { Some(seed(config)?) };
    let file = if existed {
        OpenOptions::new().read(true).write(true).open(path)?
    } else {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?
    };
    let metadata = file.metadata()?;
    let id = identity(&metadata);
    if std::fs::metadata(&config.seed).is_ok_and(|seed| identity(&seed) == id) {
        return Err(invalid("database and seed are the same file"));
    }
    if let Some(shared) = stores.get(&id).and_then(Weak::upgrade) {
        let zone = shared.current.load_full();
        if zone.apex() != &config.origin {
            return Err(invalid("database belongs to another Zone"));
        }
        check_limits(&zone, config)?;
        return Ok(shared);
    }
    lock(&file, false)?;
    let (db, zone) = if let Some(zone) = initial {
        let mut db = bbolt::Store::create(file)?;
        db.set_limit(config.max_bytes);
        db.commit(
            config.origin.canonical().as_bytes(),
            &wire::encode(zone.records())?,
        )?;
        (db, zone)
    } else {
        let db = bbolt::Store::open_limited(file, config.max_bytes)?;
        let zone = load(&db, config)?;
        (db, zone)
    };
    let shared = Arc::new(Shared {
        current: ArcSwap::from_pointee(zone),
        db: Mutex::new(Some(db)),
    });
    stores.insert(id, Arc::downgrade(&shared));
    Ok(shared)
}

#[cfg(test)]
mod tests {
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
            first.db.lock().unwrap().as_ref().unwrap().read().unwrap().0,
            b"example.org."
        );
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
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n",
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
            let db = db.as_mut().unwrap();
            let (_, records) = db.read().unwrap();
            db.commit(b"EXAMPLE.ORG.", &records).unwrap();
        }
        drop(shared);
        assert!(validate(&config).is_err());
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
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n",
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
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n",
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
        let db = super::bbolt::Store::open(std::fs::File::open(dir.join("db")).unwrap()).unwrap();
        let shared = super::Shared {
            current: arc_swap::ArcSwap::from(Arc::clone(&snapshot)),
            db: std::sync::Mutex::new(Some(db)),
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
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n",
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
        bad_checksum[72] ^= 1;
        bad_checksum[4096 + 72] ^= 1;
        for damaged in [bad_checksum, valid[..79].to_vec(), Vec::new()] {
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
                .read()
                .unwrap()
                .1
                .len()
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
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n",
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
        assert_eq!(new.current.load().records().len(), 17);
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
                    "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n",
                )
                .unwrap();
                let database = if durable { "database db\n" } else { "" };
                let text =
                    format!("dynupdate {{\nfile seed\n{database}allow key.example.org. * A\n}}");
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
                    "bytes" => {
                        config.max_bytes = super::wire::encode(before.records()).unwrap().len()
                    }
                    _ => config.max_update_records = 1,
                }
                let key: Name = "key.example.org.".parse().unwrap();
                let updates =
                    ["first.example.org.", "second.example.org."].map(|owner| ZoneRecord {
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
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n",
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
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n",
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
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n",
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
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n",
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
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n",
        )
        .unwrap();
        std::fs::hard_link(&seed, dir.join("alias")).unwrap();
        let before = std::fs::read(&seed).unwrap();
        for database in ["seed", "alias"] {
            let text = format!(
                "dynupdate {{\nfile seed\ndatabase {database}\nallow key.example.org. * A\n}}"
            );
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
            "@ 60 IN SOA ns.example.org. hostmaster.example.org. 1 60 60 60 60\n",
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
        std::fs::write(dir.join("seed"), "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\nwww 60 IN A 192.0.2.1\n").unwrap();
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
                let (_, records) = db.read().unwrap();
                let invalid_rr = ZoneRecord {
                    owner: "outside.test.".parse().unwrap(),
                    rtype: Type::A,
                    class: Class::IN,
                    ttl: 60,
                    rdata: vec![192, 0, 2, 1],
                };
                let data = match case {
                    "truncated-records" => vec![0xff, 1],
                    "invalid-zone" => super::wire::encode(&[invalid_rr]).unwrap(),
                    _ => records,
                };
                db.commit(
                    if case == "wrong-zone" {
                        b"other.example."
                    } else {
                        b"example.org."
                    },
                    &data,
                )
                .unwrap();
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
                drop(super::bbolt::Store::create(file).unwrap());
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
}

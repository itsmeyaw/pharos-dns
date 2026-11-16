use super::{ExpandedRecord, bbolt, setup::Config, update::build_zone, wire};
use crate::zone::Zone;
use arc_swap::ArcSwap;
use pharos_kv::{Db, Op};
use pharos_proto::{
    Name, Rcode,
    zone::{ZoneParser, ZoneRecord},
};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, BufReader, ErrorKind},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

type Identity = (u64, u64);
type Registry = Mutex<HashMap<Identity, Weak<Shared>>>;
static STORES: OnceLock<Registry> = OnceLock::new();

pub(super) struct Shared {
    pub(super) current: ArcSwap<Zone>,
    pub(super) db: Mutex<Option<Db>>,
    // Set by a commit that filled the update log, so the request path never has to lock `db`
    // just to ask.
    compact_due: AtomicBool,
}

// pharos-kv layout: one entry for the origin, and one entry per record whose key is 'r' plus
// the record's uncompressed wire form (RFC 1035 §4.1.3) and whose value is empty, so an UPDATE
// commits only the records it adds or removes.
const ORIGIN_KEY: &[u8] = b"origin";
const RECORD_PREFIX: u8 = b'r';

impl Shared {
    pub(super) fn memory(zone: Arc<Zone>) -> Self {
        Self {
            current: ArcSwap::from(zone),
            db: Mutex::new(None),
            compact_due: AtomicBool::new(false),
        }
    }

    // RFC 2136 §3.7: Serialize transactions with dependent prerequisites or updates.
    #[cfg(test)]
    pub(super) fn transact(
        &self,
        config: &Config,
        key: &Name,
        prereqs: &[ZoneRecord],
        updates: &[ZoneRecord],
    ) -> io::Result<(Rcode, bool)> {
        let prereqs = prereqs
            .iter()
            .map(|record| ExpandedRecord {
                record: record.clone(),
                rdata_len: record.rdata.len(),
            })
            .collect::<Vec<_>>();
        let updates = updates
            .iter()
            .map(|record| ExpandedRecord {
                record: record.clone(),
                rdata_len: record.rdata.len(),
            })
            .collect::<Vec<_>>();
        self.transact_expanded(config, key, &prereqs, &updates)
    }

    // RFC 2136 §1.1.1: carry received RDLENGTH through prerequisite and update comparison.
    pub(super) fn transact_expanded(
        &self,
        config: &Config,
        key: &Name,
        prereqs: &[ExpandedRecord],
        updates: &[ExpandedRecord],
    ) -> io::Result<(Rcode, bool)> {
        // RFC 3007 §3: Refuse updates unless the authenticated key has configured permission.
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
        // RFC 2136 §3.2: Check prerequisites against the transaction's current Zone snapshot.
        let code = super::update::prerequisites(&zone, prereqs);
        if code != Rcode::NOERROR {
            return Ok((code, false));
        }
        // RFC 3007 §3: Require an explicit configured permission for every update.
        if updates
            .iter()
            // RFC 2136 §3.3: Check requestor permission before applying the Update section.
            .any(|rr| !config.allows(key, &rr.record.owner, rr.record.rtype))
        {
            return Ok((Rcode::REFUSED, false));
        }
        let code = super::update::validate_updates(&zone, updates);
        if code != Rcode::NOERROR {
            return Ok((code, false));
        }
        let (candidate, changed) = zone
            .apply_updates_with_rdata_lengths(updates.iter().map(|rr| (&rr.record, rr.rdata_len)))
            .map_err(invalid)?;
        if !changed {
            return Ok((Rcode::NOERROR, false));
        }
        if check_limits(&candidate, config).is_err() {
            return Ok((Rcode::REFUSED, false));
        }
        if let Some(db) = db.as_mut() {
            db.commit(&record_changes(db, candidate.records())?)?;
            if db.needs_compaction() {
                self.compact_due.store(true, Ordering::Relaxed);
            }
        }
        self.current.store(Arc::new(candidate));
        // RFC 2136 §3.4.2.5: Return NOERROR after all Update operations succeed.
        Ok((Rcode::NOERROR, true))
    }
}

impl Shared {
    #[cfg(feature = "plugin-dynupdate")]
    pub(super) fn compaction_due(&self) -> bool {
        self.compact_due.swap(false, Ordering::Relaxed)
    }

    // Runs after the client has its reply: UPDATEs that arrive meanwhile wait for the lock.
    #[cfg(feature = "plugin-dynupdate")]
    pub(super) fn compact(&self) {
        let Ok(mut db) = self.db.lock() else { return };
        if let Some(db) = db.as_mut().filter(|db| db.needs_compaction())
            && let Err(error) = db.compact()
        {
            pharos_server::logging::log(
                "ERROR",
                "dynupdate",
                &format!("database compaction failed, further updates will be refused: {error}"),
            );
        }
    }
}

fn record_key(record: &ZoneRecord) -> io::Result<Vec<u8>> {
    let mut key = vec![RECORD_PREFIX];
    key.extend_from_slice(&wire::encode(std::slice::from_ref(record))?);
    Ok(key)
}

fn zone_ops(origin: &Name, records: &[ZoneRecord]) -> io::Result<Vec<Op>> {
    let mut ops = vec![Op::Put(
        ORIGIN_KEY.to_vec(),
        origin.canonical().as_bytes().to_vec(),
    )];
    for record in records {
        ops.push(Op::Put(record_key(record)?, Vec::new()));
    }
    Ok(ops)
}

// The database mirrors the published Zone while the caller holds the store lock, so the
// difference between its records and the candidate's is exactly what must be written.
fn record_changes(db: &Db, records: &[ZoneRecord]) -> io::Result<Vec<Op>> {
    let keys = records
        .iter()
        .map(record_key)
        .collect::<io::Result<Vec<_>>>()?;
    let stored = db.len().saturating_sub(1);
    let mut ops = Vec::new();
    let mut kept = 0usize;
    for key in &keys {
        if db.get(key).is_some() {
            kept += 1;
        } else {
            ops.push(Op::Put(key.clone(), Vec::new()));
        }
    }
    if kept != stored {
        let wanted = keys
            .iter()
            .map(Vec::as_slice)
            .collect::<std::collections::HashSet<_>>();
        ops.extend(
            db.iter()
                .filter(|(key, _)| key.first() == Some(&RECORD_PREFIX) && !wanted.contains(key))
                .map(|(key, _)| Op::Delete(key.to_vec())),
        );
    }
    Ok(ops)
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

fn lock(file: &File, shared: bool) -> io::Result<()> {
    pharos_kv::lock(file, shared)
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

fn zone_from(origin: &[u8], records: &[u8], config: &Config) -> io::Result<Zone> {
    if origin != config.origin.canonical().as_bytes() {
        return Err(invalid("database belongs to another Zone"));
    }
    let records = wire::decode(records, config.max_records, config.max_bytes)?;
    build_zone(
        config.origin.clone(),
        records,
        config.max_records,
        config.max_bytes,
    )
    .map_err(invalid)
}

fn load_bbolt(db: &bbolt::Store, config: &Config) -> io::Result<Zone> {
    let (origin, records) = db.read()?;
    zone_from(&origin, &records, config)
}

fn load(db: &Db, config: &Config) -> io::Result<Zone> {
    let origin = db
        .get(ORIGIN_KEY)
        .ok_or_else(|| invalid("database has no origin"))?;
    let mut records = Vec::new();
    for (key, _) in db.iter() {
        match key.split_first() {
            Some((&RECORD_PREFIX, record)) => records.extend_from_slice(record),
            _ if key == ORIGIN_KEY => {}
            _ => return Err(invalid("database has an unknown key")),
        }
    }
    zone_from(origin, &records, config)
}

fn database_load_error(path: &std::path::Path, error: io::Error) -> io::Error {
    let message = error.to_string();
    // RFC 2181 §6.1: A durable authoritative Zone without apex NS needs repair before startup.
    let repair = if message.contains("Zone apex has no NS record") {
        "; repair: restore/UPDATE NS on previous build, or recreate DB from corrected seed"
    } else {
        ""
    };
    io::Error::new(
        error.kind(),
        format!("database {}: {message}{repair}", path.display()),
    )
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
    // #93: a bbolt database is read as is; only `acquire` converts it.
    let zone = if Db::looks_like_database(&file)? {
        load(&Db::open_read_only(file)?, config)
    } else {
        load_bbolt(&bbolt::Store::open_limited(file, config.max_bytes)?, config)
    };
    zone.map(Arc::new)
        .map_err(|error| database_load_error(path, error))
}

pub(super) fn acquire(config: &Config) -> io::Result<Arc<Shared>> {
    acquire_with(config, || {})
}

fn acquire_with(config: &Config, after_stat: impl FnOnce()) -> io::Result<Arc<Shared>> {
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
    after_stat();
    let (file, mut initial) = if existed {
        (OpenOptions::new().read(true).write(true).open(path)?, None)
    } else {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(file) => (file, initial),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                match OpenOptions::new().read(true).write(true).open(path) {
                    Ok(file) => (file, None),
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        // CoreDNS follows a dangling database symlink when creating its target.
                        let file = OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create(true)
                            .truncate(false)
                            .mode(0o600)
                            .open(path)?;
                        (file, initial)
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
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
    // #93: a non-empty file with blank headers is an interrupted creation (the first state is
    // synced before the header that makes it real), so it is initialised again from the seed.
    let interrupted = file.metadata()?.len() != 0 && Db::is_blank(&file)?;
    if interrupted && initial.is_none() {
        initial = Some(seed(config)?);
    } else if !interrupted && file.metadata()?.len() != 0 {
        initial = None;
    }
    let (db, zone, id) = if let Some(zone) = initial {
        let db = Db::create(file, &zone_ops(&config.origin, zone.records())?)?;
        (db, zone, id)
    } else if Db::looks_like_database(&file)? {
        let db = Db::open(file)?;
        let zone = load(&db, config).map_err(|error| database_load_error(path, error))?;
        (db, zone, id)
    } else {
        import_bbolt(&file, path, config)?
    };
    let shared = Arc::new(Shared {
        current: ArcSwap::from_pointee(zone),
        db: Mutex::new(Some(db)),
        compact_due: AtomicBool::new(false),
    });
    stores.insert(id, Arc::downgrade(&shared));
    Ok(shared)
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

// #93: convert a bbolt database to pharos-kv. The original inode stays as `<database>.bbolt.bak`
// (a hard link, so nothing is copied), and the new file replaces the database path atomically.
fn import_bbolt(old: &File, path: &Path, config: &Config) -> io::Result<(Db, Zone, Identity)> {
    let zone = load_bbolt(
        &bbolt::Store::open_limited(old.try_clone()?, config.max_bytes)?,
        config,
    )
    .map_err(|error| database_load_error(path, error))?;
    let old_meta = old.metadata()?;
    // The database path may be a symlink; replace its target, not the link.
    let target = std::fs::canonicalize(path)?;
    let backup = suffixed(&target, ".bbolt.bak");
    match std::fs::hard_link(&target, &backup) {
        Ok(()) => {}
        // A crash between the link and the rename leaves the same inode under both names.
        Err(error)
            if error.kind() == ErrorKind::AlreadyExists
                && std::fs::metadata(&backup)
                    .is_ok_and(|b| identity(&b) == identity(&old_meta)) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            return Err(invalid(format!(
                "{} already exists; move it away to convert the bbolt database",
                backup.display()
            )));
        }
        Err(error) => return Err(error),
    }
    let temp = suffixed(&target, ".import");
    match std::fs::remove_file(&temp) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(old_meta.mode() & 0o777)
        .open(&temp)?;
    let created = (|| -> io::Result<(Db, Identity)> {
        lock(&file, false)?;
        let id = identity(&file.metadata()?);
        let db = Db::create(file, &zone_ops(&config.origin, zone.records())?)?;
        std::fs::rename(&temp, &target)?;
        if let Some(parent) = target.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok((db, id))
    })();
    let (db, id) = created.inspect_err(|_| {
        let _ = std::fs::remove_file(&temp);
    })?;
    pharos_server::logging::log(
        "INFO",
        "dynupdate",
        &format!(
            "converted bbolt database {} to the pharos-kv format; the original is kept as {}",
            target.display(),
            backup.display()
        ),
    );
    Ok((db, zone, id))
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
        let db =
            pharos_kv::Db::open_read_only(std::fs::File::open(dir.join("db")).unwrap()).unwrap();
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
    fn record_set(
        records: &[pharos_proto::zone::ZoneRecord],
    ) -> std::collections::BTreeSet<Vec<u8>> {
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
}

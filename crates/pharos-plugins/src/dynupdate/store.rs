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
    // #93: a blank file (empty or zeroed headers) is an interrupted creation, so seed it again.
    let interrupted = Db::is_blank(&file)?;
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
mod tests;

use super::{bbolt, setup::Config, update::build_zone, wire};
use crate::zone::Zone;
use arc_swap::ArcSwap;
use pharos_proto::zone::ZoneParser;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, BufReader, ErrorKind},
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};

type Identity = (u64, u64);
type Registry = Mutex<HashMap<Identity, Weak<Shared>>>;
static STORES: OnceLock<Registry> = OnceLock::new();

pub(super) struct Shared {
    pub(super) current: ArcSwap<Zone>,
    pub(super) db: Mutex<bbolt::Store>,
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
    if zone.records().len() > config.max_records
        || wire::encode(zone.records())?.len() > config.max_bytes
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
    load(&bbolt::Store::open(file)?, config).map(Arc::new)
}

pub(super) fn acquire(config: &Config) -> io::Result<Arc<Shared>> {
    let path = config
        .database
        .as_ref()
        .ok_or_else(|| invalid("database required"))?;
    let mut stores = registry().lock().map_err(invalid)?;
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
        db.commit(
            config.origin.canonical().as_bytes(),
            &wire::encode(zone.records())?,
        )?;
        (db, zone)
    } else {
        let db = bbolt::Store::open(file)?;
        let zone = load(&db, config)?;
        (db, zone)
    };
    let shared = Arc::new(Shared {
        current: ArcSwap::from_pointee(zone),
        db: Mutex::new(db),
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
        let dir = std::env::temp_dir().join(format!(
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
        assert_eq!(first.current.load().serial(), Some(1));
        assert_eq!(first.db.lock().unwrap().read().unwrap().0, b"example.org.");
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
        let dir = std::env::temp_dir().join(format!(
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
            let (_, records) = db.read().unwrap();
            db.commit(b"EXAMPLE.ORG.", &records).unwrap();
        }
        drop(shared);
        assert!(validate(&config).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

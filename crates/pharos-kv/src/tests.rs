use super::{Db, Op};
use std::{
    fs::{File, OpenOptions},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(super) fn path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "pharos-kv-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

pub(super) fn rw(path: &PathBuf) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap()
}

pub(super) fn put(key: &str, value: &str) -> Op {
    Op::Put(key.into(), value.into())
}

type Model = std::collections::BTreeMap<Vec<u8>, Vec<u8>>;

fn contents(db: &Db) -> Vec<(Vec<u8>, Vec<u8>)> {
    db.iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect()
}

fn reopen(path: &PathBuf) -> Vec<(Vec<u8>, Vec<u8>)> {
    contents(&Db::open(rw(path)).unwrap())
}

fn model(model: &Model) -> Vec<(Vec<u8>, Vec<u8>)> {
    model.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

fn arm(db: &Db, steps: usize, torn: bool) {
    arm_io(&db.io, steps, torn);
}

fn arm_io(io: &super::Io, steps: usize, torn: bool) {
    use std::sync::atomic::Ordering::SeqCst;
    let now = io.fault.count.load(SeqCst);
    io.fault.at.store(now + steps, SeqCst);
    io.fault.torn.store(torn, SeqCst);
}

#[test]
fn committed_batches_survive_reopen() {
    let path = path();
    let mut db = Db::create(rw(&path), &[put("origin", "example.org.")]).unwrap();
    db.commit(&[put("a", "1"), put("b", "2")]).unwrap();
    db.commit(&[Op::Delete("a".into()), put("c", "3")]).unwrap();
    drop(db);
    let db = Db::open(rw(&path)).unwrap();
    let all: Vec<_> = db.iter().collect();
    assert_eq!(
        all,
        [
            (&b"b"[..], &b"2"[..]),
            (b"c", b"3"),
            (b"origin", b"example.org.")
        ]
    );
    assert_eq!(db.get(b"a"), None);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn compaction_preserves_state_across_many_commits() {
    let path = path();
    let mut db = Db::create(rw(&path), &[]).unwrap();
    let mut expected = Model::new();
    let mut compactions = 0;
    for i in 0..700u32 {
        let key = format!("k{}", i % 50).into_bytes();
        let value = i.to_le_bytes().to_vec();
        db.commit(&[Op::Put(key.clone(), value.clone())]).unwrap();
        expected.insert(key, value);
        if db.needs_compaction() {
            db.compact().unwrap();
            compactions += 1;
        }
    }
    assert!(compactions >= 2);
    assert_eq!(contents(&db), model(&expected));
    drop(db);
    assert_eq!(reopen(&path), model(&expected));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn commit_that_overflows_the_log_is_folded_into_a_snapshot() {
    let path = path();
    let mut db = Db::create(rw(&path), &[]).unwrap();
    let mut expected = Model::new();
    // Never call compact(): the log region fills and commit() must fold by itself.
    for i in 0..600u32 {
        let key = format!("k{}", i % 7).into_bytes();
        db.commit(&[Op::Put(key.clone(), i.to_le_bytes().to_vec())])
            .unwrap();
        expected.insert(key, i.to_le_bytes().to_vec());
    }
    drop(db);
    assert_eq!(reopen(&path), model(&expected));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn torn_last_record_recovers_the_previous_state() {
    let path = path();
    let mut db = Db::create(rw(&path), &[]).unwrap();
    db.commit(&[put("a", "1")]).unwrap();
    db.commit(&[put("b", "2")]).unwrap();
    let before = contents(&db);
    db.commit(&[put("c", "3")]).unwrap();
    let last = db.header.log.off + 2 * 4096;
    drop(db);
    std::os::unix::fs::FileExt::write_all_at(&rw(&path), &[0xff; 64], last + 20).unwrap();
    assert_eq!(reopen(&path), before);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn records_of_an_abandoned_history_are_not_replayed() {
    let path = path();
    let mut db = Db::create(rw(&path), &[]).unwrap();
    db.commit(&[put("a", "1")]).unwrap();
    db.commit(&[put("b", "2")]).unwrap();
    db.commit(&[put("c", "3")]).unwrap();
    let second = db.header.log.off + 4096;
    drop(db);
    // Tear record 2; record 3 behind it stays intact and checksum-valid on its own.
    std::os::unix::fs::FileExt::write_all_at(&rw(&path), &[0; 4096], second).unwrap();
    let mut db = Db::open(rw(&path)).unwrap();
    assert_eq!(db.get(b"b"), None);
    db.commit(&[put("d", "4")]).unwrap();
    drop(db);
    let db = Db::open(rw(&path)).unwrap();
    assert_eq!(db.get(b"d"), Some(&b"4"[..]));
    assert_eq!(db.get(b"c"), None);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn damaged_header_is_refused_rather_than_rolling_back_commits() {
    let path = path();
    let mut db = Db::create(rw(&path), &[]).unwrap();
    db.commit(&[put("a", "1")]).unwrap();
    db.compact().unwrap();
    db.commit(&[put("b", "2")]).unwrap();
    drop(db);
    // Generation 1 lives in header block 1; the older header would silently lose "b".
    std::os::unix::fs::FileExt::write_all_at(&rw(&path), &[0xaa; 16], 4096 + 100).unwrap();
    let error = Db::open(rw(&path)).err().unwrap();
    assert!(error.to_string().contains("header block 1"), "{error}");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn crash_during_create_leaves_a_file_that_can_be_created_again() {
    let initial = [put("origin", "x"), put("a", "1")];
    for torn in [false, true] {
        for steps in 0..64 {
            let path = path();
            let io = super::Io::new(rw(&path));
            arm_io(&io, steps, torn);
            let result = Db::create_with(io, &initial);
            let db = Db::open_path(&path).unwrap();
            let got = contents(&db);
            drop(db);
            std::fs::remove_file(path).unwrap();
            if result.is_ok() {
                assert_eq!(got.len(), 2, "steps {steps}");
                break;
            }
            assert!(
                got.is_empty() || got.len() == 2,
                "steps {steps} torn {torn}"
            );
        }
    }
}

#[test]
fn is_blank_accepts_empty_and_zeroed_headers_only() {
    let path = path();
    std::fs::write(&path, b"").unwrap();
    assert!(Db::is_blank(&File::open(&path).unwrap()).unwrap());
    std::fs::write(&path, vec![0u8; 20000]).unwrap();
    assert!(Db::is_blank(&File::open(&path).unwrap()).unwrap());
    std::fs::write(&path, b"SQLite format 3\0").unwrap();
    assert!(!Db::is_blank(&File::open(&path).unwrap()).unwrap());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn record_framing_is_covered_by_the_checksum() {
    let path = path();
    let mut db = Db::create(rw(&path), &[]).unwrap();
    db.commit(&[put("a", "1")]).unwrap();
    db.commit(&[put("b", "2")]).unwrap();
    let log = db.header.log.off;
    drop(db);
    // Changing the length field of record 1 must end replay there, not skip or misparse.
    std::os::unix::fs::FileExt::write_all_at(&rw(&path), &[0xff], log + 4).unwrap();
    assert_eq!(Db::open(rw(&path)).unwrap().len(), 0);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn damaged_snapshot_or_headers_are_rejected() {
    let path = path();
    let mut db = Db::create(rw(&path), &[put("a", "1")]).unwrap();
    let snapshot = db.header.snap[db.header.live].off;
    db.commit(&[put("b", "2")]).unwrap();
    drop(db);
    let original = std::fs::read(&path).unwrap();
    let mut bad = original.clone();
    bad[snapshot as usize + 9] ^= 1;
    std::fs::write(&path, &bad).unwrap();
    assert!(Db::open(rw(&path)).is_err());
    let mut bad = original.clone();
    bad[..8192].fill(0);
    std::fs::write(&path, &bad).unwrap();
    assert!(Db::open(rw(&path)).is_err());
    std::fs::write(&path, &original[..100]).unwrap();
    assert!(Db::open(rw(&path)).is_err());
    std::fs::write(&path, b"not a database at all").unwrap();
    assert!(Db::open(rw(&path)).is_err());
    assert!(Db::create(rw(&path), &[]).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn state_outgrowing_its_regions_moves_to_new_ones() {
    let path = path();
    let mut db = Db::create(rw(&path), &[put("small", "x")]).unwrap();
    let first = std::fs::metadata(&path).unwrap().len();
    let big = vec![7u8; 3 << 20];
    db.commit(&[Op::Put(b"big".to_vec(), big.clone())]).unwrap();
    db.commit(&[put("after", "y")]).unwrap();
    assert!(std::fs::metadata(&path).unwrap().len() > first + (3 << 20));
    drop(db);
    let mut db = Db::open(rw(&path)).unwrap();
    assert_eq!(db.get(b"big"), Some(&big[..]));
    assert_eq!(db.get(b"after"), Some(&b"y"[..]));
    db.compact().unwrap();
    db.commit(&[Op::Delete(b"big".to_vec())]).unwrap();
    drop(db);
    let db = Db::open(rw(&path)).unwrap();
    assert_eq!((db.get(b"big"), db.len()), (None, 2));
    std::fs::remove_file(path).unwrap();
}

// Crash at every write/sync of `act`, with whole and half-written writes: after reopening
// the state must be the one before or the one after, never anything else.
fn crash_matrix(setup: impl Fn(&mut Db), act: impl Fn(&mut Db) -> std::io::Result<()>) {
    let fresh = || {
        let path = path();
        let mut db = Db::create(rw(&path), &[put("origin", "x")]).unwrap();
        setup(&mut db);
        (path, db)
    };
    let (reference, mut db) = fresh();
    let old = contents(&db);
    act(&mut db).unwrap();
    let new = contents(&db);
    std::fs::remove_file(reference).unwrap();
    for torn in [false, true] {
        for steps in 0..64 {
            let (path, mut db) = fresh();
            arm(&db, steps, torn);
            let result = act(&mut db);
            drop(db);
            let got = reopen(&path);
            std::fs::remove_file(path).unwrap();
            if result.is_ok() {
                assert_eq!(got, new, "steps {steps}");
                assert!(steps >= 2, "act must perform I/O");
                break;
            }
            assert!(got == old || got == new, "steps {steps} torn {torn}");
        }
    }
}

#[test]
fn crash_during_a_commit_leaves_old_or_new_state() {
    crash_matrix(
        |db| db.commit(&[put("a", "1")]).unwrap(),
        |db| db.commit(&[put("b", "2")]),
    );
}

#[test]
fn crash_during_compaction_leaves_the_same_state() {
    crash_matrix(|db| db.commit(&[put("a", "1")]).unwrap(), Db::compact);
}

#[test]
fn crash_during_a_commit_that_relocates_regions_leaves_old_or_new_state() {
    crash_matrix(
        |db| db.commit(&[put("a", "1")]).unwrap(),
        |db| db.commit(&[Op::Put(b"big".to_vec(), vec![1; 2 << 20])]),
    );
}

#[test]
fn failed_io_poisons_the_store_even_if_the_disk_recovers() {
    let path = path();
    let mut db = Db::create(rw(&path), &[]).unwrap();
    arm(&db, 0, false);
    assert!(db.commit(&[put("a", "1")]).is_err());
    arm(&db, usize::MAX / 2, false);
    db.io
        .fault
        .dead
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(db.commit(&[put("b", "2")]).is_err());
    assert!(db.compact().is_err());
    assert_eq!(db.get(b"a"), None);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn read_only_open_sees_the_data_and_changes_nothing() {
    let path = path();
    let mut db = Db::create(rw(&path), &[]).unwrap();
    db.commit(&[put("a", "1")]).unwrap();
    drop(db);
    let before = std::fs::read(&path).unwrap();
    let mut db = Db::open_read_only(File::open(&path).unwrap()).unwrap();
    assert_eq!(db.get(b"a"), Some(&b"1"[..]));
    assert!(db.commit(&[put("b", "2")]).is_err());
    assert!(db.compact().is_err());
    drop(db);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn open_path_creates_a_private_locked_database() {
    use std::os::unix::fs::PermissionsExt;
    let path = path();
    let mut db = Db::open_path(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    db.commit(&[put("a", "1")]).unwrap();
    let busy = Db::open_path(&path).err().unwrap();
    assert_eq!(busy.kind(), std::io::ErrorKind::WouldBlock);
    drop(db);
    assert_eq!(Db::open_path(&path).unwrap().get(b"a"), Some(&b"1"[..]));
    std::fs::remove_file(path).unwrap();
}

// The crash matrix cannot reorder writes, so check the ordering rules directly: a snapshot
// is synced before the header that names it, and a commit is synced before it returns.
#[test]
fn data_is_synced_before_the_header_that_publishes_it() {
    let path = path();
    let mut db = Db::create(rw(&path), &[put("a", "1")]).unwrap();
    let (snapshot_off, header_off) = (db.header.snap[1].off, 4096);
    db.io.fault.events.lock().unwrap().clear();
    db.compact().unwrap();
    let events = db.io.fault.events.lock().unwrap().clone();
    let at = |e: (char, u64)| events.iter().position(|x| *x == e).unwrap();
    assert!(events[at(('w', snapshot_off))..at(('w', header_off))].contains(&('s', 0)));
    assert_eq!(events.last(), Some(&('s', 0)));
    events_clear(&db);
    db.commit(&[put("b", "2")]).unwrap();
    let events = db.io.fault.events.lock().unwrap().clone();
    assert!(matches!(events[..], [('w', _), ('s', 0)]));
    std::fs::remove_file(path).unwrap();
}

fn events_clear(db: &Db) {
    db.io.fault.events.lock().unwrap().clear();
}

#[test]
fn looks_like_database_tells_headers_from_other_files() {
    let path = path();
    std::fs::write(&path, b"SQLite format 3\0 and more bytes").unwrap();
    assert!(!Db::looks_like_database(&File::open(&path).unwrap()).unwrap());
    std::fs::write(&path, b"").unwrap();
    assert!(!Db::looks_like_database(&File::open(&path).unwrap()).unwrap());
    std::fs::remove_file(&path).unwrap();
    let db = Db::create(rw(&path), &[]).unwrap();
    drop(db);
    // A damaged header still looks like ours, so its error is ours.
    std::os::unix::fs::FileExt::write_all_at(&rw(&path), &[0xff; 4], 40).unwrap();
    assert!(Db::looks_like_database(&File::open(&path).unwrap()).unwrap());
    std::fs::remove_file(path).unwrap();
}

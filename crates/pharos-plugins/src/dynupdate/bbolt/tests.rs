use super::Store;
use std::{
    fs::OpenOptions,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "pharos-bbolt-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
}

fn go(mode: &str, path: &std::path::Path) -> Option<std::process::Output> {
    match Command::new("go")
        .args(["run", ".", mode])
        .arg(path)
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/bbolt"))
        .output()
    {
        Ok(output) => Some(output),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping bbolt interop: Go is not installed");
            None
        }
        Err(error) => panic!("failed to run Go: {error}"),
    }
}

#[test]
fn rejects_existing_unrecognized_database() {
    let path = path();
    std::fs::write(&path, b"not a bbolt database").unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(Store::open(file).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn impossible_allocation_is_an_error() {
    assert!(super::zeroed(usize::MAX).is_err());
}

#[test]
fn reads_go_bbolt_database() {
    let path = path();
    let Some(output) = go("write", &path) else {
        return;
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let store = Store::open(file).unwrap();
    assert_eq!(
        store.read().unwrap(),
        (b"example.org.".to_vec(), b"record data".to_vec())
    );
    drop(store);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn rejects_corrupt_empty_key_even_when_zone_records_are_intact() {
    use std::os::unix::fs::FileExt;
    let path = path();
    let Some(output) = go("write-complex", &path) else {
        return;
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let store = Store::open(file).unwrap();
    let mut corrupted = false;
    for id in 2..store.meta.high {
        let Ok(page) = store.page(id) else { continue };
        if super::u16_at(&page, 8).unwrap() != super::LEAF {
            continue;
        }
        let count = usize::from(super::u16_at(&page, 10).unwrap());
        for index in 0..count {
            let element = super::HEADER + index * 16;
            let start = element + super::u32_at(&page, element + 4).unwrap() as usize;
            let len = super::u32_at(&page, element + 8).unwrap() as usize;
            if page.get(start..start + len) == Some(b"extra-0000".as_slice()) {
                store
                    .file
                    .write_all_at(
                        &0u32.to_ne_bytes(),
                        id * store.meta.page_size as u64 + element as u64 + 8,
                    )
                    .unwrap();
                corrupted = true;
                break;
            }
        }
        if corrupted {
            break;
        }
    }
    assert!(corrupted);
    assert!(store.read().is_err());
    drop(store);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn rejects_corrupt_branch_key_even_when_children_are_valid() {
    use std::os::unix::fs::FileExt;
    let path = path();
    let Some(output) = go("write-many-keys", &path) else {
        return;
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let store = Store::open(file).unwrap();
    let root = store
        .tree(store.meta.root, &mut std::collections::BTreeSet::new())
        .unwrap();
    let bucket = super::u64_at(&root.get(b"dynupdate-v1".as_slice()).unwrap().1, 0).unwrap();
    let page = store.page(bucket).unwrap();
    assert_eq!(super::u16_at(&page, 8).unwrap(), super::BRANCH);
    store
        .file
        .write_all_at(
            &0u32.to_ne_bytes(),
            bucket * store.meta.page_size as u64 + super::HEADER as u64 + 4,
        )
        .unwrap();
    assert!(store.read().is_err());
    drop(store);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn truncated_or_flipped_coredns_database_returns_errors_without_panics() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dynupdate/coredns.db"
    );
    let original = std::fs::read(fixture).unwrap();
    let path = path();
    for len in (0..original.len()).step_by(257) {
        std::fs::write(&path, &original[..len]).unwrap();
        let result = std::panic::catch_unwind(|| {
            let file = std::fs::File::open(&path).unwrap();
            Store::open(file).and_then(|store| store.read())
        });
        assert!(result.is_ok(), "panicked at length {len}");
    }
    for index in (0..original.len()).step_by(61) {
        let mut damaged = original.clone();
        damaged[index] ^= 0x55;
        std::fs::write(&path, &damaged).unwrap();
        let result = std::panic::catch_unwind(|| {
            let file = std::fs::File::open(&path).unwrap();
            Store::open(file).and_then(|store| store.read())
        });
        assert!(result.is_ok(), "panicked on flip at {index}");
    }
    std::fs::remove_file(path).unwrap();
}

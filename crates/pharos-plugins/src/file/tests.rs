use super::*;

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

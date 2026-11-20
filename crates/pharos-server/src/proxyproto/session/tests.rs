use super::*;

const TTL: Duration = Duration::from_millis(50);

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn put(sessions: &mut Sessions, key: &str, source: &str, now: Instant) {
    sessions.store(addr(key), (addr(source), ""), now);
}

fn lookup(sessions: &mut Sessions, key: &str, now: Instant) -> Option<SocketAddr> {
    sessions.lookup(addr(key), now, TTL, &mut String::new())
}

#[test]
fn stored_session_is_found() {
    let now = Instant::now();
    let mut sessions = Sessions::new(DEFAULT_MAX_SESSIONS);
    put(&mut sessions, "10.0.0.1:5000", "192.168.1.1:12345", now);
    assert_eq!(
        lookup(&mut sessions, "10.0.0.1:5000", now),
        Some(addr("192.168.1.1:12345"))
    );
}

#[test]
fn lookup_misses_on_an_empty_cache() {
    let mut sessions = Sessions::new(DEFAULT_MAX_SESSIONS);
    assert_eq!(lookup(&mut sessions, "10.0.0.1:5000", Instant::now()), None);
}

#[test]
fn expired_session_is_missing_and_released() {
    let now = Instant::now();
    let mut sessions = Sessions::new(DEFAULT_MAX_SESSIONS);
    put(&mut sessions, "10.0.0.1:5000", "192.168.1.1:12345", now);
    let later = now + Duration::from_millis(100);
    assert_eq!(lookup(&mut sessions, "10.0.0.1:5000", later), None);
    assert!(sessions.is_empty());
}

#[test]
fn lookup_refreshes_the_expiry() {
    let now = Instant::now();
    let mut sessions = Sessions::new(DEFAULT_MAX_SESSIONS);
    put(&mut sessions, "10.0.0.1:5000", "192.168.1.1:12345", now);
    assert!(
        lookup(
            &mut sessions,
            "10.0.0.1:5000",
            now + Duration::from_millis(30)
        )
        .is_some()
    );
    // 60 ms after the store: past the original expiry, inside the refreshed one.
    assert!(
        lookup(
            &mut sessions,
            "10.0.0.1:5000",
            now + Duration::from_millis(60)
        )
        .is_some()
    );
}

#[test]
fn store_refreshes_the_expiry_and_replaces_the_source() {
    let now = Instant::now();
    let mut sessions = Sessions::new(DEFAULT_MAX_SESSIONS);
    put(&mut sessions, "10.0.0.1:5000", "192.168.1.1:1", now);
    put(
        &mut sessions,
        "10.0.0.1:5000",
        "192.168.1.2:2",
        now + Duration::from_millis(40),
    );
    assert_eq!(
        lookup(
            &mut sessions,
            "10.0.0.1:5000",
            now + Duration::from_millis(80)
        ),
        Some(addr("192.168.1.2:2"))
    );
    assert_eq!(sessions.len(), 1);
}

#[test]
fn shortened_ttl_applies_to_sessions_stored_under_a_longer_one() {
    let now = Instant::now();
    let mut sessions = Sessions::new(DEFAULT_MAX_SESSIONS);
    sessions.store(addr("10.0.0.1:5000"), (addr("192.168.1.1:1"), ""), now);
    let later = now + Duration::from_millis(30);
    let short = Duration::from_millis(10);
    assert_eq!(
        sessions.lookup(addr("10.0.0.1:5000"), later, short, &mut String::new()),
        None
    );
}

#[test]
fn custom_capacity_caps_the_cache() {
    let now = Instant::now();
    let mut sessions = Sessions::new(5);
    for port in 0..10 {
        let key = SocketAddr::from(([10, 0, 0, 1], port));
        let source = SocketAddr::from(([1, 1, 1, 1], port));
        sessions.store(key, (source, ""), now);
    }
    assert_eq!(sessions.len(), 5);
}

#[test]
fn full_cache_evicts_the_least_recently_used_session() {
    let now = Instant::now();
    let mut sessions = Sessions::new(2);
    put(&mut sessions, "10.0.0.1:1", "1.1.1.1:1", now);
    put(&mut sessions, "10.0.0.2:2", "2.2.2.2:2", now);
    put(&mut sessions, "10.0.0.3:3", "3.3.3.3:3", now);
    assert_eq!(lookup(&mut sessions, "10.0.0.1:1", now), None);
    assert!(lookup(&mut sessions, "10.0.0.2:2", now).is_some());
    assert!(lookup(&mut sessions, "10.0.0.3:3", now).is_some());
}

#[test]
fn lookup_protects_a_session_from_eviction() {
    let now = Instant::now();
    let mut sessions = Sessions::new(2);
    put(&mut sessions, "10.0.0.1:1", "1.1.1.1:1", now);
    put(&mut sessions, "10.0.0.2:2", "2.2.2.2:2", now);
    assert!(lookup(&mut sessions, "10.0.0.1:1", now).is_some());
    put(&mut sessions, "10.0.0.3:3", "3.3.3.3:3", now);
    assert!(lookup(&mut sessions, "10.0.0.1:1", now).is_some());
    assert_eq!(lookup(&mut sessions, "10.0.0.2:2", now), None);
}

#[test]
fn released_slots_are_reused() {
    let now = Instant::now();
    let mut sessions = Sessions::new(1);
    for port in 0..100 {
        let key = SocketAddr::from(([10, 0, 0, 1], port));
        sessions.store(key, (addr("1.1.1.1:1"), ""), now);
    }
    assert_eq!((sessions.len(), sessions.nodes.len()), (1, 1));
}

#[test]
fn lookup_copies_the_tlv_hex() {
    let now = Instant::now();
    let mut sessions = Sessions::new(DEFAULT_MAX_SESSIONS);
    sessions.store(
        addr("10.0.0.1:5000"),
        (addr("192.168.1.1:1"), "ea0001ff"),
        now,
    );
    let mut tlv = String::from("stale");
    sessions.lookup(addr("10.0.0.1:5000"), now, TTL, &mut tlv);
    assert_eq!(tlv, "ea0001ff");
}

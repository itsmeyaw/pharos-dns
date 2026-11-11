use pharos_proto::{Message, Name, Rcode};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

#[test]
fn context_keeps_query_and_borrowed_metadata() {
    let wire = [0_u8; 12];
    let query = Message::parse(&wire).unwrap();
    assert_eq!(query.as_wire(), &wire);
    let domain: Name = ".".parse().unwrap();
    let mut buffer = Vec::with_capacity(512);
    let mut slots = [None; 2];
    let mut context = Context {
        query,
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut buffer,
        max_response_size: 512,
    };
    assert!(context.metadata.insert("whoami/client", "127.0.0.1"));
    assert_eq!(context.metadata.get("whoami/client"), Some("127.0.0.1"));
    assert_eq!(
        Outcome::Unanswered(Rcode::REFUSED),
        Outcome::Unanswered(Rcode::REFUSED)
    );
}

#[test]
fn metadata_can_store_short_values_from_a_plugin() {
    let mut slots = [None; 2];
    let mut metadata = Metadata::new(&mut slots);
    let value = String::from("127.0.0.1:53");
    assert!(metadata.insert_inline("forward/upstream", &value));
    drop(value);
    assert_eq!(metadata.get("forward/upstream"), Some("127.0.0.1:53"));
    assert!(metadata.insert_inline("forward/upstream", "[::1]:53"));
    assert_eq!(metadata.get("forward/upstream"), Some("[::1]:53"));
    assert!(!metadata.insert_inline("forward/upstream", &"x".repeat(65)));
}

#[test]
fn metadata_replacements_follow_last_write_across_storage_types() {
    let mut slots = [None; 2];
    let mut metadata = Metadata::new(&mut slots);
    assert!(metadata.insert_copied("test/key", "copied"));
    assert!(metadata.insert("test/key", "borrowed"));
    assert_eq!(metadata.get("test/key"), Some("borrowed"));
    assert!(metadata.insert_inline("test/key", "inline"));
    assert_eq!(metadata.get("test/key"), Some("inline"));
    assert!(metadata.insert_copied("test/key", "new"));
    assert_eq!(metadata.get("test/key"), Some("new"));
    for _ in 0..1000 {
        assert!(metadata.insert_copied("test/key", "again"));
    }
    assert_eq!(metadata.get("test/key"), Some("again"));
}

// Derived from CoreDNS v1.15.0 plugin/metadata/metadata_test.go TestMetadataServeDNS.
#[test]
fn metadata_retains_values_from_multiple_providers() {
    let mut slots = [None; 3];
    let mut metadata = Metadata::new(&mut slots);
    for (key, value) in [
        ("test/key1", "testvalue1"),
        ("test/key2", "two"),
        ("test/key3", "testvalue3"),
    ] {
        assert!(metadata.insert(key, value));
    }
    assert_eq!(metadata.get("test/key1"), Some("testvalue1"));
    assert_eq!(metadata.get("test/key2"), Some("two"));
    assert_eq!(metadata.get("test/key3"), Some("testvalue3"));
    assert_eq!(metadata.get("test/missing"), None);
}

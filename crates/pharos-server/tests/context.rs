use pharos_proto::{Message, Name, Rcode};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

struct InspectChild;
impl pharos_server::Next for InspectChild {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        assert_eq!(cx.query.id(), 2);
        assert_eq!(cx.metadata.get("test/before"), Some("old"));
        assert!(cx.metadata.insert("test/after", "new"));
        cx.response.extend_from_slice(&[1, 2, 3]);
        Outcome::Response
    }
}

#[tokio::test]
async fn nested_query_preserves_metadata_and_response() {
    let wire = [0_u8; 12];
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 2];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert!(cx.metadata.insert("test/before", "old"));
    let mut child = wire;
    child[1] = 2;
    assert_eq!(
        cx.run_with_query(&child, InspectChild).await,
        Outcome::Response
    );
    assert_eq!(cx.query.id(), 0);
    assert_eq!(cx.metadata.get("test/after"), Some("new"));
    assert_eq!(cx.response, &[1, 2, 3]);
}

struct PendingChild;
impl pharos_server::Next for PendingChild {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        cx.metadata.insert("test/after", "new");
        std::future::pending().await
    }
}

#[test]
fn cancelled_query_view_restores_parent_and_keeps_metadata() {
    use std::{
        future::Future,
        task::{Context as TaskContext, Poll, Waker},
    };
    let wire = [0_u8; 12];
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::new();
    let mut slots = [None; 2];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let query = cx.query.with_flags(0x0100);
    {
        let future = cx.run_with_query_view(query, PendingChild);
        let mut future = std::pin::pin!(future);
        assert_eq!(
            future
                .as_mut()
                .poll(&mut TaskContext::from_waker(Waker::noop())),
            Poll::Pending
        );
    }
    assert_eq!(cx.query.flags(), 0x0100);
    assert_eq!(cx.metadata.get("test/after"), Some("new"));
}

struct MutateChild;
impl pharos_server::Next for MutateChild {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        cx.query = cx.query.with_flags(0x0100);
        if cx.query.question_count() != 0 {
            let name: Name = "changed.example.".parse().unwrap();
            cx.query = cx
                .query
                .with_question_name(pharos_proto::NameRef::parse(name.as_wire(), 0).unwrap())
                .with_question_type(pharos_proto::Type::AAAA)
                .with_question_class(pharos_proto::Class::CH);
        }
        Outcome::Drop
    }
}

#[tokio::test]
async fn nested_query_propagates_downstream_header_changes() {
    let wire = b"\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\x01\0\x01";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(cx.run_with_query(wire, MutateChild).await, Outcome::Drop);
    assert_eq!(cx.query.flags(), 0x0100);
    let q = cx.query.questions().next().unwrap();
    assert_eq!(q.name.to_string(), "changed.example.");
    assert_eq!(q.qtype, pharos_proto::Type::AAAA);
    assert_eq!(q.qclass, pharos_proto::Class::CH);
}

#[test]
fn cancelled_nested_query_restores_metadata() {
    use std::{
        future::Future,
        task::{Context as TaskContext, Poll, Waker},
    };
    let wire = [0_u8; 12];
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 2];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    cx.metadata.insert("test/before", "old");
    {
        let future = cx.run_with_query(&wire, PendingChild);
        let mut future = std::pin::pin!(future);
        assert_eq!(
            future
                .as_mut()
                .poll(&mut TaskContext::from_waker(Waker::noop())),
            Poll::Pending
        );
    }
    assert_eq!(cx.metadata.get("test/before"), Some("old"));
    assert_eq!(cx.metadata.get("test/after"), Some("new"));
}

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

use pharos_proto::{Message, Name, Rcode};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

#[test]
fn context_keeps_query_and_borrowed_metadata() {
    let wire = [0_u8; 12];
    let query = Message::parse(&wire).unwrap();
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

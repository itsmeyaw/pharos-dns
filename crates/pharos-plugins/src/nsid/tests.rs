use super::*;
use pharos_proto::Name;
use pharos_server::{Metadata, Protocol, Transport};

struct Return(Outcome);

impl Next for Return {
    async fn run(self, _cx: &mut Context<'_, '_>) -> Outcome {
        self.0
    }
}

#[tokio::test]
async fn strips_unsolicited_nsid_and_preserves_other_options() {
    let query = [
        0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut response = Vec::with_capacity(512);
    response.extend_from_slice(&[
        0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 10, 0, 3, 0, 1, 1,
        0, 12, 0, 1, 9,
    ]);
    let domain: Name = ".".parse().unwrap();
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:53".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let plugin = Nsid {
        data: b"NSID".to_vec(),
    };
    assert_eq!(
        plugin.serve(&mut cx, Return(Outcome::Response)).await,
        Outcome::Response
    );
    let message = Message::parse(&response).unwrap();
    assert_eq!(
        message.opt().unwrap().options().iter().collect::<Vec<_>>(),
        [EdnsOption::Padding(&[9])]
    );
}

#[tokio::test]
async fn preserves_nonresponse_outcomes() {
    let query = [
        0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0,
    ];
    let domain: Name = ".".parse().unwrap();
    let plugin = Nsid {
        data: b"NSID".to_vec(),
    };
    for outcome in [
        Outcome::Drop,
        Outcome::Unanswered(pharos_proto::Rcode::REFUSED),
        Outcome::Error(Error::NoNextPlugin),
        Outcome::Stream(pharos_server::Stream::new(|_| Ok(false))),
    ] {
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:53".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            plugin.serve(&mut cx, Return(outcome.clone())).await,
            outcome
        );
        assert!(response.is_empty());
    }
}

#[test]
fn replaces_all_existing_nsid_options_and_preserves_others() {
    let query = [
        0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0,
    ];
    let mut response = Vec::with_capacity(512);
    response.extend_from_slice(&[
        0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 15, 0, 3, 0, 1, 1,
        0, 12, 0, 1, 9, 0, 3, 0, 1, 2,
    ]);
    let domain: Name = ".".parse().unwrap();
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:53".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    update_nsid(&mut cx, Some(b"NSID")).unwrap();
    let message = Message::parse(&response).unwrap();
    assert_eq!(
        message.opt().unwrap().options().iter().collect::<Vec<_>>(),
        [
            EdnsOption::Nsid(b"NSID"),
            EdnsOption::Padding(&[9]),
            EdnsOption::Nsid(b"NSID")
        ]
    );
}

#[test]
fn rejects_oversized_identifier_without_mutating_response() {
    let query = [
        0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0,
    ];
    let mut response = Vec::with_capacity(65535);
    response.extend_from_slice(&[0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let original = response.clone();
    let domain: Name = ".".parse().unwrap();
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:53".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        update_nsid(&mut cx, Some(&vec![b'x'; 65535])),
        Err(Error::ResponseBufferTooSmall)
    );
    assert_eq!(response, original);
}

#[test]
fn truncates_records_after_opt_before_replacing_nsid() {
    let query = [
        0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 4, 0, 3, 0, 0,
    ];
    let mut response = Vec::with_capacity(512);
    response.extend_from_slice(&[
        0, 1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1,
        0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1,
    ]);
    let domain: Name = ".".parse().unwrap();
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&query).unwrap(),
        client: "127.0.0.1:53".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    update_nsid(&mut cx, Some(b"NSID")).unwrap();
    let message = Message::parse(&response).unwrap();
    assert!(message.tc());
    assert_eq!(message.additional_count(), 1);
    assert_eq!(
        message.opt().unwrap().options().iter().next(),
        Some(EdnsOption::Nsid(b"NSID"))
    );
}

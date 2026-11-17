use super::*;
use pharos_server::{Metadata, Transport};
use std::sync::{Arc, Mutex};

#[test]
fn ixfr_serial_order_uses_rfc1982_half_space() {
    use crate::serial::serial_at_least;

    assert!(serial_at_least(7, 7));
    assert!(serial_at_least(0, u32::MAX));
    assert!(!serial_at_least(u32::MAX, 0));
    assert!(!serial_at_least(1 << 31, 0));
}

#[test]
fn transfer_cidr_matches_ipv4_and_ipv6_prefixes() {
    use super::in_network;

    assert!(in_network(
        "192.0.2.42".parse().unwrap(),
        "192.0.2.0".parse().unwrap(),
        24
    ));
    assert!(!in_network(
        "192.0.3.42".parse().unwrap(),
        "192.0.2.0".parse().unwrap(),
        24
    ));
    assert!(in_network(
        "2001:db8::42".parse().unwrap(),
        "2001:db8::".parse().unwrap(),
        32
    ));
    assert!(!in_network(
        "2001:db9::42".parse().unwrap(),
        "2001:db8::".parse().unwrap(),
        32
    ));
    assert!(in_network(
        "192.0.2.42".parse().unwrap(),
        "203.0.113.0".parse().unwrap(),
        0
    ));
    assert!(super::destination("192.0.2.0/33").is_none());
}

#[test]
fn transfer_matches_equivalent_client_addresses() {
    // RFC 5952 §4: Accept all legitimate IPv6 text representations.
    for (configured, client, allowed) in [
        ("2001:DB8:0::1", "[2001:db8::1]:1234", true),
        ("::ffff:192.0.2.1", "192.0.2.1:1234", true),
        ("192.0.2.1", "[::ffff:192.0.2.1]:1234", true),
        ("2001:db8::2", "[2001:db8::1]:1234", false),
        ("192.0.2.0/24", "192.0.2.1:1234", true),
    ] {
        let domain: Name = ".".parse().unwrap();
        let wire = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 252, 0, 1];
        let mut response = Vec::new();
        let mut slots = [];
        let cx = Context {
            query: pharos_proto::Message::parse(&wire).unwrap(),
            client: client.parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Tcp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let transfer = Transfer {
            zones: vec![TransferZone {
                domains: vec![domain.clone()],
                destinations: vec![destination(configured).unwrap()],
                source: None,
            }],
        };
        let provider = TestProvider {
            id: 1,
            answer: Answer::Stream,
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        assert_eq!(
            matches!(
                transfer.process(&cx, Some(&provider)),
                Some(Outcome::Stream(_))
            ),
            allowed,
            "{configured} vs {client}"
        );
    }
}

#[test]
fn transfer_ipv6_prefix_matches_ipv4_client() {
    // RFC 4291 §2.5.5.2: IPv4-mapped IPv6 addresses identify IPv4 peers.
    let domain: Name = ".".parse().unwrap();
    let wire = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 252, 0, 1];
    let mut response = Vec::new();
    let mut slots = [];
    let cx = Context {
        query: pharos_proto::Message::parse(&wire).unwrap(),
        client: "192.0.2.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Tcp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let transfer = Transfer {
        zones: vec![TransferZone {
            domains: vec![domain.clone()],
            destinations: vec![destination("::ffff:192.0.2.0/120").unwrap()],
            source: None,
        }],
    };
    let provider = TestProvider {
        id: 1,
        answer: Answer::Stream,
        calls: Arc::new(Mutex::new(Vec::new())),
    };
    assert!(matches!(
        transfer.process(&cx, Some(&provider)),
        Some(Outcome::Stream(_))
    ));
}

#[test]
fn transfer_rejects_scoped_destinations_at_setup() {
    // RFC 4007 §11.2: A zone identifier carries scope and cannot be ignored.
    for address in ["fe80::1%eth0", "[fe80::1%1]:53"] {
        let corefile = format!(". {{\n transfer {{\n to {address}\n }}\n}}");
        let blocks = pharos_corefile::parse("Corefile", &corefile).unwrap();
        let Err(error) = pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives())
        else {
            panic!("scoped destinations must be rejected");
        };
        assert!(error.to_string().contains("scoped transfer destination"));
    }
    assert!(destination("example.org:53").is_none());
}

#[tokio::test]
async fn notify_reports_cidr_destinations_as_unsupported() {
    let zone: Name = "example.org.".parse().unwrap();
    let transfer = Transfer {
        zones: vec![TransferZone {
            domains: vec![zone.clone()],
            destinations: vec![Destination::Network {
                address: "192.0.2.0".parse().unwrap(),
                prefix: 24,
            }],
            source: None,
        }],
    };

    let error = transfer.notify(&zone).await.unwrap_err();
    assert!(error.to_string().contains("CIDR"));
}

#[derive(Clone, Copy, Debug)]
enum Answer {
    None,
    Stream,
    Error,
}

#[derive(Debug)]
pub(crate) struct TestProvider {
    id: u8,
    answer: Answer,
    calls: Arc<Mutex<Vec<u8>>>,
}

impl Transferer for TestProvider {
    fn transfer(
        &self,
        _: TransferRequest<'_>,
    ) -> Result<Option<pharos_server::Stream>, pharos_server::Error> {
        self.calls.lock().unwrap().push(self.id);
        match self.answer {
            Answer::None => Ok(None),
            Answer::Stream => Ok(Some(pharos_server::Stream::new(|_| Ok(false)))),
            Answer::Error => Err(pharos_server::Error::InvalidQuery),
        }
    }
}

// CoreDNS transfer.go selects the first authoritative Transferer in Plugin order.
#[tokio::test]
async fn generated_chain_tries_transferers_in_order() {
    for (first, second, expected_calls, expected) in [
        (Answer::Stream, Answer::Stream, &[1][..], 0),
        (Answer::None, Answer::Stream, &[1, 2][..], 0),
        (Answer::None, Answer::None, &[1, 2][..], 1),
        (Answer::Error, Answer::Stream, &[1][..], 2),
    ] {
        let blocks = pharos_corefile::parse("Corefile", ". {\n transfer {\n to *\n }\n}").unwrap();
        let mut chain = pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives())
            .unwrap()
            .remove(0)
            .config;
        let calls = Arc::new(Mutex::new(Vec::new()));
        chain.transfer_test_first = Some(TestProvider {
            id: 1,
            answer: first,
            calls: calls.clone(),
        });
        chain.transfer_test_second = Some(TestProvider {
            id: 2,
            answer: second,
            calls: calls.clone(),
        });
        // RFC 5936 §2.1.2: The AXFR query names the zone and carries QTYPE AXFR and class.
        let wire = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 252, 0, 1];
        let domain: Name = ".".parse().unwrap();
        let mut response = Vec::new();
        let mut slots = [];
        let mut cx = Context {
            query: pharos_proto::Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Tcp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let result = chain.serve(&mut cx).await;
        match expected {
            0 => assert!(matches!(result, Outcome::Stream(_))),
            1 => assert_eq!(result, Outcome::Error(pharos_server::Error::NoNextPlugin)),
            _ => assert_eq!(result, Outcome::Error(pharos_server::Error::InvalidQuery)),
        }
        assert_eq!(&*calls.lock().unwrap(), expected_calls);
    }
}

#[test]
fn ixfr_validates_authority_soa_owner_and_class() {
    use pharos_proto::{Message, MessageBuilder, Section};

    // RFC 1995 §3: The Authority SOA identifies the Zone and class being transferred.
    let zone: Name = "example.org.".parse().unwrap();
    // RFC 1035 §3.3.13: SOA RDATA has two names followed by five 32-bit fields.
    let soa_rdata = [
        0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5,
    ];
    for (owner, class, accepted) in [
        ("other.example.", Class::IN, false),
        ("example.org.", Class::CH, false),
        ("example.org.", Class::IN, true),
    ] {
        let owner: Name = owner.parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 7, 0).unwrap();
        builder
            .question(
                NameRef::parse(zone.as_wire(), 0).unwrap(),
                Type::IXFR,
                Class::IN,
            )
            .unwrap();
        builder
            .record(
                Section::Authority,
                NameRef::parse(owner.as_wire(), 0).unwrap(),
                Type::SOA,
                class,
                0,
                &soa_rdata,
            )
            .unwrap();
        let _ = builder.finish();

        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "192.0.2.1:1234".parse().unwrap(),
            local: "192.0.2.53:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Tcp,
            domain: &zone,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let transfer = Transfer {
            zones: vec![TransferZone {
                domains: vec![zone.clone()],
                destinations: vec![Destination::All],
                source: None,
            }],
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let provider = TestProvider {
            id: 1,
            answer: Answer::Stream,
            calls: Arc::clone(&calls),
        };

        let outcome = transfer.process(&cx, Some(&provider));
        if accepted {
            assert!(matches!(outcome, Some(Outcome::Stream(_))));
            assert_eq!(&*calls.lock().unwrap(), &[1]);
        } else {
            assert_eq!(outcome, Some(Outcome::Unanswered(Rcode::SERVFAIL)));
            assert!(calls.lock().unwrap().is_empty());
        }
    }
}

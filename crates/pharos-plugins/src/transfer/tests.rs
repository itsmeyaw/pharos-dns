use super::*;
use pharos_server::{Metadata, Transport};
use std::sync::{Arc, Mutex};

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

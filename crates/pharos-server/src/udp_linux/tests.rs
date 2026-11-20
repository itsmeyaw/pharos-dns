use super::*;
use crate::{Action, Protocol};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

struct Echo;

impl Handler for Echo {
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        response.extend_from_slice(query);
        Action::Respond
    }
}

#[tokio::test]
async fn answers_first_datagram_after_idle_start() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let (shutdown, receiver) = watch::channel(false);
    let _worker = spawn(server, Arc::new(Echo), receiver);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"ping", address).await.unwrap();
    let mut buffer = [0; 16];
    let length = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..length], b"ping");
    drop(shutdown);
}

struct BatchProbe {
    started: Arc<AtomicUsize>,
    cancelled: watch::Sender<bool>,
}
impl Handler for BatchProbe {
    fn parallel_query(&self, query: &[u8], _: SocketAddr) -> Option<watch::Receiver<bool>> {
        (query == [1]).then(|| self.cancelled.subscribe())
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        // recvmmsg(2): a batch can contain both ordinary datagrams and a probe.
        if query == [1] {
            response.extend_from_slice(query);
            return Action::Respond;
        }
        self.started.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }
}

#[tokio::test(flavor = "current_thread")]
async fn full_worker_handles_probe_behind_ordinary_datagrams_in_batch() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let started = Arc::new(AtomicUsize::new(0));
    let (shutdown, receiver) = watch::channel(false);
    let worker = spawn(
        server,
        Arc::new(BatchProbe {
            started: started.clone(),
            cancelled: watch::channel(false).0,
        }),
        receiver,
    );
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_nonblocking(true).unwrap();
    for count in 1..=crate::udp::MAX_IN_FLIGHT {
        client.send_to(&[0], address).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while started.load(Ordering::SeqCst) < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    for index in 0..BATCH {
        client
            .send_to(&[u8::from(index == BATCH - 1)], address)
            .unwrap();
    }
    let client = UdpSocket::from_std(client).unwrap();
    let mut response = [0; 8];
    let (length, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response[..length], &[1]);
    shutdown.send_replace(true);
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

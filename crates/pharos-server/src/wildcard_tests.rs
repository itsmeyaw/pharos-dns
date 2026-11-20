use super::{
    Action, Handler, Listener, Protocol, bind_ipv6_dual, canonical_peer, optional_ipv6, udp,
};
use std::{
    io,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
};

#[test]
fn canonical_peer_preserves_native_ipv6_scope() {
    let scoped = SocketAddr::V6(SocketAddrV6::new(
        "fe80::1".parse::<Ipv6Addr>().unwrap(),
        53,
        7,
        3,
    ));
    assert_eq!(canonical_peer(scoped), scoped);
    assert_eq!(
        canonical_peer("[::ffff:127.0.0.1]:53".parse().unwrap()),
        "127.0.0.1:53".parse().unwrap()
    );
}

#[test]
fn unavailable_ipv6_falls_back_but_other_errors_remain_errors() {
    assert_eq!(
        optional_ipv6::<()>(Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT))).unwrap(),
        None
    );
    assert_eq!(
        optional_ipv6::<()>(Err(io::Error::from(io::ErrorKind::AddrNotAvailable))).unwrap(),
        None
    );
    assert_eq!(optional_ipv6(Ok(7)).unwrap(), Some(7));
    assert!(
        optional_ipv6::<()>(Err(io::Error::new(io::ErrorKind::AddrInUse, "occupied"))).is_err()
    );
}

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

#[derive(Debug)]
struct WorkerCount(usize);
impl Handler for WorkerCount {
    fn udp_workers(&self) -> usize {
        self.0
    }
    async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, _: &mut Vec<u8>) -> Action {
        Action::Drop
    }
}

#[tokio::test]
async fn listener_binds_the_requested_number_of_udp_sockets() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static BINDS: AtomicUsize = AtomicUsize::new(0);
    fn counting_bind(address: SocketAddr) -> io::Result<std::net::UdpSocket> {
        BINDS.fetch_add(1, Ordering::SeqCst);
        udp::bind(address)
    }
    let listener = Listener::bind_with_ipv6(
        "127.0.0.1:0".parse().unwrap(),
        Echo,
        3,
        bind_ipv6_dual,
        counting_bind,
    )
    .await
    .unwrap();
    assert_eq!(BINDS.load(Ordering::SeqCst), 3);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn listener_rejects_zero_udp_workers() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static BINDS: AtomicUsize = AtomicUsize::new(0);
    fn counting_bind(address: SocketAddr) -> io::Result<std::net::UdpSocket> {
        BINDS.fetch_add(1, Ordering::SeqCst);
        udp::bind(address)
    }
    let result = Listener::bind_with_ipv6(
        "127.0.0.1:0".parse().unwrap(),
        Echo,
        0,
        bind_ipv6_dual,
        counting_bind,
    )
    .await;
    let error = match result {
        Err(error) => error,
        Ok(listener) => {
            listener.shutdown().await.unwrap();
            panic!("zero UDP workers must be rejected");
        }
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(BINDS.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn listener_registry_rejects_zero_udp_workers_for_existing_listener() {
    let key = super::ListenerKey {
        transport: super::Transport::Dns,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let mut registry = super::ListenerRegistry::default();
    registry
        .apply(std::collections::HashMap::from([(key, WorkerCount(1))]))
        .await
        .unwrap();
    let address = registry.get(&key).unwrap().local_addr();

    let error = registry
        .apply(std::collections::HashMap::from([(key, WorkerCount(0))]))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(registry.get(&key).unwrap().local_addr(), address);
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn reload_replaces_only_changed_udp_workers_and_keeps_tcp() {
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct Counted(usize, u8);
    impl Handler for Counted {
        fn udp_workers(&self) -> usize {
            self.0
        }
        async fn handle(
            &self,
            _: &[u8],
            _: SocketAddr,
            _: Protocol,
            response: &mut Vec<u8>,
        ) -> Action {
            response.push(self.1);
            Action::Respond
        }
    }
    let key = super::ListenerKey {
        transport: super::Transport::Dns,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let mut registry = super::ListenerRegistry::default();
    registry
        .apply(HashMap::from([(key, Counted(2, 1))]))
        .await
        .unwrap();
    let listener = registry.get(&key).unwrap();
    let address = listener.local_addr();
    let ids: Vec<_> = listener
        .udp_tasks
        .iter()
        .map(tokio::task::JoinHandle::id)
        .collect();
    assert_eq!(ids.len(), 2);
    let mut tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    registry
        .apply(HashMap::from([(key, Counted(2, 2))]))
        .await
        .unwrap();
    assert_eq!(
        registry
            .get(&key)
            .unwrap()
            .udp_tasks
            .iter()
            .map(tokio::task::JoinHandle::id)
            .collect::<Vec<_>>(),
        ids
    );
    registry
        .apply(HashMap::from([(key, Counted(3, 3))]))
        .await
        .unwrap();
    let listener = registry.get(&key).unwrap();
    assert_eq!(listener.local_addr(), address);
    let new_ids: Vec<_> = listener
        .udp_tasks
        .iter()
        .map(tokio::task::JoinHandle::id)
        .collect();
    assert_eq!(new_ids.len(), 3);
    assert!(new_ids.iter().all(|id| !ids.contains(id)));
    tcp.write_all(&[0, 1, 42]).await.unwrap();
    let mut response = [0; 3];
    tcp.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0, 1, 3]);
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(b"q", address).await.unwrap();
    let mut byte = [0];
    tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(byte, [3]);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while registry
            .get(&key)
            .unwrap()
            .tasks
            .iter()
            .skip(1)
            .any(|task| !task.is_finished())
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    registry
        .apply(HashMap::from([(key, Counted(1, 4))]))
        .await
        .unwrap();
    let listener = registry.get(&key).unwrap();
    assert_eq!(listener.udp_tasks.len(), 1);
    assert_eq!(
        listener.tasks.len(),
        4,
        "completed workers should be reaped"
    );
    drop(tcp);
    registry.shutdown().await.unwrap();
}

async fn assert_ipv4_fallback(listener: Listener) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    assert!(listener.local_addr().is_ipv4());
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(b"query", ("127.0.0.1", listener.local_addr().port()))
        .await
        .unwrap();
    let mut response = [0; 16];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv_from(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&response[..len], b"query");
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", listener.local_addr().port()))
        .await
        .unwrap();
    tcp.write_u16(5).await.unwrap();
    tcp.write_all(b"query").await.unwrap();
    let len = tokio::time::timeout(std::time::Duration::from_secs(2), tcp.read_u16())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, 5);
    let mut response = [0; 5];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tcp.read_exact(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&response, b"query");
    drop(tcp);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn wildcard_falls_back_to_ipv4_when_ipv6_tcp_is_unavailable() {
    fn unavailable(_: SocketAddr) -> io::Result<tokio::net::TcpListener> {
        Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT))
    }
    let listener =
        Listener::bind_with_ipv6("[::]:0".parse().unwrap(), Echo, 1, unavailable, udp::bind)
            .await
            .unwrap();
    assert_ipv4_fallback(listener).await;
}

#[tokio::test]
async fn wildcard_falls_back_to_ipv4_when_ipv6_udp_is_unavailable() {
    use std::sync::atomic::{AtomicBool, Ordering};

    static TRIED_IPV6_UDP: AtomicBool = AtomicBool::new(false);
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        return;
    }
    fn unavailable(address: SocketAddr) -> io::Result<std::net::UdpSocket> {
        if address.is_ipv6() {
            TRIED_IPV6_UDP.store(true, Ordering::Relaxed);
            Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
        } else {
            udp::bind(address)
        }
    }
    let listener = Listener::bind_with_ipv6(
        "[::]:0".parse().unwrap(),
        Echo,
        1,
        bind_ipv6_dual,
        unavailable,
    )
    .await
    .unwrap();
    assert!(TRIED_IPV6_UDP.load(Ordering::Relaxed));
    assert_ipv4_fallback(listener).await;
}

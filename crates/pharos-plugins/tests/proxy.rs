use pharos_plugins::proxy::{Options, Proxy, Transport};
use tokio::net::UdpSocket;

const QUERY: &[u8] = &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];

#[tokio::test]
async fn exchanges_a_query_with_a_udp_upstream() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = server.recv_from(&mut wire).await.unwrap();
        wire[2] |= 0x80;
        server.send_to(&wire[..len], peer).await.unwrap();
    });
    let proxy = Proxy::new(address);
    let mut response = [0; 512];
    let result = proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    assert_eq!(result.len, QUERY.len());
    assert_eq!(&response[..2], &QUERY[..2]);
    assert_ne!(response[2] & 0x80, 0);
    task.await.unwrap();
}

#[tokio::test]
async fn exchanges_a_query_with_a_tcp_upstream() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        let mut wire = [0; 512];
        stream.read_exact(&mut wire[..len]).await.unwrap();
        wire[2] |= 0x80;
        stream.write_u16(len as u16).await.unwrap();
        stream.write_all(&wire[..len]).await.unwrap();
    });
    let proxy = Proxy::new(address);
    let mut response = [0; 512];
    let result = proxy
        .exchange(QUERY, &mut response, Transport::Tcp, Options::default())
        .await
        .unwrap();
    assert_eq!(result.transport, Transport::Tcp);
    assert_eq!(&response[..2], &QUERY[..2]);
    task.await.unwrap();
}

#[tokio::test]
async fn reuses_udp_connection_for_sequential_queries() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let mut peers = Vec::new();
        for _ in 0..2 {
            let (len, peer) = server.recv_from(&mut wire).await.unwrap();
            peers.push(peer);
            wire[2] |= 0x80;
            server.send_to(&wire[..len], peer).await.unwrap();
        }
        peers
    });
    let proxy = Proxy::new(address);
    let mut response = [0; 512];
    for _ in 0..2 {
        proxy
            .exchange(QUERY, &mut response, Transport::Udp, Options::default())
            .await
            .unwrap();
    }
    let peers = task.await.unwrap();
    assert_eq!(peers[0], peers[1]);
}

#[tokio::test]
async fn prefer_udp_retries_truncated_response_over_tcp() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(address).await.unwrap();
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = udp.recv_from(&mut wire).await.unwrap();
        wire[2] |= 0x82;
        udp.send_to(&wire[..len], peer).await.unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        stream.read_exact(&mut wire[..len]).await.unwrap();
        wire[2] |= 0x80;
        stream.write_u16(len as u16).await.unwrap();
        stream.write_all(&wire[..len]).await.unwrap();
    });
    let proxy = Proxy::new(address);
    let mut response = [0; 512];
    let result = proxy
        .exchange(
            QUERY,
            &mut response,
            Transport::Tcp,
            Options {
                prefer_udp: true,
                ..Options::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(result.transport, Transport::Tcp);
    assert_eq!(response[2] & 0x02, 0);
    task.await.unwrap();
}

#[tokio::test]
async fn rejects_a_response_with_the_wrong_question() {
    use pharos_plugins::proxy::Error;
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = Proxy::new(server.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = server.recv_from(&mut wire).await.unwrap();
        wire[2] |= 0x80;
        wire[len - 1] = 3;
        server.send_to(&wire[..len], peer).await.unwrap();
    });
    let mut response = [0; 512];
    assert!(matches!(
        proxy
            .exchange(QUERY, &mut response, Transport::Udp, Options::default())
            .await,
        Err(Error::Mismatch)
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn expired_connections_are_not_reused() {
    use std::time::Duration;
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut proxy = Proxy::new(server.local_addr().unwrap());
    proxy.set_expire(Duration::ZERO);
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let mut peers = Vec::new();
        for _ in 0..2 {
            let (len, peer) = server.recv_from(&mut wire).await.unwrap();
            peers.push(peer);
            wire[2] |= 0x80;
            server.send_to(&wire[..len], peer).await.unwrap();
        }
        peers
    });
    let mut response = [0; 512];
    for _ in 0..2 {
        proxy
            .exchange(QUERY, &mut response, Transport::Udp, Options::default())
            .await
            .unwrap();
    }
    let peers = task.await.unwrap();
    assert_ne!(peers[0], peers[1]);
}

#[tokio::test]
async fn records_exchange_metrics_in_registry() {
    use pharos_server::metrics::Registry;
    let registry = Registry::new("v", "r", "rust");
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut proxy = Proxy::new(server.local_addr().unwrap());
    proxy.set_metrics(&registry, "forward");
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        for _ in 0..2 {
            let (len, peer) = server.recv_from(&mut wire).await.unwrap();
            wire[2] |= 0x80;
            server.send_to(&wire[..len], peer).await.unwrap();
        }
    });
    let mut response = [0; 512];
    for _ in 0..2 {
        proxy
            .exchange(QUERY, &mut response, Transport::Udp, Options::default())
            .await
            .unwrap();
    }
    task.await.unwrap();
    let mut metrics = String::new();
    registry.encode(&mut metrics);
    assert!(metrics.contains("pharos_proxy_conn_cache_hits_total"));
    assert!(metrics.contains("pharos_proxy_conn_cache_misses_total"));
    assert!(metrics.contains("pharos_proxy_request_duration_seconds_count"));
}

#[tokio::test]
async fn ignores_out_of_order_udp_response_ids() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = Proxy::new(server.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = server.recv_from(&mut wire).await.unwrap();
        wire[2] |= 0x80;
        wire[0] ^= 1;
        server.send_to(&wire[..len], peer).await.unwrap();
        wire[0] ^= 1;
        server.send_to(&wire[..len], peer).await.unwrap();
    });
    let mut response = [0; 512];
    proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    assert_eq!(&response[..2], &QUERY[..2]);
    task.await.unwrap();
}

#[tokio::test]
async fn read_timeout_is_configurable() {
    use pharos_plugins::proxy::Error;
    use std::{io, time::Duration};
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut proxy = Proxy::new(server.local_addr().unwrap());
    proxy.set_read_timeout(Duration::from_millis(20));
    let mut response = [0; 512];
    let error = proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Io(err) if err.kind() == io::ErrorKind::TimedOut));
}

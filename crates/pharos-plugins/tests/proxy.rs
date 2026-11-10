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

#[tokio::test]
async fn exchange_error_starts_health_check() {
    use std::time::Duration;
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut proxy = Proxy::new(server.local_addr().unwrap());
    proxy.set_read_timeout(Duration::from_millis(20));
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let _query = server.recv_from(&mut wire).await.unwrap();
        let (len, peer) = tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut wire))
            .await
            .unwrap()
            .unwrap();
        let check = pharos_proto::Message::parse(&wire[..len]).unwrap();
        assert!(check.rd());
        assert_eq!(
            check.questions().next().unwrap().qtype,
            pharos_proto::Type::NS
        );
        wire[2] |= 0x80;
        server.send_to(&wire[..len], peer).await.unwrap();
    });
    let mut response = [0; 512];
    assert!(
        proxy
            .exchange(QUERY, &mut response, Transport::Udp, Options::default())
            .await
            .is_err()
    );
    task.await.unwrap();
}

#[tokio::test]
async fn signed_query_preserves_its_id_on_the_wire() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = Proxy::new(server.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = server.recv_from(&mut wire).await.unwrap();
        assert_eq!(&wire[..2], &[0x12, 0x34]);
        wire[2] |= 0x80;
        server.send_to(&wire[..len], peer).await.unwrap();
    });
    let mut query = QUERY.to_vec();
    query[11] = 1;
    query.extend_from_slice(&[0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 0]);
    let mut response = [0; 512];
    proxy
        .exchange(&query, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn force_tcp_takes_precedence_in_protocol_selection() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    for (client, force_tcp, prefer_udp, expected) in [
        (Transport::Udp, false, false, Transport::Udp),
        (Transport::Tcp, false, false, Transport::Tcp),
        (Transport::Tcp, false, true, Transport::Udp),
        (Transport::Udp, true, false, Transport::Tcp),
        (Transport::Udp, true, true, Transport::Tcp),
        (Transport::Tcp, true, true, Transport::Tcp),
    ] {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(address).await.unwrap();
        let upstream = tokio::spawn(async move {
            let mut wire = [0; 512];
            if expected == Transport::Udp {
                let (len, peer) = udp.recv_from(&mut wire).await.unwrap();
                wire[2] |= 0x80;
                udp.send_to(&wire[..len], peer).await.unwrap();
            } else {
                let (mut stream, _) = tcp.accept().await.unwrap();
                let len = usize::from(stream.read_u16().await.unwrap());
                stream.read_exact(&mut wire[..len]).await.unwrap();
                wire[2] |= 0x80;
                stream.write_u16(len as u16).await.unwrap();
                stream.write_all(&wire[..len]).await.unwrap();
            }
        });
        let proxy = Proxy::new(address);
        let mut response = [0; 512];
        let result = proxy
            .exchange(
                QUERY,
                &mut response,
                client,
                Options {
                    force_tcp,
                    prefer_udp,
                },
            )
            .await
            .unwrap();
        assert_eq!(result.transport, expected);
        upstream.await.unwrap();
    }
}

#[tokio::test]
async fn ignores_short_udp_responses_before_valid_response() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = Proxy::new(server.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = server.recv_from(&mut wire).await.unwrap();
        server.send_to(&wire[..2], peer).await.unwrap();
        wire[2] |= 0x80;
        server.send_to(&wire[..len], peer).await.unwrap();
    });
    let mut response = [0; 512];
    assert!(
        proxy
            .exchange(QUERY, &mut response, Transport::Udp, Options::default())
            .await
            .is_ok()
    );
    upstream.await.unwrap();
}

#[tokio::test]
async fn short_tcp_response_is_a_transport_error() {
    use pharos_plugins::proxy::Error;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = Proxy::new(listener.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let len = usize::from(stream.read_u16().await.unwrap());
        let mut wire = [0; 512];
        stream.read_exact(&mut wire[..len]).await.unwrap();
        stream.write_u16(2).await.unwrap();
        stream.write_all(&wire[..2]).await.unwrap();
    });
    let mut response = [0; 512];
    assert!(
        matches!(proxy.exchange(QUERY, &mut response, Transport::Tcp, Options::default()).await, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData)
    );
    upstream.await.unwrap();
}

#[tokio::test]
async fn malformed_upstream_response_starts_health_check() {
    use pharos_plugins::proxy::Error;
    use std::{io, time::Duration};
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = Proxy::new(server.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (_, peer) = server.recv_from(&mut wire).await.unwrap();
        wire[2] |= 0x80;
        server.send_to(&wire[..12], peer).await.unwrap();
        let (len, peer) = tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut wire))
            .await
            .unwrap()
            .unwrap();
        wire[2] |= 0x80;
        server.send_to(&wire[..len], peer).await.unwrap();
    });
    let mut response = [0; 512];
    assert!(
        matches!(proxy.exchange(QUERY, &mut response, Transport::Udp, Options::default()).await, Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidData)
    );
    upstream.await.unwrap();
}

#[tokio::test]
async fn udp_record_overflow_returns_truncated_response_and_reuses_socket() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = Proxy::new(server.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let mut first = None;
        for index in 0..2 {
            let (len, peer) = server.recv_from(&mut wire).await.unwrap();
            if index == 0 {
                first = Some(peer);
                wire[2] |= 0x80;
                wire[7] = 1;
                wire[len] = 0;
                wire[len + 1] = 0;
                server.send_to(&wire[..len + 2], peer).await.unwrap();
            } else {
                assert_eq!(Some(peer), first);
                wire[2] |= 0x80;
                server.send_to(&wire[..len], peer).await.unwrap();
            }
        }
    });
    let mut response = [0; 512];
    let result = proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    let message = pharos_proto::Message::parse(&response[..result.len]).unwrap();
    assert!(message.qr() && message.tc());
    assert_eq!(message.id(), 0x1234);
    assert_eq!(message.question_count(), 1);
    assert_eq!(message.answer_count(), 0);
    assert_eq!(message.authority_count(), 0);
    assert_eq!(message.additional_count(), 0);
    proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn malformed_udp_wrong_id_is_ignored_before_valid_response() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = Proxy::new(server.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = server.recv_from(&mut wire).await.unwrap();
        let mut bad = [0; 13];
        bad[..12].copy_from_slice(&wire[..12]);
        bad[0] ^= 1;
        bad[2] |= 0x80;
        bad[12] = 1;
        server.send_to(&bad, peer).await.unwrap();
        wire[2] |= 0x80;
        server.send_to(&wire[..len], peer).await.unwrap();
    });
    let mut response = [0; 512];
    proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    task.await.unwrap();
}

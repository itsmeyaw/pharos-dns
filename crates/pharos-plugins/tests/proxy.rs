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
                wire[3] = 3;
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
    assert_eq!(message.rcode(), pharos_proto::Rcode::NXDOMAIN);
    let question = message.questions().next().unwrap();
    assert_eq!(question.name.to_string(), ".");
    assert_eq!(question.qtype, pharos_proto::Type::NS);
    assert_eq!(question.qclass, pharos_proto::Class::IN);
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

#[tokio::test]
async fn idle_cap_applies_per_transport() {
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind(tcp.local_addr().unwrap()).await.unwrap();
    let mut proxy = Proxy::new(tcp.local_addr().unwrap());
    proxy.set_max_idle_conns(1);
    let upstream = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = udp.recv_from(&mut wire).await.unwrap();
        wire[2] |= 0x80;
        udp.send_to(&wire[..len], peer).await.unwrap();
        // Accept once: an idle UDP socket must not stop the TCP connection from being cached.
        let (mut stream, _) = tcp.accept().await.unwrap();
        for _ in 0..2 {
            let len = usize::from(stream.read_u16().await.unwrap());
            stream.read_exact(&mut wire[..len]).await.unwrap();
            wire[2] |= 0x80;
            stream.write_u16(len as u16).await.unwrap();
            stream.write_all(&wire[..len]).await.unwrap();
        }
    });
    let mut response = [0; 512];
    for protocol in [Transport::Udp, Transport::Tcp, Transport::Tcp] {
        tokio::time::timeout(
            Duration::from_secs(2),
            proxy.exchange(QUERY, &mut response, protocol, Options::default()),
        )
        .await
        .expect("TCP connection reused")
        .unwrap();
    }
    upstream.await.unwrap();
}

#[tokio::test]
async fn max_age_expires_connections_even_when_recently_used() {
    use std::time::Duration;
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut proxy = Proxy::new(server.local_addr().unwrap());
    proxy.set_max_age(Duration::from_millis(300));
    let upstream = tokio::spawn(async move {
        let mut peers = Vec::new();
        let mut wire = [0; 512];
        for _ in 0..3 {
            let (len, peer) = server.recv_from(&mut wire).await.unwrap();
            peers.push(peer);
            wire[2] |= 0x80;
            server.send_to(&wire[..len], peer).await.unwrap();
        }
        peers
    });
    let mut response = [0; 512];
    proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(320)).await;
    proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    let peers = upstream.await.unwrap();
    assert_eq!(peers[0], peers[1]);
    assert_ne!(peers[1], peers[2]);
}

#[tokio::test]
async fn unlimited_idle_cache_rotates_connections_fifo() {
    use std::cell::RefCell;
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = Proxy::new(server.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        let mut wire = [0; 512];
        let mut peers = Vec::new();
        for _ in 0..4 {
            let (len, peer) = server.recv_from(&mut wire).await.unwrap();
            peers.push(peer);
            wire[2] |= 0x80;
            server.send_to(&wire[..len], peer).await.unwrap();
        }
        peers
    });
    let mut a = [0; 512];
    let mut b = [0; 512];
    let completed = RefCell::new(Vec::new());
    tokio::join!(
        async {
            let exchange = proxy
                .exchange(QUERY, &mut a, Transport::Udp, Options::default())
                .await
                .unwrap();
            completed.borrow_mut().push(exchange.local_addr);
        },
        async {
            let exchange = proxy
                .exchange(QUERY, &mut b, Transport::Udp, Options::default())
                .await
                .unwrap();
            completed.borrow_mut().push(exchange.local_addr);
        },
    );
    for _ in 0..2 {
        proxy
            .exchange(QUERY, &mut a, Transport::Udp, Options::default())
            .await
            .unwrap();
    }
    let peers = upstream.await.unwrap();
    assert_ne!(peers[0], peers[1]);
    assert_eq!(completed.into_inner(), &peers[2..4]);
}

#[tokio::test]
async fn fifo_rotated_connections_expire_by_creation_age() {
    use std::time::Duration;
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut proxy = Proxy::new(server.local_addr().unwrap());
    proxy.set_max_age(Duration::from_millis(300));
    let upstream = tokio::spawn(async move {
        let mut wire = [0; 512];
        let mut peers = Vec::new();
        for _ in 0..6 {
            let (len, peer) = server.recv_from(&mut wire).await.unwrap();
            peers.push(peer);
            wire[2] |= 0x80;
            server.send_to(&wire[..len], peer).await.unwrap();
        }
        peers
    });
    let mut a = [0; 512];
    let mut b = [0; 512];
    let (one, two) = tokio::join!(
        proxy.exchange(QUERY, &mut a, Transport::Udp, Options::default()),
        proxy.exchange(QUERY, &mut b, Transport::Udp, Options::default())
    );
    one.unwrap();
    two.unwrap();
    for _ in 0..2 {
        proxy
            .exchange(QUERY, &mut a, Transport::Udp, Options::default())
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(320)).await;
    let (one, two) = tokio::join!(
        proxy.exchange(QUERY, &mut a, Transport::Udp, Options::default()),
        proxy.exchange(QUERY, &mut b, Transport::Udp, Options::default())
    );
    one.unwrap();
    two.unwrap();
    let peers = upstream.await.unwrap();
    let mut initial = [peers[0], peers[1]];
    let mut rotated = [peers[2], peers[3]];
    initial.sort();
    rotated.sort();
    assert_eq!(initial, rotated);
    assert!(!peers[..2].contains(&peers[4]));
    assert!(!peers[..2].contains(&peers[5]));
}

#[tokio::test]
async fn source_address_is_used_by_udp_and_tcp() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind(tcp.local_addr().unwrap()).await.unwrap();
    let mut proxy = Proxy::new(tcp.local_addr().unwrap());
    proxy.set_source_address(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let upstream = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = udp.recv_from(&mut wire).await.unwrap();
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        wire[2] |= 0x80;
        udp.send_to(&wire[..len], peer).await.unwrap();
        let (mut stream, peer) = tcp.accept().await.unwrap();
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let len = usize::from(stream.read_u16().await.unwrap());
        stream.read_exact(&mut wire[..len]).await.unwrap();
        wire[2] |= 0x80;
        stream.write_u16(len as u16).await.unwrap();
        stream.write_all(&wire[..len]).await.unwrap();
    });
    let mut response = [0; 512];
    for transport in [Transport::Udp, Transport::Tcp] {
        let result = proxy
            .exchange(QUERY, &mut response, transport, Options::default())
            .await
            .unwrap();
        assert_eq!(result.local_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
    upstream.await.unwrap();
    let mut mismatch = Proxy::new("127.0.0.1:53".parse().unwrap());
    mismatch.set_source_address(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    for transport in [Transport::Udp, Transport::Tcp] {
        assert!(
            mismatch
                .exchange(QUERY, &mut response, transport, Options::default())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn health_check_uses_configured_source_address() {
    use pharos_plugins::proxy::{Health, HealthConfig};
    use std::{
        net::{IpAddr, Ipv6Addr},
        time::Duration,
    };
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for force_tcp in [false, true] {
        let mut config = HealthConfig::new(server.local_addr().unwrap(), 1);
        config.source_address = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
        config.force_tcp = force_tcp;
        let health = Health::with_config(config);
        health.start();
        tokio::time::timeout(Duration::from_secs(1), async {
            while health.fails() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        health.stop();
    }
}

#[tokio::test]
async fn stop_closes_idle_connections_and_rejects_queries() {
    use pharos_plugins::proxy::Error;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::{Duration, timeout},
    };
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = Proxy::new(server.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.unwrap();
        let mut wire = [0; 512];
        let len = usize::from(stream.read_u16().await.unwrap());
        stream.read_exact(&mut wire[..len]).await.unwrap();
        wire[2] |= 0x80;
        stream.write_u16(len as u16).await.unwrap();
        stream.write_all(&wire[..len]).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), stream.read(&mut wire))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    });
    let mut response = [0; 512];
    proxy
        .exchange(QUERY, &mut response, Transport::Tcp, Options::default())
        .await
        .unwrap();
    proxy.stop();
    assert!(matches!(
        proxy
            .exchange(QUERY, &mut response, Transport::Tcp, Options::default())
            .await,
        Err(Error::Stopped)
    ));
    upstream.await.unwrap();
}

#[test]
fn activity_on_another_worker_sweeps_expired_sockets() {
    use std::{
        net::UdpSocket as StdUdp,
        sync::{Arc, mpsc},
        time::Duration,
    };
    let server = StdUdp::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut proxy = Proxy::new(server.local_addr().unwrap());
    proxy.set_expire(Duration::from_millis(40));
    let proxy = Arc::new(proxy);
    let (peers_tx, peers_rx) = mpsc::channel();
    let upstream = std::thread::spawn(move || {
        let mut wire = [0; 512];
        for _ in 0..2 {
            let (len, peer) = server.recv_from(&mut wire).unwrap();
            peers_tx.send(peer).unwrap();
            wire[2] |= 0x80;
            server.send_to(&wire[..len], peer).unwrap();
        }
    });
    let exchange = |proxy: Arc<Proxy>| {
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                proxy
                    .exchange(QUERY, &mut [0; 512], Transport::Udp, Options::default())
                    .await
                    .unwrap();
            });
        })
    };
    exchange(Arc::clone(&proxy)).join().unwrap();
    let first = peers_rx.recv().unwrap();
    assert!(StdUdp::bind(first).is_err());
    std::thread::sleep(Duration::from_millis(70));
    exchange(Arc::clone(&proxy)).join().unwrap();
    let second = peers_rx.recv().unwrap();
    assert_ne!(first, second);
    assert!(
        StdUdp::bind(first).is_ok(),
        "inactive worker's expired socket stayed open"
    );
    upstream.join().unwrap();
}

#[tokio::test]
async fn stop_closes_connections_returned_by_in_flight_exchanges() {
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::{Duration, timeout},
    };
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = Arc::new(Proxy::new(server.local_addr().unwrap()));
    let exchange_proxy = Arc::clone(&proxy);
    let task = tokio::spawn(async move {
        exchange_proxy
            .exchange(QUERY, &mut [0; 512], Transport::Tcp, Options::default())
            .await
            .unwrap();
    });
    let (mut stream, _) = server.accept().await.unwrap();
    let len = usize::from(stream.read_u16().await.unwrap());
    let mut wire = [0; 512];
    stream.read_exact(&mut wire[..len]).await.unwrap();
    proxy.stop();
    wire[2] |= 0x80;
    stream.write_u16(len as u16).await.unwrap();
    stream.write_all(&wire[..len]).await.unwrap();
    task.await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), stream.read(&mut wire))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn udp_health_probe_has_one_second_read_timeout() {
    use pharos_plugins::proxy::Health;
    use std::time::{Duration, Instant};
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let health = Health::new(server.local_addr().unwrap(), 2);
    let started = Instant::now();
    health.start();
    let mut wire = [0; 512];
    server.recv_from(&mut wire).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while health.fails() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(850));
    health.stop();
}

#[tokio::test]
async fn proxy_honors_explicit_health_source_configuration() {
    use pharos_plugins::proxy::HealthConfig;
    use std::{
        net::{IpAddr, Ipv6Addr},
        time::Duration,
    };
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let registry = pharos_server::metrics::Registry::new("v", "r", "rust");
    let mut proxy = Proxy::new(server.local_addr().unwrap());
    proxy.set_metrics(&registry, "forward");
    let mut config = HealthConfig::new(server.local_addr().unwrap(), 2);
    config.source_address = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
    proxy.set_health_config(config);
    let upstream = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (_, peer) = server.recv_from(&mut wire).await.unwrap();
        wire[2] |= 0x80;
        server.send_to(&wire[..12], peer).await.unwrap();
        while let Ok((len, peer)) = server.recv_from(&mut wire).await {
            wire[2] |= 0x80;
            server.send_to(&wire[..len], peer).await.unwrap();
        }
    });
    assert!(
        proxy
            .exchange(QUERY, &mut [0; 512], Transport::Udp, Options::default())
            .await
            .is_err()
    );
    tokio::time::timeout(Duration::from_millis(800), async {
        loop {
            let mut out = String::new();
            registry.encode(&mut out);
            if out.contains("pharos_proxy_healthcheck_failures_total{") {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    upstream.abort();
}

#[tokio::test]
async fn health_probes_bind_requested_loopback_source() {
    use pharos_plugins::proxy::{Health, HealthConfig};
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind(tcp.local_addr().unwrap()).await.unwrap();
    let mut wire = [0; 512];
    for force_tcp in [false, true] {
        let mut config = HealthConfig::new(tcp.local_addr().unwrap(), 2);
        config.force_tcp = force_tcp;
        config.source_address = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let health = Health::with_config(config);
        health.start();
        if force_tcp {
            let (mut stream, peer) = tokio::time::timeout(Duration::from_secs(1), tcp.accept())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            let len = usize::from(stream.read_u16().await.unwrap());
            stream.read_exact(&mut wire[..len]).await.unwrap();
            wire[2] |= 0x80;
            stream.write_u16(len as u16).await.unwrap();
            stream.write_all(&wire[..len]).await.unwrap();
        } else {
            let (len, peer) =
                tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut wire))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            wire[2] |= 0x80;
            udp.send_to(&wire[..len], peer).await.unwrap();
        }
        health.stop();
    }
}

#[tokio::test]
async fn oversized_udp_response_becomes_a_clean_truncated_response() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = Proxy::new(server.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = server.recv_from(&mut wire).await.unwrap();
        let mut reply = wire[..len].to_vec();
        reply[2] |= 0x80;
        reply[7] = 40;
        for _ in 0..40 {
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 1]);
        }
        assert!(reply.len() > 512);
        server.send_to(&reply, peer).await.unwrap();
    });
    let mut response = [0; 512];
    let result = proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    let message = pharos_proto::Message::parse(&response[..result.len]).unwrap();
    assert!(message.tc());
    assert_eq!(message.answer_count(), 0);
    assert_eq!(message.question_count(), 1);
    upstream.await.unwrap();
}

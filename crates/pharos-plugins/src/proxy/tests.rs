use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn tcp_connections_do_not_consume_the_udp_socket_use_budget() {
    // RFC 5452 §9.2: Source-port reuse limits apply to UDP sockets.
    assert_eq!(next_use_count(Transport::Tcp, u32::MAX), 0);
    assert_eq!(next_use_count(Transport::Udp, 7), 8);
    assert_eq!(next_use_count(Transport::Udp, u32::MAX), u32::MAX);
}

fn query_with_options(options: &[u8]) -> Vec<u8> {
    let mut wire = vec![
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0,
    ];
    wire[26..28].copy_from_slice(&(options.len() as u16).to_be_bytes());
    wire.extend_from_slice(options);
    wire
}

const KEEPALIVE_AND_ECS: &[u8] = &[0, 11, 0, 2, 0, 100, 0, 8, 0, 7, 0, 1, 24, 8, 192, 0, 2];

#[tokio::test]
async fn tcp_upstream_connect_disables_nagle() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = connect_tcp(listener.local_addr().unwrap(), None)
        .await
        .unwrap();
    assert!(stream.nodelay().unwrap());
}

#[tokio::test]
async fn timeout_zero_tcp_response_closes_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let len = usize::from(stream.read_u16().await.unwrap());
            let mut query = vec![0; len];
            stream.read_exact(&mut query).await.unwrap();
            let request = Message::parse(&query).unwrap();
            assert!(matches!(
                request.opt().unwrap().options().iter().next(),
                Some(EdnsOption::TcpKeepalive(None))
            ));
            let mut answer = query;
            answer[2] |= 0x80;
            answer[26..28].copy_from_slice(&6_u16.to_be_bytes());
            answer[30..32].copy_from_slice(&2_u16.to_be_bytes());
            answer.extend_from_slice(&[0, 0]);
            stream
                .write_u16(u16::try_from(answer.len()).unwrap())
                .await
                .unwrap();
            stream.write_all(&answer).await.unwrap();
        }
    });
    let proxy = Proxy::new(address);
    let query = query_with_options(&[0, 11, 0, 2, 0, 10]);
    let mut response = vec![0; usize::from(u16::MAX)];
    for _ in 0..2 {
        proxy
            .exchange(&query, &mut response, Transport::Tcp, Options::default())
            .await
            .unwrap();
    }
    server.await.unwrap();
}

#[test]
fn sanitizes_tcp_keepalive_and_ecs_scope_in_queries() {
    let mut wire = query_with_options(KEEPALIVE_AND_ECS);
    let len = wire.len();
    let opt_range = opt_rdata_range(&Message::parse(&wire).unwrap(), &wire);
    let new_len = sanitize_edns(&mut wire, len, Transport::Tcp, false, opt_range);
    let message = Message::parse(&wire[..new_len]).unwrap();
    let options: Vec<_> = message.opt().unwrap().options().iter().collect();
    assert_eq!(options[0], EdnsOption::TcpKeepalive(None));
    assert!(matches!(options[1], EdnsOption::ClientSubnet(subnet) if subnet.scope_prefix() == 0));
    assert_eq!(new_len, len - 2);
}

#[test]
fn removes_udp_keepalive_without_losing_ecs() {
    let mut wire = query_with_options(KEEPALIVE_AND_ECS);
    let len = wire.len();
    let opt_range = opt_rdata_range(&Message::parse(&wire).unwrap(), &wire);
    let new_len = sanitize_edns(&mut wire, len, Transport::Udp, false, opt_range);
    let message = Message::parse(&wire[..new_len]).unwrap();
    let options: Vec<_> = message.opt().unwrap().options().iter().collect();
    assert_eq!(options.len(), 1);
    assert!(matches!(options[0], EdnsOption::ClientSubnet(subnet) if subnet.scope_prefix() == 0));
    assert_eq!(new_len, len - 6);
}

#[test]
fn strips_ecs_for_refused_retry_and_honors_zero_keepalive() {
    let query = query_with_options(KEEPALIVE_AND_ECS);
    let mut retry = Vec::new();
    let len = without_ecs(&query, &mut retry, Transport::Tcp)
        .unwrap()
        .unwrap();
    let message = Message::parse(&retry[..len]).unwrap();
    assert_eq!(
        message.opt().unwrap().options().iter().collect::<Vec<_>>(),
        [EdnsOption::TcpKeepalive(None)]
    );

    let zero = query_with_options(&[0, 11, 0, 2, 0, 0]);
    assert!(keepalive_zero(&Message::parse(&zero).unwrap()));
}

#[test]
fn accepts_ecs_response_scope_but_requires_query_fields() {
    let request_wire = query_with_options(&KEEPALIVE_AND_ECS[6..]);
    let request = Message::parse(&request_wire).unwrap();
    let mut response_options = KEEPALIVE_AND_ECS[6..].to_vec();
    response_options[7] = 32;
    let response_wire = query_with_options(&response_options);
    let response = Message::parse(&response_wire).unwrap();
    assert!(same_ecs(&request, &response));
    response_options[8] = 193;
    let mismatched_wire = query_with_options(&response_options);
    let mismatched = Message::parse(&mismatched_wire).unwrap();
    assert!(!same_ecs(&request, &mismatched));
    let response_without_ecs_wire = query_with_options(&[]);
    let response_without_ecs = Message::parse(&response_without_ecs_wire).unwrap();
    assert!(same_ecs(&request, &response_without_ecs));
    let mut refused_wire = query_with_options(&[]);
    refused_wire[3] = 5;
    let refused = Message::parse(&refused_wire).unwrap();
    assert!(same_ecs(&request, &refused));
}

#[test]
fn normalizes_mixed_ttl_rrsets_to_lowest_ttl() {
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    wire.extend_from_slice(&[
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0,
        30, 0, 4, 192, 0, 2, 2,
    ]);
    let normalization = {
        let message = Message::parse(&wire).unwrap();
        rrsets_ttl_normalization(&message, &wire).unwrap()
    };
    assert!(normalization.changed);
    assert!(apply_rrset_ttl_normalization(
        &mut wire,
        normalization.records
    ));
    let message = Message::parse(&wire).unwrap();
    assert!(message.answers().all(|record| record.ttl == 30));
}

#[tokio::test]
async fn mixed_ttl_response_is_normalized_without_starting_health_probe() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut query = [0; 512];
        let (len, peer) = upstream.recv_from(&mut query).await.unwrap();
        let request = Message::parse(&query[..len]).unwrap();
        let question_end = 12 + request.questions().next().unwrap().name.wire_len() + 4;
        let mut response = query[..question_end].to_vec();
        response[2] |= 0x80;
        response[6..8].copy_from_slice(&2_u16.to_be_bytes());
        response[10..12].fill(0);
        response.extend_from_slice(&[
            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0,
            0, 30, 0, 4, 192, 0, 2, 2,
        ]);
        upstream.send_to(&response, peer).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(250), upstream.recv_from(&mut query))
                .await
                .is_err()
        );
    });
    let proxy = Proxy::new(address);
    let query = query_with_options(&[]);
    let mut response = [0; 512];
    let exchange = proxy
        .exchange(&query, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    assert!(
        Message::parse(&response[..exchange.len])
            .unwrap()
            .answers()
            .all(|record| record.ttl == 30)
    );
    task.await.unwrap();
}

#[test]
fn compares_rrset_owners_without_ascii_case() {
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 1, 0, 1];
    wire.extend_from_slice(&[
        1, b'a', 0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1, 1, b'A', 0, 0, 1, 0, 1, 0, 0, 0,
        30, 0, 4, 192, 0, 2, 2,
    ]);
    let normalization = {
        let message = Message::parse(&wire).unwrap();
        rrsets_ttl_normalization(&message, &wire).unwrap()
    };
    assert!(normalization.changed);
    assert!(apply_rrset_ttl_normalization(
        &mut wire,
        normalization.records
    ));
    let message = Message::parse(&wire).unwrap();
    assert!(message.answers().all(|record| record.ttl == 30));
}

#[test]
fn permits_rrsets_repeated_across_sections() {
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1];
    let rr = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1];
    wire.extend_from_slice(&rr);
    wire.extend_from_slice(&rr);
    let message = Message::parse(&wire).unwrap();
    assert!(!rrsets_ttl_normalization(&message, &wire).unwrap().changed);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn udp_sockets_enable_error_queues_for_both_families() {
    use nix::sys::socket::{
        getsockopt,
        sockopt::{Ipv4RecvErr, Ipv6RecvErr},
    };
    let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    enable_recv_err(&v4, v4.local_addr().unwrap());
    assert!(getsockopt(&v4, Ipv4RecvErr).unwrap());
    let v6 = UdpSocket::bind("[::1]:0").await.unwrap();
    enable_recv_err(&v6, v6.local_addr().unwrap());
    assert!(getsockopt(&v6, Ipv6RecvErr).unwrap());
}

#[test]
fn adaptive_dial_timeout_uses_weighted_average_and_bounds() {
    let proxy = Proxy::new("127.0.0.1:53".parse().unwrap());
    assert_eq!(proxy.dial_timeout(), Duration::from_secs(30));
    proxy.update_dial_timeout(Duration::from_secs(3));
    assert_eq!(proxy.dial_timeout(), Duration::from_secs(24));
    for _ in 0..40 {
        proxy.update_dial_timeout(Duration::ZERO);
    }
    assert_eq!(proxy.dial_timeout(), Duration::from_secs(1));
    proxy.update_dial_timeout(Duration::from_secs(120));
    assert_eq!(proxy.dial_timeout(), Duration::from_secs(30));
}

#[test]
fn only_truncated_message_and_name_errors_are_overflows() {
    for (error, expected) in [
        (MessageError::Truncated, true),
        (MessageError::Name(NameError::Truncated), true),
        (MessageError::Name(NameError::InvalidLabelType), false),
        (MessageError::Name(NameError::PointerNotBackwards), false),
        (MessageError::InvalidOpt, false),
    ] {
        assert_eq!(is_overflow(&error), expected, "{error:?}");
    }
}

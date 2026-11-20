use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

const PROXY: &str = "10.1.1.1:5000";
const CLIENT: &str = "192.0.2.1:12345";

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn v1() -> Vec<u8> {
    b"PROXY TCP4 192.0.2.1 192.0.2.53 12345 53\r\n".to_vec()
}

// PROXY protocol §2.2: PROXY command, IPv4, STREAM (0x11) or DGRAM (0x12).
fn v2(family: u8, tlvs: &[u8]) -> Vec<u8> {
    let mut wire = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    wire.extend([0x21, family]);
    wire.extend(u16::try_from(12 + tlvs.len()).unwrap().to_be_bytes());
    wire.extend([192, 0, 2, 1, 192, 0, 2, 53]);
    wire.extend(12345u16.to_be_bytes());
    wire.extend(53u16.to_be_bytes());
    wire.extend(tlvs);
    wire
}

fn config(policy: Policy) -> Config {
    let mut config = Config::new(move |_| policy);
    config.header_timeout = Duration::from_millis(200);
    config
}

async fn accept(
    config: &Config,
    wire: &[u8],
) -> io::Result<(SocketAddr, Option<Arc<str>>, Vec<u8>)> {
    let (mut client, server) = tokio::io::duplex(8192);
    client.write_all(wire).await.unwrap();
    drop(client);
    let mut accepted = config.accept_stream(server, addr(PROXY)).await?;
    let mut rest = Vec::new();
    accepted.stream.read_to_end(&mut rest).await.unwrap();
    Ok((accepted.peer, accepted.tlv, rest))
}

#[tokio::test]
async fn v1_header_replaces_the_peer_and_keeps_following_bytes() {
    let mut wire = v1();
    wire.extend(b"\x00\x1dDNS");
    let (peer, tlv, rest) = accept(&config(Policy::Use), &wire).await.unwrap();
    assert_eq!(
        (peer, tlv, rest),
        (addr(CLIENT), None, b"\x00\x1dDNS".to_vec())
    );
}

#[tokio::test]
async fn v2_header_replaces_the_peer() {
    let mut wire = v2(0x11, &[]);
    wire.extend(b"DNS");
    let (peer, _, rest) = accept(&config(Policy::Use), &wire).await.unwrap();
    assert_eq!((peer, rest), (addr(CLIENT), b"DNS".to_vec()));
}

#[tokio::test]
async fn v2_local_command_keeps_the_peer() {
    let mut wire = v2(0x00, &[]);
    wire[12] = 0x20;
    wire[14..16].copy_from_slice(&0u16.to_be_bytes());
    wire.truncate(16);
    wire.extend(b"DNS");
    let (peer, _, rest) = accept(&config(Policy::Use), &wire).await.unwrap();
    assert_eq!((peer, rest), (addr(PROXY), b"DNS".to_vec()));
}

#[tokio::test]
async fn v1_unknown_keeps_the_peer() {
    let (peer, _, rest) = accept(&config(Policy::Use), b"PROXY UNKNOWN\r\nDNS")
        .await
        .unwrap();
    assert_eq!((peer, rest), (addr(PROXY), b"DNS".to_vec()));
}

#[tokio::test]
async fn stream_without_a_header_passes_through_under_use() {
    let wire = b"\x00\x1d\x12\x34 dns query";
    let (peer, _, rest) = accept(&config(Policy::Use), wire).await.unwrap();
    assert_eq!((peer, rest), (addr(PROXY), wire.to_vec()));
}

#[tokio::test]
async fn ignore_consumes_the_header_and_keeps_the_peer() {
    let mut wire = v1();
    wire.extend(b"DNS");
    let (peer, tlv, rest) = accept(&config(Policy::Ignore), &wire).await.unwrap();
    assert_eq!((peer, tlv, rest), (addr(PROXY), None, b"DNS".to_vec()));
}

#[tokio::test]
async fn reject_refuses_a_header_and_passes_other_streams() {
    let error = accept(&config(Policy::Reject), &v1()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let (peer, _, rest) = accept(&config(Policy::Reject), b"\x00\x1dDNS")
        .await
        .unwrap();
    assert_eq!((peer, rest), (addr(PROXY), b"\x00\x1dDNS".to_vec()));
}

#[tokio::test]
async fn skip_leaves_the_header_in_the_stream() {
    let wire = v1();
    let (peer, _, rest) = accept(&config(Policy::Skip), &wire).await.unwrap();
    assert_eq!((peer, rest), (addr(PROXY), wire));
}

#[tokio::test]
async fn policy_is_chosen_per_peer() {
    let config = Config::new(|ip| {
        if ip == "10.1.1.1".parse::<IpAddr>().unwrap() {
            Policy::Use
        } else {
            Policy::Reject
        }
    });
    let (trusted, _, _) = accept(&config, &v1()).await.unwrap();
    assert_eq!(trusted, addr(CLIENT));
    let (mut client, server) = tokio::io::duplex(1024);
    client.write_all(&v1()).await.unwrap();
    let error = config
        .accept_stream(server, addr("10.9.9.9:1"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn tlv_hex_is_kept_only_when_requested() {
    let mut wire = v2(0x11, &[0xEA, 0, 2, 0xCA, 0xFE]);
    wire.extend(b"DNS");
    let mut on = config(Policy::Use);
    on.tlv_metadata = true;
    let (_, tlv, _) = accept(&on, &wire).await.unwrap();
    assert_eq!(tlv.as_deref(), Some("ea0002cafe"));
    let (_, tlv, _) = accept(&config(Policy::Use), &wire).await.unwrap();
    assert_eq!(tlv, None);
    let (_, tlv, _) = accept(&on, &v2(0x11, &[])).await.unwrap();
    assert_eq!(tlv, None);
}

#[tokio::test]
async fn header_split_across_reads_is_assembled() {
    let (mut client, server) = tokio::io::duplex(8192);
    let config = config(Policy::Use);
    let wire = v2(0x11, &[0xEA, 0, 1, 7]);
    let writer = tokio::spawn(async move {
        for chunk in wire.chunks(3) {
            client.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
        client
    });
    let accepted = config.accept_stream(server, addr(PROXY)).await.unwrap();
    assert_eq!(accepted.peer, addr(CLIENT));
    drop(writer.await.unwrap());
}

#[tokio::test]
async fn a_silent_peer_times_out() {
    let (_client, server) = tokio::io::duplex(1024);
    let mut config = config(Policy::Use);
    config.header_timeout = Duration::from_millis(50);
    let error = config
        .accept_stream(server, addr(PROXY))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn a_stalled_partial_header_times_out() {
    let (mut client, server) = tokio::io::duplex(1024);
    client.write_all(b"PROXY TCP4 192.0.2.1 ").await.unwrap();
    let mut config = config(Policy::Use);
    config.header_timeout = Duration::from_millis(50);
    let error = config
        .accept_stream(server, addr(PROXY))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn truncated_headers_fail() {
    for wire in [&v1()[..20], &v2(0x11, &[])[..20]] {
        let error = accept(&config(Policy::Use), wire).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}

#[tokio::test]
async fn malicious_headers_fail_without_unbounded_reads() {
    let mut oversized = v2(0x11, &[]);
    oversized[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    let long_v1 = [b"PROXY UNKNOWN ".as_slice(), &[b'x'; 4096]].concat();
    for wire in [
        oversized,
        long_v1,
        b"PROXY TCP4 999.0.0.1 192.0.2.53 1 2\r\n".to_vec(),
        b"PROXY TCP4 192.0.2.1 192.0.2.53 1 2\n".to_vec(),
    ] {
        let error = accept(&config(Policy::Use), &wire).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

fn datagram(
    config: &Config,
    state: &mut UdpState,
    wire: &[u8],
    peer: &str,
) -> Option<(usize, SocketAddr)> {
    config.accept_datagram(state, wire, addr(peer), 1)
}

fn tracking(policy: Policy) -> Config {
    let mut config = config(policy);
    config.udp_tracking = Some(UdpTracking {
        ttl: Duration::from_secs(60),
        max_sessions: 10,
    });
    config.tlv_metadata = true;
    config
}

#[test]
fn datagram_header_is_stripped_under_use() {
    let mut wire = v2(0x12, &[]);
    let header = wire.len();
    wire.extend(b"DNS");
    let result = datagram(&config(Policy::Use), &mut UdpState::default(), &wire, PROXY);
    assert_eq!(result, Some((header, addr(CLIENT))));
}

#[test]
fn datagram_header_is_stripped_but_ignored_under_ignore() {
    let mut wire = v2(0x12, &[]);
    let header = wire.len();
    wire.extend(b"DNS");
    let result = datagram(
        &config(Policy::Ignore),
        &mut UdpState::default(),
        &wire,
        PROXY,
    );
    assert_eq!(result, Some((header, addr(PROXY))));
}

#[test]
fn cached_tlvs_are_not_published_after_tlv_metadata_is_turned_off() {
    let mut state = UdpState::default();
    let mut wire = v2(0x12, &[0xEA, 0, 1, 7]);
    datagram(&tracking(Policy::Use), &mut state, &wire, PROXY);
    wire.clear();
    wire.extend(b"DNS");
    let mut reloaded = tracking(Policy::Use);
    reloaded.tlv_metadata = false;
    let result = datagram(&reloaded, &mut state, &wire, PROXY);
    assert_eq!(result, Some((0, addr("192.0.2.1:12345"))));
    assert_eq!(state.tlv, "");
}

#[test]
fn datagram_header_is_dropped_under_reject_and_untouched_under_skip() {
    let mut wire = v2(0x12, &[]);
    wire.extend(b"DNS");
    let mut state = UdpState::default();
    assert_eq!(
        datagram(&config(Policy::Reject), &mut state, &wire, PROXY),
        None
    );
    assert_eq!(
        datagram(&config(Policy::Skip), &mut state, &wire, PROXY),
        Some((0, addr(PROXY)))
    );
    assert_eq!(
        datagram(&config(Policy::Reject), &mut state, b"plain dns", PROXY),
        Some((0, addr(PROXY)))
    );
}

#[test]
fn datagram_headers_that_are_not_v2_datagram_headers_are_dropped() {
    let mut state = UdpState::default();
    let stream = v2(0x11, &[]);
    let mut v1 = v1();
    v1.extend(b"DNS");
    let truncated = v2(0x12, &[])[..14].to_vec();
    for wire in [&stream[..], &v1, &truncated] {
        assert_eq!(
            datagram(&config(Policy::Use), &mut state, wire, PROXY),
            None
        );
    }
}

#[test]
fn header_only_datagram_opens_a_session_for_headerless_ones() {
    let config = tracking(Policy::Use);
    let mut state = UdpState::default();
    let wire = v2(0x12, &[0xEA, 0, 1, 9]);
    assert_eq!(datagram(&config, &mut state, &wire, PROXY), None);
    assert_eq!(
        datagram(&config, &mut state, b"dns", PROXY),
        Some((0, addr(CLIENT)))
    );
    assert_eq!(state.tlv, "ea000109");
    assert_eq!(
        datagram(&config, &mut state, b"dns", "10.1.1.1:5001"),
        Some((0, addr("10.1.1.1:5001")))
    );
    assert_eq!(state.tlv, "");
}

#[test]
fn header_datagram_without_tracking_publishes_its_tlv_only_for_itself() {
    let mut config = config(Policy::Use);
    config.tlv_metadata = true;
    let mut state = UdpState::default();
    let mut wire = v2(0x12, &[0xEA, 0, 1, 9]);
    wire.extend(b"dns");
    assert!(datagram(&config, &mut state, &wire, PROXY).is_some());
    assert_eq!(state.tlv, "ea000109");
    assert_eq!(
        datagram(&config, &mut state, b"dns", PROXY),
        Some((0, addr(PROXY)))
    );
    assert_eq!(state.tlv, "");
}

#[test]
fn header_only_datagram_without_tracking_is_dropped() {
    let wire = v2(0x12, &[]);
    let result = datagram(&config(Policy::Use), &mut UdpState::default(), &wire, PROXY);
    assert_eq!(result, None);
}

#[test]
fn ignore_does_not_use_sessions() {
    let config = tracking(Policy::Ignore);
    let mut state = UdpState::default();
    assert_eq!(datagram(&config, &mut state, &v2(0x12, &[]), PROXY), None);
    assert_eq!(
        datagram(&config, &mut state, b"dns", PROXY),
        Some((0, addr(PROXY)))
    );
}

#[test]
fn expired_sessions_stop_applying() {
    let mut config = tracking(Policy::Use);
    config.udp_tracking = Some(UdpTracking {
        ttl: Duration::from_millis(20),
        max_sessions: 10,
    });
    let mut state = UdpState::default();
    assert_eq!(datagram(&config, &mut state, &v2(0x12, &[]), PROXY), None);
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(
        datagram(&config, &mut state, b"dns", PROXY),
        Some((0, addr(PROXY)))
    );
}

#[test]
fn session_capacity_is_shared_between_workers() {
    let tracking = UdpTracking {
        ttl: Duration::from_secs(1),
        max_sessions: 10,
    };
    assert_eq!(
        (share(tracking, 4), share(tracking, 1), share(tracking, 0)),
        (3, 10, 10)
    );
}

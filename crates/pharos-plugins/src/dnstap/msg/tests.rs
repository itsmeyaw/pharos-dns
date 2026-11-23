//! Ported from CoreDNS v1.15.0 plugin/dnstap/msg/msg_test.go, plus wire-format checks.
use super::decode;
use super::*;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, UNIX_EPOCH};

const HEADER: Header<'static> = Header {
    identity: b"id",
    version: b"v",
    extra: None,
};

fn encode(message: &Message<'_>, header: &Header<'_>) -> Vec<u8> {
    let mut buf = Vec::new();
    message.encode(header, &mut buf);
    buf
}

fn decoded(message: &Message<'_>) -> decode::Message {
    decode::dnstap(&encode(message, &HEADER))
        .message
        .expect("message field")
}

fn ipv4_mapped() -> IpAddr {
    // ::ffff:192.0.2.1, how a dual-stack listener reports an IPv4 client.
    IpAddr::V6("::ffff:192.0.2.1".parse().unwrap())
}

// An IPv4 client reported as an IPv4-mapped IPv6 address must be stored as 4 octets with family INET.
#[test]
fn ipv4_mapped_address_is_reported_as_inet() {
    for protocol in [SocketProtocol::Udp, SocketProtocol::Tcp] {
        let mut query = Message::new(MessageType::ClientQuery);
        query.set_query_address(SocketAddr::new(ipv4_mapped(), 53), protocol);
        let query = decoded(&query);
        assert_eq!(query.family, Some(1));
        assert_eq!(query.query_address, Some(vec![192, 0, 2, 1]));

        let mut response = Message::new(MessageType::ClientResponse);
        response.set_response_address(SocketAddr::new(ipv4_mapped(), 53), protocol);
        let response = decoded(&response);
        assert_eq!(response.family, Some(1));
        assert_eq!(response.response_address, Some(vec![192, 0, 2, 1]));
    }
}

#[test]
fn native_ipv4_is_inet_with_four_octets() {
    let mut message = Message::new(MessageType::ClientQuery);
    message.set_query_address(
        SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 53),
        SocketProtocol::Udp,
    );
    let message = decoded(&message);
    assert_eq!(message.family, Some(1));
    assert_eq!(message.query_address.map(|address| address.len()), Some(4));
}

#[test]
fn native_ipv6_is_inet6_with_sixteen_octets() {
    let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut message = Message::new(MessageType::ClientQuery);
    message.set_query_address(SocketAddr::new(ip.into(), 53), SocketProtocol::Udp);
    let message = decoded(&message);
    assert_eq!(message.family, Some(2));
    assert_eq!(message.query_address, Some(ip.octets().to_vec()));
}

// dnstap.proto IPv4-compatible `::192.0.2.1` is not IPv4-mapped, so it stays INET6.
#[test]
fn ipv4_compatible_address_stays_inet6() {
    let ip: Ipv6Addr = "::192.0.2.1".parse().unwrap();
    let mut message = Message::new(MessageType::ClientQuery);
    message.set_query_address(SocketAddr::new(ip.into(), 53), SocketProtocol::Udp);
    assert_eq!(decoded(&message).family, Some(2));
}

#[test]
fn protocol_and_ports_follow_the_setters() {
    let mut message = Message::new(MessageType::ForwarderQuery);
    message.set_query_address(
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 40000),
        SocketProtocol::Udp,
    );
    message.set_response_address(
        SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 853),
        SocketProtocol::Tcp,
    );
    let message = decoded(&message);
    // CoreDNS v1.15.0 msg.go: each setter overwrites SocketProtocol, so the last call wins.
    assert_eq!(message.protocol, Some(2));
    assert_eq!(message.query_port, Some(40000));
    assert_eq!(message.response_port, Some(853));
    assert_eq!(message.query_address, Some(vec![127, 0, 0, 1]));
    assert_eq!(message.response_address, Some(vec![10, 0, 0, 1]));
}

#[test]
fn times_split_into_seconds_and_nanoseconds() {
    let at = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
    let mut message = Message::new(MessageType::ClientResponse);
    message.set_query_time(at);
    message.set_response_time(at + Duration::from_nanos(999_999_999 - 123_456_789 + 1));
    let message = decoded(&message);
    assert_eq!(message.query_time_sec, Some(1_700_000_000));
    assert_eq!(message.query_time_nsec, Some(123_456_789));
    assert_eq!(message.response_time_sec, Some(1_700_000_001));
    assert_eq!(message.response_time_nsec, Some(0));
}

// A clock before the epoch encodes as zero rather than wrapping like Go's uint64 cast.
#[test]
fn time_before_the_epoch_is_zero() {
    let mut message = Message::new(MessageType::ClientQuery);
    message.set_query_time(UNIX_EPOCH - Duration::from_secs(1));
    let message = decoded(&message);
    assert_eq!(
        (message.query_time_sec, message.query_time_nsec),
        (Some(0), Some(0))
    );
}

#[test]
fn raw_messages_are_included_when_set() {
    let mut message = Message::new(MessageType::ClientQuery);
    assert_eq!(decoded(&message).query_message, None);
    assert_eq!(decoded(&message).response_message, None);
    message.set_query_message(&[1, 2, 3]);
    message.set_response_message(&[]);
    let message = decoded(&message);
    assert_eq!(message.query_message, Some(vec![1, 2, 3]));
    assert_eq!(message.response_message, Some(Vec::new()));
}

#[test]
fn header_fields_and_empty_extra() {
    let message = Message::new(MessageType::ClientQuery);
    let plain = decode::dnstap(&encode(&message, &HEADER));
    assert_eq!(plain.identity.as_deref(), Some(&b"id"[..]));
    assert_eq!(plain.version.as_deref(), Some(&b"v"[..]));
    assert_eq!(plain.extra, None);
    assert_eq!(plain.kind, Some(1));
    // CoreDNS sets Extra whenever `extra` is configured, even if the expansion is empty.
    let header = Header {
        extra: Some(b""),
        ..HEADER
    };
    assert_eq!(
        decode::dnstap(&encode(&message, &header)).extra,
        Some(Vec::new())
    );
    let header = Header {
        extra: Some(b"x=1"),
        ..HEADER
    };
    assert_eq!(
        decode::dnstap(&encode(&message, &header)).extra,
        Some(b"x=1".to_vec())
    );
}

// dnstap.proto Message.Type values.
#[test]
fn message_type_numbers_match_the_proto() {
    let types = [
        (MessageType::AuthQuery, 1),
        (MessageType::AuthResponse, 2),
        (MessageType::ResolverQuery, 3),
        (MessageType::ResolverResponse, 4),
        (MessageType::ClientQuery, 5),
        (MessageType::ClientResponse, 6),
        (MessageType::ForwarderQuery, 7),
        (MessageType::ForwarderResponse, 8),
        (MessageType::StubQuery, 9),
        (MessageType::StubResponse, 10),
        (MessageType::ToolQuery, 11),
        (MessageType::ToolResponse, 12),
        (MessageType::UpdateQuery, 13),
        (MessageType::UpdateResponse, 14),
    ];
    for (kind, number) in types {
        assert_eq!(decoded(&Message::new(kind)).kind, Some(number));
    }
    assert_eq!(SocketProtocol::Dot as u8, 3);
    assert_eq!(SocketProtocol::Doh as u8, 4);
}

// Hand-computed from dnstap.proto and the protobuf encoding: ascending field order, `nsec` as fixed32.
#[test]
fn golden_bytes() {
    let mut message = Message::new(MessageType::ClientQuery);
    message.set_query_address(
        SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 53),
        SocketProtocol::Udp,
    );
    message.set_query_time(UNIX_EPOCH + Duration::new(1, 2));
    assert_eq!(
        encode(&message, &HEADER),
        [
            0x0a, 0x02, b'i', b'd', // identity
            0x12, 0x01, b'v', // version
            0x72, 0x15, // message, 21 bytes
            0x08, 0x05, // type CLIENT_QUERY
            0x10, 0x01, // socket_family INET
            0x18, 0x01, // socket_protocol UDP
            0x22, 0x04, 192, 0, 2, 1, // query_address
            0x30, 0x35, // query_port 53
            0x40, 0x01, // query_time_sec
            0x4d, 0x02, 0x00, 0x00, 0x00, // query_time_nsec fixed32
            0x78, 0x01, // type MESSAGE
        ]
    );
}

#[test]
fn encoding_appends_and_reuses_capacity() {
    let mut message = Message::new(MessageType::ClientResponse);
    message.set_query_address(
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 65535),
        SocketProtocol::Tcp,
    );
    message.set_response_message(&[7; 300]);
    let mut buf = Vec::with_capacity(1024);
    message.encode(&HEADER, &mut buf);
    let first = buf.clone();
    let pointer = buf.as_ptr();
    buf.clear();
    message.encode(&HEADER, &mut buf);
    assert_eq!(buf, first);
    assert_eq!(buf.as_ptr(), pointer);
    // A 300-byte payload needs a two-byte length varint.
    let message = decode::dnstap(&buf).message.unwrap();
    assert_eq!(message.response_message, Some(vec![7; 300]));
    assert_eq!(message.query_port, Some(65535));
}

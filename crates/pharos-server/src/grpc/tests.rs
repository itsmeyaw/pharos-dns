use super::*;

#[test]
fn content_types_name_protobuf_calls() {
    for value in [
        "application/grpc",
        "application/grpc+proto",
        "application/grpc; charset=utf-8",
    ] {
        assert!(is_content_type(value), "{value}");
    }
    for value in [
        "",
        "text/plain",
        "application/grpc+json",
        "application/grpcx",
    ] {
        assert!(!is_content_type(value), "{value}");
    }
}

fn flatten(mut buf: impl Buf) -> Vec<u8> {
    let mut out = Vec::new();
    while buf.has_remaining() {
        let chunk = buf.chunk();
        out.extend_from_slice(chunk);
        let count = chunk.len();
        buf.advance(count);
    }
    out
}

#[test]
fn prefix_frames_a_message_as_one_field_protobuf() {
    let message = [1, 2, 3];
    let frame = flatten(FramePrefix::new(3).chain(&message[..]));
    // flag 0, length 5, tag 0x0a, length 3, message.
    assert_eq!(frame, [0, 0, 0, 0, 5, 0x0a, 3, 1, 2, 3]);
}

#[test]
fn prefix_uses_a_multi_octet_varint_for_a_maximum_size_message() {
    let prefix = flatten(FramePrefix::new(MAX_MESSAGE_LEN));
    // 65535 = 0xff 0xff 0x03 as a varint; the gRPC length is 1 + 3 + 65535.
    assert_eq!(prefix, [0, 0, 1, 0, 3, 0x0a, 0xff, 0xff, 0x03]);
}

#[test]
fn prefix_omits_the_default_empty_field() {
    assert_eq!(flatten(FramePrefix::new(0)), [0, 0, 0, 0, 0]);
}

#[test]
fn packet_roundtrips_through_the_prefix() {
    let message: Vec<u8> = (0..=255).cycle().take(300).collect();
    let frame = flatten(FramePrefix::new(message.len()).chain(&message[..]));
    let header = parse_header(&frame).unwrap().unwrap();
    assert_eq!(header.len, frame.len() - HEADER_LEN);
    assert_eq!(decode_packet(&frame[HEADER_LEN..]).unwrap(), message);
}

#[test]
fn header_reports_incomplete_flag_and_length() {
    assert_eq!(parse_header(&[0, 0, 0, 0]), None);
    assert_eq!(
        parse_header(&[1, 0, 0, 1, 2]),
        Some(Ok(Header {
            compressed: true,
            len: 258
        }))
    );
    let invalid = parse_header(&[2, 0, 0, 0, 0]).unwrap().unwrap_err();
    assert_eq!(invalid.code, Code::Internal);
}

// Protobuf encoding: the last occurrence of a singular field wins; unknown fields are skipped.
#[test]
fn decode_takes_the_last_field_one_and_skips_unknown_fields() {
    let payload = [
        0x08, 0x96, 0x01, // field 1 as a varint is an unknown field
        0x0a, 0x01, 0xaa, // field 1: [0xaa]
        0x15, 1, 2, 3, 4, // field 2, fixed32
        0x19, 1, 2, 3, 4, 5, 6, 7, 8, // field 3, fixed64
        0x22, 0x02, 9, 9, // field 4, length-delimited
        0x0a, 0x02, 0xbb, 0xcc, // field 1: [0xbb, 0xcc]
    ];
    assert_eq!(decode_packet(&payload).unwrap(), [0xbb, 0xcc]);
    assert_eq!(decode_packet(&[]).unwrap(), &[] as &[u8]);
}

// Protobuf encoding "Groups": a well-formed unknown group, nested or not, is skipped.
#[test]
fn decode_skips_unknown_groups() {
    let payload = [
        0x1b, 0x08, 0x01, 0x23, 0x24, 0x1c, // field 3 group holding a nested field 4 group
        0x0a, 0x01, 0xaa, // field 1
    ];
    assert_eq!(decode_packet(&payload).unwrap(), [0xaa]);
}

#[test]
fn decode_rejects_malformed_protobuf() {
    for payload in [
        &[0x0a][..],         // no length
        &[0x0a, 0x05, 1, 2], // length past the end
        &[0x0a, 0x80],       // unterminated varint
        &[0x00, 0x01],       // field number zero
        &[0x0b],             // start group, never closed
        &[0x1b, 0x24],       // group of field 3 closed by field 4
        &[0x24],             // end group with no start
        &[
            0x0a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02, 0x0a, 0x01, 0xaa,
        ], // varint over 64 bits
        &[0xf8, 0xff, 0xff, 0xff, 0x1f, 0x00], // field number 2^29
        &[0x15, 1, 2],       // short fixed32
        &[0x19, 1, 2, 3],    // short fixed64
        &[
            0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ], // huge length
    ] {
        assert!(decode_packet(payload).is_err(), "{payload:02x?}");
    }
}

#[test]
fn status_numbers_and_unknown_numbers() {
    assert_eq!(Code::from_header(b"0"), Code::Ok);
    assert_eq!(Code::from_header(b"12"), Code::Unimplemented);
    assert_eq!(Code::from_header(b"13"), Code::Internal);
    assert_eq!(Code::from_header(b"99"), Code::Unknown);
    assert_eq!(Code::from_header(b"x"), Code::Unknown);
    assert_eq!(Code::from_header(b""), Code::Unknown);
}

#[test]
fn message_escaping_roundtrips() {
    assert_eq!(escape_message("a b%c"), "a b%25c");
    assert_eq!(escape_message("é\n"), "%C3%A9%0A");
    assert_eq!(unescape_message("a b%25c %C3%A9%0A"), "a b%c é\n");
    assert_eq!(unescape_message("100%"), "100%");
    assert_eq!(unescape_message("%zz"), "%zz");
}

#[test]
fn timeouts_parse_to_durations() {
    assert_eq!(parse_timeout("1S"), Some(Duration::from_secs(1)));
    assert_eq!(parse_timeout("250m"), Some(Duration::from_millis(250)));
    assert_eq!(parse_timeout("2H"), Some(Duration::from_secs(7200)));
    assert_eq!(parse_timeout("3M"), Some(Duration::from_secs(180)));
    assert_eq!(parse_timeout("7u"), Some(Duration::from_micros(7)));
    assert_eq!(parse_timeout("9n"), Some(Duration::from_nanos(9)));
    assert_eq!(
        parse_timeout("99999999S"),
        Some(Duration::from_secs(99_999_999))
    );
    for invalid in ["", "S", "1", "123456789S", "1x", "-1S", "1.5S", "1 S"] {
        assert_eq!(parse_timeout(invalid), None, "{invalid:?}");
    }
}

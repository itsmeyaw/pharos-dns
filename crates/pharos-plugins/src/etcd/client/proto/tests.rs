use super::*;

// etcd v3 rpc.proto RangeRequest: key = 1, range_end = 2, count_only = 9.
#[test]
fn range_request_wire_form() {
    assert_eq!(
        range_request(b"foo", b"fop", false),
        [0x0a, 3, b'f', b'o', b'o', 0x12, 3, b'f', b'o', b'p']
    );
    assert_eq!(range_request(b"", b"", true), [0x48, 1]);
}

// proto3: a default value is not written, so a range over one key has no range_end.
#[test]
fn range_request_leaves_out_defaults() {
    assert_eq!(range_request(b"k", b"", false), [0x0a, 1, b'k']);
}

// etcd v3 rpc.proto LeaseTimeToLiveRequest: ID = 1, a varint.
#[test]
fn lease_request_wire_form() {
    assert_eq!(lease_time_to_live_request(5), [0x08, 5]);
    assert_eq!(lease_time_to_live_request(300), [0x08, 0xac, 0x02]);
    // Protobuf encoding "Negative numbers": int64 takes ten octets.
    assert_eq!(
        lease_time_to_live_request(-1),
        [
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01
        ]
    );
}

#[test]
fn authenticate_request_wire_form() {
    assert_eq!(
        authenticate_request("u", "pw"),
        [0x0a, 1, b'u', 0x12, 2, b'p', b'w']
    );
}

// etcd v3 rpc.proto WatchRequest: create_request = 1 holds the WatchCreateRequest.
#[test]
fn watch_create_request_wire_form() {
    assert_eq!(
        watch_create_request(b"/a", b"/b"),
        [0x0a, 8, 0x0a, 2, b'/', b'a', 0x12, 2, b'/', b'b']
    );
}

// A RangeResponse as etcd would write it: header, one KeyValue, count.
fn range_bytes() -> Vec<u8> {
    let mut bytes = vec![0x0a, 2, 0x18, 7, 0x12, 18];
    bytes.extend([0x0a, 3, b'k', b'e', b'y']);
    bytes.extend([0x10, 2, 0x18, 3, 0x20, 1]);
    bytes.extend([0x2a, 3, b'v', b'a', b'l']);
    bytes.extend([0x30, 9]);
    bytes.extend([0x20, 1]);
    bytes
}

#[test]
fn range_response_decodes_every_field() {
    let response = range_response(&range_bytes()).unwrap();
    assert_eq!(
        response,
        RangeResponse {
            revision: 7,
            kvs: vec![KeyValue {
                key: b"key".to_vec(),
                create_revision: 2,
                mod_revision: 3,
                version: 1,
                value: b"val".to_vec(),
                lease: 9,
            }],
            more: false,
            count: 1,
        }
    );
}

// Protobuf encoding: a field the reader does not know is skipped, whatever its wire type.
#[test]
fn unknown_fields_are_skipped() {
    let mut bytes = vec![0x78, 5, 0x62, 2, 0xab, 0xcd, 0x6d, 1, 2, 3, 4];
    bytes.extend([0x71, 1, 2, 3, 4, 5, 6, 7, 8]);
    bytes.extend(range_bytes());
    assert_eq!(range_response(&bytes).unwrap().count, 1);
    // The same inside a nested message.
    let mut kv = vec![0x0a, 1, b'k', 0x78, 1];
    let mut nested = vec![0x12, kv.len() as u8];
    nested.append(&mut kv);
    assert_eq!(range_response(&nested).unwrap().kvs[0].key, b"k");
}

// Protobuf encoding: a known field with another wire type is an unknown field.
#[test]
fn a_known_field_with_the_wrong_wire_type_is_ignored() {
    assert_eq!(range_response(&[0x22, 1, 7]).unwrap().count, 0);
}

#[test]
fn watch_response_decodes_created_ack_and_events() {
    // created ack: header { revision 4 }, watch_id 0 (omitted), created = true.
    let ack = watch_response(&[0x0a, 2, 0x18, 4, 0x18, 1]).unwrap();
    assert!(ack.created && !ack.canceled && ack.events.is_empty());
    assert_eq!(ack.revision, 4);
    // events = 11: a DELETE (type = 1) of key "/a".
    let delete = [0x5a, 8, 0x08, 1, 0x12, 4, 0x0a, 2, b'/', b'a'];
    let response = watch_response(&[&[0x10, 3][..], &delete].concat()).unwrap();
    assert_eq!(response.watch_id, 3);
    assert_eq!(response.events.len(), 1);
    assert_eq!(response.events[0].kind, EventKind::Delete);
    assert_eq!(response.events[0].kv.key, b"/a");
}

#[test]
fn watch_response_reports_cancel_and_compaction() {
    let response = watch_response(&[0x20, 1, 0x28, 9, 0x32, 2, b'o', b'k']).unwrap();
    assert!(response.canceled);
    assert_eq!(response.compact_revision, 9);
    assert_eq!(response.cancel_reason, "ok");
}

#[test]
fn authenticate_response_reads_the_token() {
    assert_eq!(
        authenticate_response(&[0x0a, 0, 0x12, 3, b'a', b'b', b'c']).unwrap(),
        "abc"
    );
    assert!(authenticate_response(&[0x12, 1, 0xff]).is_err());
}

#[test]
fn lease_response_reads_the_ttl() {
    let response = lease_time_to_live_response(&[0x10, 7, 0x18, 42, 0x20, 60]).unwrap();
    assert_eq!(
        (response.id, response.ttl, response.granted_ttl),
        (7, 42, 60)
    );
}

// Protobuf encoding: a cut message is an error, never a panic or a short read.
#[test]
fn every_truncation_of_a_response_is_handled() {
    let bytes = range_bytes();
    for len in 0..bytes.len() {
        let _ = range_response(&bytes[..len]);
    }
    assert!(range_response(&bytes[..bytes.len() - 1]).is_err());
    // Cut inside the KeyValue: the declared length runs past the end.
    assert!(range_response(&bytes[..10]).is_err());
}

#[test]
fn a_length_beyond_the_buffer_is_an_error() {
    assert!(range_response(&[0x12, 0xff, 0xff, 0xff, 0xff, 0x0f, 1]).is_err());
    assert!(range_response(&[0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]).is_err());
}

#[test]
fn malformed_tags_are_errors() {
    // An eleven-octet varint, a tenth octet above 1, field number 0, wire type 3 (group) and a fixed32 cut short.
    assert!(range_response(&[0xff; 11]).is_err());
    assert!(
        range_response(&[
            0x78, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
        ])
        .is_err()
    );
    assert!(range_response(&[0x00, 1]).is_err());
    assert!(range_response(&[0x1b]).is_err());
    assert!(range_response(&[0x6d, 1, 2]).is_err());
}

// A fixed pseudo-random input never panics any decoder.
#[test]
fn random_input_never_panics() {
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..5000 {
        let len = (next() % 64) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        let _ = range_response(&bytes);
        let _ = watch_response(&bytes);
        let _ = lease_time_to_live_response(&bytes);
        let _ = authenticate_response(&bytes);
    }
}

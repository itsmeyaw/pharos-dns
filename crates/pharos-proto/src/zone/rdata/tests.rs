use super::*;

#[test]
fn located_errors_identify_common_fields() {
    let origin = "example.".parse::<Name>().unwrap();
    for (rtype, fields, expected) in [
        (Type::A, vec!["999.1.1.1"], 0),
        (Type::MX, vec!["bad", "example."], 0),
        (Type::MX, vec!["10", "bad..name"], 1),
        (Type::SOA, vec![".", ".", "1", "2", "bad", "4", "5"], 4),
        (Type::DNSKEY, vec!["257", "3", "8", "AQID", "!!!!"], 4),
        (Type::SVCB, vec!["1", ".", "port=443", "ipv4hint=bad"], 3),
        (Type::SRV, vec!["1", "2", "3"], 3),
    ] {
        assert_eq!(
            parse_rdata_located(rtype, &fields, &[], &[], &origin, None)
                .unwrap_err()
                .0,
            expected
        );
    }
}

// RFC 1982 §3.2: Serial comparisons are undefined at the half-range boundary.
#[test]
fn signature_timestamp_serial_window_rejects_half_range() {
    let now = 100_i64;
    let half_range = 1_i64 << 31;
    assert_eq!(
        timestamp_serial_at(now + half_range - 1, now),
        Ok((now + half_range - 1) as u32)
    );
    assert!(timestamp_serial_at(now + half_range, now).is_err());
    assert!(timestamp_serial_at(now + half_range + 1, now).is_err());
    assert_eq!(
        timestamp_serial_at(now - half_range + 1, now),
        Ok((now - half_range + 1) as u32)
    );
    assert!(timestamp_serial_at(now - half_range, now).is_err());
}

// RFC 4034 §3.1.5: Reject year-2200 presentation dates against a fixed reference time.
#[test]
fn signature_calendar_date_outside_injected_window_is_rejected() {
    assert!(timestamp_at("22000101000000", 1_000_000_000).is_err());
}

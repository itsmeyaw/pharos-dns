use super::*;

#[test]
fn missing_and_extra_fields_report_the_boundary() {
    let origin = "example.".parse().unwrap();
    for (rtype, fields, expected) in [
        (Type::PX, &[][..], 0),
        (Type::PX, &["1", "host"][..], 2),
        (Type::PX, &["1", "host", ".", "extra"][..], 3),
        (Type::KEY, &["1", "3"][..], 2),
        (Type::SIG, &["A", "8"][..], 2),
    ] {
        assert_eq!(
            parse(rtype, fields, &[], &[], &origin, None)
                .unwrap()
                .unwrap_err()
                .0,
            expected,
            "{rtype}"
        );
    }
}

#[test]
fn oversized_and_fragmented_data_report_the_responsible_field() {
    let origin = "example.".parse().unwrap();
    let hex = "AA".repeat(65535);
    let b64 = "AAAA".repeat(21845);
    let long = "x".repeat(255);
    for (rtype, fields, expected) in [
        (Type::EID, &[hex.as_str(), "AA"][..], 1),
        (Type::DHCID, &[b64.as_str(), "AAAA"][..], 1),
        (Type::DHCID, &["AQ==", "AAAA"][..], 0),
        (Type::ISDN, &["x", long.as_str(), "x"][..], 2),
    ] {
        assert_eq!(
            parse(rtype, fields, &[], &[], &origin, None)
                .unwrap()
                .unwrap_err()
                .0,
            expected,
            "{rtype}"
        );
    }
}

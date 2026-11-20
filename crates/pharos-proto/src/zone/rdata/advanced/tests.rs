use super::*;

// RFC 1035 §3.2.1: RDLENGTH limits RDATA to 65535 octets.
#[test]
fn oversized_rdata_points_to_the_crossing_field() {
    let origin: Name = ".".parse().unwrap();
    let huge_hex = "ab".repeat(65_536);
    let hip = ["2", huge_hex.as_str(), "AQID", "extra."];
    assert_eq!(
        parse(Type::HIP, &hip, &[], &[], &origin)
            .unwrap()
            .unwrap_err()
            .0,
        1
    );
    let tkey_hex = "ab".repeat(65_535);
    let tkey = [".", "65535", tkey_hex.as_str(), "1", "ff"];
    assert_eq!(
        parse(Type::TKEY, &tkey, &[], &[], &origin)
            .unwrap()
            .unwrap_err()
            .0,
        2
    );
    let huge_base64 = "AAAA".repeat(21_845);
    let cert = ["PKIX", "1", "8", huge_base64.as_str(), "AAAA"];
    assert_eq!(
        parse(Type::CERT, &cert, &[], &[], &origin)
            .unwrap()
            .unwrap_err()
            .0,
        3
    );
    let apl = vec!["1:0.0.0.0/0"; 16_385];
    assert_eq!(
        parse(Type::APL, &apl, &[], &[], &origin)
            .unwrap()
            .unwrap_err()
            .0,
        16_383
    );
}

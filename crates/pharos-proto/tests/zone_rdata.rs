use pharos_proto::{Name, Type, zone::parse_rdata};

#[test]
fn rdata_errors_expose_field_and_preserve_messages() {
    use pharos_proto::zone::RdataParseError;
    let origin: Name = "example.".parse().unwrap();
    let error = parse_rdata(Type::A, &["invalid"], &origin).unwrap_err();
    assert!(matches!(
        &error,
        RdataParseError::InvalidField { field: 0, .. }
    ));
    assert_eq!(error.to_string(), "invalid IPv4 address");
    let error = parse_rdata(Type::MX, &[], &origin).unwrap_err();
    assert!(matches!(
        &error,
        RdataParseError::MissingField { field: 0, .. }
    ));
    assert_eq!(error.to_string(), "missing RDATA");
}

fn parse(rtype: Type, fields: &[&str]) -> Result<Vec<u8>, pharos_proto::zone::RdataParseError> {
    parse_rdata(rtype, fields, &"example.".parse::<Name>().unwrap())
}

#[test]
fn addresses_and_names() {
    assert_eq!(parse(Type::A, &["192.0.2.1"]).unwrap(), [192, 0, 2, 1]);
    assert_eq!(
        parse(Type::AAAA, &["::1"]).unwrap(),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(parse(Type::NS, &["ns"]).unwrap(), b"\x02ns\x07example\x00");
    assert_eq!(
        parse(Type::MX, &["10", "@"]).unwrap(),
        b"\x00\x0a\x07example\x00"
    );
    assert!(parse(Type::A, &["192.0.2.999"]).is_err());
    assert!(parse(Type::NS, &[]).is_err());
    assert!(parse(Type::MX, &["65536", "@"]).is_err());
}

#[test]
fn character_strings_and_escapes() {
    assert_eq!(
        parse(Type::TXT, &[r"hi\032there", r"\255\;"]).unwrap(),
        b"\x08hi there\x02\xff;"
    );
    assert_eq!(
        parse(Type::HINFO, &["cpu", "os"]).unwrap(),
        b"\x03cpu\x02os"
    );
    assert_eq!(
        parse(Type::CAA, &["128", "issue", "example.org"]).unwrap(),
        b"\x80\x05issueexample.org"
    );
    assert_eq!(
        parse(Type::URI, &["1", "2", "https://x"]).unwrap(),
        b"\x00\x01\x00\x02https://x"
    );
    assert!(parse(Type::TXT, &[]).is_err());
    assert_eq!(parse(Type::TXT, &[r"\999"]).unwrap(), [1, 231]);
    assert_eq!(parse(Type::TXT, &[&"a".repeat(256)]).unwrap().len(), 258);
    assert_eq!(parse(Type::HINFO, &["cpu"]).unwrap(), b"\x03cpu\0");
}

#[test]
fn generic_rdata_and_binary_security_fields() {
    assert_eq!(
        parse(Type(65000), &[r"\#", "4", "DEad", "beEF"]).unwrap(),
        [0xde, 0xad, 0xbe, 0xef]
    );
    assert!(parse(Type::A, &[r"\#", "0"]).unwrap().is_empty());
    assert_eq!(
        parse(Type::DS, &["1234", "8", "2", "ABCD"]).unwrap(),
        [4, 210, 8, 2, 0xab, 0xcd]
    );
    assert_eq!(
        parse(Type::DNSKEY, &["257", "3", "8", "AQID", "BA=="]).unwrap(),
        [1, 1, 3, 8, 1, 2, 3, 4]
    );
    assert_eq!(
        parse(Type::TLSA, &["3", "1", "1", "DEAD"]).unwrap(),
        [3, 1, 1, 0xde, 0xad]
    );
    assert!(parse(Type::A, &[r"\#", "3", "dead"]).is_err());
    assert!(parse(Type::DS, &["1", "8", "2", "XYZ"]).is_err());
    assert!(parse(Type::DNSKEY, &["257", "3", "8", "A==="]).is_err());
}

#[test]
fn structured_rdata() {
    assert_eq!(
        parse(Type::SRV, &["1", "2", "443", "target."]).unwrap(),
        b"\x00\x01\x00\x02\x01\xbb\x06target\x00"
    );
    assert_eq!(
        parse(Type::NAPTR, &["1", "2", "s", "SIP", "", "."]).unwrap(),
        b"\x00\x01\x00\x02\x01s\x03SIP\x00\x00"
    );
    assert_eq!(parse(Type::SOA, &["@", "@", "1", "2", "3", "4", "5"]).unwrap(), b"\x07example\x00\x07example\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05");
    assert_eq!(
        parse(Type::NSEC, &["next.", "A", "NS", "RRSIG", "TYPE257"]).unwrap(),
        b"\x04next\x00\x00\x06\x60\x00\x00\x00\x00\x02\x01\x01\x40"
    );
    assert_eq!(
        parse(Type::NSEC3PARAM, &["1", "0", "12", "-"]).unwrap(),
        [1, 0, 0, 12, 0]
    );
    assert!(parse(Type::NSEC, &["next.", "not-a-type"]).is_err());
    assert!(parse(Type::SRV, &["1", "2", "3", ".", "extra"]).is_err());
}

#[test]
fn soa_timers_accept_ttl_units() {
    let actual = parse(Type::SOA, &["@", "@", "42", "1h30m", "5m", "2w", "60s"]).unwrap();
    let expected = parse(Type::SOA, &["@", "@", "42", "5400", "300", "1209600", "60"]).unwrap();
    assert_eq!(actual, expected);
    assert!(parse(Type::SOA, &["@", "@", "1h", "1", "2", "3", "4"]).is_err());
    assert!(parse(Type::SOA, &["@", "@", "1", "999999999w", "2", "3", "4"]).is_err());
}

#[test]
fn signatures_and_nsec3_hashes() {
    assert_eq!(parse(Type::RRSIG, &["A", "8", "2", "3600", "0", "1", "123", "example.", "AQID"]).unwrap(), b"\x00\x01\x08\x02\x00\x00\x0e\x10\x00\x00\x00\x00\x00\x00\x00\x01\x00\x7b\x07example\x00\x01\x02\x03");
    assert_eq!(
        parse(Type::NSEC3, &["1", "0", "1", "AABB", "00", "A"]).unwrap(),
        [1, 0, 0, 1, 2, 0xaa, 0xbb, 20, 0, 0, 1, 0x40]
    );
    assert!(parse(Type::NSEC3, &["1", "0", "1", "-", "!"]).is_err());
}

#[test]
fn svcb_parameters_are_encoded_in_key_order() {
    assert_eq!(parse(Type::HTTPS, &["1", ".", "port=443", "alpn=h2,h3", "ipv4hint=192.0.2.1"]).unwrap(), b"\x00\x01\x00\x00\x01\x00\x06\x02h2\x02h3\x00\x03\x00\x02\x01\xbb\x00\x04\x00\x04\xc0\x00\x02\x01");
    assert_eq!(parse(Type::SVCB, &["1", ".", "mandatory=alpn,port", "alpn=h2", "port=443"]).unwrap(), b"\x00\x01\x00\x00\x00\x00\x04\x00\x01\x00\x03\x00\x01\x00\x03\x02h2\x00\x03\x00\x02\x01\xbb");
    assert_eq!(
        parse(Type::SVCB, &["1", ".", r"alpn=h2\\\044h3"]).unwrap(),
        b"\x00\x01\x00\x00\x01\x00\x06\x05h2,h3"
    );
    assert!(parse(Type::SVCB, &["1", ".", r"key1=\002h2"]).is_err());
    assert!(parse(Type::SVCB, &["1", ".", r"key1=bad"]).is_err());
    assert!(parse(Type::HTTPS, &["1", ".", "port=443", "port=80"]).is_err());
    assert_eq!(
        parse(Type::HTTPS, &["1", ".", "mandatory=port"]).unwrap(),
        b"\x00\x01\x00\x00\x00\x00\x02\x00\x03"
    );
    assert!(parse(Type::HTTPS, &["1", ".", "no-default-alpn=x"]).is_err());
    assert!(parse(Type::HTTPS, &["1", ".", "ipv6hint=::ffff:192.0.2.1"]).is_err());
}

#[test]
fn tsig_and_validation() {
    assert_eq!(
        parse(
            Type::TSIG,
            &[
                "hmac.",
                "19700101000001",
                "300",
                "2",
                "AABB",
                "42",
                "0",
                "0",
                ""
            ]
        )
        .unwrap(),
        b"\x04hmac\x00\x00\x00\x00\x00\x00\x01\x01\x2c\x00\x02\xaa\xbb\x00\x2a\x00\x00\x00\x00"
    );
    assert!(
        parse(
            Type::TSIG,
            &["hmac.", "1", "300", "3", "AABB", "42", "0", "0", ""]
        )
        .is_err()
    );
    assert_eq!(
        parse(Type::CAA, &["0", "bad-tag", "x"]).unwrap(),
        b"\0\x07bad-tagx"
    );
    assert_eq!(parse(Type::NSEC, &["next."]).unwrap(), b"\x04next\0");
    assert_eq!(
        parse(Type::ZONEMD, &["1", "1", "1", "ABCD"]).unwrap(),
        [0, 0, 0, 1, 1, 1, 0xab, 0xcd]
    );
    assert_eq!(
        parse(Type::TSIG, &["hmac.", "1", "300", "0", "42", "0", "0"]).unwrap(),
        b"\x04hmac\x00\x00\x00\x00\x00\x00\x01\x01\x2c\x00\x00\x00\x2a\x00\x00\x00\x00"
    );
}

#[test]
fn related_record_families_and_dnssec_dates() {
    assert_eq!(
        parse(Type::DNAME, &["target"]).unwrap(),
        b"\x06target\x07example\0"
    );
    assert_eq!(parse(Type::SPF, &["v=spf1"]).unwrap(), b"\x06v=spf1");
    assert_eq!(
        parse(Type::SMIMEA, &["3", "1", "1", "AB"]).unwrap(),
        [3, 1, 1, 0xab]
    );
    assert_eq!(
        parse(Type::CDS, &["1", "8", "2", "AABB"]).unwrap(),
        [0, 1, 8, 2, 0xaa, 0xbb]
    );
    assert_eq!(
        parse(Type::CDNSKEY, &["257", "3", "8", "AQID"]).unwrap(),
        [1, 1, 3, 8, 1, 2, 3]
    );
    assert_eq!(
        parse(Type::SSHFP, &["1", "2", "ABCD"]).unwrap(),
        [1, 2, 0xab, 0xcd]
    );
    assert_eq!(
        parse(Type::ZONEMD, &["1", "1", "1", "000102030405060708090A0B"]).unwrap(),
        [0, 0, 0, 1, 1, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    );
    assert_eq!(
        parse(
            Type::RRSIG,
            &[
                "A",
                "8",
                "2",
                "3600",
                "19700101000000",
                "19700101000001",
                "123",
                "example.",
                "AQID"
            ]
        )
        .unwrap(),
        parse(
            Type::RRSIG,
            &["A", "8", "2", "3600", "0", "1", "123", "example.", "AQID"]
        )
        .unwrap()
    );
    assert!(
        parse(
            Type::RRSIG,
            &["A", "8", "2", "1", "20230229000000", "0", "1", ".", "AQID"]
        )
        .is_err()
    );
}

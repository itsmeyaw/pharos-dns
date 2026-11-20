use std::time::{Duration, UNIX_EPOCH};

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, KeyPair, UnparsedPublicKey};

use super::{
    BIT_STRING, CONTEXT_0, DNS_NAME, GENERALIZED_TIME, Reader, SEQUENCE, UTC_TIME, certificate_key,
    csr, generate_certificate_key, time, tlv, validity,
};

// ITU-T X.690 §8.1.3: short form below 128 octets, long form with a length-of-length above.
#[test]
fn lengths_use_the_short_and_long_forms() {
    assert_eq!(tlv(4, &[1, 2]), [4, 2, 1, 2]);
    assert_eq!(&tlv(4, &[0; 127])[..2], [4, 127]);
    assert_eq!(&tlv(4, &[0; 128])[..3], [4, 0x81, 128]);
    assert_eq!(&tlv(4, &[0; 300])[..4], [4, 0x82, 1, 44]);
    let element = tlv(4, &[7; 300]);
    let mut reader = Reader::new(&element);
    let (tag, content, whole) = reader.next().unwrap();
    assert_eq!((tag, content.len(), whole.len()), (4, 300, 304));
    assert!(reader.next().is_none());
}

// RFC 2986 §4.2: the signature covers the CertificationRequestInfo; RFC 8555 §7.4: SANs carry the identifiers.
#[test]
fn csr_is_signed_and_lists_every_name() {
    let pkcs8 = generate_certificate_key().unwrap();
    let key = certificate_key(&pkcs8).unwrap();
    let names = ["dns.example".to_owned(), "*.dns.example".to_owned()];
    let der = csr(&key, &names).unwrap();

    let mut outer = Reader::new(Reader::new(&der).expect(SEQUENCE).unwrap());
    let (_, info, whole_info) = outer.next().unwrap();
    outer.expect(SEQUENCE).unwrap();
    let bits = outer.expect(BIT_STRING).unwrap();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key.public_key().as_ref())
        .verify(whole_info, &bits[1..])
        .unwrap();

    let mut info = Reader::new(info);
    assert_eq!(info.expect(super::INTEGER).unwrap(), [0]);
    let subject = info.expect(SEQUENCE).unwrap();
    assert!(subject.windows(11).any(|window| window == b"dns.example"));
    info.expect(SEQUENCE).unwrap();
    let attributes = info.expect(CONTEXT_0).unwrap();
    for name in names {
        let entry = tlv(DNS_NAME, name.as_bytes());
        assert!(
            attributes
                .windows(entry.len())
                .any(|window| window == entry)
        );
    }
}

// RFC 5280 §4.1.2.5.1: UTCTime years 50 to 99 are 19YY and 00 to 49 are 20YY; §4.1.2.5.2: GeneralizedTime has four digits.
#[test]
fn times_decode_both_encodings() {
    let at = |seconds| UNIX_EPOCH + Duration::from_secs(seconds);
    assert_eq!(time(UTC_TIME, b"700101000000Z"), Some(at(0)));
    assert_eq!(time(UTC_TIME, b"251120120000Z"), Some(at(1_763_640_000)));
    assert_eq!(
        time(GENERALIZED_TIME, b"20251120120000Z"),
        Some(at(1_763_640_000))
    );
    assert_eq!(
        time(GENERALIZED_TIME, b"20000229235959Z"),
        Some(at(951_868_799))
    );
    assert_eq!(time(UTC_TIME, b"251320120000Z"), None);
    assert_eq!(time(UTC_TIME, b"2511201200Z"), None);
    assert_eq!(time(UTC_TIME, "25112012000é Z".as_bytes()), None);
    assert_eq!(time(UTC_TIME, "2511201200éZ".as_bytes()), None);
}

#[test]
fn validity_is_read_from_a_certificate() {
    let pem = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/tls/server.pem"
    ))
    .unwrap();
    let der = super::super::store::pem_blocks(&pem).remove(0).1;
    let period = validity(&der).unwrap();
    assert!(period.not_before < period.not_after);
    assert!(validity(b"junk").is_none());
}

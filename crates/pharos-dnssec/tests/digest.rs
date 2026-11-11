use base64::{Engine, engine::general_purpose::STANDARD};
use pharos_dnssec::digest::{
    DigestType, cdnskey_rdata, cds_rdata, ds_digest, key_tag, signature_valid_at,
};
use pharos_proto::Name;

#[test]
fn rfc_4509_dnskey_and_ds_vector() {
    let key = STANDARD
        .decode(concat!(
            "AQOeiiR0GOMYkDshWoSKz9Xz",
            "fwJr1AYtsmx3TGkJaNXVbfi/",
            "2pHm822aJ5iI9BMzNXxeYCmZ",
            "DRD99WYwYqUSdjMmmAphXdvx",
            "egXd/M5+X7OrzKBaMbCVdFLU",
            "Uh6DhweJBjEVv5f2wwjM9Xzc",
            "nOf+EPbtG9DMBmADjFDc2w/r",
            "ljwvFw=="
        ))
        .unwrap();
    let mut rdata = vec![1, 0, 3, 5];
    rdata.extend(key);
    assert_eq!(key_tag(&rdata), Some(60485));
    let owner: Name = "DSKEY.Example.COM.".parse().unwrap();
    assert_eq!(cdnskey_rdata(&rdata).unwrap(), rdata);
    let cds = cds_rdata(&owner, &rdata, DigestType::Sha256).unwrap();
    assert_eq!(&cds[..4], &[0xec, 0x45, 5, 2]);
    assert_eq!(&cds[4..], ds_digest(&owner, &rdata, DigestType::Sha256));
    assert_eq!(cds_rdata(&owner, &[0, 0, 3], DigestType::Sha1), None);
    assert_eq!(
        ds_digest(&owner, &rdata, DigestType::Sha1),
        [
            0x2b, 0xb1, 0x83, 0xaf, 0x5f, 0x22, 0x58, 0x81, 0x79, 0xa5, 0x3b, 0x0a, 0x98, 0x63,
            0x1f, 0xad, 0x1a, 0x29, 0x21, 0x18
        ]
    );
    assert_eq!(
        ds_digest(&owner, &rdata, DigestType::Sha384),
        [
            0xab, 0x64, 0xdb, 0xeb, 0xe1, 0x3c, 0x0b, 0x6b, 0xae, 0x55, 0x8b, 0x78, 0xcc, 0xab,
            0x93, 0xb8, 0x36, 0xf8, 0xad, 0xa4, 0xcb, 0xed, 0x2d, 0x44, 0x84, 0xa8, 0x71, 0x5a,
            0x81, 0x9d, 0xe7, 0xb9, 0xe8, 0x46, 0x31, 0x5e, 0x70, 0xea, 0x5d, 0x88, 0x4b, 0x37,
            0x73, 0x94, 0xbd, 0xaf, 0x16, 0xa3,
        ]
    );
    assert_eq!(
        ds_digest(&owner, &rdata, DigestType::Sha256),
        [
            0xd4, 0xb7, 0xd5, 0x20, 0xe7, 0xbb, 0x5f, 0x0f, 0x67, 0x67, 0x4a, 0x0c, 0xce, 0xb1,
            0xe3, 0xe0, 0x61, 0x4b, 0x93, 0xc4, 0xf9, 0xe9, 0x9b, 0x83, 0x83, 0xf6, 0xa1, 0xe4,
            0x46, 0x9d, 0xa5, 0x0a,
        ]
    );
}

#[test]
fn key_tag_handles_rsa_md5_and_bad_lengths() {
    assert_eq!(key_tag(&[0, 0, 3]), None);
    assert_eq!(key_tag(&[0, 0, 3, 1, 0x12, 0x34, 0x56]), Some(0x1234));
    assert_eq!(key_tag(&[0; 65536]), None);
}

#[test]
fn signature_windows_wrap_and_include_endpoints() {
    assert!(signature_valid_at(u32::MAX - 5, 5, u32::MAX - 5));
    assert!(signature_valid_at(u32::MAX - 5, 5, 0));
    assert!(signature_valid_at(u32::MAX - 5, 5, 5));
    assert!(!signature_valid_at(u32::MAX - 5, 5, 6));
    assert!(!signature_valid_at(10, 20, 9));
    assert!(!signature_valid_at(0, 1 << 31, 1));
}

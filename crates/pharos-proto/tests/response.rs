use pharos_proto::{
    Class, Message, MessageBuilder, NameRef, ResponseClass, ResponseType, Section, Type,
    classify_response, typify_response,
};

fn response(flags: u16, qtype: Type, records: &[(Section, Type, &[u8])], do_bit: bool) -> Vec<u8> {
    let mut wire = Vec::new();
    let root = NameRef::parse(&[0], 0).unwrap();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, flags).unwrap();
    builder.question(root, qtype, Class::IN).unwrap();
    for &(section, rtype, data) in records {
        builder
            .record(section, root, rtype, Class::IN, 60, data)
            .unwrap();
    }
    if do_bit {
        builder
            .record(
                Section::Additional,
                root,
                Type::OPT,
                Class(1232),
                0x8000,
                &[],
            )
            .unwrap();
    }
    let _ = builder.finish();
    wire
}

fn typify(wire: &[u8], now: i64) -> ResponseType {
    typify_response(Some(&Message::parse(wire).unwrap()), now)
}

#[test]
fn response_types_and_classes_follow_coredns() {
    use ResponseClass::{Denial, Error, Success};
    use ResponseType::{
        Meta, NoData, NxDomain, OtherError, Positive, Referral, ServerError, Update,
    };
    assert_eq!(typify_response(None, 100), OtherError);
    let ns = [(Section::Authority, Type::NS, &b"\0"[..])];
    let soa = [(Section::Authority, Type::SOA, &b""[..])];
    let answer = [(Section::Answer, Type::A, &b"\x7f\0\0\x01"[..])];
    for (flags, qtype, records, expected, class) in [
        (0x8000, Type::A, &[][..], Positive, Success),
        (0x8000, Type::A, &answer[..], Positive, Success),
        (0x8000, Type::A, &ns[..], Referral, Success),
        (0x8000, Type::A, &soa[..], NoData, Denial),
        (0x8003, Type::A, &[][..], NxDomain, Denial),
        (0x8003, Type::A, &answer[..], OtherError, Error),
        (0x8002, Type::A, &[][..], ServerError, Error),
        (0x8004, Type::A, &[][..], ServerError, Error),
        (0x8005, Type::A, &[][..], OtherError, Error),
        (0xa000, Type::A, &[][..], Meta, Error),
        (0xa800, Type::A, &[][..], Update, Error),
        (0x8000, Type::AXFR, &[][..], Meta, Error),
        (0x8000, Type::IXFR, &[][..], Meta, Error),
    ] {
        let wire = response(flags, qtype, records, false);
        assert_eq!(typify(&wire, 100), expected, "flags={flags:x}");
        assert_eq!(classify_response(expected), class);
    }
}

#[test]
fn dnssec_signature_validity_is_checked_only_with_do() {
    // RRSIG inception 50, expiration 150, root signer, empty signature.
    let sig = b"\0\x02\x08\0\0\0\0\x3c\0\0\0\x96\0\0\0\x32\0\x01\0";
    for section in [Section::Answer, Section::Authority, Section::Additional] {
        let records = [(section, Type::RRSIG, &sig[..])];
        let wire = response(0x8000, Type::A, &records, true);
        assert_ne!(typify(&wire, 100), ResponseType::OtherError);
        assert_ne!(typify(&wire, 50), ResponseType::OtherError);
        assert_ne!(typify(&wire, 150), ResponseType::OtherError);
        assert_eq!(typify(&wire, 151), ResponseType::OtherError);
        assert_eq!(typify(&wire, 49), ResponseType::OtherError);
        let wire = response(0x8000, Type::A, &records, false);
        assert_ne!(typify(&wire, 151), ResponseType::OtherError);
    }
}

#[test]
fn malformed_dnssec_signature_is_not_classified_as_cacheable() {
    let sig = b"\0\x02\x08\0\0\0\0\x3c\0\0\0\x96\0\0\0\x32";
    let records = [(Section::Answer, Type::RRSIG, &sig[..])];
    let wire = response(0x8000, Type::A, &records, true);
    assert_eq!(typify(&wire, 100), ResponseType::OtherError);
}

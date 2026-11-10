use pharos_proto::{Class, Opcode, Rcode, Type};

#[test]
fn known_codes_have_miekg_presentation_names() {
    assert_eq!(Opcode::QUERY.to_string(), "QUERY");
    assert_eq!(Rcode::NXDOMAIN.to_string(), "NXDOMAIN");
    assert_eq!(Class::IN.to_string(), "IN");
    assert_eq!(Type::AAAA.to_string(), "AAAA");
}

#[test]
fn presentation_matches_miekg_special_cases() {
    assert_eq!(Type::NONE.to_string(), "None");
    assert_eq!(Type::RESERVED.to_string(), "Reserved");
    assert_eq!(Type::NSAP_PTR.to_string(), "NSAP-PTR");
    assert_eq!(Class::NONE.to_string(), "NONE");
    assert_eq!(Class::ANY.to_string(), "CLASS255");
    assert_eq!(Rcode::BADVERS, Rcode::BADSIG);
    assert_eq!(Rcode::BADVERS.to_string(), "BADSIG");
}

#[test]
fn unknown_values_are_preserved_and_printed_numerically() {
    assert_eq!(Opcode(15).to_string(), "OPCODE15");
    assert_eq!(Opcode::STATEFUL.to_string(), "OPCODE6");
    assert_eq!(Rcode(4095).to_string(), "RCODE4095");
    assert_eq!(Class(65535).to_string(), "CLASS65535");
    assert_eq!(Type(65534).to_string(), "TYPE65534");
    assert_eq!(Type(11).to_string(), "TYPE11");
}

#[test]
fn extended_rcode_combines_opt_and_header_bits() {
    assert_eq!(Rcode::from_parts(0, 1), Rcode::BADVERS);
    assert_eq!(Rcode::from_parts(3, 0), Rcode::NXDOMAIN);
    assert_eq!(Rcode::from_parts(0xff, 0xff), Rcode(4095));
}

#[test]
fn standard_and_extended_codes_have_expected_values() {
    let opcodes = [
        (Opcode::IQUERY, 1),
        (Opcode::STATUS, 2),
        (Opcode::NOTIFY, 4),
        (Opcode::UPDATE, 5),
    ];
    for (code, value) in opcodes {
        assert_eq!(code.0, value);
    }

    let rcodes = [
        (Rcode::NOERROR, "NOERROR"),
        (Rcode::FORMERR, "FORMERR"),
        (Rcode::SERVFAIL, "SERVFAIL"),
        (Rcode::NOTIMP, "NOTIMP"),
        (Rcode::REFUSED, "REFUSED"),
        (Rcode::YXDOMAIN, "YXDOMAIN"),
        (Rcode::YXRRSET, "YXRRSET"),
        (Rcode::NXRRSET, "NXRRSET"),
        (Rcode::NOTAUTH, "NOTAUTH"),
        (Rcode::NOTZONE, "NOTZONE"),
        (Rcode::DSOTYPENI, "DSOTYPENI"),
        (Rcode::BADKEY, "BADKEY"),
        (Rcode::BADTIME, "BADTIME"),
        (Rcode::BADMODE, "BADMODE"),
        (Rcode::BADNAME, "BADNAME"),
        (Rcode::BADALG, "BADALG"),
        (Rcode::BADTRUNC, "BADTRUNC"),
        (Rcode::BADCOOKIE, "BADCOOKIE"),
    ];
    for (code, expected) in rcodes {
        assert_eq!(code.to_string(), expected);
    }

    for (code, expected) in [(Class::CS, "CS"), (Class::CH, "CH"), (Class::HS, "HS")] {
        assert_eq!(code.to_string(), expected);
    }
    for (code, expected) in [
        (Type::A, "A"),
        (Type::OPT, "OPT"),
        (Type::DNSKEY, "DNSKEY"),
        (Type::HTTPS, "HTTPS"),
        (Type::NXNAME, "NXNAME"),
        (Type::IXFR, "IXFR"),
        (Type::ANY, "ANY"),
        (Type::RESINFO, "RESINFO"),
        (Type::DLV, "DLV"),
    ] {
        assert_eq!(code.to_string(), expected);
    }
}

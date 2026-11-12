#![forbid(unsafe_code)]

use std::{
    fs::{self, File},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use pharos_proto::{Name, zone::ZoneParser};

struct Case {
    name: String,
    origin: &'static str,
    zone: Vec<u8>,
}

fn case(name: impl Into<String>, origin: &'static str, zone: impl Into<Vec<u8>>) -> Case {
    Case {
        name: name.into(),
        origin,
        zone: zone.into(),
    }
}

// miekg/dns ztypes.go TypeToRR at b2d6c9f, including types with no text format.
const MIEKG_REGISTERED_TYPES: [u16; 80] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28,
    29, 30, 31, 32, 33, 35, 36, 37, 39, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 55, 56,
    57, 58, 59, 60, 61, 62, 63, 64, 65, 99, 100, 101, 102, 104, 105, 106, 107, 108, 109, 128, 249,
    250, 255, 256, 257, 258, 260, 261, 32768, 32769,
];

fn generic_case(ty: u16, kind: &str, length: usize, hex: &str) -> Case {
    case(
        format!("generic-{ty}-{kind}"),
        "example.",
        format!("record.example. 60 IN TYPE{ty} \\# {length} {hex}\n").into_bytes(),
    )
}

fn generic_cases() -> Vec<Case> {
    let mut result = Vec::new();
    // RFC 3597 §5 and RFC 1035 §4.1.4: known types must not bypass wire decoding.
    for ty in MIEKG_REGISTERED_TYPES {
        for (kind, length, hex) in [
            ("empty", 0, ""),
            ("octet", 1, "00"),
            ("pointer-self", 2, "c000"),
            ("pointer-forward", 5, "c002016100"),
            ("truncated-pointer", 1, "c0"),
            ("bad-length", 2, "ff"),
            ("bad-hex", 1, "zz"),
        ] {
            result.push(generic_case(ty, kind, length, hex));
        }
    }
    // RFC 6891 §6.1.2: OPT RDATA is a sequence of length-prefixed options.
    for (kind, hex) in [
        ("edns-unknown", "fde80002abcd"),
        ("edns-subnet", "0008000700011800c00002"),
        ("edns-subnet-host-bits", "0008000800011900c0000281"),
        ("edns-subnet-short-address", "0008000400012000"),
        ("edns-subnet-extra-address", "0008000800011800c00002ff"),
        ("edns-keepalive-zero", "000b00020000"),
        ("edns-keepalive-short", "000b000100"),
        ("edns-expire-extra", "000900050000000100"),
        ("edns-ede-nonutf8", "000f00030001ff"),
        ("edns-truncated", "fde80004abcd"),
        ("edns-multiple", "fde80002abcd000c0002aabb"),
    ] {
        result.push(generic_case(41, kind, hex.len() / 2, hex));
    }
    result.push(generic_case(15, "mx-pointer-forward", 7, "000ac004016100"));
    // RFC 1035 §4.2.2: even valid RDATA cannot fit a message if the whole RR exceeds 65535 bytes.
    let long_txt = format!(
        "{}fd{}",
        format!("ff{}", "61".repeat(255)).repeat(255),
        "61".repeat(253)
    );
    result.push(generic_case(
        16,
        "oversized-txt",
        long_txt.len() / 2,
        &long_txt,
    ));
    result
}

fn generic_mutations(cases: &[Case], results: &[String]) -> Vec<Case> {
    assert_eq!(cases.len(), results.len());
    let mut generated = Vec::new();
    for (case, result) in cases.iter().zip(results) {
        if !case.name.starts_with("rr-valid-") {
            continue;
        }
        let mut lines = result.lines();
        assert_eq!(lines.next(), Some("accept"), "{}: {result}", case.name);
        let fields: Vec<_> = lines
            .next()
            .expect("missing Go record")
            .split('\t')
            .collect();
        assert_eq!(fields.len(), 5, "{}: {result}", case.name);
        assert!(lines.next().is_none(), "{}: {result}", case.name);
        let ty: u16 = fields[3].parse().unwrap();
        let wire = fields[4];
        assert!(wire.len().is_multiple_of(2), "{}: {result}", case.name);
        let len = wire.len() / 2;
        generated.push(generic_case(ty, "derived-valid", len, wire));
        if len > 0 {
            generated.push(generic_case(
                ty,
                "derived-truncated",
                len - 1,
                &wire[..wire.len() - 2],
            ));
            let byte = u8::from_str_radix(&wire[..2], 16).unwrap() ^ 0xff;
            generated.push(generic_case(
                ty,
                "derived-flipped",
                len,
                &format!("{byte:02x}{}", &wire[2..]),
            ));
        }
        generated.push(generic_case(
            ty,
            "derived-extra",
            len + 1,
            &format!("{wire}00"),
        ));
        if len >= 2 {
            generated.push(generic_case(
                ty,
                "derived-pointer",
                len,
                &format!("c000{}", &wire[4..]),
            ));
        }
    }
    generated
}

#[test]
fn generic_rdata_covers_registered_types() {
    let generated = generic_cases();
    let names: std::collections::HashSet<_> =
        generated.iter().map(|case| case.name.as_str()).collect();
    assert_eq!(names.len(), generated.len(), "duplicate generic cases");
    for ty in MIEKG_REGISTERED_TYPES {
        for kind in [
            "empty",
            "octet",
            "pointer-self",
            "pointer-forward",
            "truncated-pointer",
            "bad-length",
            "bad-hex",
        ] {
            assert!(
                names.contains(format!("generic-{ty}-{kind}").as_str()),
                "missing TYPE{ty} {kind}"
            );
        }
    }
}

#[test]
fn generic_mutations_use_reference_wire_bytes() {
    let input = [case("rr-valid-NS", ".", b"ignored".as_slice())];
    let reference = ["accept\n00\t60\t1\t2\t016100\n".to_owned()];
    let mutations = generic_mutations(&input, &reference);
    let expected = [
        ("derived-valid", "3 016100"),
        ("derived-truncated", "2 0161"),
        ("derived-flipped", "3 fe6100"),
        ("derived-extra", "4 01610000"),
        ("derived-pointer", "3 c00000"),
    ];
    for (kind, rdata) in expected {
        let name = format!("generic-2-{kind}");
        let found = mutations
            .iter()
            .find(|case| case.name == name)
            .expect(&name);
        assert_eq!(
            found.zone,
            format!("record.example. 60 IN TYPE2 \\# {rdata}\n").as_bytes()
        );
    }
}

// RFC 1035 §3.1: labels are octet strings, including names embedded in RDATA.
const BYTE_NAME_CONTEXTS: [(&str, &[u8], &[u8]); 11] = [
    ("owner", b"", b".example. 60 IN A 192.0.2.1\n"),
    ("ns", b"record.example. 60 IN NS ", b".example.\n"),
    ("cname", b"record.example. 60 IN CNAME ", b".example.\n"),
    ("ptr", b"record.example. 60 IN PTR ", b".example.\n"),
    ("mx", b"record.example. 60 IN MX 10 ", b".example.\n"),
    ("srv", b"record.example. 60 IN SRV 1 2 443 ", b".example.\n"),
    (
        "soa-mname",
        b"record.example. 60 IN SOA ",
        b".example. host.example. 1 2 3 4 5\n",
    ),
    (
        "soa-rname",
        b"record.example. 60 IN SOA ns.example. ",
        b".example. 1 2 3 4 5\n",
    ),
    ("nsec", b"record.example. 60 IN NSEC ", b".example. A NS\n"),
    (
        "rrsig",
        b"record.example. 60 IN RRSIG A 8 2 3600 0 1 123 ",
        b".example. AQID\n",
    ),
    (
        "svcb",
        b"record.example. 60 IN SVCB 1 ",
        b".example. alpn=h2\n",
    ),
];
const BYTE_NAME_SEQUENCES: [&[u8]; 6] = [
    b"\xc3\xa9",
    b"\xc0\xaf",
    b"\xe2\x28\xa1",
    b"\xed\xa0\x80",
    b"\xff\x80",
    b"\x80\xff",
];

#[test]
fn covers_raw_owner_and_target_octets() {
    let cases = cases();
    let by_name: std::collections::HashMap<_, _> = cases
        .iter()
        .map(|case| (case.name.as_str(), case))
        .collect();
    assert_eq!(by_name.len(), cases.len(), "duplicate case names");
    for (context, prefix, suffix) in BYTE_NAME_CONTEXTS {
        for octet in 128..=255_u8 {
            let name = format!("byte-{context}-{octet}");
            let matching = by_name
                .get(name.as_str())
                .unwrap_or_else(|| panic!("missing {name}"));
            let expected = [prefix, &[octet], suffix].concat();
            assert_eq!(matching.zone, expected, "raw octet changed in {name}");
            assert!(std::str::from_utf8(&matching.zone).is_err());
        }
        for (index, bytes) in BYTE_NAME_SEQUENCES.iter().enumerate() {
            let name = format!("byte-{context}-sequence-{index}");
            let matching = by_name
                .get(name.as_str())
                .unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(
                matching.zone,
                [prefix, bytes, suffix].concat(),
                "bytes changed in {name}"
            );
        }
    }
}

#[test]
fn covers_coredns_fixture_manifest() {
    macro_rules! fixtures {
        ($($name:ident => $origin:literal),* $(,)?) => {
            [$( (stringify!($name), $origin) ),*]
        };
    }
    let fixtures = include!("corpus/zone-coredns/manifest.rs");
    assert_eq!(fixtures.len(), 36, "CoreDNS fixture count");
    let cases = cases();
    for (name, origin) in fixtures {
        let case_name = format!("coredns-fixture-{name}");
        let matching: Vec<_> = cases.iter().filter(|case| case.name == case_name).collect();
        assert_eq!(matching.len(), 1, "{case_name}: missing or duplicate case");
        assert_eq!(matching[0].origin, origin, "{case_name}: origin");
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/corpus/zone-coredns")
            .join(format!("{name}.zone"));
        assert_eq!(
            matching[0].zone,
            fs::read(path).unwrap(),
            "{case_name}: zone"
        );
    }
}

#[test]
fn covers_miekg_presentation_types() {
    // miekg/dns scan_rr.go and svcb.go at b2d6c9f: textual RR parse implementations.
    let types = [
        "A",
        "AAAA",
        "NS",
        "PTR",
        "NSAP-PTR",
        "RP",
        "MR",
        "MB",
        "MG",
        "HINFO",
        "ISDN",
        "MINFO",
        "MF",
        "MD",
        "MX",
        "RT",
        "AFSDB",
        "X25",
        "KX",
        "CNAME",
        "DNAME",
        "SOA",
        "SRV",
        "NAPTR",
        "TALINK",
        "LOC",
        "HIP",
        "CERT",
        "OPENPGPKEY",
        "CSYNC",
        "ZONEMD",
        "SIG",
        "RRSIG",
        "NXT",
        "NSEC",
        "NSEC3",
        "NSEC3PARAM",
        "EUI48",
        "EUI64",
        "SSHFP",
        "DNSKEY",
        "KEY",
        "CDNSKEY",
        "DS",
        "DLV",
        "CDS",
        "IPSECKEY",
        "AMTRELAY",
        "RKEY",
        "EID",
        "NIMLOC",
        "GPOS",
        "TA",
        "TLSA",
        "SMIMEA",
        "SPF",
        "AVC",
        "TXT",
        "NINFO",
        "RESINFO",
        "URI",
        "DHCID",
        "NID",
        "L32",
        "LP",
        "L64",
        "UID",
        "GID",
        "UINFO",
        "PX",
        "CAA",
        "TKEY",
        "APL",
        "SVCB",
        "HTTPS",
        "TYPE65400",
    ];
    let cases = cases();
    let names: std::collections::HashSet<_> = cases.iter().map(|case| case.name.as_str()).collect();
    assert_eq!(names.len(), cases.len(), "duplicate case names");
    assert_eq!(
        cases
            .iter()
            .filter(|case| !case.name.starts_with("rr-") && !case.name.starts_with("byte-"))
            .count(),
        409 + 36
    );
    for rtype in types {
        for kind in ["valid", "malformed"] {
            let name = format!("rr-{kind}-{rtype}");
            assert!(names.contains(name.as_str()), "missing {name}");
        }
    }
}

fn cases() -> Vec<Case> {
    let mut cases = vec![
        case(
            "miekg",
            ".",
            include_bytes!("corpus/zone-reference/miekg.zone").as_slice(),
        ),
        case(
            "coredns",
            "example.org.",
            include_bytes!("corpus/zone-reference/coredns.zone").as_slice(),
        ),
        case(
            "coredns-escape",
            "campus.edu.",
            include_bytes!("corpus/zone-reference/coredns-escape.zone").as_slice(),
        ),
        case(
            "octets",
            "example.",
            include_bytes!("corpus/zone-reference/octets.zone").as_slice(),
        ),
        case(
            "seeded",
            "example.",
            include_bytes!("corpus/zone-reference/seeded.zone").as_slice(),
        ),
        case("empty", ".", b"".as_slice()),
        case(
            "invalid-utf8",
            "example.",
            b"a 60 IN TXT \"\xff\"\n".as_slice(),
        ),
        case(
            "include-disabled",
            "example.",
            b"$INCLUDE nonexistent.zone\n".as_slice(),
        ),
    ];
    macro_rules! fixtures {
        ($($name:ident => $origin:literal),* $(,)?) => {
            vec![$({
                let name = stringify!($name);
                let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/corpus/zone-coredns")
                    .join(format!("{name}.zone"));
                let zone = fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
                case(format!("coredns-fixture-{name}"), $origin, zone)
            }),*]
        };
    }
    cases.extend(include!("corpus/zone-coredns/manifest.rs"));
    // RFC 1035 §5.1: vary owner, class/TTL order, quoting and record grammar.
    let rdata = [
        "A 192.0.2.1",
        "AAAA 2001:db8::1",
        "NS ns.example.",
        "CNAME target",
        "MX 10 mail",
        "SRV 1 2 443 target",
        "TXT \"hello; world\" \"\\000\\255\"",
        "TYPE65400 \\# 4 00ff0180",
        "SOA ns hostmaster ( 1 2 3 4 5 )",
        "A 999.1.2.3",
        "TXT \"unterminated",
        "MX nope target",
    ];
    for (i, data) in rdata.iter().enumerate() {
        for (j, header) in ["name 60 IN", "name IN 60", "@ 1h IN", "\\255 0 IN"]
            .iter()
            .enumerate()
        {
            let zone = format!("$ORIGIN example.\n{header} {data}\n");
            cases.push(case(format!("grammar-{i}-{j}"), ".", zone.into_bytes()));
        }
    }
    for octet in 0..=255 {
        cases.push(case(
            format!("escaped-{octet}"),
            "example.",
            format!("n 1 IN TXT \"\\{octet:03}\"\n").into_bytes(),
        ));
    }
    for octet in [0, 1, 9, 10, 13, 34, 59, 92, 127, 128, 192, 255] {
        let mut zone = b"a 1 IN TXT \"".to_vec();
        zone.push(octet);
        zone.extend_from_slice(b"\"\n");
        cases.push(case(format!("raw-{octet}"), "example.", zone));
    }
    let seeds = [
        b"$TTL 3600\na IN A 192.0.2.1\n".as_slice(),
        b"a 60 IN TXT \"abc\\032xyz\"\n".as_slice(),
        b"$ORIGIN example.\na IN MX 10 mail\n".as_slice(),
    ];
    for (seed, bytes) in seeds.iter().enumerate() {
        for offset in 0..bytes.len() {
            let mut zone = bytes.to_vec();
            zone.remove(offset);
            cases.push(case(format!("delete-{seed}-{offset}"), "example.", zone));
        }
    }
    // miekg/dns parse_test.go, scan_rr.go; zone_legacy.rs, zone_advanced.rs and zone_rdata.rs.
    // RFC 1035 §5.1 and RFC 3597 §5: compare textual RDATA and generic wire data.
    let types = [
        ("A", "192.0.2.1", "999.0.2.1"),
        ("AAAA", "2001:db8::1", "192.0.2.1"),
        ("NS", "ns.example.", ".."),
        ("PTR", "host.example.", ".."),
        ("NSAP-PTR", "host.example.", ".."),
        ("RP", "host.example. text.example.", ".. text.example."),
        ("MR", "host.example.", ".."),
        ("MB", "host.example.", ".."),
        ("MG", "host.example.", ".."),
        ("HINFO", "\"cpu\" \"os\"", "\"unterminated"),
        ("ISDN", "\"1234\" \"56\"", "\"unterminated"),
        ("MINFO", "host.example. error.example.", ".. error.example."),
        ("MF", "host.example.", ".."),
        ("MD", "host.example.", ".."),
        ("MX", "10 mail.example.", "65536 mail.example."),
        ("RT", "10 host.example.", "65536 host.example."),
        ("AFSDB", "10 host.example.", "65536 host.example."),
        ("X25", "311061700956", "\"unterminated"),
        ("KX", "10 host.example.", "65536 host.example."),
        ("CNAME", "host.example.", ".."),
        ("DNAME", "host.example.", ".."),
        (
            "SOA",
            "ns.example. host.example. 1 2 3 4 5",
            "ns.example. host.example. bad 2 3 4 5",
        ),
        (
            "SRV",
            "1 2 443 target.example.",
            "65536 2 443 target.example.",
        ),
        (
            "NAPTR",
            "1 2 \"s\" \"SIP\" \"\" target.example.",
            "65536 2 \"s\" \"SIP\" \"\" target.example.",
        ),
        ("TALINK", "a.example. b.example.", ".. b.example."),
        ("LOC", "51 30 12.748 N 00 07 39.611 W 0.00m", "91 N 0 E 0m"),
        ("HIP", "2 20010010 AQID rvs.example.", "256 20010010 AQID"),
        ("CERT", "PKIX 42 RSASHA256 AQID", "bad 42 8 AQID"),
        ("OPENPGPKEY", "AQID", "\"unterminated"),
        ("CSYNC", "66 3 A NS AAAA", "no 3 A"),
        ("ZONEMD", "1 1 1 000102030405060708090A0B", "no 1 1 AA"),
        (
            "SIG",
            "A 8 2 3600 0 1 123 example. AQID",
            "BADTYPE 8 2 3600 0 1 123 example. AQID",
        ),
        (
            "RRSIG",
            "A 8 2 3600 0 1 123 example. AQID",
            "BADTYPE 8 2 3600 0 1 123 example. AQID",
        ),
        ("NXT", "next.example. A NS", "next.example. NOTATYPE"),
        ("NSEC", "next.example. A NS", "next.example. NOTATYPE"),
        (
            "NSEC3",
            "1 0 1 AABB P90DG1KE8QEAN0B01613LHQDG0SOJ0TA A",
            "no 0 1 AABB P90DG1KE8QEAN0B01613LHQDG0SOJ0TA A",
        ),
        ("NSEC3PARAM", "1 0 12 -", "no 0 12 -"),
        ("EUI48", "00-00-5e-90-01-2a", "00:00:5e:90:01:2a"),
        ("EUI64", "00-00-5e-ef-00-00-00-2a", "bad"),
        ("SSHFP", "1 2 ABCD", "999 2 ABCD"),
        ("DNSKEY", "257 3 8 AQID", "65536 3 8 AQID"),
        ("KEY", "257 3 8 AQID", "65536 3 8 AQID"),
        ("CDNSKEY", "257 3 8 AQID", "65536 3 8 AQID"),
        ("DS", "1 8 2 AABB", "65536 8 2 AABB"),
        ("DLV", "1 8 2 AABB", "65536 8 2 AABB"),
        ("CDS", "1 8 2 AABB", "65536 8 2 AABB"),
        (
            "IPSECKEY",
            "10 1 2 192.0.2.1 AQID",
            "256 1 2 192.0.2.1 AQID",
        ),
        ("AMTRELAY", "10 0 1 192.0.2.1", "256 0 1 192.0.2.1"),
        ("RKEY", "257 3 8 AQID", "65536 3 8 AQID"),
        ("EID", "AABB", "\"unterminated"),
        ("NIMLOC", "AABB", "\"unterminated"),
        ("GPOS", "-32.6882 116.8652 10.0", "north 0 0"),
        ("TA", "1 8 2 AABB", "65536 8 2 AABB"),
        ("TLSA", "3 1 1 ABCD", "256 1 1 ABCD"),
        ("SMIMEA", "3 1 1 ABCD", "256 1 1 ABCD"),
        ("SPF", "\"v=spf1 -all\"", "\"unterminated"),
        ("AVC", "\"text\"", "\"unterminated"),
        ("TXT", "\"text\"", "\"unterminated"),
        ("NINFO", "\"text\"", "\"unterminated"),
        ("RESINFO", "\"text\"", "\"unterminated"),
        (
            "URI",
            "1 2 \"https://example.org/\"",
            "65536 2 \"https://example.org/\"",
        ),
        ("DHCID", "AQID", "\"unterminated"),
        ("NID", "10 0014:4fff:ff20:ee64", "65536 0014:4fff:ff20:ee64"),
        ("L32", "10 192.0.2.1", "65536 192.0.2.1"),
        ("LP", "10 host.example.", "65536 host.example."),
        ("L64", "10 0014:4fff:ff20:ee64", "65536 0014:4fff:ff20:ee64"),
        ("UID", "1234", "4294967296"),
        ("GID", "1234", "4294967296"),
        ("UINFO", "\"info\"", "\"unterminated"),
        (
            "PX",
            "1 a.example. b.example.",
            "65536 a.example. b.example.",
        ),
        (
            "CAA",
            "0 issue \"example.org\"",
            "256 issue \"example.org\"",
        ),
        ("TKEY", "gss-tsig. 2 abcd 1 ff", "gss-tsig. 256 abcd 1 ff"),
        ("APL", "1:192.0.2.0/24", "1:192.0.2.1/24"),
        ("SVCB", "1 . alpn=h2 port=443", "1 . port=not-a-number"),
        ("HTTPS", "1 . alpn=h2 port=443", "1 . port=not-a-number"),
        ("TYPE65400", "\\# 4 00ff0180", "\\# nope 00ff0180"),
    ];
    for (rtype, valid, malformed) in types {
        for (kind, data) in [("valid", valid), ("malformed", malformed)] {
            cases.push(case(
                format!("rr-{kind}-{rtype}"),
                "example.",
                format!("record.example. 60 IN {rtype} {data}\n").into_bytes(),
            ));
        }
    }
    // RFC 5155 §3.3: retain the short-hash edge case as a separate wire comparison.
    cases.push(case(
        "rr-edge-NSEC3-short-hash",
        "example.",
        b"record.example. 60 IN NSEC3 1 0 1 AABB 00 A\n".as_slice(),
    ));
    for (context, prefix, suffix) in BYTE_NAME_CONTEXTS {
        for octet in 128..=255_u8 {
            cases.push(case(
                format!("byte-{context}-{octet}"),
                "example.",
                [prefix, &[octet], suffix].concat(),
            ));
        }
        for (index, bytes) in BYTE_NAME_SEQUENCES.iter().enumerate() {
            cases.push(case(
                format!("byte-{context}-sequence-{index}"),
                "example.",
                [prefix, bytes, suffix].concat(),
            ));
        }
    }
    cases
}

fn rust_result(case: &Case) -> String {
    let origin: Name = case.origin.parse().unwrap();
    match ZoneParser::new(Cursor::new(&case.zone), origin, "live.zone")
        .collect::<Result<Vec<_>, _>>()
    {
        Err(_) => "reject\n".to_owned(),
        Ok(records) => {
            let mut result = String::from("accept\n");
            // RFC 1035 §4.1.3: compare owner, type, class, TTL and uncompressed RDATA.
            for r in records {
                let owner: String = r
                    .owner
                    .as_wire()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let rdata: String = r.rdata.iter().map(|b| format!("{b:02x}")).collect();
                result.push_str(&format!(
                    "{owner}\t{}\t{}\t{}\t{rdata}\n",
                    r.ttl, r.class.0, r.rtype.0
                ));
            }
            result
        }
    }
}

fn escaped_input(case: &Case) -> String {
    case.zone
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn oracle_temp_dir() -> TempDir {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let parent = std::env::temp_dir().join("opencode");
    fs::create_dir_all(&parent).unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = parent.join(format!(
        "pharos-zone-oracle-{}-{nonce}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&path).expect("create unique oracle temp directory");
    TempDir(path)
}

#[test]
fn parallel_oracle_temp_dirs_are_distinct() {
    let dirs: Vec<_> = std::thread::scope(|scope| {
        (0..16)
            .map(|_| scope.spawn(oracle_temp_dir))
            .map(|thread| thread.join().unwrap())
            .collect()
    });
    let paths: std::collections::HashSet<_> = dirs.iter().map(|dir| &dir.0).collect();
    assert_eq!(paths.len(), dirs.len());
    assert!(paths.iter().all(|path| path.is_dir()));
}

fn oracle() -> Option<(TempDir, PathBuf)> {
    match Command::new("go").arg("version").output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            assert_ne!(
                std::env::var("PHAROS_REQUIRE_INTEROP").as_deref(),
                Ok("1"),
                "go is not installed"
            );
            eprintln!("skipping live zone differential test: go is not installed");
            return None;
        }
        Err(e) => panic!("could not run go: {e}"),
        Ok(output) => assert!(
            output.status.success(),
            "go version failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
    }
    let reference = match std::env::var_os("PHAROS_MIEKG_DNS_DIR") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(
                path.join("go.mod").is_file(),
                "invalid PHAROS_MIEKG_DNS_DIR: {}",
                path.display()
            );
            Some(path)
        }
        None => std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join("projects/pharos-refs/miekg-dns"))
            .filter(|path| path.join("go.mod").is_file()),
    };
    let dir = oracle_temp_dir();
    let binary = dir.0.join("zone-oracle");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zone-oracle");
    for file in ["main.go", "go.mod", "go.sum"] {
        fs::copy(fixture.join(file), dir.0.join(file)).expect("copy oracle module");
    }
    if let Some(reference) = reference {
        let reference = reference
            .canonicalize()
            .expect("resolve miekg/dns checkout");
        let output = Command::new("go")
            .current_dir(&dir.0)
            .env("GOWORK", "off")
            .env("GOTOOLCHAIN", "local")
            .arg("mod")
            .arg("edit")
            .arg(format!(
                "-replace=github.com/miekg/dns={}",
                reference.display()
            ))
            .output()
            .expect("run go mod edit");
        assert!(
            output.status.success(),
            "oracle local replace failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = Command::new("go")
        .current_dir(&dir.0)
        .env("GOWORK", "off")
        .env("GOTOOLCHAIN", "local")
        .args(["build", "-mod=readonly", "-o"])
        .arg(&binary)
        .arg(".")
        .output()
        .expect("run go build");
    assert!(
        output.status.success(),
        "oracle build failed (check Go version, local checkout, module cache and GOPROXY): {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some((dir, binary))
}

fn write_frame(file: &mut File, bytes: &[u8]) {
    file.write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
        .unwrap();
    file.write_all(bytes).unwrap();
}

fn oracle_batch(binary: &Path, dir: &Path, cases: &[Case]) -> Vec<String> {
    let input_path = dir.join("input");
    let mut input = File::create(&input_path).unwrap();
    for case in cases {
        write_frame(&mut input, case.origin.as_bytes());
        write_frame(&mut input, &case.zone);
    }
    drop(input);
    let output = Command::new(binary)
        .arg("--batch")
        .stdin(Stdio::from(File::open(input_path).unwrap()))
        .output()
        .expect("run zone oracle");
    assert!(
        output.status.success(),
        "oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut frames = Cursor::new(&output.stdout);
    let mut results = Vec::with_capacity(cases.len());
    for case in cases {
        let mut length = [0; 4];
        frames
            .read_exact(&mut length)
            .unwrap_or_else(|error| panic!("{}: oracle response length: {error}", case.name));
        let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
        frames
            .read_exact(&mut bytes)
            .unwrap_or_else(|error| panic!("{}: oracle response body: {error}", case.name));
        results.push(String::from_utf8(bytes).expect("oracle response is ASCII"));
    }
    assert_eq!(
        frames.position() as usize,
        output.stdout.len(),
        "unexpected oracle output"
    );
    results
}

fn direct_oracle(binary: &Path, zone: &[u8]) -> String {
    let mut child = Command::new(binary)
        .arg("example.")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(zone).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn raw_name_octets_preserved_on_wire() {
    let Some((_dir, binary)) = oracle() else {
        return;
    };
    // RFC 1035 §3.1: name labels carry the original octets, not Unicode characters.
    for (zone, wire) in [
        (
            b"\xff.example. 60 IN A 192.0.2.1\n".as_slice(),
            "accept\n01ff076578616d706c6500\t60\t1\t1\tc0000201\n",
        ),
        (
            b"record.example. 60 IN NS \xff.example.\n".as_slice(),
            "accept\n067265636f7264076578616d706c6500\t60\t1\t2\t01ff076578616d706c6500\n",
        ),
        (
            b"record.example. 60 IN MX 10 \xc3\xa9.example.\n".as_slice(),
            "accept\n067265636f7264076578616d706c6500\t60\t1\t15\t000a02c3a9076578616d706c6500\n",
        ),
    ] {
        assert_eq!(direct_oracle(&binary, zone), wire, "Go: {zone:?}");
        assert_eq!(
            rust_result(&case("raw-wire", "example.", zone)),
            wire,
            "Rust: {zone:?}"
        );
    }
}

#[test]
fn generic_name_pointer_results_are_compared_on_wire() {
    let Some((_dir, binary)) = oracle() else {
        return;
    };
    // RFC 1035 §4.1.4: exercise pointer decoding, including a cyclic pointer.
    for (input, expected) in [
        (
            generic_case(2, "pointer-forward", 5, "c002016100"),
            "accept\n067265636f7264076578616d706c6500\t60\t1\t2\t016100\n",
        ),
        (
            generic_case(15, "mx-pointer-forward", 7, "000ac004016100"),
            "accept\n067265636f7264076578616d706c6500\t60\t1\t15\t000a016100\n",
        ),
        (generic_case(2, "pointer-self", 2, "c000"), "reject\n"),
    ] {
        assert_eq!(
            direct_oracle(&binary, &input.zone),
            expected,
            "Go: {}",
            input.name
        );
        assert_eq!(rust_result(&input), expected, "Rust: {}", input.name);
    }
}

// RFC 1035 §3.1: an absolute owner needs at least the root label octet.
const EMPTY_OWNER_CASES: [(&[u8], &str); 3] = [
    (
        b"$TTL 3600\n IN A 192.0.2.1\n",
        "accept\n\t3600\t1\t1\tc0000201\n",
    ),
    (
        b" 60 IN TXT \"abc\\032xyz\"\n",
        "accept\n\t60\t1\t16\t076162632078797a\n",
    ),
    (
        b"$ORIGIN example.\n IN MX 10 mail\n",
        "accept\n\t0\t1\t15\t000a046d61696c076578616d706c6500\n",
    ),
];

#[test]
fn empty_owner_regressions() {
    let Some((_dir, binary)) = oracle() else {
        return;
    };
    for (input, go_expected) in EMPTY_OWNER_CASES {
        let actual = direct_oracle(&binary, input);
        let rust = rust_result(&case("empty-owner", "example.", input));
        assert_eq!(
            actual, go_expected,
            "Go empty-owner output changed for {input:?}"
        );
        assert_eq!(
            rust, "reject\n",
            "Rust must not invent an owner for {input:?}"
        );
        eprintln!(
            "empty owner {input:?}: Go accepts an invalid zero-byte owner; Rust rejects (root would invent an owner)"
        );
    }
}

#[test]
fn accepted_but_unencodable_record() {
    let Some((_dir, binary)) = oracle() else {
        return;
    };
    let oversized = format!(
        "a 60 IN TXT {}",
        format!("\"{}\" ", "x".repeat(255)).repeat(260)
    );
    let go = direct_oracle(&binary, oversized.as_bytes());
    let rust = rust_result(&case("oversized", "example.", oversized.into_bytes()));
    assert!(go.starts_with("pack_error\nPackRR: "), "Go: {go}");
    assert_eq!(
        rust, "reject\n",
        "oversized record should not be representable on wire"
    );
    eprintln!("Go accepted oversized TXT but PackRR failed: {go}Rust: {rust}");
    // RFC 4034 §2.1 and RFC 9460 §2.2: invalid keys cannot become wire records.
    for (name, input, error) in [
        (
            "invalid DNSKEY base64",
            b"a 60 DNSKEY 257 3 8 !!!\n".as_slice(),
            "illegal base64",
        ),
        (
            "duplicate SVCB parameters",
            b"a 60 IN SVCB 1 . port=443 port=80\n".as_slice(),
            "repeated SVCB keys",
        ),
    ] {
        let go = direct_oracle(&binary, input);
        let rust = rust_result(&case(name, "example.", input));
        assert!(
            go.starts_with("pack_error\nPackRR: ") && go.contains(error),
            "{name}: Go: {go}"
        );
        assert_eq!(
            rust, "reject\n",
            "{name}: Rust must reject unencodable RDATA"
        );
        eprintln!("{name}: Go accepted but could not pack: {go}Rust: {rust}");
    }
}

#[test]
fn miekg_live_differential() {
    let Some((dir, binary)) = oracle() else {
        return;
    };
    assert_eq!(
        direct_oracle(&binary, b"a 60 IN TXT \"\\000\\255\"\n"),
        "accept\n0161076578616d706c6500\t60\t1\t16\t0200ff\n"
    );
    assert_eq!(direct_oracle(&binary, b"a IN A invalid\n"), "reject\n");
    let mut cases = cases();
    let mut results = oracle_batch(&binary, &dir.0, &cases);
    let mut generic = generic_cases();
    generic.extend(generic_mutations(&cases, &results));
    results.extend(oracle_batch(&binary, &dir.0, &generic));
    cases.extend(generic);
    let mut mismatches = Vec::new();
    let mut pack_errors = Vec::new();
    let mut pack_error_rust_accepts = Vec::new();
    let mut invalid_examples = Vec::new();
    let mut empty_owners = 0;
    for (case, expected) in cases.iter().zip(&results) {
        let actual = rust_result(case);
        // RFC 1035 §5.1: the unescaped '(' in sequence 2 is zone syntax, not a label octet.
        let malformed_bytes = case.name.starts_with("byte-") && case.name.ends_with("-sequence-2");
        if case.name.starts_with("rr-valid-")
            || (case.name.starts_with("byte-") && !malformed_bytes)
        {
            let mut lines = expected.lines();
            let accepted = lines.next() == Some("accept")
                && lines.next().is_some_and(|record| {
                    !record.starts_with('\t') && record.split('\t').count() == 5
                })
                && lines.next().is_none();
            if !accepted {
                invalid_examples.push(format!(
                    "{}: expected one packable Go record, got {}",
                    case.name, expected
                ));
            }
        } else if (case.name.starts_with("rr-malformed-") || malformed_bytes)
            && expected != "reject\n"
        {
            invalid_examples.push(format!(
                "{}: expected Go rejection, got {}",
                case.name, expected
            ));
        }
        if let Some((_, go_expected)) = EMPTY_OWNER_CASES
            .iter()
            .find(|(input, _)| case.origin == "example." && *input == case.zone)
        {
            assert_eq!(&expected, go_expected, "{} Go result changed", case.name);
            assert_eq!(actual, "reject\n", "{} Rust result changed", case.name);
            eprintln!(
                "{}: Go accepts an invalid zero-byte owner; Rust rejects it",
                case.name
            );
            empty_owners += 1;
            continue;
        }
        // A packing error means Go accepted the text but supplied no comparable wire.
        if expected.starts_with("pack_error\n") {
            let input = if case.zone.len() > 512 {
                format!("<{} bytes; see {} generator>", case.zone.len(), case.name)
            } else {
                escaped_input(case)
            };
            let rust = if actual.len() > 512 {
                format!("accept ({} output bytes)\n", actual.len())
            } else {
                actual.clone()
            };
            let detail = format!(
                "{}: input=\"{}\"\nGo accepted but could not encode: {}Rust: {}",
                case.name, input, expected, rust
            );
            if actual != "reject\n" {
                pack_error_rust_accepts.push(detail.clone());
            }
            pack_errors.push(detail);
            continue;
        }
        if *expected != actual {
            mismatches.push(format!(
                "{}: input=\"{}\"\nGo: {}Rust: {}",
                case.name,
                escaped_input(case),
                expected,
                actual
            ));
        }
    }
    assert_eq!(
        empty_owners,
        EMPTY_OWNER_CASES.len(),
        "empty-owner mutations must be checked"
    );
    if !pack_errors.is_empty() {
        eprintln!(
            "{} Go-accepted but unencodable cases (wire-only contract):\n{}",
            pack_errors.len(),
            pack_errors.join("\n")
        );
    }
    assert!(
        mismatches.is_empty() && pack_error_rust_accepts.is_empty() && invalid_examples.is_empty(),
        "{} / {} mismatches:\n{}\n{} Go-accepted but unencodable cases Rust incorrectly accepted (wire-only contract requires rejection):\n{}\n{} invalid examples:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n"),
        pack_error_rust_accepts.len(),
        pack_error_rust_accepts.join("\n"),
        invalid_examples.len(),
        invalid_examples.join("\n")
    );
}

#[test]
fn missing_go_fails_only_when_interop_is_required() {
    for (required, success) in [(false, true), (true, false)] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "miekg_live_differential", "--nocapture"])
            .env("PATH", "/nonexistent");
        if required {
            child.env("PHAROS_REQUIRE_INTEROP", "1");
        } else {
            child.env_remove("PHAROS_REQUIRE_INTEROP");
        }
        let output = child.output().unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("go is not installed"));
    }
}

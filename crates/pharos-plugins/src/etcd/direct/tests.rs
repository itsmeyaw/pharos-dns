use super::*;

fn wire(name: &Name) -> Vec<u8> {
    name.as_wire().to_vec()
}

// RFC 1035 §3.1: the stack parse reads the names the heap parse reads, and rejects the ones it rejects.
#[test]
fn wire_parses_like_name() {
    let long_label = format!("{}.test.", "a".repeat(64));
    let long_name = format!("{}.", vec!["a".repeat(63); 4].join("."));
    let escaped = [
        "a\\.b.test.",
        "a\\065b.test.",
        "\\256.test.",
        "a\\",
        ".",
        "a..b.",
        "a.b",
    ];
    for text in [
        "a.b.test.",
        "A.B.Test.",
        "xn--caf-dma.test.",
        long_label.as_str(),
        long_name.as_str(),
    ]
    .into_iter()
    .chain(escaped)
    {
        let expected = text.parse::<Name>().ok().map(|name| wire(&name));
        let got = Wire::parse(text).map(|parsed| parsed.bytes[..parsed.len].to_vec());
        assert_eq!(got, expected, "{text}");
    }
}

// CoreDNS v1.15.0 plugin/backend_lookup.go SOA: `ns.dns.ZONE` and `hostmaster.ZONE` are made like `Name::parse`.
#[test]
fn wire_under_makes_the_names_name_parse_makes() {
    let zone: Name = "skydns.test.".parse().unwrap();
    for labels in [&["ns", "dns"][..], &["hostmaster"][..]] {
        let expected = Name::parse(&labels.join("."), &zone).unwrap();
        let got = Wire::under(labels, &zone).unwrap();
        assert_eq!(&got.bytes[..got.len], expected.as_wire());
    }
    let root: Name = ".".parse().unwrap();
    assert_eq!(Wire::under(&["ns"], &root).unwrap().len, 4);
    // RFC 1035 §2.3.4: a name is at most 255 octets, so a long zone leaves room for some names only.
    for (label, fits) in [(60, [true, false]), (62, [false, false])] {
        let zone: Name = format!("{}.", vec!["a".repeat(label); 4].join("."))
            .parse()
            .unwrap();
        for (labels, fit) in [
            (&["ns", "dns"][..], fits[0]),
            (&["hostmaster"][..], fits[1]),
        ] {
            assert_eq!(Name::parse(&labels.join("."), &zone).is_ok(), fit);
            assert_eq!(Wire::under(labels, &zone).is_some(), fit);
        }
    }
}

// RFC 4343 §3.1: names are the same ignoring ASCII case.
#[test]
fn wire_names_are_the_same_ignoring_case() {
    let (a, b, c) = (
        Wire::parse("A.b.test.").unwrap(),
        Wire::parse("a.B.TEST.").unwrap(),
        Wire::parse("a.c.test.").unwrap(),
    );
    assert!(a.same(&b));
    assert!(!a.same(&c));
}

// miekg/dns Fqdn: a host is made fully qualified, and an escaped final dot does not count.
#[test]
fn fqdn_adds_the_final_dot_unless_there_is_one() {
    let mut buf = String::new();
    assert_eq!(fqdn_into("a.b.", &mut buf), "a.b.");
    assert_eq!(fqdn_into("a.b", &mut buf), "a.b.");
    assert_eq!(fqdn_into("a\\.", &mut buf), "a\\..");
}

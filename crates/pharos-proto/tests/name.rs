use std::collections::{BTreeSet, HashSet};

use pharos_proto::{Name, NameError, NameRef};
use proptest::prelude::*;

fn name(value: &str) -> Name {
    value.parse().unwrap()
}

#[test]
fn parses_and_prints_miekg_escapes() {
    let value = name(r"a\.b.\\.\001.");

    assert_eq!(value.to_string(), r"a\.b.\\.\001.");
}

#[test]
fn prints_miekg_special_characters() {
    let wire = [9, b'.', b' ', b'\'', b'@', b';', b'(', b')', b'"', b'\\', 0];
    let borrowed = NameRef::parse(&wire, 0).unwrap();
    let expected = r#"\.\ \'\@\;\(\)\"\\."#;
    assert_eq!(borrowed.to_string(), expected);
    assert_eq!(borrowed.to_name().to_string(), expected);
    assert_eq!(expected.parse::<Name>().unwrap().as_wire(), wire);
}

#[test]
fn escaped_final_dot_is_relative() {
    let origin = name("example.");
    assert_eq!(
        Name::parse(r"a\.", &origin).unwrap().to_string(),
        r"a\..example."
    );
    assert!(r"a\.".parse::<Name>().is_err());
    assert!("é".parse::<Name>().is_err());
    assert!("".parse::<Name>().is_err());
}

#[test]
fn invalid_decimal_escapes_return_errors() {
    for input in [r"\256.", r"\999."] {
        assert_eq!(input.parse::<Name>(), Err(NameError::InvalidEscape));
    }
}

#[test]
fn resolves_relative_names_and_at_against_origin() {
    let origin = name("example.com.");

    assert_eq!(
        Name::parse("www", &origin).unwrap(),
        name("www.example.com.")
    );
    assert_eq!(Name::parse("@", &origin).unwrap(), origin);
    assert_eq!(Name::parse("www.", &origin).unwrap(), name("www."));
}

#[test]
fn compares_names_ascii_case_insensitively() {
    let mixed = name("WWW.Example.COM.");
    let lower = name("www.example.com.");

    assert_eq!(mixed, lower);
    assert_eq!(mixed.canonical(), "www.example.com.");
    assert_eq!(HashSet::from([mixed.clone(), lower.clone()]).len(), 1);
    assert_eq!(BTreeSet::from([mixed, lower]).len(), 1);
}

#[test]
fn orders_names_in_dnssec_canonical_order() {
    let mut names = vec![name("z.example."), name("a.example."), name("example.")];

    names.sort();

    assert_eq!(
        names,
        vec![name("example."), name("a.example."), name("z.example.")]
    );
}

#[test]
fn orders_rfc_4034_canonical_example() {
    let expected = [
        "example.",
        "a.example.",
        "yljkjljk.a.example.",
        "Z.a.example.",
        r"\001.z.example.",
        "*.z.example.",
        r"\200.z.example.",
    ];
    let mut names: Vec<_> = expected.iter().rev().map(|value| name(value)).collect();
    names.sort();
    assert_eq!(names, expected.map(name));
}

#[test]
fn accepts_maximum_length_and_label_count() {
    let max_wire = [1, b'a']
        .repeat(127)
        .into_iter()
        .chain([0])
        .collect::<Vec<_>>();
    let max_name = NameRef::parse(&max_wire, 0).unwrap().to_name();
    assert_eq!(max_name.as_wire().len(), 255);
    assert_eq!(max_name.label_count(), 127);
    assert!(max_name.is_subdomain_of(&name(".")));
    assert_eq!(max_name.parent().unwrap().label_count(), 126);
    assert_eq!(
        max_name.to_string().parse::<Name>().unwrap().as_wire(),
        max_wire
    );
    assert!(format!("{}.", "a".repeat(64)).parse::<Name>().is_err());
}

#[test]
fn matches_domain_suffixes_and_parents() {
    let full_name = name("www.eu.example.com.");
    let domain = name("example.com.");

    assert!(full_name.is_subdomain_of(&domain));
    assert_eq!(full_name.label_count(), 4);
    assert_eq!(full_name.parent(), Some(name("eu.example.com.")));
    assert_eq!(name("com.").parent(), Some(name(".")));
    assert_eq!(name(".").parent(), None);
    assert_eq!(
        Name::longest_match(&full_name, [name("com."), domain.clone()]),
        Some(domain)
    );
}

#[test]
fn follows_backwards_compression_pointers_without_allocating() {
    let message = b"\x07example\x03com\0\x03www\xc0\0";
    let value = NameRef::parse(message, 13).unwrap();

    assert_eq!(value.to_string(), "www.example.com.");
    assert_eq!(value.wire_len(), 6);
    assert_eq!(value, name("WWW.EXAMPLE.COM."));
}

#[test]
fn rejects_compression_target_overlapping_its_pointer() {
    let message = b"\x03a\xc0\x00\x00";
    assert_eq!(
        NameRef::parse(message, 2).unwrap_err(),
        NameError::PointerNotBackwards
    );
}

#[test]
fn rejects_hostile_wire_names() {
    let forward_pointer = b"\xc0\x02\0";
    let unsupported_label = b"\x40";
    let truncated_label = b"\x03ab";
    let long_label = [vec![64], vec![b'a'; 64], vec![0]].concat();
    let long_name = [
        vec![63],
        vec![b'a'; 63],
        vec![63],
        vec![b'b'; 63],
        vec![63],
        vec![b'c'; 63],
        vec![63],
        vec![b'd'; 63],
        vec![0],
    ]
    .concat();
    let pointer_chain = {
        let mut message = vec![0];
        message.extend_from_slice(&[0xc0, 0]);
        for index in 2..=256 {
            let target = 1 + 2 * (index - 2);
            message.push(0xc0 | ((target >> 8) as u8));
            message.push(target as u8);
        }
        message
    };

    for (message, offset) in [
        (forward_pointer.as_slice(), 0),
        (unsupported_label.as_slice(), 0),
        (truncated_label.as_slice(), 0),
        (long_label.as_slice(), 0),
        (long_name.as_slice(), 0),
        (pointer_chain.as_slice(), pointer_chain.len() - 2),
        (&[][..], 0),
    ] {
        assert!(NameRef::parse(message, offset).is_err());
    }
}

#[test]
fn rejects_invalid_presentation_names() {
    assert!(matches!(
        "a..example.".parse::<Name>(),
        Err(NameError::EmptyLabel)
    ));
    assert_eq!(name(r"a\12.example.").to_string(), "a12.example.");
    assert!(matches!(
        Name::parse("a\\", &name(".")),
        Err(NameError::InvalidEscape)
    ));
}

#[test]
fn compares_borrowed_names_without_copying() {
    let wire = b"\x03www\x07example\x03com\0\x03WWW\xc0\x04";
    let left = NameRef::parse(wire, 0).unwrap();
    let right = NameRef::parse(wire, 17).unwrap();
    assert_eq!(left, right);
}

#[test]
fn bounds_compression_hops_and_cycles() {
    let mut message = vec![0];
    for index in 0..256 {
        let target = if index == 0 { 0 } else { 1 + 2 * (index - 1) };
        message.push(0xc0 | ((target >> 8) as u8));
        message.push(target as u8);
    }
    assert!(NameRef::parse(&message, 1 + 2 * 254).is_ok());
    assert_eq!(
        NameRef::parse(&message, 1 + 2 * 255).unwrap_err(),
        NameError::PointerLimit
    );
    assert!(NameRef::parse(b"\x01a\xc0\x00", 0).is_err());
    for message in [
        &b"\xc0"[..],
        &b"\xc0\x00"[..],
        &b"\x80"[..],
        &b"\x00\xc0\x02"[..],
    ] {
        let offset = if message.len() == 3 { 1 } else { 0 };
        assert!(NameRef::parse(message, offset).is_err());
    }
}

proptest! {
    #[test]
    fn presentation_and_wire_round_trip(labels in prop::collection::vec("[a-zA-Z0-9]{1,10}", 0..8)) {
        let text = if labels.is_empty() { ".".to_owned() } else { format!("{}.", labels.join(".")) };
        let original: Name = text.parse().unwrap();
        let from_presentation: Name = original.to_string().parse().unwrap();
        let from_wire = NameRef::parse(original.as_wire(), 0).unwrap().to_name();

        prop_assert_eq!(from_presentation, original.clone());
        prop_assert_eq!(from_wire, original);
    }

    #[test]
    fn arbitrary_wire_labels_preserve_case_and_octets(labels in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..32), 0..7)) {
        let mut wire = Vec::new();
        for label in labels {
            wire.push(label.len() as u8);
            wire.extend(label);
        }
        wire.push(0);
        let original = NameRef::parse(&wire, 0).unwrap().to_name();
        let parsed: Name = original.to_string().parse().unwrap();
        prop_assert_eq!(parsed.as_wire(), wire.as_slice());
    }

    #[test]
    fn hostile_input_never_panics(message in prop::collection::vec(any::<u8>(), 0..300), offset in any::<usize>(), text in ".{0,300}") {
        let _ = NameRef::parse(&message, offset);
        let _ = text.parse::<Name>();
        let _ = Name::parse(&text, &name("."));
    }
}

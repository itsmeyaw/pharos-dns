use super::{
    Action, INLINE_RRSET_TTLS, RegexMatcher, RrsetKey, cname_replacement, rrset_minimum_ttls,
};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};

#[test]
fn cached_regex_matches_the_capture_engine() {
    for pattern in [
        r"^(.*)\.example\.$",
        r"^([a-z]{1,8}\.){1,8}example\.$",
        r"\bexample\b",
        r"^(alpha|beta|gamma|delta)\.example\.$",
        r"^((a|b|c|d)?)+\.example\.$",
        r"(?i:k)\.example\.$",
        r"\p{Greek}+",
    ] {
        let matcher = RegexMatcher::new(pattern).unwrap();
        let reference = regex::Regex::new(pattern).unwrap();
        for name in [
            ".",
            "example.",
            "www.example.",
            "beta.example.",
            "bbb.example.",
            "K.example.",
            "other.test.",
            "\\195\\169.example.",
        ] {
            assert_eq!(
                matcher.is_match(name),
                reference.is_match(name),
                "{pattern} {name}"
            );
        }
    }
}

#[test]
fn cname_match_ignores_ascii_case() {
    let blocks = pharos_corefile::parse(
        "Corefile",
        r".:53 {
 rewrite cname Old.Example. new.example.
 rewrite cname regex old\.example\. new.example.
}",
    )
    .unwrap();
    let mut chains =
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
    let rewrite = chains.remove(0).config.rewrite.unwrap();
    let value: pharos_proto::Name = "Old.Example.".parse().unwrap();
    let value = pharos_proto::NameRef::parse(value.as_wire(), 0).unwrap();
    for rule in &rewrite.rules {
        let Action::Cname(matcher, replacement) = &rule.action else {
            panic!("expected CNAME rule parsed from Corefile");
        };
        assert_eq!(
            cname_replacement(matcher, replacement, value)
                .unwrap()
                .1
                .to_string(),
            "new.example."
        );
    }
}

#[test]
fn cname_regex_setup_preserves_uppercase_escapes() {
    for (pattern, candidate, expected) in [
        (r"^\D+\.example\.$", "letters.example.", true),
        (r"^\D+\.example\.$", "123.example.", false),
        (r"^\W+\.example\.$", "-.example.", true),
        (r"^\W+\.example\.$", "letters.example.", false),
    ] {
        let corefile = format!(".:53 {{\n rewrite cname regex {pattern} target.example.\n}}");
        let blocks = pharos_corefile::parse("Corefile", &corefile).unwrap();
        let mut chains =
            pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
        let rewrite = chains.remove(0).config.rewrite.unwrap();
        let Action::Cname(matcher, replacement) = &rewrite.rules[0].action else {
            panic!("expected parsed CNAME regex rule");
        };
        let name: Name = candidate.parse().unwrap();
        let name = NameRef::parse(name.as_wire(), 0).unwrap();
        assert_eq!(
            cname_replacement(matcher, replacement, name).is_some(),
            expected,
            "{pattern} against {candidate}"
        );
    }
}

// RFC 2181 §5.2: Overflow RRsets keep the same lowest-TTL semantics.
#[test]
fn rrset_ttl_table_keeps_minimum_above_inline_capacity() {
    let root: Name = ".".parse().unwrap();
    let mut wire = Vec::with_capacity(16_384);
    let mut builder = MessageBuilder::new(&mut wire, 16_384, 1, 0x8180).unwrap();
    builder
        .question(
            NameRef::parse(root.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let mut names = Vec::new();
    for index in 0..=INLINE_RRSET_TTLS {
        let name: Name = format!("n{index}.example.").parse().unwrap();
        builder
            .record(
                Section::Answer,
                NameRef::parse(name.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
                index as u32,
                &[192, 0, 2, 1],
            )
            .unwrap();
        names.push(name);
    }
    builder
        .record(
            Section::Answer,
            NameRef::parse(names.last().unwrap().as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
            1,
            &[192, 0, 2, 2],
        )
        .unwrap();
    let _ = builder.finish();
    let message = Message::parse(&wire).unwrap();
    let ttls = rrset_minimum_ttls(&message);
    let overflow = NameRef::parse(names.last().unwrap().as_wire(), 0).unwrap();
    let key = RrsetKey {
        owner: overflow,
        rtype: Type::A,
        class: Class::IN,
    };
    assert_eq!(ttls.get(&key), Some(1));
}

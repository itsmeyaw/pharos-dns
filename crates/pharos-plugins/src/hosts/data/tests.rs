use super::*;

#[test]
fn parses_scoped_addresses_aliases_and_wildcards() {
    let map = Map::parse(
            &b"127.0.0.2 Odin odinalias # comment\n127.0.0.3 odin\n::2 odin\nfe80::1%lo0 localhost\n127.1.1.2 *.example.org\ninvalid invalid\n"[..],
            &[".".parse().unwrap()], true, "Inline hosts entries");
    assert_eq!(
        map.lookup("odin.", true),
        [
            "127.0.0.2".parse::<IpAddr>().unwrap(),
            "127.0.0.3".parse().unwrap()
        ]
    );
    assert_eq!(
        map.lookup("ODIN.", false),
        ["::2".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        map.lookup("localhost.", false),
        ["fe80::1".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        map.lookup("a.example.org.", true),
        ["127.1.1.2".parse::<IpAddr>().unwrap()]
    );
    assert!(map.lookup("a.b.example.org.", true).is_empty());
    assert_eq!(
        map.reverse
            .get(&"127.0.0.2".parse::<IpAddr>().unwrap())
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["odin.", "odinalias."]
    );
    assert!(
        !map.reverse
            .contains_key(&"127.1.1.2".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn long_fields_do_not_discard_following_names_or_lines() {
    let input = format!(
        "127.0.0.1 {} one.example.org\n127.0.0.2 two.example.org\n",
        "x".repeat(70_000)
    );
    let map = Map::parse(
        input.as_bytes(),
        &["example.org.".parse().unwrap()],
        false,
        "Inline hosts entries",
    );
    assert_eq!(
        map.lookup("one.example.org.", true),
        ["127.0.0.1".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        map.lookup("two.example.org.", true),
        ["127.0.0.2".parse::<IpAddr>().unwrap()]
    );
    assert!(map.reverse.is_empty());
}

#[test]
fn vertical_tab_and_form_feed_separate_fields() {
    let map = Map::parse(
        &b"127.0.0.1\x0bfoo\x0cbar\n"[..],
        &[".".parse().unwrap()],
        true,
        "Inline hosts entries",
    );
    assert_eq!(
        map.lookup("foo.", true),
        ["127.0.0.1".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        map.lookup("bar.", true),
        ["127.0.0.1".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn invalid_raw_unicode_host_names_are_skipped() {
    let root: Name = ".".parse().unwrap();
    let map = Map::parse(
        &b"192.0.2.1 m\xc3\xbcnich.example\n192.0.2.2 m\\195\\188nich.example\n"[..],
        &[root],
        false,
        "test hosts",
    );
    assert_eq!(map.v4.len(), 1);
    assert_eq!(
        map.lookup(r"m\195\188nich.example.", true),
        ["192.0.2.2".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn exact_and_wildcard_lookup_is_separate_per_family() {
    let input = &b"192.0.2.1 *.example.org\n192.0.2.2 x.example.org\n2001:db8::1 *.example.org\n192.0.2.3 *.deep.example.org\n"[..];
    let map = Map::parse(input, &["example.org.".parse().unwrap()], true, "test");
    assert_eq!(
        map.lookup("x.example.org.", true),
        ["192.0.2.2".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        map.lookup("x.example.org.", false),
        ["2001:db8::1".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        map.lookup("y.example.org.", true),
        ["192.0.2.1".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(
        map.lookup("y.deep.example.org.", true),
        ["192.0.2.3".parse::<IpAddr>().unwrap()]
    );
    assert!(map.lookup("deep.example.org.", false).len() == 1);
    assert!(map.lookup("a.b.deep.example.org.", true).is_empty());
}

#[test]
fn oversized_address_discards_only_its_line() {
    let input = format!(
        "{} ignored.example.org\n192.0.2.1 valid.example.org\n",
        "1".repeat(1025)
    );
    let map = Map::parse(input.as_bytes(), &[".".parse().unwrap()], true, "test");
    assert!(map.lookup("ignored.example.org.", true).is_empty());
    assert_eq!(
        map.lookup("valid.example.org.", true),
        ["192.0.2.1".parse::<IpAddr>().unwrap()]
    );
}

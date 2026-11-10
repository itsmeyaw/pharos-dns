use pharos_corefile::parse;

#[test]
fn parses_server_blocks_and_nested_directives() {
    let blocks = parse(
        "Corefile",
        "a,\n b {\n foo one {\n nested { value }\n }\n bar two\n}\nc {\n baz\n}",
    )
    .unwrap();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].keys(), ["a", "b"]);
    assert_eq!(blocks[1].keys(), ["c"]);
    let texts: Vec<_> = blocks[0].directives["foo"]
        .iter()
        .map(|t| t.text.as_str())
        .collect();
    assert_eq!(texts, ["foo", "one", "{", "nested", "{", "value", "}", "}"]);
    assert_eq!(blocks[0].directives["bar"][1].text, "two");
}

#[test]
fn rejects_unclosed_blocks_and_dangling_commas() {
    for text in ["a,", "a, {\n}", "a {\n foo {\n x", "a {\n foo\n"] {
        let error = parse("Corefile", text).unwrap_err();
        assert_eq!(error.file, "Corefile");
        assert!(error.line > 0);
    }
}

#[test]
fn unbraced_server_block_and_repeated_directives() {
    let blocks = parse("Corefile", "a\n foo one\n foo two").unwrap();
    assert_eq!(blocks[0].directives["foo"].len(), 4);
    assert_eq!(parse("Corefile", "a").unwrap()[0].keys(), ["a"]);
}

#[test]
fn caddy_server_block_cases() {
    let cases: &[(&str, &[&[&str]])] = &[
        ("localhost", &[&["localhost"]]),
        ("localhost:1234\n dir1 foo bar", &[&["localhost:1234"]]),
        (
            "host1:80, http://host2.com\n dir1 foo bar\n dir2 baz",
            &[&["host1:80", "http://host2.com"]],
        ),
        (
            "http://host1.com,\n http://host2.com,\n https://host3.com",
            &[&["http://host1.com", "http://host2.com", "https://host3.com"]],
        ),
        (
            "localhost:1234 {\n}\n localhost:2015 {\n}",
            &[&["localhost:1234"], &["localhost:2015"]],
        ),
        ("", &[]),
        ("\"\"", &[]),
    ];
    for (input, expected) in cases {
        let blocks = parse("Corefile", input).unwrap();
        let actual: Vec<Vec<&str>> = blocks
            .iter()
            .map(|b| b.keys().iter().map(String::as_str).collect())
            .collect();
        assert_eq!(actual, *expected, "{input:?}");
    }
    for input in [
        "localhost:1234, http://host2,",
        "localhost\n dir1 {\n foo",
        "localhost\n dir1 {\n } }",
    ] {
        assert!(parse("Corefile", input).is_err(), "{input:?}");
    }
}

#[test]
fn key_normalization_reports_source_location() {
    let blocks = parse("named.Corefile", ".bad {\n}\n").unwrap();
    let error = blocks[0].normalize_keys().unwrap_err();
    assert_eq!(error.file, "named.Corefile");
    assert_eq!(error.line, 1);
    let blocks = parse("Corefile", "example.org,\n 10.0.0.0/8 {\n}\n").unwrap();
    let keys = blocks[0].normalize_keys().unwrap();
    assert_eq!(keys[0].domain, "example.org.");
    assert_eq!(keys[1].domain, "10.in-addr.arpa.");
}

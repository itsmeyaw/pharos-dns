use pharos_corefile::parse;

#[test]
fn parses_server_blocks_and_nested_directives() {
    let blocks = parse(
        "Corefile",
        "a,\n b {\n foo one {\n nested { value }\n }\n bar two\n}\nc {\n baz\n}",
    )
    .unwrap();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].keys, ["a", "b"]);
    assert_eq!(blocks[1].keys, ["c"]);
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
    assert_eq!(parse("Corefile", "a").unwrap()[0].keys, ["a"]);
}

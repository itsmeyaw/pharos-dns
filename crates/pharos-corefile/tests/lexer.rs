use pharos_corefile::lex;

#[test]
fn caddy_lexer_cases() {
    let cases = [
        ("\u{feff}:8080", vec![(1, ":8080")]),
        (
            "host:123\n\n directive",
            vec![(1, "host:123"), (3, "directive")],
        ),
        (
            "a {\n # comment\n b # comment\n}",
            vec![(1, "a"), (1, "{"), (3, "b"), (4, "}")],
        ),
        (
            r#"a "quoted \"value\" \\ end" b"#,
            vec![(1, "a"), (1, "quoted \"value\" \\\\ end"), (1, "b")],
        ),
        (
            "a \"one\ntwo\" b\r\nc",
            vec![(1, "a"), (1, "one\ntwo"), (2, "b"), (3, "c")],
        ),
        (
            "empty \"\" string",
            vec![(1, "empty"), (1, ""), (1, "string")],
        ),
        ("abc#comment\nnext", vec![(1, "abc"), (2, "next")]),
        ("unclosed \"value", vec![(1, "unclosed"), (1, "value")]),
    ];
    for (input, expected) in cases {
        let tokens = lex("Corefile", input);
        let actual: Vec<_> = tokens.iter().map(|t| (t.line, t.text.as_str())).collect();
        assert_eq!(actual, expected, "{input:?}");
        assert!(tokens.iter().all(|t| t.file == "Corefile"));
    }
}

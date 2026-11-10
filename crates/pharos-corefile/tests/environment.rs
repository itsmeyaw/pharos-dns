use pharos_corefile::parse_with_env;

#[test]
fn replaces_both_environment_syntaxes_in_keys_and_arguments() {
    let blocks = parse_with_env(
        "Corefile",
        "{%HOST%}:{$PORT}\n di{$NAME} \"hello {$NAME}\" {$MISSING} {%EMPTY} {$}",
        |name| match name {
            "HOST" => Some("example.org".into()),
            "PORT" => Some("53".into()),
            "NAME" => Some("world".into()),
            _ => None,
        },
    )
    .unwrap();
    assert_eq!(blocks[0].keys, ["example.org:53"]);
    let args = &blocks[0].directives["diworld"];
    assert_eq!(
        args.iter().map(|t| t.text.as_str()).collect::<Vec<_>>(),
        ["di{$NAME}", "hello world", "", "{%EMPTY}", "{$}"]
    );
}

#[test]
fn expands_environment_values_that_contain_more_references() {
    let blocks = parse_with_env("Corefile", "{$OUTER}", |name| match name {
        "OUTER" => Some("{$INNER}".into()),
        "INNER" => Some("example.org".into()),
        _ => None,
    })
    .unwrap();
    assert_eq!(blocks[0].keys, ["example.org"]);
}

#[test]
fn recursive_environment_values_do_not_grow_without_bound() {
    let blocks = parse_with_env("Corefile", "{$LOOP}", |_| Some("{$LOOP}{$LOOP}".into())).unwrap();
    assert_eq!(blocks[0].keys, ["{$LOOP}{$LOOP}"]);
}

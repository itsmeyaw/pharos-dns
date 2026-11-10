use pharos_corefile::{BlockContext, Cursor, Directive, Error, configure, parse};

fn record(cursor: &mut Cursor<'_>, block: &mut BlockContext<Vec<String>>) -> Result<(), Error> {
    while cursor.next() {
        let name = cursor.val().to_owned();
        let args = cursor.remaining_args();
        block.config.push(format!("{name}:{}", args.join(",")));
    }
    Ok(())
}

#[test]
fn setup_runs_in_plugin_order_and_shares_configuration() {
    let blocks = parse(
        "Corefile",
        "a.test b.test {\n second 2\n first 1\n second 3\n}",
    )
    .unwrap();
    let registry = [
        Directive {
            name: "first",
            once: true,
            setup: record,
        },
        Directive {
            name: "second",
            once: false,
            setup: record,
        },
    ];
    let result = configure(&blocks, &registry).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0]
            .keys()
            .iter()
            .map(|key| key.domain.as_str())
            .collect::<Vec<_>>(),
        ["a.test.", "b.test."]
    );
    assert_eq!(result[0].config, ["first:1", "second:2", "second:3"]);
}

#[test]
fn unknown_and_once_only_directives_report_locations() {
    let registry = [Directive {
        name: "first",
        once: true,
        setup: record,
    }];
    let unknown = parse("Corefile", ". {\n mystery thing\n}").unwrap();
    let error = configure(&unknown, &registry).unwrap_err();
    assert_eq!(
        (error.file.as_str(), error.line, error.message.as_str()),
        ("Corefile", 2, "Unknown directive 'mystery'")
    );
    let twice = parse(
        "Corefile",
        ". {\n first {\n nested first\n }\n first value\n}",
    )
    .unwrap();
    let error = configure(&twice, &registry).unwrap_err();
    assert_eq!(error.line, 5);
    assert!(error.message.contains("first"));
}

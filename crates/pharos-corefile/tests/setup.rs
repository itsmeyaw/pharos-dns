use pharos_corefile::{BlockContext, Cursor, Directive, Error, configure, parse};

fn record(cursor: &mut Cursor<'_>, block: &mut BlockContext<Vec<String>>) -> Result<(), Error> {
    while cursor.next() {
        let name = cursor.val().to_owned();
        let args = cursor.remaining_args();
        block.config.push(format!("{name}:{}", args.join(",")));
    }
    Ok(())
}

fn view(_: &mut Cursor<'_>, block: &mut BlockContext<Vec<String>>) -> Result<(), Error> {
    block.view = true;
    Ok(())
}

fn bind(cursor: &mut Cursor<'_>, block: &mut BlockContext<Vec<String>>) -> Result<(), Error> {
    cursor.next();
    block.listen_addresses = cursor.remaining_args();
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
fn directive_registry_can_be_borrowed_from_the_caller() {
    let name = String::from("first");
    let registry = [Directive {
        name: &name,
        once: false,
        setup: record,
    }];
    let blocks = parse("Corefile", ". {\n first value\n}").unwrap();
    assert_eq!(
        configure(&blocks, &registry).unwrap()[0].config,
        ["first:value"]
    );
}

#[test]
fn empty_public_directive_tokens_do_not_panic() {
    let mut blocks = parse("Corefile", ". {\n}").unwrap();
    blocks[0].directives.insert("unknown".into(), Vec::new());
    let registry: &[Directive<'_, Vec<String>>] = &[];
    assert!(configure(&blocks, registry).is_err());
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

#[test]
fn validates_duplicate_keys_and_listener_overlaps() {
    let registry = [
        Directive {
            name: "view",
            once: true,
            setup: view,
        },
        Directive {
            name: "bind",
            once: true,
            setup: bind,
        },
    ];
    for (input, valid) in [
        ("example.org {\n}\nEXAMPLE.ORG:53 {\n}", false),
        ("example.org example.org", false),
        ("example.org {\n}\ntls://example.org {\n}", true),
        ("example.org {\n}\nexample.org:54 {\n}", true),
        ("example.org {\n}\nsub.example.org {\n}", true),
        ("example.org {\n view\n}\nexample.org", true),
        ("example.org {\n}\nexample.org {\n view\n}", true),
        (
            "example.org {\n bind 127.0.0.1\n}\nexample.org {\n bind 127.0.0.2\n}",
            true,
        ),
        ("example.org {\n bind 127.0.0.1\n}\nexample.org", false),
        (
            "example.org {\n}\nexample.org {\n bind 127.0.0.1\n view\n}",
            false,
        ),
        (
            "example.org {\n bind 127.0.0.1\n view\n}\nexample.org",
            true,
        ),
    ] {
        let blocks = parse("Corefile", input).unwrap();
        let result = configure(&blocks, &registry);
        assert_eq!(result.is_ok(), valid, "{input}: {result:?}");
        if let Err(error) = result {
            assert_eq!(error.file, "Corefile");
        }
    }
}

#[test]
fn coredns_overlap_checker_reports_conflicting_addresses() {
    let registry = [Directive {
        name: "bind",
        once: true,
        setup: bind,
    }];
    for (input, expected) in [
        (
            ". {\n}\n. {\n}",
            "cannot serve dns://.:53 - it is already defined",
        ),
        (
            ". {\n}\n.:54 {\n}\n. {\n bind 127.0.0.1\n}",
            "cannot serve dns://.:53 on 127.0.0.1 - zone overlap listener capacity with dns://.:53",
        ),
        (
            ". {\n bind 127.0.0.1\n}\n.:54 {\n}\n. {\n bind 127.0.0.1\n}",
            "cannot serve dns://.:53 on 127.0.0.1 - it is already defined",
        ),
        (
            ". {\n bind 127.0.0.1 128.0.0.1 129.0.0.1\n}\n.:54 {\n}\n. {\n}",
            "cannot serve dns://.:53 - zone overlap listener capacity with dns://.:53 on 129.0.0.1",
        ),
        (
            ". {\n bind 127.0.0.1\n}\ncom {\n bind 127.0.0.1\n}\ncom {\n}",
            "cannot serve dns://com.:53 - zone overlap listener capacity with dns://com.:53 on 127.0.0.1",
        ),
    ] {
        let error = configure(&parse("Corefile", input).unwrap(), &registry).unwrap_err();
        assert_eq!(error.message, expected);
    }
}

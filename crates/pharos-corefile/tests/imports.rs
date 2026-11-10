use pharos_corefile::parse;
use std::{fs, path::PathBuf};

fn fixture_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!("pharos-imports-{}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn imports_snippets_and_files_in_both_scopes() {
    let dir = fixture_dir();
    fs::write(dir.join("inner.conf"), "two 2\n").unwrap();
    fs::write(dir.join("a.server"), "second {\n three\n}\n").unwrap();
    let source =
        "(common) {\n one 1\n}\nfirst {\n import common\n import inner.conf\n}\nimport *.server\n";
    let blocks = parse(&dir.join("Corefile").to_string_lossy(), source).unwrap();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].directives["one"][1].text, "1");
    assert_eq!(blocks[0].directives["two"][1].text, "2");
    assert_eq!(blocks[1].keys, ["second"]);
    assert_eq!(
        blocks[0].directives["two"][0].file,
        dir.join("inner.conf").to_string_lossy()
    );
}

#[test]
fn rejects_extra_arguments_missing_files_and_import_cycles() {
    let dir = fixture_dir();
    let filename = dir.join("Corefile");
    fs::write(dir.join("cycle"), "import cycle\n").unwrap();
    for source in [
        "import absent",
        "import absent extra",
        "import cycle",
        "(loop) {\n import loop\n}\nimport loop",
    ] {
        assert!(
            parse(&filename.to_string_lossy(), source).is_err(),
            "{source}"
        );
    }
    assert!(
        parse(&filename.to_string_lossy(), "import *.missing")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn imports_inside_directive_blocks() {
    let dir = fixture_dir();
    fs::write(dir.join("options"), "option value\n").unwrap();
    let source = "first {\n proxy {\n import options\n }\n}";
    let blocks = parse(&dir.join("Corefile").to_string_lossy(), source).unwrap();
    assert_eq!(
        blocks[0].directives["proxy"]
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>(),
        ["proxy", "{", "option", "value", "}"]
    );
}

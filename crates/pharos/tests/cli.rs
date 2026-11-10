#![forbid(unsafe_code)]

use std::process::Command;

#[test]
fn version_uses_pharos_identity() {
    for flag in ["--version", "-V"] {
        let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
            .arg(flag)
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.starts_with("Pharos-0.1.0\nCoreDNS-1.15.0 compatible\n"),
            "{text}"
        );
    }
}

#[test]
fn legacy_flags_explain_replacements() {
    for (old, new) in [
        ("-conf", "--conf"),
        ("-dns.port", "--port"),
        ("-pidfile", "--pidfile"),
        ("-plugins", "--plugins"),
        ("-version", "--version"),
        ("-quiet", "--quiet"),
        ("-log-format", "--log-format"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
            .arg(old)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains(&format!("use {new} instead of {old}"))
        );
    }
}

#[test]
fn plugins_list_enabled_directives() {
    let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
        .arg("--plugins")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("whoami\n"));
}

#[test]
fn invalid_flags_fail() {
    for args in [
        vec!["--port", "no"],
        vec!["--port", "65536"],
        vec!["--conf"],
        vec!["--log-format", "xml"],
        vec!["--unknown"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!output.stderr.is_empty());
    }
}

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

#![forbid(unsafe_code)]

use std::process::Command;

#[test]
fn check_sets_up_without_listening_and_reports_applicable_deviations() {
    use std::io::Write;
    use std::process::Stdio;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pharos"))
        .args(["check", "--conf", "stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    write!(
        child.stdin.take().unwrap(),
        ".:{port} {{\n cache 30\n kubernetes cluster.local\n}}\n"
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "stdin",
        "cache",
        "kubernetes",
        "Negative Responses use the SOA MINIMUM",
        "API client creation",
        "Other built-in Directives are disabled by default",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(!text.contains("## hosts"), "{text}");
}

#[test]
fn check_errors_match_startup_and_flags_keep_cli_exit_codes() {
    use std::io::Write;
    use std::process::Stdio;
    let run = |args: &[&str]| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pharos"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b".:53 {\nmissing\n}\n")
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let startup = run(&["--conf", "stdin"]);
    let check = run(&["check", "--conf", "stdin"]);
    assert_eq!(check.status.code(), Some(1));
    assert_eq!(check.stderr, startup.stderr);
    for (args, message) in [
        (&["check", "-conf"][..], "use --conf instead of -conf"),
        (&["check", "--unknown"][..], "unknown argument"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains(message));
    }
    let help = Command::new(env!("CARGO_BIN_EXE_pharos"))
        .args(["check", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stderr).contains("pharos check"));
}

#[test]
fn check_uses_the_same_corefile_lookup_order_as_startup() {
    if std::path::Path::new("/etc/pharos/pharos.conf").exists() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("pharos-check-lookup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Corefile"), ". {\nwhoami\n}\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
        .arg("check")
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("Corefile: Corefile;"));
    assert!(text.contains("## whoami"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn check_accepts_upstream_default_corefiles() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corefiles");
    for (file, expected) in [
        (
            "kubeadm",
            &[
                "Negative Responses use the SOA MINIMUM",
                "API client creation and kubeconfig validation",
            ][..],
        ),
        (
            "addon",
            &[
                "Negative Responses use the SOA MINIMUM",
                "API client creation and kubeconfig validation",
            ][..],
        ),
        (
            "helm",
            &[
                "Negative Responses use the SOA MINIMUM",
                "API client creation and kubeconfig validation",
            ][..],
        ),
        (
            "k3s",
            &[
                "Negative Responses use the SOA MINIMUM",
                "API client creation and kubeconfig validation",
                "Pharos discards names that are not valid DNS names or UTF-8",
            ][..],
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
            .arg("check")
            .arg("--conf")
            .arg(dir.join(file))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{file}: {}\n{text}",
            String::from_utf8_lossy(&output.stderr)
        );
        for entry in expected {
            assert!(text.contains(entry), "{file}: missing {entry}\n{text}");
        }
    }
}

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
        assert!(
            text.contains(&format!(
                "{}/{}, rustc ",
                std::env::consts::OS,
                std::env::consts::ARCH
            )),
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
        ("-help", "--help"),
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
fn help_flags_print_usage_and_exit_successfully() {
    for flag in ["-h", "--help"] {
        let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
            .arg(flag)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stdout.is_empty());
        let usage = String::from_utf8(output.stderr).unwrap();
        assert!(
            usage.lines().skip(1).all(|line| line.starts_with("  ")),
            "{usage}"
        );
        for option in [
            "Usage:",
            "--help",
            "--conf",
            "--port",
            "--pidfile",
            "--plugins",
            "--version",
            "--quiet",
            "--log-format",
        ] {
            assert!(usage.contains(option), "{usage}");
        }
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
    assert!(String::from_utf8_lossy(&output.stdout).contains("kubernetes\n"));
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

#[test]
fn corefile_errors_report_their_source() {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_pharos"))
        .args(["--conf", "stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b".:1053 {\nmissing\n}\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("stdin:2: Unknown directive 'missing'")
    );

    let path = std::env::temp_dir().join(format!("pharos-cli-{}", std::process::id()));
    std::fs::write(&path, ".:1053 {\nmissing\n}\n").unwrap();
    for flag in ["-c", "--conf"] {
        let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
            .arg(flag)
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&format!("{}:2:", path.display()))
        );
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn log_formats_are_accepted() {
    for format in ["text", "json"] {
        let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
            .args(["--log-format", format, "-V"])
            .output()
            .unwrap();
        assert!(output.status.success());
    }
}

#[test]
fn corefile_fallback_and_parse_errors_report_location() {
    let dir = std::env::temp_dir().join(format!("pharos-lookup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Corefile"), ". {\nwhoami\n").unwrap();
    if !std::path::Path::new("/etc/pharos/pharos.conf").exists() {
        let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
            .current_dir(&dir)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("Corefile:2:"));
    }
    std::fs::remove_dir_all(dir).unwrap();
}

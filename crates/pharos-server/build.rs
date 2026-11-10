#![forbid(unsafe_code)]

use std::process::Command;

fn output(command: &str, args: &[&str]) -> String {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .filter(|result| result.status.success())
        .and_then(|result| String::from_utf8(result.stdout).ok())
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn main() {
    let revision = output("git", &["rev-parse", "--short=12", "HEAD"]);
    let head = output("git", &["rev-parse", "--git-path", "HEAD"]);
    let reference = output("git", &["symbolic-ref", "-q", "HEAD"]);
    let reference_path = output("git", &["rev-parse", "--git-path", &reference]);
    for path in [head, reference_path] {
        if path != "unknown" {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let rustc = output(
        &std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned()),
        &["--version"],
    );
    println!("cargo:rustc-env=PHAROS_REVISION={revision}");
    println!("cargo:rustc-env=PHAROS_RUSTC={rustc}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUSTC");
}

#![forbid(unsafe_code)]

use std::process::Command;

fn main() {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .unwrap_or_else(|| "rustc unknown".into());
    let revision = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=PHAROS_RUSTC={version}");
    println!("cargo:rustc-env=PHAROS_REVISION={revision}");
    println!("cargo:rerun-if-changed=build.rs");
    for name in ["HEAD", "packed-refs"] {
        watch_git_path(name);
    }
    if let Ok(output) = Command::new("git")
        .args(["symbolic-ref", "-q", "HEAD"])
        .output()
        && output.status.success()
    {
        watch_git_path(String::from_utf8_lossy(&output.stdout).trim());
    }
}

fn watch_git_path(name: &str) {
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "--git-path", name])
        .output()
        && output.status.success()
    {
        println!(
            "cargo:rerun-if-changed={}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
}

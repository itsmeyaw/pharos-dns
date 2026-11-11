use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const VERSION: &str = "0.26.3";

pub(crate) fn binary(root: &Path) -> PathBuf {
    root.join("target/hickory")
        .join(VERSION)
        .join("bin/hickory-dns")
}

pub(crate) fn build(root: &Path) -> Result<PathBuf, String> {
    let destination = binary(root);
    if fs::metadata(&destination).is_ok_and(|m| m.is_file() && m.len() > 0) {
        return Ok(destination);
    }
    // `cargo install` builds in a temporary directory and only installs on success.
    let output = Command::new("cargo")
        .args(["install", "hickory-dns", "--locked", "--version", VERSION])
        .arg("--root")
        .arg(root.join("target/hickory").join(VERSION))
        .output()
        .map_err(|error| format!("could not run cargo install hickory-dns: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "could not build Hickory DNS ({}): {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(destination)
}

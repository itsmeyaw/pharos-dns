#![forbid(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

const FORBID_UNSAFE: &str = "#![forbid(unsafe_code)]";

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("check") => check(),
        _ => {
            eprintln!("usage: cargo xtask check");
            ExitCode::FAILURE
        }
    }
}

fn check() -> ExitCode {
    for args in [
        &["fmt", "--all", "--check"][..],
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
        &["test", "--workspace"],
        &["deny", "check"],
    ] {
        if let Err(message) = run_cargo(args) {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let crates = match pharos_crates(root) {
        Ok(crates) => crates,
        Err(message) => {
            eprintln!("unsafe-code gate failed: {message}");
            return ExitCode::FAILURE;
        }
    };
    match unsafe_gate(&crates) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("unsafe-code gate failed: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run_cargo(args: &[&str]) -> Result<(), String> {
    if args.first() == Some(&"deny")
        && Command::new("cargo-deny")
            .arg("--version")
            .status()
            .is_err()
    {
        return Err(
            "cargo-deny is required; install it with: cargo install --locked cargo-deny".to_owned(),
        );
    }

    match Command::new("cargo").args(args).status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("cargo {} failed with {status}", args.join(" "))),
        Err(error) => Err(format!("could not run cargo {}: {error}", args.join(" "))),
    }
}

fn pharos_crates(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut crates = fs::read_dir(root.join("crates"))
        .map_err(|error| format!("{}: {error}", root.join("crates").display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    crates.push(root.join("xtask"));
    Ok(crates)
}

fn unsafe_gate(crates: &[PathBuf]) -> Result<(), String> {
    for crate_root in crates {
        let source_root = crate_root.join("src");
        let crate_root_source = if source_root.join("lib.rs").exists() {
            source_root.join("lib.rs")
        } else {
            source_root.join("main.rs")
        };
        let source = fs::read_to_string(&crate_root_source)
            .map_err(|error| format!("{}: {error}", crate_root_source.display()))?;
        if !source.trim_start().starts_with(FORBID_UNSAFE) {
            return Err(format!(
                "{} is missing {FORBID_UNSAFE}",
                crate_root_source.display()
            ));
        }

        for source_file in rust_sources(crate_root)? {
            let source = fs::read_to_string(&source_file)
                .map_err(|error| format!("{}: {error}", source_file.display()))?;
            if contains_unsafe_code(&source) {
                return Err(format!("unsafe keyword in {}", source_file.display()));
            }
        }
    }
    Ok(())
}

fn rust_sources(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let mut sources = Vec::new();
    for entry in
        fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_dir() {
            sources.extend(rust_sources(&path)?);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
    Ok(sources)
}

// cargo-geiger is unreliable on new toolchains, so scan Rust tokens locally instead.
fn contains_unsafe_code(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index = skip_block_comment(bytes, index + 2)
            }
            b'"' => index = skip_quoted(bytes, index + 1, b'"'),
            b'\'' => index = skip_char_literal(bytes, index),
            b'r' => {
                if let Some(end) = raw_string_end(bytes, index) {
                    index = end;
                } else if bytes.get(index + 1) == Some(&b'#') {
                    index += 2;
                    while index < bytes.len()
                        && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                    {
                        index += 1;
                    }
                } else {
                    let start = index;
                    index += 1;
                    while index < bytes.len()
                        && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                    {
                        index += 1;
                    }
                    if &source[start..index] == "unsafe" {
                        return true;
                    }
                }
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                if &source[start..index] == "unsafe" {
                    return true;
                }
            }
            _ => index += 1,
        }
    }
    false
}

fn skip_block_comment(bytes: &[u8], mut index: usize) -> usize {
    let mut depth = 1;
    while index + 1 < bytes.len() && depth > 0 {
        match (bytes[index], bytes[index + 1]) {
            (b'/', b'*') => {
                depth += 1;
                index += 2;
            }
            (b'*', b'/') => {
                depth -= 1;
                index += 2;
            }
            _ => index += 1,
        }
    }
    index
}

fn skip_quoted(bytes: &[u8], mut index: usize, quote: u8) -> usize {
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
        } else if bytes[index] == quote {
            return index + 1;
        } else {
            index += 1;
        }
    }
    index
}

fn skip_char_literal(bytes: &[u8], start: usize) -> usize {
    if bytes.get(start + 1) == Some(&b'\\') {
        return skip_quoted(bytes, start + 2, b'\'');
    }
    let width = match bytes.get(start + 1) {
        Some(0..=0x7f) => 1,
        Some(0xc0..=0xdf) => 2,
        Some(0xe0..=0xef) => 3,
        Some(0xf0..=0xf7) => 4,
        _ => return start + 1,
    };
    let Some(character) = bytes
        .get(start + 1..start + 1 + width)
        .and_then(|character| std::str::from_utf8(character).ok())
        .and_then(|source| source.chars().next())
    else {
        return start + 1;
    };
    let end = start + 1 + character.len_utf8();
    if bytes.get(end) == Some(&b'\'') {
        end + 1
    } else {
        start + 1
    }
}

fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut quote = start + 1;
    while bytes.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }
    let hashes = quote - start - 1;
    let mut index = quote + 1;
    while index < bytes.len() {
        if bytes[index] == b'"'
            && bytes
                .get(index + 1..index + 1 + hashes)
                .is_some_and(|ending| ending.iter().all(|byte| *byte == b'#'))
        {
            return Some(index + 1 + hashes);
        }
        index += 1;
    }
    Some(index)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::Path,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::unsafe_gate;

    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn unsafe_gate_rejects_code_but_ignores_comments_and_strings() {
        let fixture = TempFixture::new();
        fixture.crate_with_source(
            "safe",
            "#![forbid(unsafe_code)]\n// unsafe\nconst NOTE: &str = \"unsafe\";\nfn raw_identifier() { let r#unsafe = 0; }\n",
        );
        assert!(unsafe_gate(&[fixture.path().join("safe")]).is_ok());

        fixture.crate_with_source(
            "unsafe_code",
            "#![forbid(unsafe_code)]\nfn needs_unsafe() { unsafe {} }\n",
        );
        assert!(unsafe_gate(&[fixture.path().join("unsafe_code")]).is_err());
    }

    #[test]
    fn unsafe_gate_requires_forbid_attribute() {
        let fixture = TempFixture::new();
        fixture.crate_with_source("missing_forbid", "pub fn safe() {}\n");

        assert!(unsafe_gate(&[fixture.path().join("missing_forbid")]).is_err());
    }

    #[test]
    fn unsafe_gate_detects_code_after_a_lifetime() {
        let fixture = TempFixture::new();
        fixture.crate_with_source(
            "lifetime",
            "#![forbid(unsafe_code)]\nfn needs_unsafe(_: &'static str) { unsafe {} }\n",
        );

        assert!(unsafe_gate(&[fixture.path().join("lifetime")]).is_err());
    }

    struct TempFixture {
        path: std::path::PathBuf,
    }

    impl TempFixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "pharos-xtask-test-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn crate_with_source(&self, name: &str, source: &str) {
            let src = self.path.join(name).join("src");
            fs::create_dir_all(&src).unwrap();
            fs::write(src.join("lib.rs"), source).unwrap();
        }
    }

    impl Drop for TempFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }
}

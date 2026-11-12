#![forbid(unsafe_code)]

mod bench;
mod compare;
mod coredns;
mod differential;
mod e2e;
mod hickory;
mod query;

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::Duration,
};

const FORBID_UNSAFE: &str = "#![forbid(unsafe_code)]";
const FUZZ_TARGETS: &[&str] = &["message", "name", "roundtrip", "differential", "zone"];

fn main() -> ExitCode {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "check" => check(),
        [command] if command == "coredns" => match coredns::build(root()) {
            Ok(path) => {
                println!("{}", path.display());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        [command] if command == "hickory" => match hickory::build(root()) {
            Ok(path) => {
                println!("{}", path.display());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        [command] if command == "diff" => diff(false),
        [command, flag] if command == "diff" && flag == "--self-test" => diff(true),
        [command] if command == "e2e" => e2e(false),
        [command, flag] if command == "e2e" && flag == "--keep" => e2e(true),
        [command] if command == "fuzz" => fuzz(false),
        [command, flag] if command == "fuzz" && flag == "--short" => fuzz(true),
        [command, rest @ ..] if command == "bench" => match bench::run(root(), rest) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!(
                "usage: cargo xtask check | coredns | hickory | diff [--self-test] | e2e [--keep] | fuzz [--short] | bench [--corefile <path>] [--save-baseline <name> | --baseline <name>]"
            );
            ExitCode::FAILURE
        }
    }
}

fn e2e(keep: bool) -> ExitCode {
    match e2e::run(root(), keep) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

fn cached_coredns() -> PathBuf {
    root().join("target/coredns/v1.15.0/coredns")
}

fn diff(self_test: bool) -> ExitCode {
    let coredns = cached_coredns();
    if !coredns.is_file() {
        eprintln!("CoreDNS is not cached; run cargo xtask coredns first");
        return ExitCode::FAILURE;
    }
    match differential::run(root(), &coredns, self_test) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn fuzz_args(target: &str, short: bool) -> Vec<&str> {
    let mut args = vec!["+nightly", "fuzz", "run"];
    // The installed Apple Silicon nightly's ASan runtime hangs before libFuzzer starts.
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        args.extend(["--sanitizer", "none"]);
    }
    args.push(target);
    args.extend(["--", "-timeout=10"]);
    if short {
        args.push("-max_total_time=60");
    }
    args
}

#[cfg(unix)]
fn configure_fuzz_command(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_fuzz_command(_: &mut Command) {}

fn stop_fuzz_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // POSIX process groups let cancellation include cargo-fuzz and libFuzzer descendants.
        let result = Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stderr(std::process::Stdio::null())
            .status();
        if !matches!(result, Ok(status) if status.success()) {
            let _ = child.kill();
        }
    }
    #[cfg(not(unix))]
    let _ = child.kill();
}

fn fuzz(short: bool) -> ExitCode {
    if Command::new("cargo-fuzz")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("cargo-fuzz is required; install it with: cargo install cargo-fuzz");
        return ExitCode::FAILURE;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    for target in FUZZ_TARGETS {
        if let Err(error) = seed_corpus(root, target) {
            eprintln!("could not seed {target} corpus: {error}");
            return ExitCode::FAILURE;
        }
    }

    let oracle = root.join("crates/pharos-proto/fuzz/target/zone-oracle");
    let built = Command::new("go")
        .args(["build", "-o"])
        .arg(&oracle)
        .arg(".")
        .current_dir(root.join("crates/pharos-proto/tests/fixtures/zone-oracle"))
        .env("GOWORK", "off")
        .status();
    if !matches!(built, Ok(status) if status.success()) {
        eprintln!("could not build the miekg/dns zone oracle (Go 1.26+ required): {built:?}");
        return ExitCode::FAILURE;
    }

    let mut children = Vec::new();
    for target in FUZZ_TARGETS {
        let mut command = Command::new("cargo");
        command
            .args(fuzz_args(target, short))
            .env("PHAROS_ZONE_ORACLE", &oracle)
            .current_dir(root.join("crates/pharos-proto"));
        configure_fuzz_command(&mut command);
        match command.spawn() {
            Ok(child) => children.push((*target, child)),
            Err(error) => {
                eprintln!("could not start {target}: {error}");
                for (_, mut child) in children {
                    stop_fuzz_group(&mut child);
                    let _ = child.wait();
                }
                return ExitCode::FAILURE;
            }
        }
    }
    while !children.is_empty() {
        for index in (0..children.len()).rev() {
            match children[index].1.try_wait() {
                Ok(Some(status)) if status.success() => {
                    children.swap_remove(index);
                }
                Ok(None) => {}
                result => {
                    eprintln!("fuzz target {} failed: {result:?}", children[index].0);
                    for (_, mut child) in children {
                        stop_fuzz_group(&mut child);
                        let _ = child.wait();
                    }
                    return ExitCode::FAILURE;
                }
            }
        }
        if !children.is_empty() {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    ExitCode::SUCCESS
}

fn seed_corpus(root: &Path, target: &str) -> std::io::Result<()> {
    let destination = root.join("crates/pharos-proto/fuzz/corpus").join(target);
    fs::create_dir_all(&destination)?;
    let (source, seed) = if target == "zone" {
        ("crates/pharos-proto/tests/corpus/zone-reference", "zone")
    } else {
        ("crates/pharos-proto/tests/corpus", "bin")
    };
    for entry in fs::read_dir(root.join(source))? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == seed) {
            let target = destination.join(path.file_name().unwrap());
            if !target.exists() {
                fs::copy(path, target)?;
            }
        }
    }
    Ok(())
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
        Ok(()) if cached_coredns().is_file() => diff(false),
        Ok(()) => {
            println!("CoreDNS not cached; skipping differential scenarios");
            ExitCode::SUCCESS
        }
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

    match Command::new("cargo")
        .args(args)
        .env("PHAROS_REQUIRE_INTEROP", "1")
        .status()
    {
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

        // The separate fuzz workspace contains generated libFuzzer code and build artifacts.
        let excluded = if crate_root
            .file_name()
            .is_some_and(|name| name == "pharos-proto")
        {
            Some(crate_root.join("fuzz"))
        } else {
            None
        };
        for source_file in rust_sources(crate_root, excluded.as_deref())? {
            let source = fs::read_to_string(&source_file)
                .map_err(|error| format!("{}: {error}", source_file.display()))?;
            if contains_unsafe_code(&source) {
                return Err(format!("unsafe keyword in {}", source_file.display()));
            }
        }
    }
    Ok(())
}

fn rust_sources(directory: &Path, excluded: Option<&Path>) -> Result<Vec<PathBuf>, String> {
    let mut sources = Vec::new();
    for entry in
        fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_dir() && Some(path.as_path()) != excluded {
            sources.extend(rust_sources(&path, excluded)?);
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

    use super::{fuzz_args, pharos_crates, seed_corpus, unsafe_gate};

    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    #[cfg(unix)]
    #[test]
    fn fuzz_cleanup_terminates_grandchild_processes() {
        use std::{
            io::{BufRead, BufReader},
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 30 & echo $!; wait"])
            .stdout(Stdio::piped());
        super::configure_fuzz_command(&mut command);
        let mut child = command.spawn().unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let grandchild: u32 = line.trim().parse().unwrap();
        super::stop_fuzz_group(&mut child);
        let _ = child.wait();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let alive = Command::new("kill")
                .args(["-0", &grandchild.to_string()])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success();
            if !alive {
                break;
            }
            if Instant::now() >= deadline {
                let _ = Command::new("kill")
                    .args(["-KILL", &grandchild.to_string()])
                    .status();
                panic!("fuzzer grandchild survived cleanup");
            }
            std::thread::yield_now();
        }
    }

    #[test]
    fn fuzz_commands_limit_only_short_runs() {
        let mut expected = vec!["+nightly", "fuzz", "run"];
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            expected.extend(["--sanitizer", "none"]);
        }
        expected.extend(["message", "--", "-timeout=10"]);
        assert_eq!(fuzz_args("message", false), expected);
        expected.push("-max_total_time=60");
        assert_eq!(fuzz_args("message", true), expected);
    }

    #[test]
    fn unsafe_gate_scans_pharos_but_not_separate_fuzz_workspace() {
        let fixture = TempFixture::new();
        fixture.crate_with_source("crates/pharos-proto", "#![forbid(unsafe_code)]\n");
        fixture.crate_with_source("xtask", "#![forbid(unsafe_code)]\n");
        fixture.crate_with_source("crates/pharos-proto/fuzz/target/generated", "unsafe {}\n");
        let crates = pharos_crates(fixture.path()).unwrap();
        assert!(unsafe_gate(&crates).is_ok());
        fixture.crate_with_source("crates/pharos-proto/tests/other", "unsafe {}\n");
        assert!(unsafe_gate(&crates).is_err());
    }

    #[test]
    fn seeds_are_copied_without_overwriting_corpus_or_fixtures() {
        let fixture = TempFixture::new();
        let source = fixture.path().join("crates/pharos-proto/tests/corpus");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("seed.bin"), b"message").unwrap();
        fs::write(source.join("README.md"), b"not a seed").unwrap();
        seed_corpus(fixture.path(), "message").unwrap();
        let target = fixture
            .path()
            .join("crates/pharos-proto/fuzz/corpus/message");
        assert_eq!(fs::read(target.join("seed.bin")).unwrap(), b"message");
        assert!(!target.join("README.md").exists());
        fs::write(target.join("seed.bin"), b"existing").unwrap();
        seed_corpus(fixture.path(), "message").unwrap();
        assert_eq!(fs::read(target.join("seed.bin")).unwrap(), b"existing");
        assert_eq!(fs::read(source.join("seed.bin")).unwrap(), b"message");
    }

    #[test]
    fn zone_target_is_seeded_with_reference_zones() {
        let fixture = TempFixture::new();
        let source = fixture
            .path()
            .join("crates/pharos-proto/tests/corpus/zone-reference");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("a.zone"), b"a 60 IN A 192.0.2.1\n").unwrap();
        fs::write(source.join("a.expected"), b"not a seed").unwrap();
        fs::write(source.parent().unwrap().join("seed.bin"), b"message").unwrap();
        seed_corpus(fixture.path(), "zone").unwrap();
        let target = fixture.path().join("crates/pharos-proto/fuzz/corpus/zone");
        assert!(target.join("a.zone").exists());
        assert!(!target.join("a.expected").exists());
        assert!(!target.join("seed.bin").exists());
    }

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

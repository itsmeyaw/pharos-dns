use std::{
    ffi::OsStr,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

const VERSION: &str = "v1.15.0";
const REPOSITORY: &str = "https://github.com/coredns/coredns.git";
static NEXT_BUILD: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn build(root: &Path) -> Result<PathBuf, String> {
    build_with(
        root,
        OsStr::new("git"),
        OsStr::new("go"),
        OsStr::new(REPOSITORY),
    )
}

fn build_with(root: &Path, git: &OsStr, go: &OsStr, repository: &OsStr) -> Result<PathBuf, String> {
    let root = root.canonicalize().map_err(|error| {
        format!(
            "could not resolve workspace root {}: {error}",
            root.display()
        )
    })?;
    let cache = root.join("target/coredns");
    let destination = cache.join(VERSION).join("coredns");
    match fs::metadata(&destination) {
        Ok(metadata) if metadata.is_file() && metadata.len() > 0 => return Ok(destination),
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "could not inspect {}: {error}",
                destination.display()
            ));
        }
    }

    let version = Command::new(go).arg("version").output().map_err(|error| {
        format!("Go is required to build CoreDNS; install Go and ensure it is on PATH: {error}")
    })?;
    if !version.status.success() {
        return Err(format!(
            "could not run Go: {}",
            String::from_utf8_lossy(&version.stderr)
        ));
    }

    fs::create_dir_all(&cache)
        .map_err(|error| format!("could not create {}: {error}", cache.display()))?;
    let build_dir = loop {
        let path = cache.join(format!(
            ".build-{}-{}",
            std::process::id(),
            NEXT_BUILD.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&path) {
            Ok(()) => break BuildDir(path),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("could not create {}: {error}", path.display())),
        }
    };
    let source = build_dir.0.join("source");
    run(
        Command::new(git)
            .args([
                "clone",
                "--depth",
                "1",
                "--branch",
                VERSION,
                "--single-branch",
            ])
            .arg(repository)
            .arg(&source),
        "clone CoreDNS",
    )?;

    let binary = build_dir.0.join("coredns");
    run(
        Command::new(go)
            .args(["build", "-o"])
            .arg(&binary)
            .current_dir(&source)
            .env("CGO_ENABLED", "0")
            .env("GOWORK", "off")
            .env_remove("GOFLAGS")
            .env_remove("GOOS")
            .env_remove("GOARCH"),
        "build CoreDNS",
    )?;
    let metadata = fs::metadata(&binary).map_err(|error| {
        format!(
            "CoreDNS build did not produce {}: {error}",
            binary.display()
        )
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "CoreDNS build produced an invalid binary: {}",
            binary.display()
        ));
    }
    let directory = cache.join(VERSION);
    fs::create_dir_all(&directory)
        .map_err(|error| format!("could not create {}: {error}", directory.display()))?;
    fs::rename(&binary, &destination)
        .map_err(|error| format!("could not cache {}: {error}", destination.display()))?;
    Ok(destination)
}

fn run(command: &mut Command, action: &str) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|error| format!("could not {action}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "could not {action} ({}): {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

struct BuildDir(PathBuf);

impl Drop for BuildDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::build_with;

    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "pharos-coredns-test-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn script(&self, name: &str, body: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            path
        }

        fn run(&self, git: &Path, go: &Path) -> Result<PathBuf, String> {
            build_with(
                &self.0,
                git.as_os_str(),
                go.as_os_str(),
                "upstream".as_ref(),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn builds_pinned_source_and_reuses_binary_without_tools() {
        let fixture = Fixture::new();
        let git = fixture.script(
            "git",
            "printf '%s\\n' \"$@\" > \"$0.args\"\nfor last do :; done\nmkdir -p \"$last\"",
        );
        let go = fixture.script(
            "go",
            "if [ \"$1\" = version ]; then exit 0; fi\nprintf '%s\\n' \"$CGO_ENABLED\" \"$PWD\" \"$@\" > \"$0.args\"\nwhile [ \"$1\" != -o ]; do shift; done\nprintf binary > \"$2\"",
        );
        let binary = fixture.run(&git, &go).unwrap();
        assert_eq!(
            binary,
            fixture
                .0
                .canonicalize()
                .unwrap()
                .join("target/coredns/v1.15.0/coredns")
        );
        assert_eq!(fs::read(&binary).unwrap(), b"binary");
        let git_args = fs::read_to_string(fixture.0.join("git.args")).unwrap();
        assert!(git_args.contains("--branch\nv1.15.0\n"));
        assert!(git_args.contains("--depth\n1\n"));
        let go_args = fs::read_to_string(fixture.0.join("go.args")).unwrap();
        assert!(go_args.starts_with("0\n"));
        assert!(go_args.contains("\nbuild\n"));
        assert!(!go_args.contains("-tags"));
        let missing = fixture.0.join("missing");
        assert_eq!(fixture.run(&missing, &missing).unwrap(), binary);
    }

    #[test]
    fn reports_missing_go_before_cloning() {
        let fixture = Fixture::new();
        let missing = fixture.0.join("missing");
        let error = fixture.run(&missing, &missing).unwrap_err();
        assert!(error.contains("Go") && error.contains("install"), "{error}");
        assert!(!fixture.0.join("target/coredns/v1.15.0/coredns").exists());
    }

    #[test]
    fn reports_build_failure_without_caching_partial_binary() {
        let fixture = Fixture::new();
        let git = fixture.script("git", "for last do :; done\nmkdir -p \"$last\"");
        let go = fixture.script(
            "go",
            "if [ \"$1\" = version ]; then exit 0; fi\nwhile [ \"$1\" != -o ]; do shift; done\nprintf partial > \"$2\"\necho compile-failed >&2\nexit 1",
        );
        let error = fixture.run(&git, &go).unwrap_err();
        assert!(error.contains("compile-failed"), "{error}");
        assert!(!fixture.0.join("target/coredns/v1.15.0/coredns").exists());
    }

    #[test]
    fn reports_clone_failure() {
        let fixture = Fixture::new();
        let git = fixture.script("git", "echo clone-failed >&2\nexit 1");
        let go = fixture.script("go", "exit 0");
        let error = fixture.run(&git, &go).unwrap_err();
        assert!(error.contains("clone-failed"), "{error}");
    }
}

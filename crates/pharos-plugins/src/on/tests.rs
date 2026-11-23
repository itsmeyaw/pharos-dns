use std::{path::Path, time::Duration};

use pharos_corefile::{Cursor, lex};
use pharos_server::{Lifecycle, Phase};

use super::{Event, Hook, parse, shlex};

fn parse_text(text: &str) -> Result<Vec<Hook>, pharos_corefile::Error> {
    let tokens = lex("Corefile", text);
    parse(&mut Cursor::new("Corefile", &tokens))
}

fn lifecycle(text: &str) -> Lifecycle {
    let mut lifecycle = Lifecycle::default();
    for hook in parse_text(text).unwrap() {
        hook.register(&mut lifecycle);
    }
    lifecycle
}

async fn appears(path: &Path) -> bool {
    for _ in 0..200 {
        if path.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

// Derived from go-shlex v0.0.0-20150515145356 shlex_test.go.
#[test]
fn shlex_splits_like_go_shlex() {
    for (input, expected) in [
        ("one two three", vec!["one", "two", "three"]),
        (
            "one \"два ${three}\" four",
            vec!["one", "два ${three}", "four"],
        ),
        (
            "one 'два ${three}' four",
            vec!["one", "два ${three}", "four"],
        ),
        (
            "onefile *file one?ile onefil[de]",
            vec!["onefile", "*file", "one?ile", "onefil[de]"],
        ),
        (
            "one two \"three four\" \"five \\\"six\\\"\" seven#eight # nine # ten\n eleven",
            vec![
                "one",
                "two",
                "three four",
                "five \"six\"",
                "seven#eight",
                "eleven",
            ],
        ),
        ("a\\ b", vec!["a b"]),
        ("\"\"", vec![""]),
        ("", vec![]),
    ] {
        assert_eq!(shlex::split(input).unwrap(), expected, "{input}");
    }
}

#[test]
fn shlex_rejects_bad_input() {
    for input in ["\"open", "'open", "trailing\\", "`tick", "é"] {
        assert!(shlex::split(input).is_err(), "{input}");
    }
}

// Derived from coredns/caddy v1.1.4 onevent/on_test.go `TestSetup` and `TestCommandParse`.
#[test]
fn parse_validates_event_and_command() {
    for (input, valid) in [
        ("on", false),
        ("on xyz cmd arg", false),
        ("on startup", false),
        ("on startup \"\"", false),
        ("on startup cmd arg", true),
        ("on shutdown cmd arg &", true),
        ("on certrenew cmd arg", true),
        ("on STARTUP cmd", true),
        ("on startup echo 'open", false),
    ] {
        assert_eq!(parse_text(input).is_ok(), valid, "{input}");
    }
}

#[test]
fn parse_keeps_event_command_and_arguments() {
    let hooks =
        parse_text("on startup cmd arg1 arg2\non shutdown cmd arg1 arg2 &\non certrenew cmd")
            .unwrap();
    let expected = [
        (Event::Startup, "cmd", vec!["arg1", "arg2"]),
        (Event::Shutdown, "cmd", vec!["arg1", "arg2", "&"]),
        (Event::CertRenew, "cmd", vec![]),
    ];
    assert_eq!(hooks.len(), expected.len());
    for (hook, (event, command, args)) in hooks.iter().zip(expected) {
        assert_eq!((hook.event, hook.command.as_str()), (event, command));
        assert_eq!(hook.args, args);
    }
}

// coredns/caddy v1.1.4 onevent/on.go: Corefile tokens are re-joined and split again shell-style.
#[test]
fn parse_resplits_joined_arguments() {
    let hooks = parse_text("on startup echo \"a b\" 'c d'").unwrap();
    assert_eq!(hooks[0].args, ["a", "b", "c d"]);
}

#[test]
fn trailing_ampersand_is_the_only_background_marker() {
    let hook = |text: &str| parse_text(text).unwrap().remove(0);
    assert!(hook("on shutdown cmd a &").background());
    assert!(!hook("on shutdown cmd & a").background());
    assert!(!hook("on shutdown &").background());
    assert_eq!(hook("on shutdown cmd a &").arguments(), ["a"]);
}

// coredns/caddy v1.1.4 caddy.go: InstanceStartupEvent follows the old instance's shutdown, so not Started.
#[tokio::test]
async fn startup_fires_on_instance_startup_only() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("startup");
    let lifecycle = lifecycle(&format!("on startup touch {}", marker.display()));
    for phase in [Phase::Startup, Phase::Started] {
        lifecycle.run(phase).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!marker.exists());
    lifecycle.run(Phase::InstanceStartup).await.unwrap();
    assert!(appears(&marker).await);
}

#[tokio::test]
async fn startup_runs_once_per_lifecycle_run() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("log");
    let lifecycle = lifecycle(&format!("on startup sh -c 'echo x >> {}'", log.display()));
    lifecycle.run(Phase::InstanceStartup).await.unwrap();
    assert!(appears(&log).await);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "x\n");
}

async fn pid_of(path: &Path) -> String {
    for _ in 0..200 {
        if let Ok(text) = std::fs::read_to_string(path)
            && text.ends_with('\n')
        {
            return text.trim().to_owned();
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{path:?} never got a pid");
}

fn alive(pid: &str) -> bool {
    std::process::Command::new("kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}

// Pharos policy: a hung blocking `startup` command dies with its instance, so Reloads cannot pile them up.
#[tokio::test]
async fn hung_blocking_startup_command_is_killed_at_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("pid");
    let lifecycle = lifecycle(&format!(
        "on startup sh -c 'echo $$ > {}; exec sleep 30'",
        pidfile.display()
    ));
    lifecycle.run(Phase::InstanceStartup).await.unwrap();
    let pid = pid_of(&pidfile).await;
    assert!(alive(&pid));
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert!(!alive(&pid));
}

// coredns/caddy v1.1.4 onevent/hook/hook.go: a `&` command is started and never waited for or stopped.
#[tokio::test]
async fn background_startup_command_outlives_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("pid");
    let lifecycle = lifecycle(&format!(
        "on startup sh -c 'echo $$ > {}; exec sleep 30' &",
        pidfile.display()
    ));
    lifecycle.run(Phase::InstanceStartup).await.unwrap();
    let pid = pid_of(&pidfile).await;
    lifecycle.run(Phase::Shutdown).await.unwrap();
    let survived = alive(&pid);
    let _ = std::process::Command::new("kill").arg(&pid).status();
    assert!(survived);
}

#[tokio::test]
async fn shutdown_waits_for_a_blocking_command() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("shutdown");
    let lifecycle = lifecycle(&format!("on shutdown touch {}", marker.display()));
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert!(marker.exists());
}

#[tokio::test]
async fn shutdown_ampersand_does_not_wait() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("shutdown");
    let lifecycle = lifecycle(&format!("on shutdown touch {} &", marker.display()));
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert!(appears(&marker).await);
}

#[tokio::test]
async fn shutdown_is_suppressed_by_reload_until_it_fails() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("shutdown");
    let lifecycle = lifecycle(&format!("on shutdown touch {}", marker.display()));
    lifecycle.run(Phase::Restart).await.unwrap();
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert!(!marker.exists());
    lifecycle.run(Phase::RestartFailed).await.unwrap();
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert!(marker.exists());
}

// coredns/caddy v1.1.4 plugins.go: nothing emits `certrenew`.
#[tokio::test]
async fn certrenew_never_fires() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("certrenew");
    let lifecycle = lifecycle(&format!("on certrenew touch {}", marker.display()));
    for phase in [
        Phase::Startup,
        Phase::Started,
        Phase::InstanceStartup,
        Phase::Restart,
        Phase::RestartFailed,
        Phase::Shutdown,
    ] {
        lifecycle.run(phase).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!marker.exists());
}

// Derived from coredns/caddy v1.1.4 onevent/hook/hook_test.go: failures are errors, never panics.
#[tokio::test]
async fn failing_and_missing_commands_do_not_fail_the_lifecycle() {
    let lifecycle = lifecycle(
        "on startup false\non startup pharos-no-such-binary\non shutdown false\non shutdown pharos-no-such-binary",
    );
    lifecycle.run(Phase::InstanceStartup).await.unwrap();
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn slow_startup_command_does_not_block_started() {
    let lifecycle = lifecycle("on startup sleep 30");
    tokio::time::timeout(
        Duration::from_secs(2),
        lifecycle.run(Phase::InstanceStartup),
    )
    .await
    .expect("InstanceStartup waited for the command")
    .unwrap();
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn slow_shutdown_command_is_bounded() {
    let lifecycle = lifecycle("on shutdown sleep 30");
    let started = tokio::time::Instant::now();
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(30));
}

// Never invoke a shell: metacharacters stay literal arguments.
#[tokio::test]
async fn command_is_not_run_through_a_shell() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("injected");
    let lifecycle = lifecycle(&format!("on shutdown echo ; touch {}", marker.display()));
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert!(!marker.exists());
}

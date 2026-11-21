//! `on` Directive: run a command on a lifecycle event, as coredns/caddy `onevent`.

pub(crate) mod setup;
mod shlex;
#[cfg(test)]
mod tests;

use std::{
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use pharos_corefile::{Cursor, Error};
use pharos_server::{Lifecycle, Phase, logging};
use tokio::{process::Command, time::timeout};

// Pharos policy: a hung `shutdown` command may delay process exit by at most this long.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(5);

/// Events `on` accepts (coredns/caddy v1.1.4 onevent/hook/config.go `SupportedEvents`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Startup,
    Shutdown,
    CertRenew,
}

impl Event {
    // coredns/caddy v1.1.4 onevent/on.go: the event name is matched case-insensitively.
    fn parse(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "startup" => Some(Self::Startup),
            "shutdown" => Some(Self::Shutdown),
            "certrenew" => Some(Self::CertRenew),
            _ => None,
        }
    }
}

/// One `on EVENT COMMAND [ARGS...]` line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hook {
    pub event: Event,
    pub command: String,
    /// As written, so a trailing `&` stays in the list.
    pub args: Vec<String>,
}

/// Parse every `on` line of one Server Block.
pub fn parse(cursor: &mut Cursor<'_>) -> Result<Vec<Hook>, Error> {
    let mut hooks = Vec::new();
    // coredns/caddy v1.1.4 onevent/on.go `onParse`: each `on` line is one hook.
    while cursor.next() {
        if !cursor.next_arg() {
            return Err(cursor.arg_err());
        }
        let name = cursor.val().to_owned();
        let event = Event::parse(&name).ok_or_else(|| {
            cursor.error(format!("Wrong event name or event not supported: '{name}'"))
        })?;
        // coredns/caddy v1.1.4 onevent/on.go: arguments are re-joined and split shell-style.
        let line = cursor.remaining_args().join(" ");
        let mut parts = shlex::split(&line)
            .map_err(|error| cursor.error(format!("error parsing command: {error}")))?
            .into_iter();
        // coredns/caddy v1.1.4 commands.go `SplitCommandAndArgs`: an empty command is an error.
        let command = parts
            .next()
            .ok_or_else(|| cursor.error(format!("no command contained in '{line}'")))?;
        hooks.push(Hook {
            event,
            command,
            args: parts.collect(),
        });
    }
    Ok(hooks)
}

impl Hook {
    // coredns/caddy v1.1.4 onevent/hook/hook.go: a trailing `&` argument means non-blocking.
    fn background(&self) -> bool {
        self.args.last().is_some_and(|arg| arg == "&")
    }

    fn arguments(&self) -> &[String] {
        let end = self.args.len() - usize::from(self.background());
        &self.args[..end]
    }

    fn line(&self) -> String {
        std::iter::once(self.command.as_str())
            .chain(self.arguments().iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Start the command directly (no shell) and wait for it, logging failures.
    async fn execute(&self, kill_on_drop: bool) {
        let mut command = Command::new(&self.command);
        // coredns/caddy v1.1.4 onevent/hook/hook.go: the child shares stdin, stdout and stderr.
        command
            .args(self.arguments())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(kill_on_drop);
        let blocking = !self.background();
        logging::log(
            "INFO",
            "on",
            &format!(
                "{} Command \"{}\"",
                if blocking { "Blocking" } else { "Nonblocking" },
                self.line()
            ),
        );
        let failure = match command.spawn() {
            Err(error) => Some(error.to_string()),
            Ok(mut child) => match child.wait().await {
                Err(error) => Some(error.to_string()),
                // coredns/caddy v1.1.4 onevent/hook/hook.go: only a blocking command's exit status is an error.
                Ok(status) if blocking && !status.success() => Some(status.to_string()),
                Ok(_) => None,
            },
        };
        if let Some(failure) = failure {
            logging::log(
                "ERROR",
                "on",
                &format!("error on '{}' hook: {failure}", self.line()),
            );
        }
    }

    /// Register the hook with the Lifecycle; no hook ever blocks Reload or Query serving.
    pub(crate) fn register(self, lifecycle: &mut Lifecycle) {
        let hook = Arc::new(self);
        match hook.event {
            // coredns/caddy v1.1.4 plugins.go: CoreDNS never emits `certrenew`, so it registers nothing.
            Event::CertRenew => {}
            // coredns/caddy v1.1.4 caddy.go: InstanceStartupEvent follows the listeners, on Reload too.
            Event::Startup => lifecycle.register_sync(Phase::Started, move || {
                let hook = Arc::clone(&hook);
                tokio::spawn(async move { hook.execute(false).await });
                Ok(())
            }),
            Event::Shutdown => {
                // coredns/caddy v1.1.4 sigtrap.go: ShutdownEvent fires on process exit, not on Reload.
                let reloading = Arc::new(AtomicBool::new(false));
                for (phase, value) in [(Phase::Restart, true), (Phase::RestartFailed, false)] {
                    let reloading = Arc::clone(&reloading);
                    lifecycle.register_sync(phase, move || {
                        reloading.store(value, Ordering::Relaxed);
                        Ok(())
                    });
                }
                lifecycle.register(Phase::Shutdown, move || {
                    let hook = Arc::clone(&hook);
                    let reloading = Arc::clone(&reloading);
                    async move {
                        if reloading.load(Ordering::Relaxed) {
                            return Ok(());
                        }
                        if hook.background() {
                            tokio::spawn(async move { hook.execute(false).await });
                        } else if timeout(SHUTDOWN_WAIT, hook.execute(true)).await.is_err() {
                            logging::log(
                                "ERROR",
                                "on",
                                &format!("error on '{}' hook: timed out", hook.line()),
                            );
                        }
                        Ok(())
                    }
                });
            }
        }
    }
}

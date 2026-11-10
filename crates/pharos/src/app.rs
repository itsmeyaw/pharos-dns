use crate::Options;
use pharos_server::{Listener, Phase, startup_domains};
use std::{
    collections::BTreeMap,
    fs,
    future::Future,
    io::{self, Read},
    path::Path,
};
use tokio::signal::unix::{Signal, SignalKind, signal};

fn configuration(options: &Options) -> Result<(String, String), String> {
    if options.conf.as_deref() == Some("stdin") {
        let mut contents = String::new();
        io::stdin()
            .read_to_string(&mut contents)
            .map_err(|e| format!("stdin: {e}"))?;
        return Ok(("stdin".into(), contents));
    }
    let selected = options.conf.as_deref().map(String::from).or_else(|| {
        ["/etc/pharos/pharos.conf", "Corefile"]
            .into_iter()
            .find(|path| Path::new(path).exists())
            .map(String::from)
    });
    if let Some(path) = selected {
        let contents = fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
        Ok((path, contents))
    } else {
        Ok(("<default>".into(), default_corefile(options)))
    }
}

fn default_corefile(options: &Options) -> String {
    // shortcut: omit log when disabled; remove this fallback when #18 lands.
    let log = if pharos_plugins::directives().iter().any(|d| d.name == "log") {
        "log\n"
    } else {
        ""
    };
    format!(".:{} {{\nwhoami\n{log}}}\n", options.port.unwrap_or(53))
}

// shortcut: initialize logging when the logging infrastructure from #17 lands.
fn init_logging(_format: &str) {}

struct Signals {
    interrupt: Signal,
    terminate: Signal,
    quit: Signal,
    reload: Signal,
    hangup: Signal,
}
impl Signals {
    fn new() -> io::Result<Self> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            quit: signal(SignalKind::quit())?,
            reload: signal(SignalKind::user_defined1())?,
            hangup: signal(SignalKind::hangup())?,
        })
    }
}

pub async fn run(options: Options) -> Result<u8, (u8, String)> {
    init_logging(options.log_format.as_deref().unwrap_or("text"));
    let mut signals = Signals::new().map_err(|e| (1, e.to_string()))?;
    let (file, input) = configuration(&options).map_err(|e| (1, e))?;
    let mut blocks = pharos_corefile::parse(&file, &input).map_err(|e| (1, e.to_string()))?;
    if blocks.is_empty() {
        blocks = pharos_corefile::parse("<default>", &default_corefile(&options))
            .map_err(|e| (1, e.to_string()))?;
    }
    for block in &mut blocks {
        block.set_default_dns_port(options.port.unwrap_or(53));
    }
    let blocks = pharos_corefile::configure(&blocks, pharos_plugins::directives())
        .map_err(|e| (1, e.to_string()))?;
    let mut domains = BTreeMap::<String, Vec<String>>::new();
    for block in &blocks {
        for key in block.keys() {
            for address in &block.listen_addresses {
                domains
                    .entry(format!("{address}:{}", key.port))
                    .or_default()
                    .push(key.domain.clone());
            }
        }
    }
    let (servers, lifecycle) = pharos_plugins::servers(blocks).map_err(|e| (1, e.to_string()))?;
    let mut listeners = Vec::new();
    for (key, server) in servers {
        listeners.push(
            Listener::bind(key.address, server)
                .await
                .map_err(|e| (1, format!("{}: {e}", key.address)))?,
        );
    }
    lifecycle
        .run(Phase::Startup)
        .await
        .map_err(|e| (1, e.to_string()))?;
    if !options.quiet {
        for (address, domains) in domains {
            print!(
                "{}",
                startup_domains(
                    "",
                    &address,
                    &domains.iter().map(String::as_str).collect::<Vec<_>>()
                )
            );
        }
        crate::version();
    }
    if let Some(path) = &options.pidfile
        && let Err(error) = fs::write(path, format!("{}\n", std::process::id()))
    {
        eprintln!("[ERROR] Could not write pidfile: {path}: {error}");
    }
    let terminate = loop {
        tokio::select! {
            _ = signals.interrupt.recv() => break false,
            _ = signals.terminate.recv() => break true,
            _ = signals.quit.recv() => { remove_pidfile(&options); return Ok(0); },
            _ = signals.hangup.recv() => {},
            _ = signals.reload.recv() => {
                // shortcut: wire Reload to configuration replacement in M1.
                eprintln!("Reload");
            },
        }
    };
    let stop = async {
        let mut result = Ok(());
        for listener in listeners {
            if let Err(error) = listener.shutdown().await
                && result.is_ok()
            {
                result = Err(error);
            }
        }
        result
    };
    let shutdown = shutdown(
        terminate,
        lifecycle.run(Phase::Shutdown),
        || remove_pidfile(&options),
        stop,
    );
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            code = &mut shutdown => return Ok(code),
            _ = signals.interrupt.recv() => { remove_pidfile(&options); return Ok(2); },
            _ = signals.quit.recv() => { remove_pidfile(&options); return Ok(0); },
            _ = signals.hangup.recv() => {},
            _ = signals.terminate.recv() => {},
            _ = signals.reload.recv() => { eprintln!("Reload"); },
        }
    }
}

async fn shutdown(
    terminate: bool,
    hooks: impl Future<Output = io::Result<()>>,
    remove: impl FnOnce(),
    stop: impl Future<Output = io::Result<()>>,
) -> u8 {
    let hooks = hooks.await;
    if let Err(error) = &hooks {
        eprintln!("{error}");
    }
    remove();
    let stopped = stop.await;
    if let Err(error) = &stopped {
        eprintln!("{error}");
    }
    if hooks.is_err() {
        4
    } else if terminate && stopped.is_err() {
        3
    } else {
        0
    }
}

fn remove_pidfile(options: &Options) {
    if let Some(path) = &options.pidfile {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, io};

    use super::shutdown;

    #[tokio::test]
    async fn shutdown_hooks_run_before_pidfile_removal_and_listener_stop() {
        for (terminate, hook_fails, stop_fails, expected) in [
            (true, false, false, 0),
            (true, true, false, 4),
            (true, false, true, 3),
            (true, true, true, 4),
            (false, false, true, 0),
            (false, true, true, 4),
        ] {
            let steps = RefCell::new(Vec::new());
            let hooks = async {
                steps.borrow_mut().push("hooks");
                if hook_fails {
                    Err(io::Error::other("hook"))
                } else {
                    Ok(())
                }
            };
            let remove = || steps.borrow_mut().push("pidfile");
            let stop = async {
                steps.borrow_mut().push("stop");
                if stop_fails {
                    Err(io::Error::other("stop"))
                } else {
                    Ok(())
                }
            };
            assert_eq!(shutdown(terminate, hooks, remove, stop).await, expected);
            assert_eq!(*steps.borrow(), ["hooks", "pidfile", "stop"]);
        }
    }
}

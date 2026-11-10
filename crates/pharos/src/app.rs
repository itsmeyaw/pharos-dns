use crate::Options;
use pharos_server::{Listener, Phase, startup_domains};
use std::{
    collections::BTreeMap,
    fs,
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
        // shortcut: omit log when disabled; remove this fallback when #18 lands.
        let log = if pharos_plugins::directives().iter().any(|d| d.name == "log") {
            "log\n"
        } else {
            ""
        };
        Ok((
            "<default>".into(),
            format!(".:{} {{\nwhoami\n{log}}}\n", options.port.unwrap_or(53)),
        ))
    }
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
    if let Some(path) = &options.pidfile {
        fs::write(path, format!("{}\n", std::process::id()))
            .map_err(|e| (1, format!("{path}: {e}")))?;
    }
    loop {
        tokio::select! {
            _ = signals.interrupt.recv() => break,
            _ = signals.terminate.recv() => break,
            _ = signals.quit.recv() => { remove_pidfile(&options); return Ok(0); },
            _ = signals.hangup.recv() => {},
            _ = signals.reload.recv() => {
                // shortcut: wire Reload to configuration replacement in M1.
                eprintln!("Reload");
            },
        }
    }
    let shutdown = async {
        let mut code = 0;
        for listener in listeners {
            if let Err(error) = listener.shutdown().await {
                eprintln!("{error}");
                code = 3;
            }
        }
        if let Err(error) = lifecycle.run(Phase::Shutdown).await {
            eprintln!("{error}");
            code = 4;
        }
        code
    };
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            code = &mut shutdown => { remove_pidfile(&options); return Ok(code); },
            _ = signals.interrupt.recv() => { remove_pidfile(&options); return Ok(2); },
            _ = signals.quit.recv() => { remove_pidfile(&options); return Ok(0); },
            _ = signals.hangup.recv() => {},
            _ = signals.terminate.recv() => {},
            _ = signals.reload.recv() => { eprintln!("Reload"); },
        }
    }
}

fn remove_pidfile(options: &Options) {
    if let Some(path) = &options.pidfile {
        let _ = fs::remove_file(path);
    }
}

use crate::Options;
use pharos_server::{
    Lifecycle, ListenerRegistry, Phase,
    logging::{self, LogFormat},
    startup_domains,
};
use std::{
    collections::BTreeMap,
    fmt::Write,
    fs,
    future::Future,
    io::{self, Read},
    path::Path,
    time::Duration,
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
    format!(".:{} {{\nwhoami\nlog\n}}\n", options.port.unwrap_or(53))
}

fn init_logging(format: &str) {
    logging::init(if format == "json" {
        LogFormat::Json
    } else {
        LogFormat::Text
    });
}

type Domains = BTreeMap<String, Vec<String>>;
type ReloadConfig = Option<pharos_plugins::reload::Reload>;

fn parse_blocks(
    options: &Options,
    file: &str,
    input: &str,
) -> Result<Vec<pharos_corefile::ServerBlock>, String> {
    let blocks = pharos_corefile::parse(file, input).map_err(|e| e.to_string())?;
    if blocks.is_empty() {
        pharos_corefile::parse("<default>", &default_corefile(options)).map_err(|e| e.to_string())
    } else {
        Ok(blocks)
    }
}

fn prepare(
    options: &Options,
    file: &str,
    input: &str,
    metrics: &pharos_server::metrics::Registry,
) -> Result<
    (
        pharos_plugins::Servers,
        Lifecycle,
        Domains,
        ReloadConfig,
        String,
    ),
    String,
> {
    let mut blocks = parse_blocks(options, file, input)?;
    let hash = corefile_hash(&blocks);
    for block in &mut blocks {
        block.set_default_dns_port(options.port.unwrap_or(53));
    }
    let blocks = pharos_corefile::configure(&blocks, pharos_plugins::directives())
        .map_err(|e| e.to_string())?;
    let reload_config = blocks.iter().filter_map(|block| block.config.reload).last();
    let mut domains = Domains::new();
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
    let (servers, lifecycle) = pharos_plugins::servers_with_registry(blocks, metrics.clone())
        .map_err(|e| e.to_string())?;
    Ok((servers, lifecycle, domains, reload_config, hash))
}

fn digest_hex(digest: aws_lc_rs::digest::Digest) -> String {
    let mut output = String::with_capacity(128);
    for byte in digest.as_ref() {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

fn corefile_hash(blocks: &[pharos_corefile::ServerBlock]) -> String {
    fn count(context: &mut aws_lc_rs::digest::Context, value: usize) {
        context.update(&(value as u64).to_be_bytes());
    }
    fn text(context: &mut aws_lc_rs::digest::Context, value: &str) {
        count(context, value.len());
        context.update(value.as_bytes());
    }
    let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA512);
    count(&mut context, blocks.len());
    for block in blocks {
        count(&mut context, block.keys().len());
        for key in block.keys() {
            text(&mut context, key);
        }
        count(&mut context, block.directives.len());
        for (directive, tokens) in &block.directives {
            text(&mut context, directive);
            count(&mut context, tokens.len());
            for (index, token) in tokens.iter().enumerate() {
                if index > 0 {
                    let previous = &tokens[index - 1];
                    let same_line = previous.file == token.file
                        && previous.line + previous.text.matches('\n').count() == token.line;
                    context.update(&[u8::from(same_line)]);
                }
                text(&mut context, &token.text);
            }
        }
    }
    digest_hex(context.finish())
}

fn interval(config: pharos_plugins::reload::Reload) -> Duration {
    if config.jitter.is_zero() {
        return config.interval;
    }
    let mut bytes = [0; 8];
    if let Err(error) = getrandom::getrandom(&mut bytes) {
        logging::log("ERROR", "reload", &format!("Jitter unavailable: {error}"));
        return config.interval;
    }
    let jitter = config.jitter.as_nanos() as u64;
    let offset = u64::from_ne_bytes(bytes) % jitter;
    config.interval - Duration::from_nanos(jitter / 2) + Duration::from_nanos(offset)
}

fn reread(options: &Options, initial: &str) -> Result<(String, String), String> {
    if options.conf.as_deref() == Some("stdin") {
        Ok(("stdin".to_owned(), initial.to_owned()))
    } else {
        configuration(options)
    }
}

async fn reload(
    options: &Options,
    initial: &str,
    listeners: &mut ListenerRegistry,
    lifecycle: &mut Lifecycle,
    metrics: &pharos_server::metrics::Registry,
) -> Option<(ReloadConfig, String)> {
    let result = async {
        lifecycle
            .run(Phase::Restart)
            .await
            .map_err(|e| e.to_string())?;
        let (file, input) = reread(options, initial)?;
        let (servers, next, _, reload_config, hash) = prepare(options, &file, &input, metrics)?;
        if let Err(error) = next.run(Phase::Startup).await {
            let _ = next.run(Phase::Restart).await;
            let _ = next.run(Phase::Shutdown).await;
            return Err(error.to_string());
        }
        let retired = match listeners.apply(servers).await {
            Ok(retired) => retired,
            Err(error) => {
                let _ = next.run(Phase::Restart).await;
                let _ = next.run(Phase::Shutdown).await;
                return Err(error.to_string());
            }
        };
        while retired
            .iter()
            .any(|state| std::sync::Arc::strong_count(state) > 1)
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        if let Err(error) = lifecycle.run(Phase::Shutdown).await {
            logging::log("ERROR", "", &format!("Reload shutdown: {error}"));
        }
        *lifecycle = next;
        Ok((reload_config, hash))
    }
    .await;
    match result {
        Ok(config) => Some(config),
        Err(error) => {
            metrics.reload_failed();
            logging::log("ERROR", "", &format!("Reload failed: {error}"));
            if let Err(error) = lifecycle.run(Phase::RestartFailed).await {
                logging::log("ERROR", "", &format!("Reload recovery failed: {error}"));
            }
            None
        }
    }
}

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
    let metrics = pharos_server::metrics::Registry::default();
    let (servers, mut lifecycle, domains, reload_config, mut current_hash) =
        prepare(&options, &file, &input, &metrics).map_err(|e| (1, e))?;
    let mut listeners = ListenerRegistry::default();
    listeners
        .apply(servers)
        .await
        .map_err(|e| (1, e.to_string()))?;
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
        logging::log(
            "ERROR",
            "",
            &format!("Could not write pidfile: {path}: {error}"),
        );
    }
    let mut poll_interval = reload_config.map(interval);
    let mut poll_at = poll_interval.map(|duration| tokio::time::Instant::now() + duration);
    if poll_at.is_some() {
        metrics.reload_version(current_hash.clone());
    }
    let terminate = loop {
        tokio::select! {
            _ = signals.interrupt.recv() => break false,
            _ = signals.terminate.recv() => break true,
            _ = signals.quit.recv() => { remove_pidfile(&options); return Ok(0); },
            _ = signals.hangup.recv() => {},
            _ = signals.reload.recv() => {
                logging::log("INFO", "", "SIGUSR1: Reloading");
                if let Some((config, loaded_hash)) = reload(&options, &input, &mut listeners, &mut lifecycle, &metrics).await {
                    current_hash = loaded_hash;
                    poll_interval = config.map(interval);
                    poll_at = poll_interval.map(|duration| tokio::time::Instant::now() + duration);
                    if poll_at.is_some() { metrics.reload_version(current_hash.clone()); }
                }
            },
            _ = async { match poll_at { Some(at) => tokio::time::sleep_until(at).await, None => std::future::pending().await } } => {
                poll_at = poll_interval.map(|duration| tokio::time::Instant::now() + duration);
                if let Ok((file, observed)) = reread(&options, &input)
                    && let Ok(blocks) = parse_blocks(&options, &file, &observed) {
                    let observed_hash = corefile_hash(&blocks);
                    if observed_hash != current_hash {
                        current_hash = observed_hash;
                        if let Some((config, loaded_hash)) = reload(&options, &input, &mut listeners, &mut lifecycle, &metrics).await {
                            current_hash = loaded_hash;
                            poll_interval = config.map(interval);
                            poll_at = poll_interval.map(|duration| tokio::time::Instant::now() + duration);
                        }
                        metrics.reload_version(current_hash.clone());
                    }
                }
            },
        }
    };
    let stop = listeners.shutdown();
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
            _ = signals.reload.recv() => logging::log("INFO", "", "SIGUSR1: Reloading"),
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
        logging::log("ERROR", "", &error.to_string());
    }
    remove();
    let stopped = stop.await;
    if let Err(error) = &stopped {
        logging::log("ERROR", "", &error.to_string());
    }
    // Caddy's SIGTERM path sets 3 after the hooks' 4, so a stop failure wins.
    if terminate && stopped.is_err() {
        3
    } else if hooks.is_err() {
        4
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

    use super::{digest_hex, interval, shutdown};

    #[test]
    fn sha512_and_jitter_match_reload_contract() {
        assert_eq!(
            digest_hex(aws_lc_rs::digest::digest(
                &aws_lc_rs::digest::SHA512,
                b"abc"
            )),
            concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
        let config = pharos_plugins::reload::Reload {
            interval: std::time::Duration::from_secs(10),
            jitter: std::time::Duration::from_secs(4),
        };
        for _ in 0..100 {
            let duration = interval(config);
            assert!(duration >= std::time::Duration::from_secs(8));
            assert!(duration < std::time::Duration::from_secs(12));
        }
    }

    #[tokio::test]
    async fn shutdown_hooks_run_before_pidfile_removal_and_listener_stop() {
        for (terminate, hook_fails, stop_fails, expected) in [
            (true, false, false, 0),
            (true, true, false, 4),
            (true, false, true, 3),
            (true, true, true, 3),
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

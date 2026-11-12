#![forbid(unsafe_code)]
#![recursion_limit = "512"]
//! Pharos command-line binary.
//!
//! Exit codes follow CoreDNS v1.15.0 and coredns/caddy v1.1.4's
//! `coremain/run.go`, `sigtrap.go`, `sigtrap_posix.go` and `caddy.go`:
//!
//! | Code | Meaning |
//! | --- | --- |
//! | 0 | Help, version, Plugin listing, SIGQUIT, or successful shutdown |
//! | 1 | Configuration, startup, or log-format error |
//! | 2 | Invalid flag or second SIGINT during shutdown |
//! | 3 | Listener stop failure after SIGTERM |
//! | 4 | Shutdown hook failure |
//!
//! See `docs/compatibility.md` for remaining differences.

mod app;
mod compatibility;

use std::process::ExitCode;

#[derive(Default)]
struct Options {
    help: bool,
    conf: Option<String>,
    port: Option<u16>,
    pidfile: Option<String>,
    plugins: bool,
    version: bool,
    quiet: bool,
    log_format: Option<String>,
    check: bool,
}

fn options() -> Result<Options, (u8, String)> {
    let mut options = Options::default();
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().is_some_and(|arg| arg == "check") {
        args.next();
        options.check = true;
    }
    while let Some(arg) = args.next() {
        let (flag, value) = arg
            .split_once('=')
            .map_or((arg.as_str(), None), |(a, b)| (a, Some(b.to_owned())));
        let replacement = match flag {
            "-conf" => Some("--conf"),
            "-dns.port" => Some("--port"),
            "-pidfile" => Some("--pidfile"),
            "-plugins" => Some("--plugins"),
            "-version" => Some("--version"),
            "-quiet" => Some("--quiet"),
            "-log-format" => Some("--log-format"),
            "-help" => Some("--help"),
            _ => None,
        };
        if let Some(replacement) = replacement {
            return Err((2, format!("use {replacement} instead of {flag}")));
        }
        if options.check && !matches!(flag, "--help" | "-h" | "--conf" | "-c") {
            return Err((2, format!("unknown argument: {arg}")));
        }
        match flag {
            "--help" | "-h" if value.is_none() => {
                options.help = true;
                return Ok(options);
            }
            "--conf" | "-c" | "--port" | "-p" | "--pidfile" | "--log-format" => {
                let value = value
                    .or_else(|| args.next())
                    .ok_or_else(|| (2, format!("{flag} requires a value")))?;
                match flag {
                    "--conf" | "-c" => options.conf = Some(value),
                    "--port" | "-p" => {
                        options.port = Some(
                            value
                                .parse()
                                .map_err(|_| (2, format!("invalid port: {value}")))?,
                        )
                    }
                    "--pidfile" => options.pidfile = Some(value),
                    _ => {
                        if value != "text" && value != "json" {
                            return Err((1, format!("invalid log format: {value}")));
                        }
                        options.log_format = Some(value);
                    }
                }
            }
            "--plugins" if value.is_none() => options.plugins = true,
            "--version" | "-V" if value.is_none() => options.version = true,
            "--quiet" | "-q" if value.is_none() => options.quiet = true,
            _ => {
                return Err((
                    if flag.starts_with('-') { 2 } else { 1 },
                    format!("unknown argument: {arg}"),
                ));
            }
        }
    }
    Ok(options)
}

fn main() -> ExitCode {
    // Plugin Chain poll depth can exceed Tokio's 2 MiB default; see #90.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024)
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            pharos_server::logging::log("ERROR", "", &error.to_string());
            return ExitCode::from(1);
        }
    };
    runtime.block_on(async_main())
}

async fn async_main() -> ExitCode {
    let options = match options() {
        Ok(options) => options,
        Err((code, error)) => {
            eprintln!("{error}");
            return ExitCode::from(code);
        }
    };
    if options.help {
        if options.check {
            eprint!(
                "Usage: pharos check [--conf <path|stdin>]\n  -h, --help               Print help\n  -c, --conf <path|stdin>  Corefile path or stdin\n"
            );
        } else {
            eprint!(concat!(
                "Usage: pharos [OPTIONS]\n",
                "  check                         Validate configuration without serving\n",
                "  -h, --help                    Print help\n",
                "  -c, --conf <path|stdin>       Corefile path or stdin\n",
                "  -p, --port <port>             Default DNS port (default: 53)\n",
                "      --pidfile <path>          Write process ID to path\n",
                "      --plugins                 List enabled Plugins\n",
                "  -V, --version                 Print version\n",
                "  -q, --quiet                   Suppress startup output\n",
                "      --log-format <text|json>  Select log format\n",
            ));
        }
    } else if options.version {
        version();
    } else if options.plugins {
        print!("{}", pharos_plugins::plugins_listing());
    } else if options.check {
        if let Err(error) = app::check(&options) {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    } else {
        match app::run(options).await {
            Ok(code) => return ExitCode::from(code),
            Err((code, error)) => {
                eprintln!("{error}");
                return ExitCode::from(code);
            }
        }
    }
    ExitCode::SUCCESS
}

fn version() {
    println!(
        "Pharos-{}\nCoreDNS-1.15.0 compatible\n{}/{}, {}, {}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        env!("PHAROS_RUSTC"),
        env!("PHAROS_REVISION")
    );
}

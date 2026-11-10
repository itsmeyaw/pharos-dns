#![forbid(unsafe_code)]

mod app;

use std::process::ExitCode;

#[derive(Default)]
struct Options {
    conf: Option<String>,
    port: Option<u16>,
    pidfile: Option<String>,
    plugins: bool,
    version: bool,
    quiet: bool,
    log_format: Option<String>,
}

fn options() -> Result<Options, (u8, String)> {
    let mut options = Options::default();
    let mut args = std::env::args().skip(1);
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
            _ => None,
        };
        if let Some(replacement) = replacement {
            return Err((2, format!("use {replacement} instead of {flag}")));
        }
        match flag {
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

#[tokio::main]
async fn main() -> ExitCode {
    let options = match options() {
        Ok(options) => options,
        Err((code, error)) => {
            eprintln!("{error}");
            return ExitCode::from(code);
        }
    };
    if options.version {
        version();
    } else if options.plugins {
        print!("{}", pharos_plugins::plugins_listing());
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
        "Pharos-{}\nCoreDNS-1.15.0 compatible",
        env!("CARGO_PKG_VERSION")
    );
}

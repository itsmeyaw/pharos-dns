//! Hosts Directive configuration.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use pharos_corefile::{Cursor, Error, Fallthrough, origins_from_args_or_server_block};
use pharos_server::{Context, Next, Outcome};

mod data;

#[derive(Debug)]
pub struct Hosts {
    pub path: PathBuf,
    pub domains: Vec<String>,
    pub fallthrough: Fallthrough,
    pub fallthrough_unsupported: bool,
    pub ttl: u32,
    pub reload: Duration,
    pub auto_reverse: bool,
    pub inline: Vec<String>,
}

impl Hosts {
    pub fn parse(cursor: &mut Cursor<'_>, server_domains: &[&str]) -> Result<Self, Error> {
        cursor.next();
        let source = cursor.file().to_owned();
        let args = cursor.remaining_args();
        let mut path = PathBuf::from(args.first().map_or("/etc/hosts", String::as_str));
        if args.first().is_some() && path.is_relative() {
            path = Path::new(&source)
                .parent()
                .unwrap_or(Path::new(""))
                .join(path);
        }
        if args.first().is_some() {
            match std::fs::metadata(&path) {
                Ok(metadata) if metadata.is_dir() => pharos_server::logging::log(
                    "WARN",
                    "hosts",
                    &format!("Hosts file {:?} is a directory", path),
                ),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    pharos_server::logging::log(
                        "WARN",
                        "hosts",
                        &format!("File does not exist: {}", path.display()),
                    )
                }
                Err(error) => {
                    return Err(cursor.error(format!(
                        "unable to access hosts file '{}': {error}",
                        path.display()
                    )));
                }
            }
        }
        let zones = args
            .get(1..)
            .unwrap_or_default()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let mut hosts = Self {
            path,
            domains: origins_from_args_or_server_block(&zones, server_domains),
            fallthrough: Fallthrough::default(),
            fallthrough_unsupported: false,
            ttl: 3600,
            reload: Duration::from_secs(5),
            auto_reverse: true,
            inline: Vec::new(),
        };
        while cursor.next_block() {
            let option = cursor.val().to_owned();
            let args = cursor.remaining_args();
            match option.as_str() {
                "fallthrough" => hosts
                    .fallthrough
                    .set_domains_from_args(&args.iter().map(String::as_str).collect::<Vec<_>>()),
                "fallthrough_unsupported" if args.is_empty() => {
                    hosts.fallthrough_unsupported = true
                }
                "fallthrough_unsupported" => return Err(cursor.arg_err()),
                "no_reverse" => hosts.auto_reverse = false,
                "ttl" => {
                    let value = args
                        .first()
                        .ok_or_else(|| cursor.error("ttl needs a time in seconds"))?;
                    let value = value
                        .parse::<u32>()
                        .map_err(|_| cursor.error("invalid ttl"))?;
                    if !(1..=65535).contains(&value) {
                        return Err(cursor.error("invalid ttl"));
                    }
                    hosts.ttl = value;
                }
                "reload" => {
                    if args.len() != 1 {
                        return Err(cursor.arg_err());
                    }
                    let value = &args[0];
                    let magnitude = value.strip_prefix('-').unwrap_or(value);
                    if value.starts_with('-') && magnitude.starts_with(['-', '+']) {
                        return Err(cursor.error("invalid reload duration"));
                    }
                    let duration = crate::health::parse_duration(magnitude)
                        .ok_or_else(|| cursor.error("invalid reload duration"))?;
                    if value.starts_with('-') && !duration.is_zero() {
                        return Err(cursor.error("negative reload duration"));
                    }
                    hosts.reload = duration;
                }
                _ if hosts.fallthrough.domains.is_empty() => hosts.inline.push(
                    std::iter::once(option)
                        .chain(args)
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
                _ => return Err(cursor.error(format!("unknown property '{option}'"))),
            }
        }
        if hosts.fallthrough_unsupported && hosts.fallthrough.domains.is_empty() {
            return Err(cursor.error("fallthrough_unsupported requires fallthrough"));
        }
        Ok(hosts)
    }
}

impl pharos_server::Plugin for Hosts {
    async fn serve<N: Next + Send>(&self, _cx: &mut Context<'_>, _next: N) -> Outcome {
        Outcome::Error(pharos_server::Error::NotImplemented)
    }
}

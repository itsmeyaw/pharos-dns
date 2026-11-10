//! Hosts Directive configuration.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use pharos_corefile::{Cursor, Error, Fallthrough, origins_from_args_or_server_block};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Opcode, Rcode, Section, Type};
use pharos_server::{Context, Next, Outcome, Protocol};

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
    domain_names: Vec<Name>,
    fallthrough_names: Vec<Name>,
    entries: data::Map,
    inline_entries: data::Map,
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
            domain_names: Vec::new(),
            fallthrough_names: Vec::new(),
            entries: data::Map::default(),
            inline_entries: data::Map::default(),
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
        hosts.domain_names = hosts
            .domains
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        hosts.fallthrough_names = hosts
            .fallthrough
            .domains
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        hosts.inline_entries = data::Map::parse(
            hosts.inline.join("\n").as_bytes(),
            &hosts.domain_names,
            hosts.auto_reverse,
            "Inline hosts entries",
        );
        if let Ok(file) = std::fs::File::open(&hosts.path) {
            hosts.entries = data::Map::parse(
                file,
                &hosts.domain_names,
                hosts.auto_reverse,
                &format!("Hosts file {:?}", hosts.path),
            );
        }
        Ok(hosts)
    }
}

impl pharos_server::Plugin for Hosts {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        let mut wire = [0u8; 255];
        let mut len = 0;
        for label in question.name.labels() {
            wire[len] = label.len() as u8;
            len += 1;
            for byte in label {
                wire[len] = byte.to_ascii_lowercase();
                len += 1;
            }
        }
        len += 1;
        let key = &wire[..len];
        if question.qtype != Type::PTR && !contains(key, &self.domain_names) {
            return next.run(cx).await;
        }
        let fallthrough = contains(key, &self.fallthrough_names);
        let ptr = if question.qtype == Type::PTR {
            reverse_address(question.name)
        } else {
            None
        };
        let names1 = ptr.and_then(|ip| self.entries.reverse.get(&ip));
        let names2 = ptr.and_then(|ip| self.inline_entries.reverse.get(&ip));
        if question.qtype == Type::PTR && names1.is_none() && names2.is_none() {
            return next.run(cx).await;
        }
        if question.qtype != Type::A
            && question.qtype != Type::AAAA
            && question.qtype != Type::PTR
            && self.fallthrough_unsupported
            && fallthrough
        {
            return next.run(cx).await;
        }
        let v4 = self.entries.lookup_key(key, true);
        let v6 = self.entries.lookup_key(key, false);
        let inline4 = self.inline_entries.lookup_key(key, true);
        let inline6 = self.inline_entries.lookup_key(key, false);
        let ips = if question.qtype == Type::A {
            (v4, inline4)
        } else if question.qtype == Type::AAAA {
            (v6, inline6)
        } else {
            (&[][..], &[][..])
        };
        if ips.0.is_empty()
            && ips.1.is_empty()
            && names1.is_none()
            && names2.is_none()
            && v4.is_empty()
            && v6.is_empty()
            && inline4.is_empty()
            && inline6.is_empty()
        {
            return if fallthrough {
                next.run(cx).await
            } else {
                Outcome::Unanswered(Rcode::SERVFAIL)
            };
        }
        let max = cx.max_response_size.max(512);
        if cx.response.capacity() < max {
            if cx.protocol == Protocol::Tcp {
                cx.response.reserve(max.saturating_sub(cx.response.len()));
            } else {
                return Outcome::Error(pharos_server::Error::ResponseBufferTooSmall);
            }
        }
        let mut flags = 0x8400 | (cx.query.flags() & 0x7800);
        if cx.query.opcode() == Opcode::QUERY {
            flags |= cx.query.flags() & 0x0110;
        }
        let result = (|| -> Result<(), pharos_server::Error> {
            let mut builder = MessageBuilder::new(cx.response, max, cx.query.id(), flags)
                .map_err(pharos_server::Error::Build)?;
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(pharos_server::Error::Build)?;
            for ip in ips.0.iter().chain(ips.1) {
                match ip {
                    std::net::IpAddr::V4(ip) => builder.record(
                        Section::Answer,
                        question.name,
                        question.qtype,
                        Class::IN,
                        self.ttl,
                        &ip.octets(),
                    ),
                    std::net::IpAddr::V6(ip) => builder.record(
                        Section::Answer,
                        question.name,
                        question.qtype,
                        Class::IN,
                        self.ttl,
                        &ip.octets(),
                    ),
                }
                .map_err(pharos_server::Error::Build)?;
            }
            for name in names1
                .into_iter()
                .flatten()
                .chain(names2.into_iter().flatten())
            {
                builder
                    .record(
                        Section::Answer,
                        question.name,
                        Type::PTR,
                        Class::IN,
                        self.ttl,
                        name.as_wire(),
                    )
                    .map_err(pharos_server::Error::Build)?;
            }
            let _ = builder.finish();
            Ok(())
        })();
        result.map_or_else(Outcome::Error, |()| Outcome::Response)
    }
}

fn contains(mut key: &[u8], domains: &[Name]) -> bool {
    loop {
        if domains
            .iter()
            .any(|domain| key.eq_ignore_ascii_case(domain.as_wire()))
        {
            return true;
        }
        if key[0] == 0 {
            return false;
        }
        key = &key[1 + usize::from(key[0])..];
    }
}

fn reverse_address(name: NameRef<'_>) -> Option<std::net::IpAddr> {
    let mut labels = [&[][..]; 34];
    let mut count = 0;
    for label in name.labels() {
        if count == labels.len() {
            return None;
        }
        labels[count] = label;
        count += 1;
    }
    if count == 6
        && labels[4].eq_ignore_ascii_case(b"in-addr")
        && labels[5].eq_ignore_ascii_case(b"arpa")
    {
        let mut bytes = [0; 4];
        for (i, label) in labels[..4].iter().enumerate() {
            bytes[3 - i] = std::str::from_utf8(label).ok()?.parse().ok()?;
        }
        return Some(std::net::Ipv4Addr::from(bytes).into());
    }
    if count == 34
        && labels[32].eq_ignore_ascii_case(b"ip6")
        && labels[33].eq_ignore_ascii_case(b"arpa")
    {
        let mut bytes = [0; 16];
        for (i, label) in labels[..32].iter().enumerate() {
            if label.len() != 1 {
                return None;
            }
            let digit = (label[0] as char).to_digit(16)? as u8;
            bytes[15 - i / 2] |= digit << ((i % 2) * 4);
        }
        let ip = std::net::Ipv6Addr::from(bytes);
        return Some(
            ip.to_ipv4_mapped()
                .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
        );
    }
    None
}

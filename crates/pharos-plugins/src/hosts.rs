//! Hosts Directive configuration.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use pharos_corefile::{Cursor, Error, Fallthrough, origins_from_args_or_server_block};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Opcode, Rcode, Section, Type};
use pharos_server::{Context, Next, Outcome, Protocol};

mod data;

#[derive(Debug, Default)]
struct State {
    entries: arc_swap::ArcSwap<data::Map>,
    modified: Mutex<Option<(std::time::SystemTime, u64)>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    metrics: Mutex<Option<pharos_server::metrics::HostsMetrics>>,
    inline_len: Mutex<usize>,
}

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
    state: Arc<State>,
    inline_entries: data::Map,
}

impl Hosts {
    pub(crate) fn set_metrics(&self, registry: &pharos_server::metrics::Registry) {
        *self.state.metrics.lock().unwrap() = Some(registry.hosts(&self.path.to_string_lossy()));
        *self.state.inline_len.lock().unwrap() = self.inline_entries.len();
    }
    pub(crate) fn register_hooks(&self, lifecycle: &mut pharos_server::Lifecycle) {
        let state = Arc::clone(&self.state);
        let path = self.path.clone();
        let domains = self.domain_names.clone();
        let auto_reverse = self.auto_reverse;
        let interval = self.reload;
        let start = move || {
            let state = Arc::clone(&state);
            let path = path.clone();
            let domains = domains.clone();
            async move {
                state.read(&path, &domains, auto_reverse);
                if !interval.is_zero() {
                    let task_state = Arc::clone(&state);
                    let task = tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(interval).await;
                            task_state.read(&path, &domains, auto_reverse);
                        }
                    });
                    if let Some(old) = state.task.lock().unwrap().replace(task) {
                        old.abort();
                    }
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Startup, start.clone());
        lifecycle.register(pharos_server::Phase::RestartFailed, start);
        let state = Arc::clone(&self.state);
        let stop = move || {
            let task = state.task.lock().unwrap().take();
            async move {
                if let Some(task) = task {
                    task.abort();
                    let _ = task.await;
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Restart, stop.clone());
        lifecycle.register(pharos_server::Phase::Shutdown, stop);
    }

    pub fn parse(cursor: &mut Cursor<'_>, server_domains: &[&str]) -> Result<Self, Error> {
        cursor.next();
        let args = cursor.remaining_args();
        // shortcut: relative paths use the working directory; join with `root` once that Plugin exists.
        let path = PathBuf::from(args.first().map_or("/etc/hosts", String::as_str));
        if !args.is_empty() {
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
            state: Arc::new(State::default()),
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
        Ok(hosts)
    }
}

impl State {
    fn read(&self, path: &Path, domains: &[Name], auto_reverse: bool) {
        let Ok(file) = std::fs::File::open(path) else {
            return;
        };
        let Ok(metadata) = file.metadata() else {
            return;
        };
        let Ok(modified) = metadata.modified() else {
            return;
        };
        let stamp = (modified, metadata.len());
        let mut previous = self.modified.lock().unwrap();
        if *previous == Some(stamp) {
            return;
        }
        let map = data::Map::parse(file, domains, auto_reverse, &format!("Hosts file {path:?}"));
        if let Some(metrics) = self.metrics.lock().unwrap().as_ref() {
            let timestamp = modified
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0.0, |duration| duration.as_secs_f64());
            metrics.update(map.len() + *self.inline_len.lock().unwrap(), timestamp);
        }
        self.entries.store(Arc::new(map));
        *previous = Some(stamp);
    }
}

impl pharos_server::Plugin for Hosts {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        // RFC 1035 §3.1: wire names are at most 255 octets and end with a zero-length label.
        let mut wire = [0u8; 255];
        let mut len = 0;
        // RFC 4343 §3: DNS name lookup compares ASCII letters case-insensitively.
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
        let entries = self.state.entries.load_full();
        let ptr = if question.qtype == Type::PTR {
            reverse_address(question.name)
        } else {
            None
        };
        let names1 = ptr.and_then(|ip| entries.reverse.get(&ip));
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
        let v4 = entries.lookup_key(key, true);
        let v6 = entries.lookup_key(key, false);
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
                    // RFC 1035 §3.4.1: A RDATA carries a 32-bit Internet address.
                    std::net::IpAddr::V4(ip) => builder.record(
                        Section::Answer,
                        question.name,
                        question.qtype,
                        Class::IN,
                        self.ttl,
                        &ip.octets(),
                    ),
                    // RFC 3596 §2.2: AAAA RDATA carries a 128-bit IPv6 address.
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
            // RFC 1035 §3.3.12: PTR RDATA is a domain name.
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

// RFC 1034 §3.1: a subdomain name ends with its containing domain name.
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
    // RFC 1035 §3.5: IPv4 reverse names use reversed decimal octets without leading zeros.
    if count == 6
        && labels[4].eq_ignore_ascii_case(b"in-addr")
        && labels[5].eq_ignore_ascii_case(b"arpa")
    {
        let mut bytes = [0; 4];
        for (i, label) in labels[..4].iter().enumerate() {
            if label.is_empty()
                || (label.len() > 1 && label[0] == b'0')
                || !label.iter().all(u8::is_ascii_digit)
            {
                return None;
            }
            bytes[3 - i] = std::str::from_utf8(label).ok()?.parse().ok()?;
        }
        return Some(std::net::Ipv4Addr::from(bytes).into());
    }
    // RFC 3596 §2.5: IP6.ARPA names encode IPv6 nibbles in reverse order.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_ipv4_requires_canonical_octets() {
        for (input, expected) in [
            ("1.0.0.127.in-addr.arpa.", true),
            ("01.0.0.127.in-addr.arpa.", false),
            ("+1.0.0.127.in-addr.arpa.", false),
        ] {
            let name: Name = input.parse().unwrap();
            assert_eq!(
                reverse_address(NameRef::parse(name.as_wire(), 0).unwrap()).is_some(),
                expected,
                "{input}"
            );
        }
    }
}

//! Authoritative Zones loaded from master files.

pub(crate) mod setup;
#[cfg(test)]
mod tests;
#[cfg(feature = "plugin-transfer")]
mod transfer;

pub use crate::zone::Zone;
use crate::zone::{ZoneHolder, contains};
use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Opcode, Rcode, Section, Type};
#[cfg(test)]
use pharos_proto::{Message, zone::ZoneParser};
#[cfg(test)]
use pharos_server::Protocol;
use pharos_server::{Context, Next, Outcome, Plugin};
use std::{
    io::{BufReader, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, SystemTime},
};

#[derive(Debug)]
struct Loaded {
    apex: Name,
    path: PathBuf,
    current: ZoneHolder,
    interval: Duration,
    negative_interval: bool,
    by_mtime: bool,
    modified: Mutex<Option<SystemTime>>,
    reload_gate: Mutex<()>,
}

impl Loaded {
    fn reload(&self) -> bool {
        self.reload_with_open(|path| std::fs::File::open(path))
    }

    fn reload_with_open(&self, open: impl FnOnce(&Path) -> std::io::Result<std::fs::File>) -> bool {
        // A cancelled blocking reload can outlive Restart; serialize generation swaps.
        let _gate = self.reload_gate.lock().unwrap();
        // CoreDNS samples the path mtime before opening the Zone on reload.
        let modified = if self.by_mtime {
            let modified =
                match std::fs::metadata(&self.path).and_then(|metadata| metadata.modified()) {
                    Ok(modified) => modified,
                    Err(error) => {
                        pharos_server::logging::log(
                            "ERROR",
                            "file",
                            &format!(
                                "Failed to stat Zone {} in {}: {error}",
                                self.apex,
                                self.path.display()
                            ),
                        );
                        return false;
                    }
                };
            if self
                .modified
                .lock()
                .unwrap()
                .is_some_and(|old| modified <= old)
            {
                return false;
            }
            Some(modified)
        } else {
            None
        };
        let file = match open(&self.path) {
            Ok(file) => file,
            Err(error) => {
                pharos_server::logging::log(
                    "ERROR",
                    "file",
                    &format!(
                        "Failed to open Zone {} in {}: {error}",
                        self.apex,
                        self.path.display()
                    ),
                );
                return false;
            }
        };
        let serial = if self.by_mtime {
            // RFC 1982 §7: Serial zero is an ordinary SOA serial value.
            None
        } else {
            self.current.load().as_ref().and_then(|zone| zone.serial())
        };
        let next = match Zone::load_reader_with_serial(
            self.apex.clone(),
            &self.path,
            BufReader::new(file),
            serial,
        ) {
            Ok(next) => next,
            Err(error) => {
                if error != "no change in SOA serial" {
                    pharos_server::logging::log(
                        "ERROR",
                        "file",
                        &format!(
                            "Failed to parse Zone {} in {}: {error}",
                            self.apex,
                            self.path.display()
                        ),
                    );
                }
                return false;
            }
        };
        // RFC 1035 §6.1.2: Publish a fully loaded Zone as one generation.
        self.current.store(Some(Arc::new(next)));
        if self.by_mtime {
            *self.modified.lock().unwrap() = modified;
        }
        true
    }
}

#[derive(Debug)]
pub struct File {
    zones: Vec<Arc<Loaded>>,
    fallthrough: Vec<Name>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    chain: OnceLock<Weak<crate::Chain>>,
    #[cfg(feature = "plugin-transfer")]
    notifier: crate::zone::ZoneNotifier,
    #[cfg(feature = "plugin-transfer")]
    notify_names: Vec<Name>,
}

impl File {
    fn parse(
        cursor: &mut Cursor<'_>,
        server_domains: &[&str],
        root: Option<&Path>,
    ) -> Result<Self, Error> {
        Self::parse_with_reader(cursor, server_domains, root, |apex, path, file| {
            // RFC 1982 §7: Serial zero is an ordinary SOA serial value.
            Zone::load_reader_with_serial(apex, path, BufReader::new(file), None)
        })
    }

    fn parse_with_reader(
        cursor: &mut Cursor<'_>,
        server_domains: &[&str],
        root: Option<&Path>,
        mut read_zone: impl FnMut(Name, &Path, &mut std::fs::File) -> Result<Zone, String>,
    ) -> Result<Self, Error> {
        let mut zones = Vec::new();
        let mut fallthrough = Vec::new();
        let mut reload = Duration::from_secs(60);
        let mut negative_reload = false;
        let mut by_mtime = false;
        let mut open_error = None;
        #[cfg(feature = "plugin-transfer")]
        let mut notify_names = Vec::new();
        while cursor.next() {
            let args = cursor.remaining_args();
            let path = args.first().ok_or_else(|| cursor.arg_err())?;
            let path = crate::resolve_path(path.into(), root);
            let names = args[1..].iter().map(String::as_str).collect::<Vec<_>>();
            let origins = origins_from_args_or_server_block(&names, server_domains);
            let mut opened = match std::fs::File::open(&path) {
                Ok(file) => Some(file),
                Err(error) => {
                    open_error = Some(error.to_string());
                    None
                }
            };
            let opened_mtime = opened
                .as_ref()
                .and_then(|file| file.metadata().ok())
                .and_then(|metadata| metadata.modified().ok());
            let mut parsed = Vec::new();
            for origin in origins {
                let apex: Name = origin.parse().map_err(|_| cursor.error("invalid Zone"))?;
                #[cfg(feature = "plugin-transfer")]
                notify_names.push(apex.clone());
                let current = match opened.as_mut().filter(|_| open_error.is_none()) {
                    Some(file) => {
                        file.seek(SeekFrom::Start(0))
                            .map_err(|error| cursor.error(error.to_string()))?;
                        Some(Arc::new(
                            read_zone(apex.clone(), &path, file)
                                .map_err(|error| cursor.error(error))?,
                        ))
                    }
                    None => None,
                };
                parsed.push((apex, current));
            }
            while cursor.next_block() {
                let option = cursor.val().to_owned();
                let args = cursor.remaining_args();
                match option.as_str() {
                    "fallthrough" => {
                        fallthrough.clear();
                        if args.is_empty() {
                            fallthrough.push(".".parse().map_err(|_| cursor.arg_err())?);
                        } else {
                            for domain in args {
                                let names = origins_from_args_or_server_block(&[&domain], &[]);
                                for name in names {
                                    fallthrough.push(name.parse().map_err(|_| cursor.arg_err())?);
                                }
                            }
                        }
                    }
                    "reload" if !args.is_empty() => {
                        let value = &args[0];
                        crate::health::parse_duration(value).ok_or_else(|| cursor.arg_err())?;
                        let magnitude = value.strip_prefix('-').unwrap_or(value);
                        reload = crate::health::parse_duration(magnitude)
                            .ok_or_else(|| cursor.arg_err())?;
                        negative_reload = value.starts_with('-') && !reload.is_zero();
                    }
                    "reload_by_mtime" => by_mtime = true,
                    "upstream" => {}
                    _ => return Err(cursor.arg_err()),
                }
            }
            let modified = if by_mtime && open_error.is_none() {
                opened_mtime
            } else {
                None
            };
            for (apex, current) in parsed {
                zones.retain(|zone: &Arc<Loaded>| zone.apex != apex);
                zones.push(Arc::new(Loaded {
                    apex,
                    path: path.clone(),
                    current: ZoneHolder::from(current),
                    interval: reload,
                    negative_interval: negative_reload,
                    by_mtime,
                    modified: Mutex::new(modified),
                    reload_gate: Mutex::new(()),
                }));
            }
        }
        if let Some(error) = open_error {
            if reload.is_zero() {
                return Err(cursor.error(error));
            }
            pharos_server::logging::log(
                "WARN",
                "file",
                &format!("Failed to open Zone file: {error}; retrying on reload"),
            );
        }
        Ok(Self {
            zones,
            fallthrough,
            tasks: Arc::new(Mutex::new(Vec::new())),
            chain: OnceLock::new(),
            #[cfg(feature = "plugin-transfer")]
            notifier: crate::zone::ZoneNotifier::default(),
            #[cfg(feature = "plugin-transfer")]
            notify_names,
        })
    }

    fn register_hooks(&self, lifecycle: &mut pharos_server::Lifecycle) {
        let zones = self.zones.clone();
        let tasks = Arc::clone(&self.tasks);
        #[cfg(feature = "plugin-transfer")]
        let notifier = self.notifier.clone();
        #[cfg(feature = "plugin-transfer")]
        let notify_names = self.notify_names.clone();
        let start = move || {
            let zones = zones.clone();
            let tasks = Arc::clone(&tasks);
            #[cfg(feature = "plugin-transfer")]
            let notifier = notifier.clone();
            #[cfg(feature = "plugin-transfer")]
            let notify_names = notify_names.clone();
            async move {
                if zones.iter().any(|zone| zone.negative_interval) {
                    return Err(std::io::Error::other("negative file reload interval"));
                }
                let mut tasks = tasks.lock().unwrap();
                for task in tasks.drain(..) {
                    task.abort();
                }
                #[cfg(feature = "plugin-transfer")]
                if let Some(transfer) = notifier.get() {
                    // RFC 1996 §4.1: notify Secondary Servers on startup.
                    // RFC 1035 §6.1.1: Reload Zone files off the query-serving task.
                    tasks.push(tokio::spawn(async move {
                        for apex in notify_names {
                            let _ = transfer.notify(&apex).await;
                        }
                    }));
                }
                for zone in zones {
                    if zone.interval.is_zero() {
                        continue;
                    }
                    #[cfg(feature = "plugin-transfer")]
                    let notifier = notifier.clone();
                    tasks.push(tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(zone.interval).await;
                            let reload = Arc::clone(&zone);
                            if tokio::task::spawn_blocking(move || reload.reload())
                                .await
                                .unwrap_or(false)
                            {
                                #[cfg(feature = "plugin-transfer")]
                                let transfer = notifier.get();
                                #[cfg(feature = "plugin-transfer")]
                                if let Some(transfer) = transfer {
                                    // RFC 1996 §3.1: notify Secondary Servers after Zone changes.
                                    if let Err(error) = transfer.notify(&zone.apex).await {
                                        pharos_server::logging::log(
                                            "WARN",
                                            "file",
                                            &format!("NOTIFY {}: {error}", zone.apex),
                                        );
                                    }
                                }
                            }
                        }
                    }));
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Startup, start.clone());
        lifecycle.register(pharos_server::Phase::RestartFailed, start);
        let tasks = Arc::clone(&self.tasks);
        let stop = move || {
            let tasks = std::mem::take(&mut *tasks.lock().unwrap());
            async move {
                for task in tasks {
                    task.abort();
                    let _ = task.await;
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Restart, stop.clone());
        lifecycle.register(pharos_server::Phase::Shutdown, stop);
    }
}

impl File {
    pub(crate) fn bind(&self, chain: &Arc<crate::Chain>) {
        let _ = self.chain.set(Arc::downgrade(chain));
    }

    pub(crate) fn has_zone_for(&self, name: NameRef<'_>) -> bool {
        self.zones
            .iter()
            .any(|zone| crate::name_within(name, &zone.apex))
    }

    fn special_nxdomain(
        response: &mut Vec<u8>,
        query: pharos_proto::Message<'_>,
        protocol: pharos_server::Protocol,
        max_response_size: usize,
        question: pharos_proto::Question<'_>,
        special: crate::SpecialUse,
    ) -> Outcome {
        const SOA_TAIL: &[u8] =
            b"\x06nobody\x07invalid\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\x09\x3a\x80";
        // RFC 6761 §§6.1, 6.2, 6.4 and RFC 6303 §3: answer unconfigured special names authoritatively.
        let max = max_response_size.max(512);
        if response.capacity() < max {
            if protocol == pharos_server::Protocol::Tcp {
                response.reserve(max.saturating_sub(response.len()));
            } else {
                return Outcome::Error(pharos_server::Error::ResponseBufferTooSmall);
            }
        }
        let count = question.name.labels().count();
        let start = count - special.zone_labels();
        let mut owner_wire = [0u8; 255];
        let mut owner_len = 0;
        for label in question.name.labels().skip(start) {
            owner_wire[owner_len] = label.len() as u8;
            owner_len += 1;
            owner_wire[owner_len..owner_len + label.len()].copy_from_slice(label);
            owner_len += label.len();
        }
        owner_wire[owner_len] = 0;
        owner_len += 1;
        let owner = NameRef::parse(&owner_wire[..owner_len], 0).expect("special-use Zone suffix");
        let mut flags = 0x8403 | (query.flags() & 0x7800);
        if query.opcode() == Opcode::QUERY {
            flags |= query.flags() & 0x0110;
        }
        let mut builder = match MessageBuilder::new(response, max, query.id(), flags) {
            Ok(builder) => builder,
            Err(error) => return Outcome::Error(pharos_server::Error::Build(error)),
        };
        if let Err(error) = builder.question(question.name, question.qtype, question.qclass) {
            return Outcome::Error(pharos_server::Error::Build(error));
        }
        let mut soa = [0u8; 255 + 32];
        soa[..owner_len].copy_from_slice(&owner_wire[..owner_len]);
        soa[owner_len..owner_len + SOA_TAIL.len()].copy_from_slice(SOA_TAIL);
        if let Err(error) = builder.record(
            Section::Authority,
            owner,
            Type::SOA,
            Class::IN,
            604_800,
            &soa[..owner_len + SOA_TAIL.len()],
        ) {
            return Outcome::Error(pharos_server::Error::Build(error));
        }
        let _ = builder.finish();
        Outcome::Response
    }

    pub(crate) async fn serve_with<N: Next + Send>(
        &self,
        cx: &mut Context<'_, '_>,
        next: N,
        has_next: bool,
    ) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        let mut wire = [0u8; 255];
        let mut len = 0;
        for label in question.name.labels() {
            wire[len] = label.len() as u8;
            len += 1;
            wire[len..len + label.len()].copy_from_slice(label);
            len += label.len();
        }
        len += 1;
        let name = &wire[..len];
        let Some(loaded) = self
            .zones
            .iter()
            .filter(|zone| contains(name, &zone.apex))
            .max_by_key(|zone| zone.apex.label_count())
        else {
            if let Some(special) = (question.qclass == Class::IN)
                .then(|| crate::special_use(question.name))
                .flatten()
            {
                #[cfg(feature = "plugin-forward")]
                let upstream_allowed = special.permits_upstream()
                    && self
                        .chain
                        .get()
                        .and_then(Weak::upgrade)
                        .and_then(|chain| {
                            chain
                                .forward
                                .as_ref()
                                .map(|forward| forward.allows_special(question.name))
                        })
                        .unwrap_or(false);
                #[cfg(not(feature = "plugin-forward"))]
                let upstream_allowed = false;
                if !upstream_allowed {
                    return Self::special_nxdomain(
                        cx.response,
                        cx.query,
                        cx.protocol,
                        cx.max_response_size,
                        question,
                        special,
                    );
                }
            }
            return if has_next {
                next.run(cx).await
            } else {
                Outcome::Unanswered(Rcode::REFUSED)
            };
        };
        let snapshot = loaded.current.load();
        let Some(zone) = snapshot.as_ref() else {
            return Outcome::Unanswered(Rcode::SERVFAIL);
        };
        zone.lookup(cx, next, &self.fallthrough).await
    }
}

impl Plugin for File {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        self.serve_with(cx, next, true).await
    }
}

//! Authoritative Zones loaded from master files.

pub(crate) mod setup;
#[cfg(test)]
mod tests;
#[cfg(feature = "plugin-transfer")]
mod transfer;

use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::{
    Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type,
    zone::{ZoneParser, ZoneRecord},
};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol};
use std::{
    collections::BTreeMap,
    fmt::Write,
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

struct NameText {
    bytes: [u8; 1024],
    len: usize,
}

impl std::fmt::Write for NameText {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(std::fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(std::fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Immutable authoritative Zone data, reusable by Zone-serving Plugins.
#[derive(Debug)]
pub struct Zone {
    apex: Name,
    records: Vec<ZoneRecord>,
    names: Vec<ZoneNode>,
    tree: Vec<usize>,
}

#[derive(Debug)]
struct ZoneNode {
    name: Name,
    types: BTreeMap<u16, Vec<usize>>,
    tree: bool,
}

impl Zone {
    /// Load a Zone from a master file.
    pub fn load(apex: Name, path: &Path) -> Result<Self, String> {
        let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
        Self::load_opened(apex, path, file)
    }

    fn load_opened(apex: Name, path: &Path, file: std::fs::File) -> Result<Self, String> {
        Self::load_reader(apex, path, BufReader::new(file))
    }

    fn load_reader(apex: Name, path: &Path, reader: impl BufRead) -> Result<Self, String> {
        let mut parser = ZoneParser::new(reader, apex.clone(), path.to_string_lossy());
        parser.set_include_allowed(true);
        let records = parser
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        Self::from_records(apex, records)
    }

    /// Build an immutable Zone from owned, uncompressed master-file records.
    pub fn from_records(apex: Name, records: Vec<ZoneRecord>) -> Result<Self, String> {
        let mut soa = false;
        for record in &records {
            if record.rtype == Type::SOA {
                if record.owner != apex {
                    return Err("SOA owner does not match Zone apex".into());
                }
                soa = true;
            }
            if record.rtype == Type::NSEC3 || record.rtype == Type::NSEC3PARAM {
                return Err("NSEC3 zone is not supported".into());
            }
        }
        if !soa {
            return Err("Zone has no SOA".into());
        }
        let mut nodes: BTreeMap<Name, ZoneNode> = BTreeMap::new();
        for (index, record) in records.iter().enumerate() {
            let mut suffix = record.owner.as_wire();
            loop {
                let name = NameRef::parse(suffix, 0)
                    .map_err(|error| error.to_string())?
                    .to_name();
                let node = nodes.entry(name.clone()).or_insert_with(|| ZoneNode {
                    name,
                    types: BTreeMap::new(),
                    tree: false,
                });
                if suffix.len() == record.owner.as_wire().len() {
                    node.types.entry(record.rtype.0).or_default().push(index);
                    let apex_record = record.owner == apex
                        && (matches!(record.rtype, Type::SOA | Type::NS)
                            || record.rtype == Type::RRSIG
                                && record.rdata.get(..2).is_some_and(|covered| {
                                    covered == Type::SOA.0.to_be_bytes()
                                        || covered == Type::NS.0.to_be_bytes()
                                }));
                    node.tree |= !apex_record;
                }
                if suffix[0] == 0 {
                    break;
                }
                suffix = &suffix[1 + usize::from(suffix[0])..];
            }
        }
        let names: Vec<_> = nodes.into_values().collect();
        let tree = names
            .iter()
            .enumerate()
            .filter_map(|(index, node)| node.tree.then_some(index))
            .collect();
        Ok(Self {
            apex,
            records,
            names,
            tree,
        })
    }

    /// Return this Zone's apex.
    #[must_use]
    pub fn apex(&self) -> &Name {
        &self.apex
    }

    /// Find the records at an owner and type, without allocating.
    pub fn rrset(&self, name: NameRef<'_>, kind: Type) -> impl Iterator<Item = &ZoneRecord> {
        let mut wire = [0u8; 255];
        let mut len = 0;
        for label in name.labels() {
            wire[len] = label.len() as u8;
            len += 1;
            wire[len..len + label.len()].copy_from_slice(label);
            len += label.len();
        }
        self.records_at(&wire[..len + 1], kind)
    }

    fn node(&self, name: &[u8]) -> Option<&ZoneNode> {
        self.names
            .binary_search_by(|node| canonical_cmp(node.name.as_wire(), name))
            .ok()
            .map(|index| &self.names[index])
    }

    fn records_at<'a>(
        &'a self,
        name: &[u8],
        kind: Type,
    ) -> impl Iterator<Item = &'a ZoneRecord> + use<'a> {
        self.node(name)
            .and_then(|node| node.types.get(&kind.0))
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(|index| &self.records[*index])
    }

    fn exists(&self, name: &[u8]) -> bool {
        self.node(name).is_some()
    }

    fn exact(&self, name: &[u8]) -> bool {
        self.node(name).is_some_and(|node| !node.types.is_empty())
    }

    fn cut(&self, name: &[u8], kind: Type) -> Option<&ZoneRecord> {
        if !contains_wire(name, self.apex.as_wire()) {
            return None;
        }
        let mut suffix = name;
        let mut cut = None;
        while !suffix.eq_ignore_ascii_case(self.apex.as_wire()) {
            if !(kind == Type::DS && suffix.len() == name.len())
                && let Some(rr) = self.records_at(suffix, Type::NS).next()
            {
                cut = Some(rr);
            }
            suffix = &suffix[1 + usize::from(suffix[0])..];
        }
        cut
    }

    fn dname(&self, name: &[u8]) -> Option<&ZoneRecord> {
        if !contains_wire(name, self.apex.as_wire())
            || name.eq_ignore_ascii_case(self.apex.as_wire())
        {
            return None;
        }
        let mut suffix = &name[1 + usize::from(name[0])..];
        let mut dname = None;
        loop {
            if let Some(rr) = self.records_at(suffix, Type::DNAME).next() {
                dname = Some(rr);
            }
            if suffix.eq_ignore_ascii_case(self.apex.as_wire()) {
                break;
            }
            suffix = &suffix[1 + usize::from(suffix[0])..];
        }
        dname
    }

    fn serial(&self) -> Option<u32> {
        let soa = self.records.iter().find(|rr| rr.rtype == Type::SOA)?;
        let offset = soa.rdata.len().checked_sub(20)?;
        Some(u32::from_be_bytes(
            soa.rdata.get(offset..offset + 4)?.try_into().ok()?,
        ))
    }

    fn previous_nsec(&self, name: &[u8]) -> Option<&ZoneRecord> {
        let end = self.tree.partition_point(|index| {
            canonical_cmp(self.names[*index].name.as_wire(), name) != std::cmp::Ordering::Greater
        });
        let node = self
            .tree
            .get(end.checked_sub(1)?)
            .map(|index| &self.names[*index])?;
        self.records_at(node.name.as_wire(), Type::NSEC).next()
    }
}

#[derive(Debug)]
struct Loaded {
    apex: Name,
    path: PathBuf,
    current: arc_swap::ArcSwapOption<Zone>,
    interval: Duration,
    by_mtime: bool,
    modified: Mutex<Option<SystemTime>>,
}

impl Loaded {
    fn reload(&self) -> bool {
        let Ok(file) = std::fs::File::open(&self.path) else {
            return false;
        };
        let modified = if self.by_mtime {
            let Ok(modified) = file.metadata().and_then(|metadata| metadata.modified()) else {
                return false;
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
        let Ok(next) = Zone::load_opened(self.apex.clone(), &self.path, file) else {
            return false;
        };
        if !self.by_mtime
            && self
                .current
                .load()
                .as_ref()
                .is_some_and(|old| old.serial() == next.serial())
        {
            return false;
        }
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
    #[cfg(feature = "plugin-transfer")]
    notifier: Arc<Mutex<Option<crate::transfer::Transfer>>>,
    #[cfg(feature = "plugin-transfer")]
    notify_names: Vec<Name>,
}

impl File {
    fn parse(
        cursor: &mut Cursor<'_>,
        server_domains: &[&str],
        root: Option<&Path>,
    ) -> Result<Self, Error> {
        let mut zones = Vec::new();
        let mut fallthrough = Vec::new();
        let mut reload = Duration::from_secs(60);
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
                        reload = crate::health::parse_duration(&args[0])
                            .ok_or_else(|| cursor.arg_err())?
                    }
                    "reload_by_mtime" => by_mtime = true,
                    "upstream" => {}
                    _ => return Err(cursor.arg_err()),
                }
            }
            let mut opened = match std::fs::File::open(&path) {
                Ok(file) => Some(file),
                Err(error) => {
                    open_error = Some(error.to_string());
                    None
                }
            };
            let modified = opened
                .as_ref()
                .and_then(|file| file.metadata().ok())
                .and_then(|metadata| metadata.modified().ok());
            for origin in origins {
                let apex: Name = origin.parse().map_err(|_| cursor.error("invalid Zone"))?;
                #[cfg(feature = "plugin-transfer")]
                notify_names.push(apex.clone());
                let current = match opened.as_mut().filter(|_| open_error.is_none()) {
                    Some(file) => {
                        file.seek(SeekFrom::Start(0))
                            .map_err(|error| cursor.error(error.to_string()))?;
                        Some(Arc::new(
                            Zone::load_reader(apex.clone(), &path, BufReader::new(file))
                                .map_err(|error| cursor.error(error))?,
                        ))
                    }
                    None => None,
                };
                zones.retain(|zone: &Arc<Loaded>| zone.apex != apex);
                zones.push(Arc::new(Loaded {
                    apex,
                    path: path.clone(),
                    current: arc_swap::ArcSwapOption::from(current),
                    interval: reload,
                    by_mtime,
                    modified: Mutex::new(modified),
                }));
            }
        }
        if reload.is_zero()
            && let Some(error) = open_error
        {
            return Err(cursor.error(error));
        }
        Ok(Self {
            zones,
            fallthrough,
            tasks: Arc::new(Mutex::new(Vec::new())),
            #[cfg(feature = "plugin-transfer")]
            notifier: Arc::new(Mutex::new(None)),
            #[cfg(feature = "plugin-transfer")]
            notify_names,
        })
    }

    fn register_hooks(&self, lifecycle: &mut pharos_server::Lifecycle) {
        let zones = self.zones.clone();
        let tasks = Arc::clone(&self.tasks);
        #[cfg(feature = "plugin-transfer")]
        let notifier = Arc::clone(&self.notifier);
        #[cfg(feature = "plugin-transfer")]
        let notify_names = self.notify_names.clone();
        let start = move || {
            let zones = zones.clone();
            let tasks = Arc::clone(&tasks);
            #[cfg(feature = "plugin-transfer")]
            let notifier = Arc::clone(&notifier);
            #[cfg(feature = "plugin-transfer")]
            let notify_names = notify_names.clone();
            async move {
                let mut tasks = tasks.lock().unwrap();
                for task in tasks.drain(..) {
                    task.abort();
                }
                #[cfg(feature = "plugin-transfer")]
                if let Some(transfer) = notifier.lock().unwrap().clone() {
                    // RFC 1996 §4.1: notify Secondary Servers on startup.
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
                    let notifier = Arc::clone(&notifier);
                    tasks.push(tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(zone.interval).await;
                            let reload = Arc::clone(&zone);
                            if tokio::task::spawn_blocking(move || reload.reload())
                                .await
                                .unwrap_or(false)
                            {
                                #[cfg(feature = "plugin-transfer")]
                                let transfer = { notifier.lock().unwrap().clone() };
                                #[cfg(feature = "plugin-transfer")]
                                if let Some(transfer) = transfer {
                                    // RFC 1996 §3.1: notify Secondary Servers after Zone changes.
                                    let _ = transfer.notify(&zone.apex).await;
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

// RFC 1034 §3.1: a Zone contains names at or below its apex.
fn contains(name: &[u8], apex: &Name) -> bool {
    contains_wire(name, apex.as_wire())
}

fn contains_wire(name: &[u8], apex: &[u8]) -> bool {
    let mut suffix = name;
    loop {
        if suffix.eq_ignore_ascii_case(apex) {
            return true;
        }
        if suffix[0] == 0 {
            return false;
        }
        suffix = &suffix[usize::from(suffix[0]) + 1..];
    }
}

// RFC 4034 §6.1: canonical name ordering compares lowercase labels from the root.
fn canonical_cmp(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    fn labels<'a>(mut name: &'a [u8], result: &mut [&'a [u8]; 127]) -> usize {
        let mut count = 0;
        while name[0] != 0 {
            let len = usize::from(name[0]);
            result[count] = &name[1..1 + len];
            count += 1;
            name = &name[1 + len..];
        }
        count
    }
    let mut a = [&[][..]; 127];
    let mut b = [&[][..]; 127];
    let ac = labels(left, &mut a);
    let bc = labels(right, &mut b);
    for (a, b) in a[..ac].iter().rev().zip(b[..bc].iter().rev()) {
        let order = a
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(b.iter().map(u8::to_ascii_lowercase));
        if order != std::cmp::Ordering::Equal {
            return order;
        }
    }
    ac.cmp(&bc)
}

fn write_set(
    builder: &mut MessageBuilder<'_, Vec<u8>>,
    zone: &Zone,
    source: &[u8],
    owner: NameRef<'_>,
    kind: Type,
    section: Section,
    dnssec: bool,
) -> Result<(), pharos_server::Error> {
    for rr in zone.records_at(source, kind) {
        builder
            .record(section, owner, rr.rtype, rr.class, rr.ttl, &rr.rdata)
            .map_err(pharos_server::Error::Build)?;
    }
    // RFC 4035 §3.1.1: include matching RRSIG records when DO is set.
    if dnssec && kind != Type::RRSIG {
        for rr in zone
            .records_at(source, Type::RRSIG)
            .filter(|rr| rr.rdata.get(..2) == Some(kind.0.to_be_bytes().as_slice()))
        {
            builder
                .record(section, owner, rr.rtype, rr.class, rr.ttl, &rr.rdata)
                .map_err(pharos_server::Error::Build)?;
        }
    }
    Ok(())
}

impl Plugin for File {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
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
            return next.run(cx).await;
        };
        let snapshot = loaded.current.load();
        let Some(zone) = snapshot.as_ref() else {
            return Outcome::Unanswered(Rcode::SERVFAIL);
        };
        zone.lookup(cx, next, &self.fallthrough).await
    }
}

impl Zone {
    /// Answer a Query using this immutable Zone, optionally falling through on absent names.
    pub async fn lookup<N: Next + Send>(
        &self,
        cx: &mut Context<'_, '_>,
        next: N,
        fallthrough: &[Name],
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
        let name = &wire[..len + 1];
        if !contains(name, &self.apex) {
            return next.run(cx).await;
        }
        let zone = self;
        if matches!(question.qtype, Type::AXFR | Type::IXFR) {
            return Outcome::Unanswered(Rcode::REFUSED);
        }
        if cx.query.opcode() == pharos_proto::Opcode::NOTIFY {
            return Outcome::Drop;
        }
        // RFC 1034 §4.3.2: return the first Zone Cut between the apex and QNAME.
        let cut = zone.cut(name, question.qtype);
        // RFC 6672 §3.2: DNAME applies to strict descendants of its owner.
        let dname = zone
            .dname(name)
            .filter(|rr| cut.is_none_or(|cut| rr.owner.label_count() <= cut.owner.label_count()));
        let mut cut = cut.filter(|_| dname.is_none());
        let mut wildcard = [0u8; 255];
        let mut dname_target = [0u8; 255];
        let mut source = name;
        let exists = zone.exists(name);
        let exact = zone.exact(name);
        if let Some(rr) = dname {
            let prefix = name.len() - rr.owner.as_wire().len();
            let len = prefix + rr.rdata.len();
            if len > dname_target.len() {
                return Outcome::Unanswered(Rcode::SERVFAIL);
            }
            dname_target[..prefix].copy_from_slice(&name[..prefix]);
            dname_target[prefix..len].copy_from_slice(&rr.rdata);
            source = &dname_target[..len];
            if source.eq_ignore_ascii_case(name) {
                return Outcome::Unanswered(Rcode::SERVFAIL);
            }
        } else if !exists && cut.is_none() {
            // RFC 4592 §3.3.1: the closest encloser determines wildcard synthesis.
            let mut parent = name;
            while parent[0] != 0 && !zone.exists(parent) {
                parent = &parent[1 + usize::from(parent[0])..];
            }
            if parent.len() + 2 <= wildcard.len() {
                wildcard[0] = 1;
                wildcard[1] = b'*';
                wildcard[2..2 + parent.len()].copy_from_slice(parent);
                let candidate = &wildcard[..parent.len() + 2];
                if zone.exists(candidate) {
                    source = candidate;
                }
            }
        }
        let synthesized = dname.is_none() && !std::ptr::eq(source.as_ptr(), name.as_ptr());
        if synthesized && cx.metadata.enabled() && zone.exact(source) {
            let mut text = NameText {
                bytes: [0; 1024],
                len: 0,
            };
            if let Ok(owner) = NameRef::parse(source, 0)
                && write!(text, "{owner}").is_ok()
                && let Ok(text) = std::str::from_utf8(&text.bytes[..text.len])
            {
                cx.metadata.insert_copied("zone/wildcard", text);
            }
        }
        let mut chain = [None; 10];
        let mut count = 0;
        let mut target = source;
        if dname.is_some() {
            cut = zone.cut(target, question.qtype);
        }
        if cut.is_none() && question.qtype != Type::CNAME {
            // RFC 1034 §3.6.2: follow a CNAME before answering the original QTYPE.
            while let Some(alias) = zone.records_at(target, Type::CNAME).next() {
                if count == chain.len() {
                    return Outcome::Unanswered(Rcode::SERVFAIL);
                }
                chain[count] = Some(alias);
                count += 1;
                target = &alias.rdata;
                cut = zone.cut(target, question.qtype);
                if cut.is_some() {
                    break;
                }
            }
        }
        let mut lookup_failed = false;
        let lookup = if cut.is_none()
            && (count > 0 || dname.is_some() && question.qtype != Type::CNAME)
            && (!zone.exact(target)
                || target.eq_ignore_ascii_case(zone.apex.as_wire())
                    && matches!(question.qtype, Type::NS | Type::SOA))
        {
            let target = match NameRef::parse(target, 0) {
                Ok(target) => target.to_name(),
                Err(_) => return Outcome::Unanswered(Rcode::SERVFAIL),
            };
            // RFC 1034 §3.6.2: restart a lookup when the CNAME target is not in the Zone.
            // shortcut: Self Lookup allocates; remove when #86 makes it allocation-free.
            match cx.self_lookup(&target, question.qtype).await {
                Ok(wire) => Some(wire),
                Err(_) => {
                    lookup_failed = true;
                    None
                }
            }
        } else {
            None
        };
        let external = lookup.as_ref().and_then(|wire| Message::parse(wire).ok());
        let found = dname.is_some()
            || count > 0
            || zone.records_at(target, question.qtype).next().is_some();
        let dnssec = cx.query.opt().is_some_and(|opt| opt.dnssec_ok());
        if !exact
            && !synthesized
            && cut.is_none()
            && dname.is_none()
            && fallthrough.iter().any(|apex| contains(name, apex))
        {
            return next.run(cx).await;
        }
        let rcode = if lookup_failed || lookup.is_some() && external.is_none() {
            Rcode::SERVFAIL
        } else if let Some(response) = external {
            match response.rcode() {
                Rcode::SERVFAIL => Rcode::SERVFAIL,
                Rcode::NXDOMAIN => Rcode::NXDOMAIN,
                _ => Rcode::NOERROR,
            }
        } else if exists || synthesized || cut.is_some() || dname.is_some() {
            Rcode::NOERROR
        } else {
            Rcode::NXDOMAIN
        };
        let max = cx.max_response_size.max(512);
        if cx.response.capacity() < max {
            if cx.protocol == Protocol::Tcp {
                cx.response.reserve(max.saturating_sub(cx.response.len()));
            } else {
                return Outcome::Error(pharos_server::Error::ResponseBufferTooSmall);
            }
        }
        let result = (|| -> Result<(), pharos_server::Error> {
            // RFC 1035 §4.1.1: authoritative Responses preserve Query flags and ID.
            let mut builder = MessageBuilder::new(
                cx.response,
                max,
                cx.query.id(),
                0x8000
                    | if cut.is_none() || count > 0 || dname.is_some() {
                        0x0400
                    } else {
                        0
                    }
                    | (cx.query.flags() & 0x7910)
                    | if external.is_some_and(|response| response.tc()) {
                        0x0200
                    } else {
                        0
                    }
                    | rcode.0,
            )
            .map_err(pharos_server::Error::Build)?;
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(pharos_server::Error::Build)?;
            if let Some(rr) = dname {
                let owner = NameRef::parse(rr.owner.as_wire(), 0)
                    .map_err(|_| pharos_server::Error::InvalidQuery)?;
                write_set(
                    &mut builder,
                    zone,
                    rr.owner.as_wire(),
                    owner,
                    Type::DNAME,
                    Section::Answer,
                    dnssec,
                )?;
                builder
                    .record(
                        Section::Answer,
                        question.name,
                        Type::CNAME,
                        Class::IN,
                        rr.ttl,
                        source,
                    )
                    .map_err(pharos_server::Error::Build)?;
            }
            for (index, rr) in chain[..count].iter().flatten().enumerate() {
                let owner = if index == 0 && synthesized {
                    question.name
                } else {
                    NameRef::parse(rr.owner.as_wire(), 0)
                        .map_err(|_| pharos_server::Error::InvalidQuery)?
                };
                write_set(
                    &mut builder,
                    zone,
                    rr.owner.as_wire(),
                    owner,
                    Type::CNAME,
                    Section::Answer,
                    dnssec,
                )?;
            }
            if cut.is_none() && !(dname.is_some() && question.qtype == Type::CNAME) {
                let owner = if count == 0 && synthesized {
                    question.name
                } else {
                    NameRef::parse(target, 0).map_err(|_| pharos_server::Error::InvalidQuery)?
                };
                write_set(
                    &mut builder,
                    zone,
                    target,
                    owner,
                    question.qtype,
                    Section::Answer,
                    dnssec,
                )?;
            }
            if let Some(response) = external {
                for rr in response.answers() {
                    let data = rr.data().map_err(|_| pharos_server::Error::InvalidQuery)?;
                    builder
                        .record_with(
                            Section::Answer,
                            rr.name,
                            rr.rtype,
                            rr.class,
                            rr.ttl,
                            |writer| data.write(writer),
                        )
                        .map_err(pharos_server::Error::Build)?;
                }
            }
            // RFC 2308 §3: negative Responses include the Zone SOA.
            let authority_type = if rcode == Rcode::NXDOMAIN
                || external.is_some_and(|response| {
                    response.rcode() == Rcode::NOERROR && response.answer_count() == 0
                }) {
                Type::SOA
            } else if found || cut.is_some() {
                Type::NS
            } else {
                Type::SOA
            };
            let authority_owner = cut.map_or(zone.apex.as_wire(), |rr| rr.owner.as_wire());
            if !(cut.is_none()
                && name.eq_ignore_ascii_case(zone.apex.as_wire())
                && question.qtype == Type::NS)
            {
                let owner = NameRef::parse(authority_owner, 0)
                    .map_err(|_| pharos_server::Error::InvalidQuery)?;
                write_set(
                    &mut builder,
                    zone,
                    authority_owner,
                    owner,
                    authority_type,
                    Section::Authority,
                    dnssec && cut.is_none(),
                )?;
            }
            // RFC 4035 §3.1.3.1: authenticated NODATA includes the owner's NSEC proof.
            if dnssec && !found && cut.is_none() && (exists || synthesized) {
                let owner =
                    NameRef::parse(source, 0).map_err(|_| pharos_server::Error::InvalidQuery)?;
                write_set(
                    &mut builder,
                    zone,
                    source,
                    owner,
                    Type::NSEC,
                    Section::Authority,
                    true,
                )?;
            }
            // RFC 4035 §3.1.3.2: prove the missing name and wildcard for NXDOMAIN.
            if dnssec && cut.is_none() && !exists && !synthesized && dname.is_none() {
                let first = zone.previous_nsec(name);
                if let Some(rr) = first {
                    let owner = NameRef::parse(rr.owner.as_wire(), 0)
                        .map_err(|_| pharos_server::Error::InvalidQuery)?;
                    write_set(
                        &mut builder,
                        zone,
                        rr.owner.as_wire(),
                        owner,
                        Type::NSEC,
                        Section::Authority,
                        true,
                    )?;
                }
                let mut parent = name;
                while parent[0] != 0 && !zone.exists(parent) {
                    parent = &parent[1 + usize::from(parent[0])..];
                }
                let mut proof = [0u8; 255];
                if parent.len() + 2 <= proof.len() {
                    proof[0] = 1;
                    proof[1] = b'*';
                    proof[2..2 + parent.len()].copy_from_slice(parent);
                    if let Some(rr) = zone.previous_nsec(&proof[..2 + parent.len()])
                        && first.is_none_or(|first| first.owner != rr.owner)
                    {
                        let owner = NameRef::parse(rr.owner.as_wire(), 0)
                            .map_err(|_| pharos_server::Error::InvalidQuery)?;
                        write_set(
                            &mut builder,
                            zone,
                            rr.owner.as_wire(),
                            owner,
                            Type::NSEC,
                            Section::Authority,
                            true,
                        )?;
                    }
                }
            }
            // RFC 4035 §3.1.3.3: a wildcard answer includes a nonexistence proof.
            if dnssec
                && synthesized
                && found
                && let Some(rr) = zone.previous_nsec(name)
            {
                let owner = NameRef::parse(rr.owner.as_wire(), 0)
                    .map_err(|_| pharos_server::Error::InvalidQuery)?;
                write_set(
                    &mut builder,
                    zone,
                    rr.owner.as_wire(),
                    owner,
                    Type::NSEC,
                    Section::Authority,
                    true,
                )?;
            }
            if dnssec && let Some(cut) = cut {
                let owner = NameRef::parse(cut.owner.as_wire(), 0)
                    .map_err(|_| pharos_server::Error::InvalidQuery)?;
                write_set(
                    &mut builder,
                    zone,
                    cut.owner.as_wire(),
                    owner,
                    Type::DS,
                    Section::Authority,
                    true,
                )?;
            }
            // RFC 1034 §4.3.2: Referrals include available address glue.
            if let Some(cut) = cut {
                for ns in zone.records_at(cut.owner.as_wire(), Type::NS) {
                    if !contains_wire(&ns.rdata, ns.owner.as_wire()) {
                        continue;
                    }
                    if let Ok(owner) = NameRef::parse(&ns.rdata, 0) {
                        for kind in [Type::A, Type::AAAA] {
                            write_set(
                                &mut builder,
                                zone,
                                &ns.rdata,
                                owner,
                                kind,
                                Section::Additional,
                                dnssec,
                            )?;
                        }
                    }
                }
            }
            // RFC 1035 §3.3: MX and NS targets and RFC 2782 §3: SRV targets may have address glue.
            if cut.is_none() {
                let offset = match question.qtype {
                    Type::MX | Type::SVCB | Type::HTTPS => Some(2),
                    Type::SRV => Some(6),
                    Type::NS if source.eq_ignore_ascii_case(zone.apex.as_wire()) => Some(0),
                    _ => None,
                };
                if let Some(offset) = offset {
                    for (index, rr) in zone.records_at(target, question.qtype).enumerate() {
                        let Some(address) = rr.rdata.get(offset..) else {
                            continue;
                        };
                        if !contains(address, &zone.apex)
                            || zone
                                .records_at(target, question.qtype)
                                .take(index)
                                .any(|earlier| {
                                    earlier
                                        .rdata
                                        .get(offset..)
                                        .is_some_and(|name| name.eq_ignore_ascii_case(address))
                                })
                        {
                            continue;
                        }
                        let owner = NameRef::parse(address, 0)
                            .map_err(|_| pharos_server::Error::InvalidQuery)?;
                        for kind in [Type::A, Type::AAAA] {
                            write_set(
                                &mut builder,
                                zone,
                                address,
                                owner,
                                kind,
                                Section::Additional,
                                dnssec,
                            )?;
                        }
                    }
                }
            }
            let _ = builder.finish();
            Ok(())
        })();
        result.map_or_else(Outcome::Error, |()| Outcome::Response)
    }
}

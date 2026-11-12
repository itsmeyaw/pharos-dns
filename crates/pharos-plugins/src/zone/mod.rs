//! Shared immutable authoritative Zone and atomic snapshots.

#[cfg(feature = "plugin-transfer")]
mod transfer;

use pharos_proto::{
    Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type,
    zone::{ZoneParser, ZoneRecord},
};
use pharos_server::{Context, Next, Outcome, Protocol};
use std::{
    collections::BTreeMap,
    fmt::Write,
    io::{BufRead, BufReader},
    path::Path,
};

/// Atomic holder for an optional immutable Zone snapshot.
pub type ZoneHolder = arc_swap::ArcSwapOption<Zone>;

/// Shared outgoing NOTIFY binding for Zone-serving Plugins.
#[cfg(feature = "plugin-transfer")]
#[derive(Clone, Debug, Default)]
pub struct ZoneNotifier(std::sync::Arc<std::sync::Mutex<Option<crate::transfer::Transfer>>>);

#[cfg(feature = "plugin-transfer")]
impl ZoneNotifier {
    /// Bind the transfer Plugin used to send NOTIFY messages.
    pub fn bind(&self, transfer: Option<&crate::transfer::Transfer>) {
        *self.0.lock().unwrap() = transfer.cloned();
    }

    /// Return the currently bound transfer Plugin, if any.
    #[must_use]
    pub fn get(&self) -> Option<crate::transfer::Transfer> {
        self.0.lock().unwrap().clone()
    }
}

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
    pub(crate) apex: Name,
    pub(crate) records: Vec<ZoneRecord>,
    names: Vec<ZoneNode>,
    tree: Vec<usize>,
}

#[derive(Debug)]
struct ZoneNode {
    name: Name,
    types: BTreeMap<u16, Vec<usize>>,
    tree: bool,
    tree_exists: bool,
}

impl Zone {
    /// Load a Zone from a master file.
    pub fn load(apex: Name, path: &Path) -> Result<Self, String> {
        let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
        Self::load_opened(apex, path, file)
    }

    pub(crate) fn load_opened(
        apex: Name,
        path: &Path,
        file: std::fs::File,
    ) -> Result<Self, String> {
        Self::load_reader(apex, path, BufReader::new(file))
    }

    fn load_reader(apex: Name, path: &Path, reader: impl BufRead) -> Result<Self, String> {
        Self::load_reader_with_serial(apex, path, reader, None)
    }

    pub(crate) fn load_reader_with_serial(
        apex: Name,
        path: &Path,
        reader: impl BufRead,
        previous: Option<u32>,
    ) -> Result<Self, String> {
        let mut parser = ZoneParser::new(reader, apex.clone(), path.to_string_lossy());
        parser.set_include_allowed(true);
        let mut records = Vec::new();
        let mut seen_soa = false;
        for record in parser {
            let record = record.map_err(|error| error.to_string())?;
            if record.rtype == Type::SOA {
                if record.owner != apex {
                    return Err("SOA owner does not match Zone apex".into());
                }
                if !seen_soa && previous.is_some_and(|serial| soa_serial(&record) == Some(serial)) {
                    return Err("no change in SOA serial".into());
                }
                seen_soa = true;
            }
            if matches!(record.rtype, Type::NSEC3 | Type::NSEC3PARAM) {
                return Err("NSEC3 zone is not supported".into());
            }
            records.push(record);
        }
        Self::from_records(apex, records)
    }

    /// Build an immutable Zone from owned, uncompressed master-file records.
    pub fn from_records(apex: Name, mut records: Vec<ZoneRecord>) -> Result<Self, String> {
        let apex: Name = apex
            .canonical()
            .parse()
            .map_err(|error: pharos_proto::NameError| error.to_string())?;
        let mut soa = false;
        for record in &mut records {
            if record.rtype != Type::SRV {
                record.owner = record
                    .owner
                    .canonical()
                    .parse()
                    .map_err(|error: pharos_proto::NameError| error.to_string())?;
            }
            if record.rtype == Type::SOA {
                if record.owner != apex {
                    return Err("SOA owner does not match Zone apex".into());
                }
                soa = true;
            }
            if record.rtype == Type::NSEC3 || record.rtype == Type::NSEC3PARAM {
                return Err("NSEC3 zone is not supported".into());
            }
            let offset = match record.rtype {
                Type::NS | Type::CNAME | Type::SOA => Some((0, true)),
                Type::DNAME => Some((0, false)),
                Type::MX | Type::SVCB | Type::HTTPS => Some((2, true)),
                Type::SRV => Some((6, false)),
                _ => None,
            };
            if let Some((offset, lowercase)) = offset {
                let end = normalize_rdata_name(&mut record.rdata, offset, lowercase)?;
                // RFC 1035 §§3.3.1, 3.3.11 and RFC 6672 §2.1: these RDATA fields contain only one name.
                if matches!(record.rtype, Type::NS | Type::CNAME | Type::DNAME)
                    && end != record.rdata.len()
                {
                    return Err("trailing name-only RDATA".into());
                }
                if record.rtype == Type::SOA {
                    let end = normalize_rdata_name(&mut record.rdata, end, true)?;
                    if record.rdata.len() != end + 20 {
                        return Err("invalid SOA RDATA".into());
                    }
                }
            }
        }
        if !soa {
            return Err("Zone has no SOA".into());
        }
        let last_soa = records.iter().rposition(|record| record.rtype == Type::SOA);
        let mut index = 0;
        records.retain(|record| {
            let keep = record.rtype != Type::SOA || Some(index) == last_soa;
            index += 1;
            keep
        });
        let mut nodes: BTreeMap<Name, ZoneNode> = BTreeMap::new();
        // RFC 1034 §3.1: ancestors may exist as empty nonterminals.
        for (index, record) in records.iter().enumerate() {
            let apex_record = record.owner == apex
                && (matches!(record.rtype, Type::SOA | Type::NS)
                    || record.rtype == Type::RRSIG
                        && record.rdata.get(..2).is_some_and(|covered| {
                            covered == Type::SOA.0.to_be_bytes()
                                || covered == Type::NS.0.to_be_bytes()
                        }));
            let mut suffix = record.owner.as_wire();
            loop {
                let name = NameRef::parse(suffix, 0)
                    .map_err(|error| error.to_string())?
                    .to_name();
                let node = nodes.entry(name.clone()).or_insert_with(|| ZoneNode {
                    name,
                    types: BTreeMap::new(),
                    tree: false,
                    tree_exists: false,
                });
                node.tree_exists |= !apex_record;
                if suffix.len() == record.owner.as_wire().len() {
                    node.types.entry(record.rtype.0).or_default().push(index);
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

    /// Return the Zone's immutable records.
    #[must_use]
    pub fn records(&self) -> &[ZoneRecord] {
        &self.records
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

    pub(crate) fn exists(&self, name: &[u8]) -> bool {
        self.node(name).is_some_and(|node| node.tree_exists)
    }

    pub(crate) fn exact(&self, name: &[u8]) -> bool {
        self.node(name).is_some_and(|node| node.tree)
    }

    pub(crate) fn cut(&self, name: &[u8], kind: Type) -> Option<&ZoneRecord> {
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

    pub(crate) fn serial(&self) -> Option<u32> {
        let soa = self.records.iter().find(|rr| rr.rtype == Type::SOA)?;
        soa_serial(soa)
    }

    pub(crate) fn previous_nsec(&self, name: &[u8]) -> Option<&ZoneRecord> {
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

fn soa_serial(soa: &ZoneRecord) -> Option<u32> {
    // RFC 1035 §3.3.13: SOA ends with serial and four 32-bit timing fields.
    let offset = soa.rdata.len().checked_sub(20)?;
    Some(u32::from_be_bytes(
        soa.rdata.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn rdata_target(record: &ZoneRecord, offset: usize) -> Option<&[u8]> {
    let bytes = record.rdata.get(offset..)?;
    let len = NameRef::parse(bytes, 0).ok()?.wire_len();
    bytes.get(..len)
}

fn normalize_rdata_name(
    data: &mut [u8],
    mut offset: usize,
    lowercase: bool,
) -> Result<usize, String> {
    // RFC 1035 §3.1: wire labels are length-prefixed and at most 63 octets.
    let start = offset;
    loop {
        let len = usize::from(*data.get(offset).ok_or("invalid domain name RDATA")?);
        if len > 63 {
            return Err("invalid domain name RDATA".into());
        }
        offset += 1;
        if offset - start > 255 {
            return Err("invalid domain name RDATA".into());
        }
        if len == 0 {
            return Ok(offset);
        }
        let label = data
            .get_mut(offset..offset + len)
            .ok_or("invalid domain name RDATA")?;
        if lowercase {
            label.make_ascii_lowercase();
        }
        offset += len;
    }
}

// RFC 1034 §3.1: a Zone contains names at or below its apex.
pub(crate) fn contains(name: &[u8], apex: &Name) -> bool {
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
        // RFC 1996 §3.10: a server ignores NOTIFY from a host that is not a known master.
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
        let exact = zone.exact(name)
            || name.eq_ignore_ascii_case(zone.apex.as_wire())
                && matches!(question.qtype, Type::SOA | Type::NS);
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
        } else if !exact && cut.is_none() {
            // RFC 4592 §3.3.1: the closest encloser determines wildcard synthesis.
            let mut parent = if name[0] == 0 {
                name
            } else {
                &name[1 + usize::from(name[0])..]
            };
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
        if synthesized
            && cx.metadata.enabled()
            && let Some(node) = zone.node(source).filter(|node| node.tree)
        {
            let mut text = NameText {
                bytes: [0; 1024],
                len: 0,
            };
            if let Ok(owner) = NameRef::parse(node.name.as_wire(), 0)
                && write!(text, "{owner}").is_ok()
                && let Ok(text) = std::str::from_utf8(&text.bytes[..text.len])
            {
                cx.metadata.insert_copied("zone/wildcard", text);
            }
        }
        let mut chain = [None; 10];
        let mut count = 0;
        let mut chain_limited = false;
        let mut target = source;
        if dname.is_some() {
            cut = zone.cut(target, question.qtype);
        }
        // DNAME NS targets without a Referral use Self Lookup instead of local alias walking.
        if cut.is_none()
            && question.qtype != Type::CNAME
            && !(dname.is_some() && question.qtype == Type::NS)
        {
            // RFC 1034 §3.6.2: follow a CNAME before answering the original QTYPE.
            while let Some(alias) = zone.records_at(target, Type::CNAME).next() {
                if count == chain.len() {
                    chain_limited = true;
                    break;
                }
                if alias.owner.as_wire().eq_ignore_ascii_case(&alias.rdata) {
                    return Outcome::Unanswered(Rcode::SERVFAIL);
                }
                chain[count] = Some(alias);
                count += 1;
                target = &alias.rdata;
                cut = zone.cut(target, question.qtype);
                if cut.is_some()
                    || question.qtype == Type::NS
                    || question.qtype == Type::SOA
                        && target.eq_ignore_ascii_case(zone.apex.as_wire())
                {
                    break;
                }
            }
        }
        let mut lookup_failed = false;
        let lookup = if cut.is_none()
            && !chain_limited
            && (count > 0 || dname.is_some() && question.qtype != Type::CNAME)
            && (!zone.exact(target)
                || question.qtype == Type::NS
                || question.qtype == Type::SOA && target.eq_ignore_ascii_case(zone.apex.as_wire()))
        {
            let target = match NameRef::parse(target, 0) {
                Ok(target) => target.to_name(),
                Err(_) => return Outcome::Unanswered(Rcode::SERVFAIL),
            };
            // RFC 1034 §3.6.2 and RFC 6672 §3.2: restart at CNAME or DNAME targets.
            // shortcut: CNAME/DNAME Self Lookup allocates for missing tree names, NS, and apex SOA; see #86.
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
        } else if exists || synthesized || cut.is_some() || dname.is_some() || found {
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
                    dnssec && !(index == 0 && synthesized),
                )?;
                if dnssec && index == 0 && synthesized {
                    let signature_owner = NameRef::parse(rr.owner.as_wire(), 0)
                        .map_err(|_| pharos_server::Error::InvalidQuery)?;
                    for sig in zone
                        .records_at(rr.owner.as_wire(), Type::RRSIG)
                        .filter(|sig| {
                            sig.rdata.get(..2) == Some(Type::CNAME.0.to_be_bytes().as_slice())
                        })
                    {
                        builder
                            .record(
                                Section::Answer,
                                signature_owner,
                                sig.rtype,
                                sig.class,
                                sig.ttl,
                                &sig.rdata,
                            )
                            .map_err(pharos_server::Error::Build)?;
                    }
                }
            }
            if cut.is_none()
                && !chain_limited
                && lookup.is_none()
                && !lookup_failed
                && !(dname.is_some() && question.qtype == Type::CNAME)
            {
                let owner = if count == 0 && synthesized {
                    question.name
                } else if let Some(rr) = zone.records_at(target, question.qtype).next() {
                    NameRef::parse(rr.owner.as_wire(), 0)
                        .map_err(|_| pharos_server::Error::InvalidQuery)?
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
            if dnssec && !found && cut.is_none() && (exact || synthesized) {
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
            if dnssec
                && !found
                && cut.is_none()
                && exists
                && !exact
                && !synthesized
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
                while parent[0] != 0 && !zone.node(parent).is_some_and(|node| node.tree) {
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
                && count == 0
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
                        let Some(address) = rdata_target(rr, offset) else {
                            continue;
                        };
                        // CoreDNS repeats apex NS glue but deduplicates other answer targets.
                        if !contains(address, &zone.apex)
                            || question.qtype != Type::NS
                                && zone.records_at(target, question.qtype).take(index).any(
                                    |earlier| {
                                        rdata_target(earlier, offset)
                                            .is_some_and(|name| name.eq_ignore_ascii_case(address))
                                    },
                                )
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

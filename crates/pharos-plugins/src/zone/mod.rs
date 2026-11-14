//! Shared immutable authoritative Zone and atomic snapshots.

#[cfg(feature = "plugin-transfer")]
mod transfer;
pub(crate) mod update;

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
    class: Class,
    // RFC 2308 §3: Cache the negative-answer SOA TTL cap in the Zone snapshot.
    negative_ttl: u32,
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
    // RFC 9460 §2.4.1: Track AliasMode per type to suppress ServiceMode records.
    alias_modes: u8,
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
        // RFC 1035 §5.2: Reject a zone load when any master-file entry is invalid.
        for record in parser {
            let record = record.map_err(|error| error.to_string())?;
            if record.rtype == Type::SOA {
                if record.owner != apex {
                    return Err("SOA owner does not match Zone apex".into());
                }
                // RFC 1035 §5.2: A master-file zone has one SOA RR.
                if seen_soa {
                    return Err("Zone has multiple SOA records".into());
                }
                if previous.is_some_and(|serial| soa_serial(&record) == Some(serial)) {
                    return Err("no change in SOA serial".into());
                }
                seen_soa = true;
            }
            // RFC 5155 §7.4: Reject NSEC3 zones because no NSEC3 hash is served.
            if matches!(record.rtype, Type::NSEC3 | Type::NSEC3PARAM) {
                return Err("NSEC3 zone is not supported".into());
            }
            // RFC 8976 §2.1: Keep non-apex ZONEMD records as ordinary records.
            records.push(record);
        }
        Self::from_records(apex, records)
    }

    /// Build an immutable Zone from owned, uncompressed master-file records.
    pub fn from_records(apex: Name, records: Vec<ZoneRecord>) -> Result<Self, String> {
        Self::from_records_inner(apex, records, false)
    }

    pub(crate) fn from_dynamic_records(
        apex: Name,
        records: Vec<ZoneRecord>,
    ) -> Result<Self, String> {
        Self::from_records_inner(apex, records, true)
    }

    fn from_records_inner(
        apex: Name,
        mut records: Vec<ZoneRecord>,
        allow_empty: bool,
    ) -> Result<Self, String> {
        // RFC 4343 §4.2: Preserve the supplied apex spelling until SOA owner is known.
        let mut apex = apex;
        let mut soa = false;
        let class = records
            .first()
            .map(|record| record.class)
            .ok_or("Zone has no SOA")?;
        // RFC 1035 §5.2: Every resource record in one zone has the same class.
        if records.iter().any(|record| record.class != class) {
            return Err("Zone has records in multiple classes".into());
        }
        // RFC 1034 §4.2; RFC 2181 §6.1: Zone owners stay at or below the apex.
        if records
            .iter()
            .any(|record| !contains(record.owner.as_wire(), &apex))
        {
            return Err("Zone has an out-of-zone owner".into());
        }
        // RFC 4592 §2: Wildcard owners use ordinary resource-record syntax.
        // RFC 4343 §4.2: Keep master-file owner spelling in stored ZoneRecords.
        for record in &mut records {
            // RFC 4592 §4.1: A wildcard SOA owner must be the zone apex.
            if record.rtype == Type::SOA {
                if record.owner != apex {
                    return Err("SOA owner does not match Zone apex".into());
                }
                soa = true;
            }
            if record.rtype == Type::NSEC3 || record.rtype == Type::NSEC3PARAM {
                return Err("NSEC3 zone is not supported".into());
            }
            // RFC 4592 §4.4: Do not load DNAME at a wildcard owner.
            if record.rtype == Type::DNAME && record.owner.as_wire().starts_with(&[1, b'*']) {
                return Err("DNAME at wildcard owner".into());
            }
            // miekg/dns msg.go:636-638 accepts empty dynamic-update RDATA before type decoding.
            // RFC 6672 §2.1: DNAME RDATA must include its target domain name.
            if allow_empty
                && record.rdata.is_empty()
                && !matches!(record.rtype, Type::SOA | Type::DNAME)
            {
                continue;
            }
            // RFC 4034 §3.1: RRSIG Type Covered occupies the first two octets.
            if record.rtype == Type::RRSIG && record.rdata.len() < 2 {
                return Err("invalid RRSIG RDATA".into());
            }
            let offset = match record.rtype {
                // RFC 1035 §3.3.3: MB RDATA starts with one MADNAME.
                Type::MB => Some(0),
                Type::NS | Type::CNAME | Type::SOA | Type::DNAME => Some(0),
                Type::MX | Type::SVCB | Type::HTTPS => Some(2),
                Type::SRV => Some(6),
                _ => None,
            };
            // RFC 4592 §2.3: An asterisk label in resource data is treated literally.
            if let Some(offset) = offset {
                // RFC 4343 §4.2: Preserve case in newly created names, including RDATA.
                let end = normalize_rdata_name(&mut record.rdata, offset, false)?;
                // RFC 1035 §§3.3.1, 3.3.3, 3.3.11 and RFC 6672 §2.1: these contain one name.
                if matches!(
                    record.rtype,
                    Type::MB | Type::NS | Type::CNAME | Type::DNAME
                ) && end != record.rdata.len()
                {
                    return Err("trailing name-only RDATA".into());
                }
                if record.rtype == Type::SOA {
                    // RFC 4343 §4.2: Preserve case in the SOA RNAME field too.
                    let end = normalize_rdata_name(&mut record.rdata, end, false)?;
                    if record.rdata.len() != end + 20 {
                        return Err("invalid SOA RDATA".into());
                    }
                }
            }
        }
        if !soa {
            return Err("Zone has no SOA".into());
        }
        // RFC 2181 §6.1: Every authoritative Zone has an NS RRset at its apex.
        if !records
            .iter()
            .any(|record| record.owner == apex && record.rtype == Type::NS)
        {
            return Err("Zone apex has no NS record".into());
        }
        // RFC 8976 §§2.1, 2.5: Only apex ZONEMD tuples are unique; identical RRs dedupe below.
        let mut zonemd = std::collections::HashMap::<(u8, u8), &[u8]>::new();
        for record in records
            .iter()
            .filter(|record| record.owner == apex && record.rtype == Type::ZONEMD)
        {
            let fields = record.rdata.get(4..6).ok_or("invalid ZONEMD RDATA")?;
            let key = (fields[0], fields[1]);
            if zonemd
                .get(&key)
                .is_some_and(|previous| *previous != record.rdata.as_slice())
            {
                return Err("duplicate ZONEMD scheme and hash algorithm".into());
            }
            zonemd.entry(key).or_insert(record.rdata.as_slice());
        }
        // RFC 5936 §2.2: AXFR framing carries opening and closing SOAs; keep one in the snapshot.
        let final_soa = records.iter().rposition(|record| record.rtype == Type::SOA);
        let mut index = 0;
        records.retain(|record| {
            let keep = record.rtype != Type::SOA || Some(index) == final_soa;
            index += 1;
            keep
        });
        // RFC 4343 §4.2: The apex's SOA owner preserves the case loaded from the master file.
        if let Some(soa) = records.iter().find(|record| record.rtype == Type::SOA) {
            apex = soa.owner.clone();
        }
        // RFC 2181 §§5.1–5.2: Suppress duplicate RRs and use one TTL per RRset.
        let mut unique: std::collections::HashMap<(Name, u16, u16, Vec<u8>), usize> =
            std::collections::HashMap::with_capacity(records.len());
        let mut deduplicated: Vec<ZoneRecord> = Vec::with_capacity(records.len());
        for record in records.drain(..) {
            let mut rdata = record.rdata.clone();
            // RFC 4343 §3: Name-bearing RDATA compares without ASCII case.
            if !rdata.is_empty()
                && let Some(offset) = match record.rtype {
                    Type::MB | Type::NS | Type::CNAME | Type::DNAME | Type::PTR | Type::NSEC => {
                        Some(0)
                    }
                    Type::MX | Type::AFSDB | Type::RT | Type::KX | Type::SVCB | Type::HTTPS => {
                        Some(2)
                    }
                    Type::SRV => Some(6),
                    Type::SOA => Some(0),
                    _ => None,
                }
            {
                let end = normalize_rdata_name(&mut rdata, offset, true);
                // RFC 2136 §2.5: Empty update RDATA retains its special wire meaning.
                if end.is_err()
                    || record.rtype == Type::SOA
                        && end.is_ok_and(|end| normalize_rdata_name(&mut rdata, end, true).is_err())
                {
                    rdata.clone_from(&record.rdata);
                }
            }
            let key = (record.owner.clone(), record.rtype.0, record.class.0, rdata);
            if let Some(index) = unique.get(&key) {
                deduplicated[*index].ttl = deduplicated[*index].ttl.min(record.ttl);
            } else {
                unique.insert(key, deduplicated.len());
                deduplicated.push(record);
            }
        }
        records = deduplicated;
        // RFC 4034 §3: An RRSIG RRset's TTL matches the RRset it covers.
        let covered_type = |record: &ZoneRecord| {
            if record.rtype == Type::RRSIG {
                record
                    .rdata
                    .get(..2)
                    .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                    .unwrap_or(record.rtype.0)
            } else {
                0
            }
        };
        let rrset_key = |record: &ZoneRecord| {
            (
                record.owner.clone(),
                if record.rtype == Type::RRSIG {
                    covered_type(record)
                } else {
                    record.rtype.0
                },
                record.class.0,
            )
        };
        let mut rrset_ttls =
            std::collections::HashMap::<(Name, u16, u16), u32>::with_capacity(records.len());
        let mut signature_ttls =
            std::collections::HashMap::<(Name, u16, u16), u32>::with_capacity(records.len());
        for record in &records {
            if record.rtype == Type::RRSIG {
                let ttl = signature_ttls
                    .entry(rrset_key(record))
                    .or_insert(record.ttl);
                *ttl = (*ttl).min(record.ttl);
            } else {
                let ttl = rrset_ttls.entry(rrset_key(record)).or_insert(record.ttl);
                *ttl = (*ttl).min(record.ttl);
            }
        }
        for record in &mut records {
            let key = rrset_key(record);
            record.ttl = if record.rtype == Type::RRSIG {
                rrset_ttls
                    .get(&key)
                    .or_else(|| signature_ttls.get(&key))
                    .copied()
                    .unwrap_or(record.ttl)
            } else {
                rrset_ttls[&key]
            };
        }
        let negative_ttl = records
            .iter()
            .find(|record| record.rtype == Type::SOA)
            .and_then(negative_soa_ttl)
            .ok_or("invalid SOA negative TTL")?;
        // RFC 2181 §10.1: A CNAME owner has no ordinary data or competing targets.
        let mut cnames = std::collections::HashMap::new();
        let mut other_type_owners = std::collections::HashSet::new();
        let mut dnames = std::collections::HashMap::new();
        let mut ns_owners = std::collections::HashSet::new();
        for record in &records {
            match record.rtype {
                Type::CNAME => {
                    let target = cnames
                        .entry(record.owner.clone())
                        .or_insert(record.rdata.as_slice());
                    if *target != record.rdata.as_slice() && !same_wire_name(target, &record.rdata)
                    {
                        return Err("CNAME RRset has multiple targets".into());
                    }
                }
                Type::DNAME => {
                    let target = dnames
                        .entry(record.owner.clone())
                        .or_insert(record.rdata.as_slice());
                    if !same_wire_name(target, &record.rdata) {
                        return Err("DNAME RRset has multiple targets".into());
                    }
                }
                Type::NS => {
                    ns_owners.insert(record.owner.clone());
                }
                _ => {}
            }
            if !matches!(
                record.rtype,
                Type::CNAME | Type::RRSIG | Type::SIG | Type::NSEC | Type::NXT | Type::KEY
            ) {
                other_type_owners.insert(record.owner.clone());
            }
        }
        if cnames.keys().any(|owner| other_type_owners.contains(owner)) {
            return Err("CNAME coexists with other data".into());
        }
        // RFC 6672 §2.4: DNAME RRsets are singleton and cannot coexist with CNAME.
        if dnames
            .keys()
            .any(|owner| cnames.contains_key(owner) || owner != &apex && ns_owners.contains(owner))
        {
            return Err("DNAME conflicts with other data".into());
        }
        // RFC 6672 §2.4: A DNAME owner cannot have data at any descendant.
        let dname_owners: std::collections::HashSet<_> = dnames.keys().cloned().collect();
        for record in &records {
            let mut suffix = record.owner.as_wire();
            while suffix[0] != 0 {
                suffix = &suffix[1 + usize::from(suffix[0])..];
                let ancestor = NameRef::parse(suffix, 0)
                    .map_err(|error| error.to_string())?
                    .to_name();
                if dname_owners.contains(&ancestor) {
                    return Err("Zone data exists below DNAME owner".into());
                }
            }
        }
        for record in &records {
            let (offset, error) = match record.rtype {
                Type::PTR => (Some(0), "PTR target is a CNAME alias"),
                Type::MX | Type::NS => (
                    Some(if record.rtype == Type::MX { 2 } else { 0 }),
                    "MX/NS target is a CNAME alias",
                ),
                _ => (None, ""),
            };
            if let Some(target) = offset
                .and_then(|offset| rdata_target(record, offset))
                .and_then(|wire| NameRef::parse(wire, 0).ok())
                .map(|name| name.to_name())
                && cnames.contains_key(&target)
            {
                // RFC 2181 §§10.2–10.3: PTR, MX, and NS targets cannot be aliases.
                return Err(error.into());
            }
        }
        let mut nodes: BTreeMap<Name, ZoneNode> = BTreeMap::new();
        // RFC 1034 §3.1: ancestors may exist as empty nonterminals.
        // RFC 4592 §2.2.2: A node with descendants exists even without RRsets.
        for (index, record) in records.iter().enumerate() {
            let apex_record = record.owner == apex
                && (matches!(record.rtype, Type::SOA | Type::NS)
                    || record.rtype == Type::RRSIG
                        && record.rdata.get(..2).is_some_and(|covered| {
                            covered == Type::SOA.0.to_be_bytes()
                                || covered == Type::NS.0.to_be_bytes()
                        }));
            // RFC 4592 §2.1.3: Wildcard names may have descendants and nested asterisks.
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
                    alias_modes: 0,
                });
                node.tree_exists |= !apex_record;
                if suffix.len() == record.owner.as_wire().len() {
                    node.types.entry(record.rtype.0).or_default().push(index);
                    node.tree |= !apex_record;
                    if record
                        .rdata
                        .get(..2)
                        .is_some_and(|priority| priority == [0, 0])
                    {
                        node.alias_modes |= match record.rtype {
                            Type::SVCB => 1,
                            Type::HTTPS => 2,
                            _ => 0,
                        };
                    }
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
            class,
            negative_ttl,
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

    pub(crate) fn class(&self) -> Class {
        self.class
    }

    /// Return the Zone's immutable records.
    #[must_use]
    pub fn records(&self) -> &[ZoneRecord] {
        &self.records
    }

    // RFC 1712 §5: Return GPOS data only when stored for the queried owner.
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

    // RFC 4343 §3: Owner lookup compares labels with ASCII case folding.
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
        let node = self.node(name);
        let ignore_service_mode = node.is_some_and(|node| match kind {
            Type::SVCB => node.alias_modes & 1 != 0,
            Type::HTTPS => node.alias_modes & 2 != 0,
            _ => false,
        });
        node.and_then(|node| node.types.get(&kind.0))
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(|index| &self.records[*index])
            // RFC 9460 §2.4.1: Ignore ServiceMode RRs when an AliasMode RR exists.
            .filter(move |record| {
                !ignore_service_mode
                    || record
                        .rdata
                        .get(..2)
                        .is_some_and(|priority| priority == [0, 0])
            })
    }

    // RFC 8020 §3.1: The apex exists even when only its SOA and NS define it.
    pub(crate) fn exists(&self, name: &[u8]) -> bool {
        name.eq_ignore_ascii_case(self.apex.as_wire())
            || self.node(name).is_some_and(|node| node.tree_exists)
    }

    pub(crate) fn exact(&self, name: &[u8]) -> bool {
        name.eq_ignore_ascii_case(self.apex.as_wire())
            || self.node(name).is_some_and(|node| node.tree)
    }

    // RFC 5936 §3.5: Find the enclosing delegation cut for potentially occluded names.
    pub(crate) fn cut(&self, name: &[u8], kind: Type) -> Option<&ZoneRecord> {
        if !contains_wire(name, self.apex.as_wire()) {
            return None;
        }
        let mut suffix = name;
        let mut cut = None;
        while !suffix.eq_ignore_ascii_case(self.apex.as_wire()) {
            // RFC 4035 §3.1.4.1: DS RRsets belong to the parent side of a zone cut.
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

    /// Return the SOA serial of this Zone.
    #[must_use]
    pub fn serial(&self) -> Option<u32> {
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
    if bytes.first() == Some(&0)
        && matches!(record.rtype, Type::SVCB | Type::HTTPS)
        && record
            .rdata
            .get(..2)
            .is_some_and(|priority| priority != [0, 0])
    {
        return Some(record.owner.as_wire());
    }
    let len = NameRef::parse(bytes, 0).ok()?.wire_len();
    bytes.get(..len)
}

fn same_wire_name(left: &[u8], right: &[u8]) -> bool {
    // RFC 4343 §3: DNS domain-name comparisons fold ASCII case.
    NameRef::parse(left, 0)
        .ok()
        .zip(NameRef::parse(right, 0).ok())
        .is_some_and(|(left, right)| left == right)
}

// RFC 1034 §3.6.2: Floyd traversal detects every CNAME cycle with constant extra storage.
fn cname_target_before_cut<'a>(zone: &'a Zone, name: &[u8], qtype: Type) -> Option<&'a [u8]> {
    // RFC 2136 §2.5: Empty update RDATA has no name to chase.
    if name.is_empty() {
        return None;
    }
    // RFC 1034 §4.3.2: Do not chase aliases across a Zone Cut.
    if zone.cut(name, qtype).is_some() {
        return None;
    }
    zone.records_at(name, Type::CNAME)
        .next()
        .map(|record| record.rdata.as_slice())
}

fn cname_chain_loops(zone: &Zone, start: &[u8], qtype: Type) -> bool {
    let mut slow = Some(start);
    let mut fast = Some(start);
    loop {
        slow = slow.and_then(|name| cname_target_before_cut(zone, name, qtype));
        fast = fast
            .and_then(|name| cname_target_before_cut(zone, name, qtype))
            .and_then(|name| cname_target_before_cut(zone, name, qtype));
        let (Some(slow_name), Some(fast_name)) = (slow, fast) else {
            return false;
        };
        if slow_name.eq_ignore_ascii_case(fast_name) {
            return true;
        }
    }
}

// RFC 2308 §3: Negative cache TTL is min(SOA TTL, SOA MINIMUM).
fn negative_soa_ttl(soa: &ZoneRecord) -> Option<u32> {
    let minimum = soa.rdata.get(soa.rdata.len().checked_sub(4)?..)?;
    let minimum = u32::from_be_bytes(minimum.try_into().ok()?);
    Some(soa.ttl.min(minimum))
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
    if name.is_empty() {
        return false;
    }
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
    fn label_offsets(mut name: &[u8], offsets: &mut [u8; 127]) -> usize {
        let mut count = 0;
        let mut offset = 0;
        while name[0] != 0 {
            let len = usize::from(name[0]);
            offsets[count] = offset as u8;
            count += 1;
            name = &name[1 + len..];
            offset += 1 + len;
        }
        count
    }
    let mut a = [0; 127];
    let mut b = [0; 127];
    let ac = label_offsets(left, &mut a);
    let bc = label_offsets(right, &mut b);
    // RFC 4343 §3: DNS name lookup matches ASCII letters without regard to case.
    for index in 0..ac.min(bc) {
        let left = &left[usize::from(a[ac - index - 1])..];
        let right = &right[usize::from(b[bc - index - 1])..];
        let order = left[1..1 + usize::from(left[0])]
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(
                right[1..1 + usize::from(right[0])]
                    .iter()
                    .map(u8::to_ascii_lowercase),
            );
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
) -> Result<bool, pharos_server::Error> {
    // RFC 2308 §3: Negative-answer SOA and its RRSIG use min(TTL, MINIMUM).
    let ttl_cap = (section == Section::Authority && kind == Type::SOA).then_some(zone.negative_ttl);
    let output_ttl = |ttl: u32| ttl_cap.map_or(ttl, |cap| ttl.min(cap));
    // RFC 2181 §10.2: PTR RRsets may contain multiple records.
    let mut has_records = false;
    for rr in zone.records_at(source, kind) {
        has_records = true;
        builder
            .record(
                section,
                owner,
                rr.rtype,
                rr.class,
                output_ttl(rr.ttl),
                &rr.rdata,
            )
            .map_err(pharos_server::Error::Build)?;
    }
    // RFC 9460 §4.3: Include DNSSEC records with Additional RRsets when DO is set.
    // RFC 4592 §4.8: Include a wildcard RRset's RRSIG with synthesized data when DO is set.
    // RFC 4035 §3.1.1: include matching RRSIG records when DO is set.
    if dnssec && has_records && kind != Type::RRSIG {
        for rr in zone
            .records_at(source, Type::RRSIG)
            .filter(|rr| rr.rdata.get(..2) == Some(kind.0.to_be_bytes().as_slice()))
        {
            builder
                .record(
                    section,
                    owner,
                    rr.rtype,
                    rr.class,
                    output_ttl(rr.ttl),
                    &rr.rdata,
                )
                .map_err(pharos_server::Error::Build)?;
        }
    }
    Ok(has_records)
}

impl Zone {
    /// Answer a Query using this immutable Zone, optionally falling through on absent names.
    pub async fn lookup<N: Next + Send>(
        &self,
        cx: &mut Context<'_, '_>,
        next: N,
        fallthrough: &[Name],
    ) -> Outcome {
        self.lookup_inner(cx, next, fallthrough, true).await
    }

    #[cfg(feature = "plugin-auto")]
    pub(crate) async fn lookup_auto<N: Next + Send>(
        &self,
        cx: &mut Context<'_, '_>,
        next: N,
    ) -> Outcome {
        self.lookup_inner(cx, next, &[], false).await
    }

    async fn lookup_inner<N: Next + Send>(
        &self,
        cx: &mut Context<'_, '_>,
        next: N,
        fallthrough: &[Name],
        drop_notify: bool,
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
            if question.qclass != zone.class {
                // RFC 5936 §§2.1.2, 2.2.1 Note e: QCLASS mismatch means NOTAUTH.
                let max = cx.max_response_size.max(512);
                if cx.response.capacity() < max {
                    if cx.protocol == Protocol::Tcp {
                        cx.response.reserve(max.saturating_sub(cx.response.len()));
                    } else {
                        return Outcome::Error(pharos_server::Error::ResponseBufferTooSmall);
                    }
                }
                let result = (|| -> Result<(), pharos_server::Error> {
                    let mut builder = MessageBuilder::new(
                        cx.response,
                        max,
                        cx.query.id(),
                        0x8000 | (cx.query.flags() & 0x0100) | Rcode::NOTAUTH.0,
                    )
                    .map_err(pharos_server::Error::Build)?;
                    builder
                        .question(question.name, question.qtype, question.qclass)
                        .map_err(pharos_server::Error::Build)?;
                    let _ = builder.finish();
                    Ok(())
                })();
                return result.map_or_else(Outcome::Error, |_| Outcome::Response);
            }
            return Outcome::Unanswered(Rcode::REFUSED);
        }
        // RFC 1035 §3.7.1: A zone answers only queries for its class.
        if question.qclass != self.class && question.qclass != Class::ANY {
            return next.run(cx).await;
        }
        // RFC 1996 §3.10: a server ignores NOTIFY from a host that is not a known master.
        if drop_notify && cx.query.opcode() == pharos_proto::Opcode::NOTIFY {
            return Outcome::Drop;
        }
        // RFC 1034 §4.3.2: return the first Zone Cut between the apex and QNAME.
        // RFC 2181 §6.1: A parent zone stops authoritative answers at each child cut.
        // RFC 4343 §3: Case differences do not change Zone Cut selection.
        let cut = zone.cut(name, question.qtype);
        // RFC 6672 §2.3: DNAME redirects strict descendants, not its owner.
        let dname = zone
            .dname(name)
            .filter(|rr| cut.is_none_or(|cut| rr.owner.label_count() <= cut.owner.label_count()));
        let mut cut = cut.filter(|_| dname.is_none());
        let mut wildcard = [0u8; 255];
        let mut dname_target = [0u8; 255];
        let mut source = name;
        let mut yxdomain = false;
        // RFC 8020 §3.1: An existing empty non-terminal returns NOERROR with no answer.
        let exists = zone.exists(name);
        // RFC 4592 §2.3: An asterisk in QNAME matches only an existing asterisk label.
        let exact = zone.exact(name)
            || name.eq_ignore_ascii_case(zone.apex.as_wire())
                && matches!(question.qtype, Type::SOA | Type::NS);
        if let Some(rr) = dname {
            let target = &rr.rdata;
            // RFC 6672 §2.2: Replace only whole labels matching the DNAME owner suffix.
            let prefix = name.len() - rr.owner.as_wire().len();
            let len = prefix + target.len();
            if len > dname_target.len() {
                // RFC 6672 §2.2: An overlong substitution returns YXDOMAIN with DNAME proof.
                yxdomain = true;
            } else {
                dname_target[..prefix].copy_from_slice(&name[..prefix]);
                dname_target[prefix..len].copy_from_slice(target);
                source = &dname_target[..len];
            }
            if !yxdomain && source.eq_ignore_ascii_case(name) {
                return Outcome::Unanswered(Rcode::SERVFAIL);
            }
        // RFC 4592 §4.5: Wildcard synthesis matches the RR owner, not the SRV Name field.
        // RFC 4592 §2.2.3: An existing empty non-terminal blocks wildcard synthesis.
        } else if !exists && cut.is_none() {
            // RFC 1183 §3.3: Wildcard RT records use the same matching as MX records.
            // RFC 4592 §3.3.1: the closest encloser determines wildcard synthesis.
            let mut parent = if name[0] == 0 {
                name
            } else {
                &name[1 + usize::from(name[0])..]
            };
            // RFC 4592 §2.2: An existing intervening name blocks wildcard synthesis.
            while parent[0] != 0 && !zone.exists(parent) {
                parent = &parent[1 + usize::from(parent[0])..];
            }
            // RFC 4592 §2.1.1: An asterisk label is encoded as 0x01 0x2a on the wire.
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
        let mut chain: [Option<&ZoneRecord>; 10] = [None; 10];
        let mut count = 0;
        let mut chain_limited = false;
        let mut empty_alias = false;
        let mut target = source;
        if dname.is_some() {
            cut = zone.cut(target, question.qtype);
        }
        // DNAME NS targets without a Referral use Self Lookup instead of local alias walking.
        // RFC 1034 §3.6.2: CNAME queries do not restart at the canonical name.
        if cut.is_none()
            && question.qtype != Type::CNAME
            && !yxdomain
            && !(dname.is_some() && question.qtype == Type::NS)
        {
            // RFC 1034 §4.3.2: Follow a matched CNAME and restart lookup at its target.
            // RFC 2181 §10.2: PTR lookup names may alias even though PTR targets may not.
            let mut next_alias = zone.records_at(target, Type::CNAME).next();
            if next_alias.is_some() && cname_chain_loops(zone, target, question.qtype) {
                return Outcome::Unanswered(Rcode::SERVFAIL);
            }
            while let Some(alias) = next_alias {
                if count == chain.len() {
                    chain_limited = true;
                    break;
                }
                chain[count] = Some(alias);
                count += 1;
                if alias.rdata.is_empty() {
                    empty_alias = true;
                    break;
                }
                target = &alias.rdata;
                cut = zone.cut(target, question.qtype);
                if cut.is_some()
                    || question.qtype == Type::NS
                    || question.qtype == Type::SOA
                        && target.eq_ignore_ascii_case(zone.apex.as_wire())
                {
                    break;
                }
                next_alias = zone.records_at(target, Type::CNAME).next();
            }
        }
        let mut lookup_failed = false;
        let lookup = if cut.is_none()
            && !chain_limited
            && !empty_alias
            && !yxdomain
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
        // RFC 4592 §4.7: Never synthesize an NSEC RR at a wildcard-expanded owner.
        let wildcard_nsec = synthesized && question.qtype == Type::NSEC;
        // RFC 7344 §3.1: CDS is served as a regular resource record type.
        let found = dname.is_some()
            || count > 0
            || !wildcard_nsec && zone.records_at(target, question.qtype).next().is_some();
        let dnssec = cx.query.opt().is_some_and(|opt| opt.dnssec_ok());
        if !exact
            && !synthesized
            && cut.is_none()
            && dname.is_none()
            && fallthrough.iter().any(|apex| contains(name, apex))
        {
            return next.run(cx).await;
        }
        // RFC 6604 §3: The xNAME-chain response RCODE reflects the final query cycle.
        let rcode = if yxdomain {
            Rcode::YXDOMAIN
        } else if lookup_failed || lookup.is_some() && external.is_none() {
            Rcode::SERVFAIL
        } else if let Some(response) = external {
            match response.rcode() {
                Rcode::SERVFAIL => Rcode::SERVFAIL,
                Rcode::NXDOMAIN => Rcode::NXDOMAIN,
                _ => Rcode::NOERROR,
            }
        // RFC 8659 §6.2: An unknown RR type at an existing name returns RCODE 0.
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
            // RFC 1035 §4.1.1: OPCODE identifies the operation; RD is a Query flag.
            // RFC 4035 §3.1.6: Clear CD in authoritative responses.
            // RFC 2181 §6.1: Clear AA on pure referrals at a zone cut.
            // RFC 1034 §3.7.1: QCLASS=* responses can never be authoritative.
            let mut builder = MessageBuilder::new(
                cx.response,
                max,
                cx.query.id(),
                0x8000
                    | if question.qclass != Class::ANY
                        && (cut.is_none() || count > 0 || dname.is_some())
                    {
                        0x0400
                    } else {
                        0
                    }
                    | (cx.query.flags()
                        & if !drop_notify && cx.query.opcode() != pharos_proto::Opcode::QUERY {
                            0x7800
                        } else {
                            0x7900
                        })
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
            // RFC 6672 §3.1: Include the DNAME and synthesized CNAME in the answer.
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
                // RFC 6672 §3.1: The synthesized CNAME uses QNAME and the DNAME TTL.
                if !yxdomain {
                    builder
                        .record(
                            Section::Answer,
                            question.name,
                            Type::CNAME,
                            rr.class,
                            rr.ttl,
                            source,
                        )
                        .map_err(pharos_server::Error::Build)?;
                }
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
                    // RFC 4035 §3.1.3.3: A wildcard CNAME RRSIG uses expanded QNAME as owner.
                    for sig in zone
                        .records_at(rr.owner.as_wire(), Type::RRSIG)
                        .filter(|sig| {
                            sig.rdata.get(..2) == Some(Type::CNAME.0.to_be_bytes().as_slice())
                        })
                    {
                        builder
                            .record(
                                Section::Answer,
                                question.name,
                                sig.rtype,
                                sig.class,
                                sig.ttl,
                                &sig.rdata,
                            )
                            .map_err(pharos_server::Error::Build)?;
                    }
                }
            }
            // RFC 4431 §2: DLV may be served at the apex as an ordinary record.
            // RFC 6672 §3.1: Answer synthesized CNAME queries in the DNAME branch.
            if cut.is_none()
                && !chain_limited
                && lookup.is_none()
                && !lookup_failed
                && !wildcard_nsec
                && !(dname.is_some() && question.qtype == Type::CNAME)
            {
                let owner = if count == 0 && synthesized {
                    question.name
                } else if let Some(rr) = zone.records_at(target, question.qtype).next() {
                    // RFC 9460 §2.3: SVCB answers retain the target RRset owner after CNAME.
                    NameRef::parse(rr.owner.as_wire(), 0)
                        .map_err(|_| pharos_server::Error::InvalidQuery)?
                } else {
                    NameRef::parse(target, 0).map_err(|_| pharos_server::Error::InvalidQuery)?
                };
                // RFC 3225 §3: Return explicitly queried DNSSEC RRsets regardless of DO.
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
            // RFC 2308 §2.1.1: Authoritative NXDOMAIN responses use SOA without NS records.
            // RFC 2181 §7.1: Place an SOA added to an authoritative answer in Authority.
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
                // RFC 9471 §3.3: Referral responses copy delegated NS records to Authority.
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
                // RFC 4035 §3.1.3.2: Empty non-terminals are closest enclosers too.
                while parent[0] != 0 && !zone.exists(parent) {
                    parent = &parent[1 + usize::from(parent[0])..];
                }
                let mut proof = [0u8; 255];
                if parent.len() + 2 <= proof.len() {
                    proof[0] = 1;
                    proof[1] = b'*';
                    proof[2..2 + parent.len()].copy_from_slice(parent);
                    // RFC 4035 §3.1.3.2: Include a shared NSEC proof only once in Authority.
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
            // RFC 4035 §§3.1.3.3–3.1.3.4: Wildcard answers and NODATA need a closer-name proof.
            if dnssec
                && synthesized
                && let Some(rr) = zone.previous_nsec(name)
                && !source.eq_ignore_ascii_case(rr.owner.as_wire())
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
            // RFC 4035 §3.1.4: DNSSEC referrals prove either DS presence or absence.
            if dnssec && let Some(cut) = cut {
                let owner = NameRef::parse(cut.owner.as_wire(), 0)
                    .map_err(|_| pharos_server::Error::InvalidQuery)?;
                // RFC 4035 §3.1.4: A delegation without DS needs its NSEC denial instead.
                if !write_set(
                    &mut builder,
                    zone,
                    cut.owner.as_wire(),
                    owner,
                    Type::DS,
                    Section::Authority,
                    true,
                )? {
                    write_set(
                        &mut builder,
                        zone,
                        cut.owner.as_wire(),
                        owner,
                        Type::NSEC,
                        Section::Authority,
                        true,
                    )?;
                }
            }
            // RFC 1034 §4.3.2: Referrals include available address glue.
            if let Some(cut) = cut {
                // RFC 9471 §3.2: Include available in-zone glue for sibling nameservers.
                for ns in zone.records_at(cut.owner.as_wire(), Type::NS) {
                    if !contains(&ns.rdata, &zone.apex) {
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
            // RFC 1035 §3.3: MX and NS targets and RFC 2782 §3: SRV targets may have glue.
            // RFC 3596 §2.3: AAAA queries do not trigger additional section processing.
            if cut.is_none() {
                // RFC 1706 §5: NSAP answers do not trigger additional address processing.
                let target_offset = match question.qtype {
                    // RFC 1035 §3.3.3: MB MADNAME is the single name in its RDATA.
                    Type::MB => Some(0),
                    Type::MX => Some(2),
                    // RFC 1183 §§1, 3.3 and RFC 2230 §3.1: process their host targets.
                    Type::AFSDB | Type::RT | Type::KX => Some(2),
                    // RFC 9460 §§2.5.2, 4.1: ServiceMode TargetName "." maps to its owner.
                    Type::SVCB | Type::HTTPS => Some(2),
                    Type::SRV => Some(6),
                    Type::NS if source.eq_ignore_ascii_case(zone.apex.as_wire()) => Some(0),
                    _ => None,
                };
                // RFC 1035 §§3.3.9, 3.3.11; RFC 2782 §3; RFC 1183 §§1, 3.3; RFC 2230 §3.1; RFC 9460 §4.1: Select target data types.
                let additional_types: &[Type] = match question.qtype {
                    Type::MB => &[Type::A],
                    Type::MX | Type::AFSDB => &[Type::A, Type::AAAA],
                    Type::RT => &[Type::A, Type::AAAA, Type::X25, Type::ISDN],
                    Type::SVCB => &[Type::A, Type::AAAA, Type::SVCB],
                    Type::HTTPS => &[Type::A, Type::AAAA, Type::HTTPS],
                    Type::KX | Type::SRV | Type::NS => &[Type::A, Type::AAAA],
                    _ => &[],
                };
                if let Some(offset) = target_offset {
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
                        for &kind in additional_types {
                            // RFC 9460 §4.1: Do not repeat an owner's binding RRset in Additional.
                            if matches!(kind, Type::SVCB | Type::HTTPS)
                                && address.eq_ignore_ascii_case(rr.owner.as_wire())
                            {
                                continue;
                            }
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

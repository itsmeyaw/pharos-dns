use super::*;
use pharos_proto::zone::ZoneRecord;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub(super) struct Member {
    id: Vec<u8>,
    pub zone: Name,
    pub coo: Option<Name>,
    pub groups: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub(super) struct Catalog {
    pub members: Vec<Member>,
}

#[derive(Default, Debug)]
pub(super) struct State {
    catalogs: HashMap<Name, Catalog>,
    members: HashMap<Name, HashSet<Name>>,
    dynamic: HashMap<Name, (Name, Vec<u8>)>,
}

fn labels(name: &Name) -> Vec<Vec<u8>> {
    NameRef::parse(name.as_wire(), 0)
        .unwrap()
        .labels()
        .map(|label| label.iter().map(u8::to_ascii_lowercase).collect())
        .collect()
}

fn target(record: &ZoneRecord) -> Result<Name, &'static str> {
    // RFC 9432 §4.1: Member-zone names are carried in PTR record RDATA.
    let target = NameRef::parse(&record.rdata, 0).map_err(|_| "invalid catalog target")?;
    target
        .to_name()
        .canonical()
        .parse()
        .map_err(|_| "invalid catalog target")
}

fn text(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut result = Vec::new();
    let mut left = data;
    while let Some((&length, rest)) = left.split_first() {
        let (part, rest) = rest
            .split_at_checked(usize::from(length))
            .ok_or("invalid catalog TXT")?;
        result.extend_from_slice(part);
        left = rest;
    }
    Ok(result)
}

pub(super) fn parse(origin: &Name, records: &[ZoneRecord]) -> Result<Catalog, &'static str> {
    let origin_labels = labels(origin);
    let mut version = Vec::new();
    let mut soa = false;
    let mut ns = false;
    let mut ptr: HashMap<Vec<u8>, Vec<Name>> = HashMap::new();
    let mut coo: HashMap<Vec<u8>, Vec<Name>> = HashMap::new();
    let mut groups: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();
    // RFC 9432 §4.1: Catalog RR TTL values have no meaning and are ignored.
    for record in records {
        // RFC 9432 §4.1: Every resource record in a catalog zone uses class IN.
        if record.class != Class::IN {
            return Err("catalog record is not IN");
        }
        let owner = labels(&record.owner);
        if owner == origin_labels {
            soa |= record.rtype == Type::SOA;
            ns |= record.rtype == Type::NS;
        }
        if !owner.ends_with(&origin_labels) {
            continue;
        }
        let prefix = &owner[..owner.len() - origin_labels.len()];
        // RFC 9432 §3: Ignore catalog records with no supported processing rule.
        if record.rtype == Type::TXT && prefix.len() == 1 && prefix[0] == b"version" {
            version.push(text(&record.rdata)?);
        // RFC 9432 §4.3.2: Store group values opaque; this consumer recognizes none.
        } else if record.rtype == Type::TXT
            // RFC 9432 §4.3.2: The group property is TXT data handled by the consumer.
            && prefix.len() == 3
            && prefix[0] == b"group"
            && prefix[2] == b"zones"
        {
            groups
                .entry(prefix[1].clone())
                .or_default()
                .push(text(&record.rdata)?);
        // RFC 9432 §4.1: each member is one PTR record under a uniquely tagged member node.
        } else if record.rtype == Type::PTR {
            // RFC 9432 §4.1: Member nodes are direct children of the zones label.
            if prefix.len() == 2 && prefix[1] == b"zones" {
                ptr.entry(prefix[0].clone())
                    .or_default()
                    .push(target(record)?);
            // RFC 9432 §4.3.1: a member's coo property names its prospective new catalog.
            } else if prefix.len() == 3 && prefix[0] == b"coo" && prefix[2] == b"zones" {
                coo.entry(prefix[1].clone())
                    .or_default()
                    .push(target(record)?);
            }
        }
    }
    // RFC 9432 §§4, 4.2.1: A catalog requires apex SOA and NS records and version "2".
    if !soa || !ns || version.len() != 1 || version[0] != b"2" {
        return Err("invalid catalog version or apex");
    }
    let mut seen = HashSet::new();
    let mut members = Vec::new();
    // RFC 9432 §4.1: Each member PTR has one target, unique within the catalog.
    for (id, zones) in ptr {
        if zones.len() != 1 || !seen.insert(zones[0].clone()) {
            return Err("duplicate catalog member");
        }
        let owners = coo.remove(&id).unwrap_or_default();
        if owners.len() > 1 {
            return Err("duplicate catalog coo");
        }
        let mut groups = groups.remove(&id).unwrap_or_default();
        groups.sort();
        members.push(Member {
            id,
            zone: zones[0].clone(),
            coo: owners.into_iter().next(),
            groups,
        });
    }
    members.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(Catalog { members })
}

pub(super) fn apply(shared: &Arc<Shared>, source: &SecondaryZone, catalog: Catalog) {
    let mut tasks = shared.tasks.lock().unwrap();
    if !shared.running.load(Ordering::Relaxed) {
        return;
    }
    tasks.retain(|task| !task.is_finished());
    let origin = &source.config.apex;
    let mut state = shared.catalogs.lock().unwrap();
    state.catalogs.insert(origin.clone(), catalog.clone());
    let mut zones = (**shared.zones.load()).clone();
    let mut admitted = HashSet::new();
    for member in &catalog.members {
        if source.config.catalog.as_ref().is_some_and(|allowed| {
            !allowed.is_empty()
                && !allowed
                    .iter()
                    .any(|suffix| member.zone.is_subdomain_of(suffix))
        }) {
            continue;
        }
        admitted.insert(member.zone.clone());
        let existing = zones
            .iter()
            .find(|zone| zone.config.apex == member.zone)
            .cloned();
        let mut preserve = None;
        // RFC 9432 §5.2: Ignore member-name clashes unless old coo signals migration.
        if let Some(existing) = existing {
            let Some((owner, id)) = state.dynamic.get(&member.zone) else {
                continue;
            };
            if owner == origin && id == &member.id {
                continue;
            }
            // RFC 9432 §5.5: Move a member only when the old catalog sets coo.
            if owner != origin {
                let source_member = state.catalogs.get(owner).and_then(|catalog| {
                    catalog.members.iter().find(|item| item.zone == member.zone)
                });
                if !source_member.is_some_and(|item| item.coo.as_ref() == Some(origin)) {
                    continue;
                }
                // RFC 9432 §§4.3.1, 7: Preserve state only when member labels match.
                if source_member.is_some_and(|item| item.id == member.id && id == &member.id) {
                    preserve = Some(Arc::clone(&existing));
                }
            }
            // RFC 9432 §§5.4, 5.6: Remove old state before re-adding a changed label.
            if let Some(task) = existing.task.lock().unwrap().take() {
                task.abort();
            }
            zones.retain(|zone| zone.config.apex != member.zone);
        }
        let zone = Arc::new(SecondaryZone::new(ZoneConfig {
            apex: member.zone.clone(),
            from: source.config.from.clone(),
            catalog: None,
        }));
        if let Some(old) = preserve {
            zone.current.store(old.current.load_full());
            zone.expired
                .store(old.expired.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        state
            .dynamic
            .insert(member.zone.clone(), (origin.clone(), member.id.clone()));
        pharos_server::logging::log(
            "INFO",
            "secondary",
            &format!(
                "Added catalog member {} with {} groups",
                member.zone,
                member.groups.len()
            ),
        );
        // RFC 9432 §5.1: apply valid catalog changes automatically to the running server.
        zones.push(Arc::clone(&zone));
        let task = tokio::spawn(update::run(Arc::clone(shared), Arc::clone(&zone)));
        *zone.task.lock().unwrap() = Some(task.abort_handle());
        tasks.push(task);
    }
    let previous = state
        .members
        .insert(origin.clone(), admitted.clone())
        .unwrap_or_default();
    // RFC 9432 §5.3: Remove a member and its associated state only when this catalog owns it.
    for removed in previous.difference(&admitted) {
        if state
            .dynamic
            .get(removed)
            .is_some_and(|(owner, _)| owner == origin)
        {
            if let Some(zone) = zones.iter().find(|zone| &zone.config.apex == removed)
                && let Some(task) = zone.task.lock().unwrap().take()
            {
                task.abort();
            }
            zones.retain(|zone| &zone.config.apex != removed);
            state.dynamic.remove(removed);
        }
    }
    shared.zones.store(Arc::new(zones));
}

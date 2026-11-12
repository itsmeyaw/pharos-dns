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
    for record in records {
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
        if record.rtype == Type::TXT && prefix.len() == 1 && prefix[0] == b"version" {
            version.push(text(&record.rdata)?);
        } else if record.rtype == Type::TXT
            && prefix.len() == 3
            && prefix[0] == b"group"
            && prefix[2] == b"zones"
        {
            groups
                .entry(prefix[1].clone())
                .or_default()
                .push(text(&record.rdata)?);
        } else if record.rtype == Type::PTR {
            if prefix.len() == 2 && prefix[1] == b"zones" {
                ptr.entry(prefix[0].clone())
                    .or_default()
                    .push(target(record)?);
            } else if prefix.len() == 3 && prefix[0] == b"coo" && prefix[2] == b"zones" {
                coo.entry(prefix[1].clone())
                    .or_default()
                    .push(target(record)?);
            }
        }
    }
    // RFC 9432 §§4.1, 5.1: a catalog has SOA, NS, and one supported version.
    if !soa || !ns || version.len() != 1 || version[0] != b"2" {
        return Err("invalid catalog version or apex");
    }
    let mut seen = HashSet::new();
    let mut members = Vec::new();
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
        if let Some(existing) = existing {
            let Some((owner, id)) = state.dynamic.get(&member.zone) else {
                continue;
            };
            if owner == origin && id == &member.id {
                continue;
            }
            if owner != origin {
                let source_member = state.catalogs.get(owner).and_then(|catalog| {
                    catalog.members.iter().find(|item| item.zone == member.zone)
                });
                if !source_member.is_some_and(|item| item.coo.as_ref() == Some(origin)) {
                    continue;
                }
                if source_member.is_some_and(|item| item.id == member.id && id == &member.id) {
                    preserve = Some(Arc::clone(&existing));
                }
            }
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
        zones.push(Arc::clone(&zone));
        let task = tokio::spawn(update::run(Arc::clone(shared), Arc::clone(&zone)));
        *zone.task.lock().unwrap() = Some(task.abort_handle());
        shared.tasks.lock().unwrap().push(task);
    }
    let previous = state
        .members
        .insert(origin.clone(), admitted.clone())
        .unwrap_or_default();
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

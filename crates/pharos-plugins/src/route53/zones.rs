use super::{Api, convert_page};
use crate::zone::{Zone, ZoneHolder, contains};
use pharos_proto::Name;
use std::sync::Arc;
use tokio::task::JoinSet;

/// One Route 53 hosted zone and the immutable Zone snapshot built from it.
#[derive(Debug)]
pub(super) struct Hosted {
    pub(super) id: String,
    pub(super) current: ZoneHolder,
}

/// The hosted zones configured for one ZONE, in Corefile order.
#[derive(Debug)]
pub(super) struct Group {
    pub(super) dns: String,
    pub(super) apex: Name,
    pub(super) hosted: Vec<Hosted>,
}

impl Group {
    pub(super) fn new(dns: &str, ids: &[String]) -> Result<Self, String> {
        // CoreDNS v1.15.0 plugin/route53/route53.go New: file.NewZone makes the origin fully qualified.
        let fqdn = if dns.ends_with('.') {
            dns.to_owned()
        } else {
            format!("{dns}.")
        };
        let apex = fqdn
            .parse()
            .map_err(|error| format!("invalid zone {dns:?}: {error}"))?;
        Ok(Self {
            dns: dns.to_owned(),
            apex,
            hosted: ids
                .iter()
                .map(|id| Hosted {
                    id: id.clone(),
                    current: ZoneHolder::default(),
                })
                .collect(),
        })
    }
}

/// CoreDNS logs the ZONE names as a Go slice: `[a. b.]`.
pub(super) fn names(groups: &[Group]) -> String {
    let names = groups.iter().map(|group| group.dns.as_str());
    format!("[{}]", names.collect::<Vec<_>>().join(" "))
}

// CoreDNS v1.15.0 plugin/route53/route53.go updateZones: each hosted zone swaps only after its full pagination succeeded.
async fn refresh_hosted<A: Api>(api: &A, group: &Group, hosted: &Hosted) -> Result<(), String> {
    let mut records = Vec::new();
    let mut start = None;
    loop {
        let page = api
            .list_record_sets(&hosted.id, start.as_ref())
            .await
            .map_err(|error| {
                format!(
                    "failed to list resource records for {}:{} from route53: {error}",
                    group.dns, hosted.id
                )
            })?;
        convert_page(&page.sets, &mut records);
        // CoreDNS v1.15.0 plugin/route53/route53.go updateZones: a truncated page continues at the Next* record.
        match page.next {
            Some(next) => start = Some(next),
            None => break,
        }
    }
    // RFC 1034 §4.2: a Zone holds only names at or below its apex; CoreDNS inserts other owners but never serves them.
    let total = records.len();
    records.retain(|record| contains(record.owner.as_wire(), &group.apex));
    if records.len() != total {
        pharos_server::logging::log(
            "WARN",
            "route53",
            &format!(
                "Dropped {} resource record(s) outside {} from hosted zone {}",
                total - records.len(),
                group.dns,
                hosted.id
            ),
        );
    }
    let zone = Zone::from_dynamic_records(group.apex.clone(), records).map_err(|error| {
        format!(
            "failed to build zone {}:{} from route53: {error}",
            group.dns, hosted.id
        )
    })?;
    // RFC 1035 §6.1.2: publish a fully loaded Zone as one generation.
    hosted.current.store(Some(Arc::new(zone)));
    Ok(())
}

/// Refreshes every ZONE concurrently; a failure keeps that hosted zone's previous snapshot and does not stop the others.
pub(super) async fn update_zones<A: Api + 'static>(
    api: &Arc<A>,
    groups: &Arc<[Group]>,
) -> Result<(), String> {
    let mut tasks = JoinSet::new();
    // CoreDNS v1.15.0 plugin/route53/route53.go updateZones: one goroutine per ZONE name.
    for index in 0..groups.len() {
        let (api, groups) = (Arc::clone(api), Arc::clone(groups));
        tasks.spawn(async move {
            let group = &groups[index];
            // CoreDNS v1.15.0 plugin/route53/route53.go updateZones: the first failing hosted zone ends that ZONE's update.
            for hosted in &group.hosted {
                refresh_hosted(&*api, group, hosted).await?;
            }
            Ok::<(), String>(())
        });
    }
    let mut errors = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(error),
            Err(error) => errors.push(format!("update task failed: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        // CoreDNS v1.15.0 plugin/route53/route53.go updateZones: errors are reported as a Go slice.
        Err(format!("errors updating zones: [{}]", errors.join(" ")))
    }
}

/// Checks every hosted zone, then loads them all; the errors carry CoreDNS's setup prefixes.
pub(super) async fn initialize<A: Api + 'static>(
    api: &Arc<A>,
    groups: &Arc<[Group]>,
) -> Result<(), String> {
    // CoreDNS v1.15.0 plugin/route53/route53.go New: ListHostedZonesByName must succeed for every ZONE:ID.
    for group in groups.iter() {
        for hosted in &group.hosted {
            api.check_hosted_zone(&group.dns, &hosted.id)
                .await
                .map_err(|error| format!("failed to create route53 plugin: {error}"))?;
        }
    }
    // CoreDNS v1.15.0 plugin/route53/route53.go Run: the first update must succeed.
    update_zones(api, groups)
        .await
        .map_err(|error| format!("failed to initialize route53 plugin: {error}"))
}

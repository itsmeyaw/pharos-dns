use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use pharos_corefile::{BlockContext, Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::Name;

use super::{CloudDns, DnsName, Hosted, Instance, Shared, api::DEFAULT_ENDPOINT, auth};
use crate::zone::ZoneHolder;

// CoreDNS v1.15.0 plugin/clouddns/setup.go: the default update frequency is one minute.
const DEFAULT_REFRESH: Duration = Duration::from_secs(60);

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<crate::Chain>,
) -> Result<(), Error> {
    let clouddns = parse(cursor)?;
    clouddns.register_hooks(&mut block.config.lifecycle);
    block.config.clouddns = Some(clouddns);
    Ok(())
}

// CoreDNS v1.15.0 plugin/clouddns/setup.go setup: every `clouddns` line is a handler of its own.
pub(super) fn parse(cursor: &mut Cursor<'_>) -> Result<CloudDns, Error> {
    let mut instances = Vec::new();
    while cursor.next() {
        instances.push(Arc::new(parse_line(cursor)?));
    }
    Ok(CloudDns {
        shared: Arc::new(Shared {
            instances,
            tasks: Mutex::new(Vec::new()),
        }),
    })
}

fn parse_line(cursor: &mut Cursor<'_>) -> Result<Instance, Error> {
    let names = parse_zones(cursor)?;
    let mut fallthrough = Vec::new();
    let mut refresh = DEFAULT_REFRESH;
    let mut credentials = None;
    let mut endpoint = DEFAULT_ENDPOINT.to_owned();
    while cursor.next_block() {
        let property = cursor.val().to_owned();
        match property.as_str() {
            // CoreDNS v1.15.0 plugin/clouddns/setup.go: `upstream` takes and ignores its arguments.
            "upstream" => {
                cursor.remaining_args();
            }
            "credentials" => {
                if !cursor.next_arg() {
                    return Err(cursor.arg_err());
                }
                let path = PathBuf::from(cursor.val());
                // CoreDNS v1.15.0 plugin/clouddns/setup.go getCredType: the file is read now and its `type` checked.
                auth::credential_type(&path).map_err(|error| {
                    cursor.error(format!(
                        "invalid credentials file {:?}: {error}",
                        cursor.val()
                    ))
                })?;
                credentials = Some(path);
            }
            "endpoint" => {
                if !cursor.next_arg() {
                    return Err(cursor.arg_err());
                }
                endpoint = cursor.val().to_owned();
            }
            "fallthrough" => fallthrough = parse_fallthrough(cursor)?,
            "refresh" => {
                if !cursor.next_arg() {
                    return Err(cursor.arg_err());
                }
                refresh = parse_refresh(cursor.val()).map_err(|error| cursor.error(error))?;
            }
            _ => return Err(cursor.error(format!("unknown property {property:?}"))),
        }
    }
    Ok(Instance {
        names,
        fallthrough,
        refresh,
        credentials,
        endpoint,
        api: Mutex::new(None),
    })
}

// RFC 1034 §3.1: `ZONE:PROJECT_ID:HOSTED_ZONE_NAME` names a domain and the hosted zone that holds its records.
fn parse_zones(cursor: &mut Cursor<'_>) -> Result<Vec<DnsName>, Error> {
    let root: Name = ".".parse().expect("the root name parses");
    let mut names: Vec<DnsName> = Vec::new();
    let mut seen = Vec::new();
    for arg in cursor.remaining_args() {
        let invalid = || cursor.error(format!("invalid zone {arg:?}"));
        let mut parts = arg.splitn(3, ':');
        let (Some(dns_name), Some(project), Some(zone)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid());
        };
        if dns_name.is_empty() || project.is_empty() || zone.is_empty() {
            return Err(invalid());
        }
        if seen.contains(&arg) {
            return Err(cursor.error(format!("conflict zone {arg:?}")));
        }
        // miekg/dns Fqdn: the zone name becomes absolute; the hosted zones of one name keep their order.
        let apex = Name::parse(dns_name, &root).map_err(|_| invalid())?;
        let hosted = Hosted {
            project: project.to_owned(),
            zone: zone.to_owned(),
            current: ZoneHolder::empty(),
        };
        match names.iter_mut().find(|name| name.apex == apex) {
            Some(name) => name.hosted.push(hosted),
            None => names.push(DnsName {
                apex,
                hosted: vec![hosted],
            }),
        }
        seen.push(arg);
    }
    Ok(names)
}

// CoreDNS v1.15.0 plugin/pkg/fall: no arguments means every zone.
fn parse_fallthrough(cursor: &mut Cursor<'_>) -> Result<Vec<Name>, Error> {
    let args = cursor.remaining_args();
    let invalid = || cursor.arg_err();
    if args.is_empty() {
        return Ok(vec![".".parse().map_err(|_| invalid())?]);
    }
    let mut zones = Vec::new();
    for domain in &args {
        for name in origins_from_args_or_server_block(&[domain], &[]) {
            zones.push(name.parse().map_err(|_| invalid())?);
        }
    }
    Ok(zones)
}

// CoreDNS v1.15.0 plugin/clouddns/setup.go: an integer is seconds, anything else a Go duration; it must be positive.
fn parse_refresh(text: &str) -> Result<Duration, String> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    let duration = if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
        crate::health::parse_duration(&format!("{text}s"))
    } else {
        crate::health::parse_duration(text)
    }
    .ok_or_else(|| format!("unable to parse duration: {text:?}"))?;
    if duration.is_zero() {
        return Err(format!("refresh interval must be greater than 0: {text:?}"));
    }
    Ok(duration)
}

#[cfg(test)]
mod tests;

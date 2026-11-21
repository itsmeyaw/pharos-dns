use pharos_corefile::{BlockContext, Cursor, Error};

use super::{
    Azure,
    config::{Config, Environment, Secret, ZoneSpec},
};

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<crate::Chain>,
) -> Result<(), Error> {
    // CoreDNS v1.15.0 plugin/azure/setup.go setup: one handler per Server Block serves every `azure` line.
    let azure = Azure::new(parse(cursor)?).map_err(|error| cursor.error(error))?;
    azure.register_hooks(&mut block.config.lifecycle);
    block.config.azure = Some(azure);
    Ok(())
}

fn one_arg<'a>(cursor: &Cursor<'_>, args: &'a [String]) -> Result<&'a str, Error> {
    match args {
        [arg] => Ok(arg),
        _ => Err(cursor.arg_err()),
    }
}

/// CoreDNS v1.15.0 plugin/azure/setup.go parse.
pub(super) fn parse(cursor: &mut Cursor<'_>) -> Result<Config, Error> {
    let mut config = Config::default();
    while cursor.next() {
        let args = cursor.remaining_args();
        // CoreDNS v1.15.0 plugin/azure/setup.go parse: `access` applies only to the zones of the current line.
        let line_start = config.zones.len();
        for arg in &args {
            // CoreDNS v1.15.0 plugin/azure/setup.go parse: split on the first `:`; neither side may be empty.
            let (resource_group, zone) = arg
                .split_once(':')
                .filter(|(resource_group, zone)| !resource_group.is_empty() && !zone.is_empty())
                .ok_or_else(|| cursor.error(format!("invalid resource group/zone: {arg:?}")))?;
            // CoreDNS v1.15.0 plugin/azure/setup.go parse: a resource group lists a zone once.
            if config
                .zones
                .iter()
                .any(|spec| spec.resource_group == resource_group && spec.zone == zone)
            {
                return Err(cursor.error(format!("conflicting zone: {arg:?}")));
            }
            config.zones.push(ZoneSpec {
                resource_group: resource_group.to_owned(),
                zone: zone.to_owned(),
                private: false,
            });
        }

        while cursor.next_block() {
            let property = cursor.val().to_owned();
            let args = cursor.remaining_args();
            match property.as_str() {
                "subscription" => config.subscription = one_arg(cursor, &args)?.to_owned(),
                "tenant" => config.tenant = one_arg(cursor, &args)?.to_owned(),
                "client" => config.client = one_arg(cursor, &args)?.to_owned(),
                "secret" => config.secret = Secret::new(one_arg(cursor, &args)?),
                "environment" => {
                    let name = one_arg(cursor, &args)?;
                    config.environment = Environment::from_name(name).ok_or_else(|| {
                        cursor.error(format!(
                            "cannot set azure environment: no cloud environment matching {name:?}"
                        ))
                    })?;
                }
                "fallthrough" => {
                    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
                    config.fallthrough.set_domains_from_args(&args);
                }
                "access" => {
                    let private = match one_arg(cursor, &args)? {
                        "public" => false,
                        "private" => true,
                        other => {
                            return Err(cursor.error(format!(
                                "invalid access value: can be public/private, found: {other}"
                            )));
                        }
                    };
                    for spec in &mut config.zones[line_start..] {
                        spec.private = private;
                    }
                }
                "refresh" => config.refresh = refresh(cursor, one_arg(cursor, &args)?)?,
                other => return Err(cursor.error(format!("unknown property: {other:?}"))),
            }
        }
    }
    Ok(config)
}

/// CoreDNS v1.15.0 plugin/azure/setup.go parse: a bare integer counts seconds, else a Go duration; it must be positive.
fn refresh(cursor: &Cursor<'_>, value: &str) -> Result<std::time::Duration, Error> {
    let text = if value.parse::<i64>().is_ok() {
        format!("{value}s")
    } else {
        value.to_owned()
    };
    let duration = crate::health::parse_duration(&text)
        .ok_or_else(|| cursor.error(format!("unable to parse duration: {value:?}")))?;
    // parse_duration clamps a negative duration to zero, so one check covers both.
    if duration.is_zero() {
        return Err(cursor.error(format!("refresh interval must be greater than 0: {text:?}")));
    }
    Ok(duration)
}

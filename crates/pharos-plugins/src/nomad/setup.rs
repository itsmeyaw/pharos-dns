use pharos_corefile::{BlockContext, Cursor, Error};

use super::{DEFAULT_TTL, Nomad, Settings};

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<crate::Chain>,
) -> Result<(), Error> {
    // CoreDNS v1.15.0 plugin/nomad/setup.go setup has no once-only check, but its `parse` reads one `c.Next()` and so drops later Directives; Pharos builds one chained instance per Directive.
    loop {
        let settings = parse(cursor)?;
        let nomad = Nomad::new(settings, &|name| std::env::var(name).ok())
            .map_err(|message| cursor.error(message))?;
        nomad.register(&mut block.config.lifecycle);
        match &mut block.config.nomad {
            Some(first) => first.push(nomad),
            none => *none = Some(nomad),
        }
        if !cursor.has_next() {
            return Ok(());
        }
    }
}

// CoreDNS v1.15.0 plugin/nomad/setup.go parse.
pub(super) fn parse(cursor: &mut Cursor<'_>) -> Result<Settings, Error> {
    if !cursor.next() {
        return Err(cursor.error("expected 'nomad' token"));
    }
    let args = cursor.remaining_args();
    let mut settings = Settings {
        // CoreDNS v1.15.0 plugin/nomad/setup.go parse: only the first argument is the zone.
        zone: args
            .into_iter()
            .next()
            .unwrap_or_else(|| "service.nomad".to_owned()),
        ttl: DEFAULT_TTL,
        filter: String::new(),
        token: None,
        addresses: Vec::new(),
    };
    while cursor.next_block() {
        // CoreDNS v1.15.0 plugin/nomad/setup.go parse: property names are matched in lower case.
        let selector = cursor.val().to_lowercase();
        let args = cursor.remaining_args();
        match selector.as_str() {
            "address" => {
                if args.is_empty() {
                    return Err(cursor.error("at least one address is required"));
                }
                settings.addresses.extend(args);
            }
            "filter" => settings.filter = one(cursor, args, "exactly one filter is required")?,
            "token" => settings.token = Some(one(cursor, args, "exactly one token is required")?),
            "ttl" => {
                let value = one(cursor, args, "exactly one ttl value is required")?;
                // CoreDNS v1.15.0 plugin/nomad/setup.go parse: `strconv.Atoi`, then a range check.
                let seconds: i64 = value
                    .parse()
                    .map_err(|error| cursor.error(format!("error parsing ttl: {error}")))?;
                settings.ttl = u32::try_from(seconds)
                    .ok()
                    .filter(|ttl| *ttl <= 3600)
                    .ok_or_else(|| {
                        cursor.error(format!("ttl must be in range [0, 3600]: {seconds}"))
                    })?;
            }
            other => return Err(cursor.error(format!("unknown property '{other}'"))),
        }
    }
    Ok(settings)
}

fn one(cursor: &Cursor<'_>, args: Vec<String>, message: &str) -> Result<String, Error> {
    let mut args = args.into_iter();
    match (args.next(), args.next()) {
        (Some(arg), None) => Ok(arg),
        _ => Err(cursor.error(message)),
    }
}

#[cfg(test)]
mod tests;

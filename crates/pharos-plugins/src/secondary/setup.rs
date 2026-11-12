use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::Name;

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), Error> {
    let domains = block
        .keys()
        .iter()
        .map(|key| key.domain.as_str())
        .collect::<Vec<_>>();
    let secondary = super::Secondary::parse(cursor, &domains)?;
    secondary.register_hooks(&mut block.config.lifecycle);
    block.config.secondary = Some(secondary);
    Ok(())
}

pub(super) fn parse(
    cursor: &mut Cursor<'_>,
    domains: &[&str],
) -> Result<(Vec<super::ZoneConfig>, Vec<Name>), Error> {
    let mut zones = Vec::new();
    let mut fallthrough = Vec::new();
    while cursor.next() {
        let args = cursor.remaining_args();
        let origins = origins_from_args_or_server_block(
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            domains,
        );
        let mut from = Vec::new();
        let mut catalog: Option<Vec<Name>> = None;
        let mut has_transfer = false;
        while cursor.next_block() {
            let option = cursor.val().to_owned();
            let args = cursor.remaining_args();
            match option.as_str() {
                "transfer" => {
                    if args.first().map(String::as_str) != Some("from") || args.len() < 2 {
                        return Err(cursor.arg_err());
                    }
                    has_transfer = true;
                    for address in &args[1..] {
                        from.push(normalize_address(address).ok_or_else(|| cursor.arg_err())?);
                    }
                }
                "catalog" => {
                    let names = args
                        .iter()
                        .map(|arg| {
                            let names = origins_from_args_or_server_block(&[arg.as_str()], &[]);
                            names
                                .into_iter()
                                .next()
                                .and_then(|name| name.parse().ok())
                                .ok_or_else(|| cursor.arg_err())
                        })
                        .collect::<Result<Vec<Name>, Error>>()?;
                    match &mut catalog {
                        Some(existing) if existing.is_empty() || names.is_empty() => {
                            existing.clear()
                        }
                        Some(existing) => {
                            for name in names {
                                if !existing.contains(&name) {
                                    existing.push(name);
                                }
                            }
                        }
                        None => catalog = Some(names),
                    }
                }
                "fallthrough" => {
                    fallthrough.clear();
                    let names = if args.is_empty() {
                        vec![".".to_owned()]
                    } else {
                        origins_from_args_or_server_block(
                            &args.iter().map(String::as_str).collect::<Vec<_>>(),
                            &[],
                        )
                    };
                    for name in names {
                        fallthrough.push(name.parse().map_err(|_| cursor.arg_err())?);
                    }
                }
                _ => return Err(cursor.error(format!("unknown property '{option}'"))),
            }
        }
        if !has_transfer {
            return Err(cursor.error("secondary zones require a transfer from property"));
        }
        for origin in origins {
            let apex = origin.parse().map_err(|_| cursor.error("invalid Zone"))?;
            zones.retain(|zone: &super::ZoneConfig| zone.apex != apex);
            zones.push(super::ZoneConfig {
                apex,
                from: from.clone(),
                catalog: catalog.clone(),
            });
        }
    }
    Ok((zones, fallthrough))
}

fn normalize_address(value: &str) -> Option<String> {
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return Some(std::net::SocketAddr::new(ip, 53).to_string());
    }
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        (host, rest.strip_prefix(':')?)
    } else {
        value.rsplit_once(':')?
    };
    host.split('%').next()?.parse::<std::net::IpAddr>().ok()?;
    let port = if port.is_empty() { "53" } else { port };
    Some(if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

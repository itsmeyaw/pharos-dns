use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use std::{path::Path, time::Duration};

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), Error> {
    let domains = block
        .keys()
        .iter()
        .map(|key| key.domain.as_str())
        .collect::<Vec<_>>();
    let auto = parse(cursor, &domains, crate::root_path(&block.config))?;
    #[cfg(feature = "plugin-prometheus")]
    auto.metric_zones().set_static_names(
        domains
            .iter()
            .map(|name| name.parse().map_err(|_| cursor.error("invalid Domain")))
            .collect::<Result<Vec<_>, _>>()?,
    );
    auto.register_hooks(&mut block.config.lifecycle);
    block.config.auto = Some(auto);
    Ok(())
}

fn parse(
    cursor: &mut Cursor<'_>,
    domains: &[&str],
    root: Option<&Path>,
) -> Result<super::Auto, Error> {
    let mut directory = std::path::PathBuf::new();
    let mut regex = regex::Regex::new(r"db\.(.*)").unwrap();
    let mut template = "${1}".to_owned();
    let mut interval = Duration::from_secs(60);
    let mut origins = Vec::new();
    while cursor.next() {
        let args = cursor.remaining_args();
        origins = origins_from_args_or_server_block(
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            domains,
        )
        .into_iter()
        .map(|name| name.parse().map_err(|_| cursor.error("invalid Domain")))
        .collect::<Result<Vec<_>, _>>()?;
        while cursor.next_block() {
            let option = cursor.val().to_owned();
            let args = cursor.remaining_args();
            match option.as_str() {
                "directory" => {
                    if args.len() != 1 && args.len() != 3 {
                        return Err(cursor.arg_err());
                    }
                    directory = crate::resolve_path(args[0].clone().into(), root);
                    match std::fs::metadata(&directory) {
                        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                            return Err(cursor.error(error.to_string()));
                        }
                        Err(_) => pharos_server::logging::log(
                            "WARN",
                            "auto",
                            &format!("Directory does not exist: {}", directory.display()),
                        ),
                        Ok(_) => {}
                    }
                    if args.len() == 3 {
                        if args[1].len() > 10000 {
                            return Err(cursor.error("regexp too large"));
                        }
                        regex = regex::Regex::new(&args[1])
                            .map_err(|error| cursor.error(error.to_string()))?;
                        if regex.captures_len() < 2 {
                            return Err(cursor.error("Need at least one sub expression"));
                        }
                        template = args[2].replace('{', "${");
                    }
                }
                "reload" => {
                    let value = args.first().ok_or_else(|| cursor.arg_err())?;
                    interval =
                        crate::health::parse_duration(value).ok_or_else(|| cursor.arg_err())?;
                    if value.starts_with('-')
                        && crate::health::parse_duration(&value[1..]).is_some_and(|d| !d.is_zero())
                    {
                        return Err(cursor.arg_err());
                    }
                }
                "upstream" => {}
                _ => return Err(cursor.error(format!("unknown property '{option}'"))),
            }
        }
    }
    Ok(super::Auto::new(
        origins, directory, regex, template, interval,
    ))
}

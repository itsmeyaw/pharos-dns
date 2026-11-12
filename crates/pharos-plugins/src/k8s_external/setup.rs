use pharos_corefile::{Cursor, Error, Fallthrough, origins_from_args_or_server_block};

#[derive(Debug)]
pub struct Config {
    pub zones: Vec<String>,
    pub apex: String,
    pub ttl: u32,
    pub headless: bool,
    pub fallthrough: Fallthrough,
}

pub fn parse(cursor: &mut Cursor<'_>, server_domains: &[&str]) -> Result<Config, Error> {
    let mut config = Config {
        zones: Vec::new(),
        apex: "dns".into(),
        ttl: 5,
        headless: false,
        fallthrough: Fallthrough::default(),
    };
    while cursor.next() {
        let args = cursor.remaining_args();
        config.zones = origins_from_args_or_server_block(
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            server_domains,
        );
        while cursor.next_block() {
            let option = cursor.val().to_owned();
            let args = cursor.remaining_args();
            match option.as_str() {
                "ttl" => {
                    let value = args.first().ok_or_else(|| cursor.arg_err())?;
                    let ttl = value.parse::<i32>().map_err(|_| cursor.arg_err())?;
                    if !(0..=3600).contains(&ttl) {
                        return Err(cursor.error("ttl must be in range [0, 3600]"));
                    }
                    config.ttl = ttl as u32;
                }
                "apex" => config.apex = args.first().ok_or_else(|| cursor.arg_err())?.clone(),
                "headless" => config.headless = true,
                "fallthrough" => config
                    .fallthrough
                    .set_domains_from_args(&args.iter().map(String::as_str).collect::<Vec<_>>()),
                _ => return Err(cursor.error(format!("unknown property '{option}'"))),
            }
        }
    }
    Ok(config)
}

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), Error> {
    let domains = block
        .keys()
        .iter()
        .map(|key| key.domain.as_str())
        .collect::<Vec<_>>();
    let config = parse(cursor, &domains)?;
    block.config.k8s_external =
        Some(super::External::new(config).map_err(|error| cursor.error(error.to_string()))?);
    Ok(())
}

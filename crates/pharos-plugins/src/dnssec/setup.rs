use std::path::{Path, PathBuf};

use pharos_corefile::{BlockContext, Cursor, Error};
use pharos_dnssec::keys::KeyPair;
use pharos_proto::Name;

use super::Dnssec;

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<crate::Chain>,
) -> Result<(), Error> {
    cursor.next();
    let args = cursor.remaining_args();
    let server_domains = block
        .keys()
        .iter()
        .map(|key| key.domain.as_str())
        .collect::<Vec<_>>();
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let domains = pharos_corefile::origins_from_args_or_server_block(&args, &server_domains);
    let root: Name = ".".parse().expect("root name");
    let zones: Vec<Name> = domains
        .iter()
        .map(|domain| Name::parse(domain, &root).map_err(|_| cursor.error("invalid dnssec domain")))
        .collect::<Result<_, _>>()?;
    let mut keys = Vec::new();
    let mut capacity = 10_000;
    while cursor.next_block() {
        match cursor.val() {
            "cache_capacity" => {
                let args = cursor.remaining_args();
                capacity = args
                    .first()
                    .ok_or_else(|| cursor.arg_err())?
                    .parse()
                    .map_err(|_| cursor.error("invalid cache capacity"))?;
            }
            "key" => {
                let args = cursor.remaining_args();
                let kind = args.first().ok_or_else(|| cursor.arg_err())?;
                match kind.as_str() {
                    "file" | "aws_secretsmanager" => {
                        if args.len() < 2 {
                            return Err(cursor.arg_err());
                        }
                        for name in &args[1..] {
                            let key = if kind == "file" {
                                let base = name
                                    .strip_suffix(".key")
                                    .or_else(|| name.strip_suffix(".private"))
                                    .unwrap_or(name);
                                let base = crate::resolve_path(
                                    PathBuf::from(base),
                                    crate::root_path(&block.config),
                                );
                                load_file(&base).map_err(|err| cursor.error(err))?
                            } else {
                                #[cfg(feature = "dnssec-aws")]
                                {
                                    super::aws::load(name).map_err(|err| cursor.error(err))?
                                }
                                #[cfg(not(feature = "dnssec-aws"))]
                                {
                                    return Err(cursor.error(
                                        "aws_secretsmanager requires the dnssec-aws feature",
                                    ));
                                }
                            };
                            keys.push(key);
                        }
                    }
                    _ => {}
                }
            }
            _ => return Err(cursor.error("unknown dnssec property")),
        }
    }
    for key in &keys {
        if !zones
            .iter()
            .any(|zone| zone.is_subdomain_of(&key.public.owner))
        {
            return Err(cursor.error("DNSKEY owner cannot sign any configured domain"));
        }
    }
    let public = keys
        .iter()
        .map(|key| {
            let mut data = key.public.flags.to_be_bytes().to_vec();
            data.extend_from_slice(&[key.public.protocol, key.public.algorithm]);
            data.extend_from_slice(&key.public.public_key);
            data
        })
        .collect();
    block.config.dnssec = Some(Dnssec {
        zones,
        keys,
        public,
        capacity,
        cache: Default::default(),
        metrics: Vec::new(),
    });
    Ok(())
}

fn load_file(base: &Path) -> Result<KeyPair, String> {
    let mut public = base.as_os_str().to_os_string();
    public.push(".key");
    let mut private = base.as_os_str().to_os_string();
    private.push(".private");
    KeyPair::from_files(public, private).map_err(|err| err.to_string())
}

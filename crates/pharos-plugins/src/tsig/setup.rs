use pharos_corefile::{BlockContext, Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::{Name, Opcode, TsigAlgorithm, TsigKey, Type};

use super::{Secret, Tsig};

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<crate::Chain>,
) -> Result<(), Error> {
    cursor.next();
    let args = cursor.remaining_args();
    let domains = block
        .keys()
        .iter()
        .map(|key| key.domain.as_str())
        .collect::<Vec<_>>();
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let zones = origins_from_args_or_server_block(&args, &domains)
        .iter()
        .map(|zone| {
            zone.parse::<Name>()
                .map_err(|_| cursor.error("invalid Domain"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut plugin = Tsig {
        zones,
        secrets: Vec::new(),
        types: Vec::new(),
        opcodes: Vec::new(),
        all_types: false,
        all_opcodes: false,
    };
    while cursor.next_block() {
        let property = cursor.val().to_owned();
        let args = cursor.remaining_args();
        match property.as_str() {
            "secret" if args.len() == 2 => add_secret(cursor, &mut plugin, &args[0], &args[1])?,
            "secrets" if args.len() == 1 => {
                let input =
                    std::fs::read_to_string(&args[0]).map_err(|e| cursor.error(e.to_string()))?;
                for (name, secret) in
                    pharos_proto::parse_key_file(&input).map_err(|e| cursor.error(e.to_string()))?
                {
                    add_secret(cursor, &mut plugin, &name, &secret)?;
                }
            }
            "require" if !args.is_empty() => {
                plugin.types.clear();
                if args[0] == "all" {
                    plugin.all_types = true;
                } else if args[0] != "none" {
                    for value in &args {
                        let typ = Type::from_mnemonic(value)
                            .filter(|typ| typ.to_string() == *value)
                            .ok_or_else(|| cursor.error("unknown query type"))?;
                        plugin.types.push(typ);
                    }
                }
            }
            "require_opcode" if !args.is_empty() => {
                plugin.opcodes.clear();
                if args[0] == "all" {
                    plugin.all_opcodes = true;
                } else if args[0] != "none" {
                    for value in &args {
                        let opcode = Opcode::from_mnemonic(value)
                            .filter(|opcode| opcode.to_string() == *value)
                            .ok_or_else(|| cursor.error("unknown opcode"))?;
                        plugin.opcodes.push(opcode);
                    }
                }
            }
            _ => return Err(cursor.error("invalid tsig property")),
        }
    }
    block.config.tsig = Some(plugin);
    Ok(())
}

fn add_secret(
    cursor: &Cursor<'_>,
    plugin: &mut Tsig,
    name: &str,
    secret: &str,
) -> Result<(), Error> {
    let absolute = if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.")
    };
    let name: Name = absolute
        .parse()
        .map_err(|_| cursor.error("invalid key name"))?;
    let name: Name = name.canonical().parse().expect("canonical name");
    if plugin.secrets.iter().any(|existing| existing.name == name) {
        return Err(cursor.error("key redefined"));
    }
    let keys = pharos_proto::decode_secret(secret).ok().map(|secret| {
        [
            TsigAlgorithm::Sha1,
            TsigAlgorithm::Sha224,
            TsigAlgorithm::Sha256,
            TsigAlgorithm::Sha384,
            TsigAlgorithm::Sha512,
        ]
        .map(|algorithm| TsigKey::new(name.clone(), algorithm, &secret))
    });
    plugin.secrets.push(Secret { name, keys });
    Ok(())
}

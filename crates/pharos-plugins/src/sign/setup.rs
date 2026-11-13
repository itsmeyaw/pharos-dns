use std::{path::PathBuf, sync::Arc};

use pharos_corefile::{BlockContext, Cursor, Error, origins_from_args_or_server_block};
use pharos_dnssec::keys::KeyPair;

use super::{Sign, Signer, register_hooks};

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<crate::Chain>,
) -> Result<(), Error> {
    let domains: Vec<_> = block.keys().iter().map(|key| key.domain.as_str()).collect();
    let mut signers = Vec::new();
    while cursor.next() {
        let args = cursor.remaining_args();
        let source = args.first().ok_or_else(|| cursor.arg_err())?;
        if source.contains('\u{fffd}') {
            return Err(cursor.error("invalid Zone file path"));
        }
        let source = crate::resolve_path(PathBuf::from(source), crate::root_path(&block.config));
        let names: Vec<_> = args[1..].iter().map(String::as_str).collect();
        let origins = origins_from_args_or_server_block(&names, &domains);
        let mut directory = PathBuf::from("/var/lib/coredns");
        let mut keys = Vec::new();
        while cursor.next_block() {
            let option = cursor.val().to_owned();
            let args = cursor.remaining_args();
            match option.as_str() {
                "directory" if args.len() == 1 => {
                    directory = crate::resolve_path(
                        PathBuf::from(&args[0]),
                        crate::root_path(&block.config),
                    )
                }
                "directory" => return Err(cursor.arg_err()),
                "key" => {
                    let kind = args.first().ok_or_else(|| cursor.arg_err())?;
                    match kind.as_str() {
                        "file" => {
                            if args.len() < 2 {
                                return Err(cursor.arg_err());
                            }
                            for name in &args[1..] {
                                let base = name
                                    .strip_suffix(".key")
                                    .or_else(|| name.strip_suffix(".private"))
                                    .unwrap_or(name);
                                let base = crate::resolve_path(
                                    PathBuf::from(base),
                                    crate::root_path(&block.config),
                                );
                                let mut public = base.as_os_str().to_os_string();
                                public.push(".key");
                                let mut private = base.as_os_str().to_os_string();
                                private.push(".private");
                                let key = KeyPair::from_files(public, private)
                                    .map_err(|err| cursor.error(err.to_string()))?;
                                if key.public.flags & 257 != 257 {
                                    return Err(cursor.error("DNSKEY is not a KSK"));
                                }
                                keys.push(key);
                            }
                        }
                        "directory" => return Err(cursor.error("key directory is not implemented")),
                        _ => {}
                    }
                }
                _ => return Err(cursor.error("unknown sign property")),
            }
        }
        let keys = Arc::new(keys);
        // CoreDNS shares key records across origins and leaves their owner set to the last origin.
        let key_owner = origins
            .last()
            .map(|origin| origin.parse().map_err(|_| cursor.error("invalid Zone")))
            .transpose()?;
        for origin in origins {
            let mut jitter = [0_u8; 8];
            getrandom::getrandom(&mut jitter).map_err(|error| cursor.error(error.to_string()))?;
            signers.push(Signer {
                apex: origin.parse().map_err(|_| cursor.error("invalid Zone"))?,
                key_owner: key_owner
                    .clone()
                    .ok_or_else(|| cursor.error("missing Zone"))?,
                source: source.clone(),
                directory: directory.clone(),
                keys: Arc::clone(&keys),
                inception_jitter: u32::from_ne_bytes(jitter[..4].try_into().unwrap()) % (18 * 3600),
                expiration_jitter: u32::from_ne_bytes(jitter[4..].try_into().unwrap())
                    % (5 * 86400),
            });
        }
    }
    register_hooks(&mut block.config.lifecycle, signers);
    block.config.sign = Some(Sign);
    Ok(())
}

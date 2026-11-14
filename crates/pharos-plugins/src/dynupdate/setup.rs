use pharos_corefile::{Cursor, Error, normalize_domain};
use pharos_proto::{Name, Type};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub(super) struct Permission {
    key: Name,
    owner: Option<Name>,
    types: Vec<Type>,
    all_types: bool,
}

#[derive(Debug)]
pub(super) struct Config {
    pub(super) origin: Name,
    pub(super) seed: PathBuf,
    pub(super) database: Option<PathBuf>,
    pub(super) permissions: Vec<Permission>,
    pub(super) max_records: usize,
    pub(super) max_bytes: usize,
    pub(super) max_update_records: usize,
}

impl Config {
    pub(super) fn configured_key(&self, key: &Name) -> bool {
        self.permissions.iter().any(|rule| &rule.key == key)
    }

    // RFC 3007 §3.1: Match update permissions by principal, owner name, and RR type.
    pub(super) fn allows(&self, key: &Name, owner: &Name, kind: Type) -> bool {
        self.permissions.iter().any(|rule| {
            &rule.key == key
                && rule.owner.as_ref().is_none_or(|name| name == owner)
                && (rule.all_types || rule.types.contains(&kind))
        })
    }
}

// RFC 3007 §3.1.1: Dynamic UPDATE must not create, modify, or delete NXT records.
pub(super) fn unsupported(kind: Type) -> bool {
    matches!(
        kind,
        Type::SIG
            | Type::KEY
            | Type::NXT
            | Type::DS
            | Type::RRSIG
            | Type::NSEC
            | Type::DNSKEY
            | Type::NSEC3
            | Type::NSEC3PARAM
            | Type::TALINK
            | Type::CDS
            | Type::CDNSKEY
            | Type::ZONEMD
            | Type::TA
            | Type::DLV
    )
}

// miekg/dns v1.1.73 ztypes.go:11-92: only types with RR constructors are accepted.
pub(super) fn known(kind: Type) -> bool {
    matches!(
        kind,
        Type::A
            | Type::AAAA
            | Type::AFSDB
            | Type::AMTRELAY
            | Type::ANY
            | Type::APL
            | Type::AVC
            | Type::CAA
            | Type::CDNSKEY
            | Type::CDS
            | Type::CERT
            | Type::CNAME
            | Type::CSYNC
            | Type::DHCID
            | Type::DLV
            | Type::DNAME
            | Type::DNSKEY
            | Type::DS
            | Type::EID
            | Type::EUI48
            | Type::EUI64
            | Type::GID
            | Type::GPOS
            | Type::HINFO
            | Type::HIP
            | Type::HTTPS
            | Type::IPSECKEY
            | Type::ISDN
            | Type::KEY
            | Type::KX
            | Type::L32
            | Type::L64
            | Type::LOC
            | Type::LP
            | Type::MB
            | Type::MD
            | Type::MF
            | Type::MG
            | Type::MINFO
            | Type::MR
            | Type::MX
            | Type::NAPTR
            | Type::NID
            | Type::NIMLOC
            | Type::NINFO
            | Type::NS
            | Type::NSAP_PTR
            | Type::NSEC
            | Type::NSEC3
            | Type::NSEC3PARAM
            | Type::NULL
            | Type::NXNAME
            | Type::NXT
            | Type::OPENPGPKEY
            | Type::OPT
            | Type::PTR
            | Type::PX
            | Type::RESINFO
            | Type::RKEY
            | Type::RP
            | Type::RRSIG
            | Type::RT
            | Type::SIG
            | Type::SMIMEA
            | Type::SOA
            | Type::SPF
            | Type::SRV
            | Type::SSHFP
            | Type::SVCB
            | Type::TA
            | Type::TALINK
            | Type::TKEY
            | Type::TLSA
            | Type::TSIG
            | Type::TXT
            | Type::UID
            | Type::UINFO
            | Type::URI
            | Type::X25
            | Type::ZONEMD
    )
}

// CoreDNS plugin/normalize.go:65: allow names may omit the trailing dot.
fn fully_qualified(value: &str) -> String {
    if value.ends_with('.') {
        value.to_owned()
    } else {
        format!("{value}.")
    }
}

fn policy_type(raw: &str) -> Option<Type> {
    let kind = Type::from_mnemonic(raw).or_else(|| {
        raw.to_ascii_uppercase()
            .strip_prefix("TYPE")?
            .parse::<u16>()
            .ok()
            .map(Type)
    })?;
    if !known(kind)
        || kind == Type::NONE
        || unsupported(kind)
        || matches!(
            kind,
            Type::AXFR
                | Type::IXFR
                | Type::MAILA
                | Type::MAILB
                | Type::OPT
                | Type::TKEY
                | Type::TSIG
        )
        || kind.to_string().starts_with("TYPE")
        || kind == Type::RESERVED
    {
        return None;
    }
    Some(kind)
}

pub(super) fn parse(
    cursor: &mut Cursor<'_>,
    server_domains: &[&str],
    root: Option<&Path>,
) -> Result<Config, Error> {
    if !cursor.next() {
        return Err(cursor.arg_err());
    }
    let args = cursor.remaining_args();
    if args.len() > 1 {
        return Err(cursor.arg_err());
    }
    let names = if let Some(origin) = args.first() {
        normalize_domain(origin)
    } else {
        let mut names = server_domains
            .iter()
            .flat_map(|name| normalize_domain(name))
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        names
    };
    if names.len() != 1 {
        return Err(cursor.error("exactly one Zone is required"));
    }
    let origin: Name = names[0].parse().map_err(|_| cursor.error("invalid Zone"))?;
    let mut seed = None;
    let mut database = None;
    let mut permissions = Vec::new();
    let mut max_records = 10000;
    let mut max_bytes = 8 << 20;
    let mut max_update_records = 1024;
    let mut seen = HashSet::new();
    while cursor.next_block() {
        let option = cursor.val().to_owned();
        let args = cursor.remaining_args();
        if option != "allow" && !seen.insert(option.clone()) {
            return Err(cursor.error("duplicate option"));
        }
        match option.as_str() {
            "file" | "database" => {
                if args.len() != 1 || option == "database" && args[0].is_empty() {
                    return Err(cursor.arg_err());
                }
                let path = crate::resolve_path(args[0].as_str().into(), root);
                if option == "file" {
                    seed = Some(path);
                } else {
                    database = Some(path);
                }
            }
            "max_records" | "max_bytes" | "max_update_records" => {
                if args.len() != 1 {
                    return Err(cursor.arg_err());
                }
                let value = args[0]
                    .parse::<isize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| cursor.arg_err())? as usize;
                match option.as_str() {
                    "max_records" => max_records = value,
                    "max_bytes" => max_bytes = value,
                    _ => max_update_records = value,
                }
            }
            "allow" => {
                if args.len() < 3 || args[0].is_empty() || matches!(args[0].as_str(), "*" | "@") {
                    return Err(cursor.arg_err());
                }
                let key: Name = fully_qualified(&args[0])
                    .parse()
                    .map_err(|_| cursor.arg_err())?;
                let owner = match args[1].as_str() {
                    "*" => None,
                    "@" => Some(origin.clone()),
                    value => Some(
                        fully_qualified(value)
                            .parse::<Name>()
                            .map_err(|_| cursor.arg_err())?,
                    ),
                };
                if owner
                    .as_ref()
                    .is_some_and(|name| !name.is_subdomain_of(&origin))
                {
                    return Err(cursor.arg_err());
                }
                let all_types = args[2] == "*";
                if all_types && args.len() != 3 {
                    return Err(cursor.arg_err());
                }
                let types = if all_types {
                    Vec::new()
                } else {
                    args[2..]
                        .iter()
                        .map(|value| policy_type(value).ok_or_else(|| cursor.arg_err()))
                        .collect::<Result<Vec<_>, _>>()?
                };
                permissions.push(Permission {
                    key,
                    owner,
                    types,
                    all_types,
                });
            }
            _ => return Err(cursor.arg_err()),
        }
    }
    // RFC 3007 §3: Deny updates unless the administrator configures permissions.
    if permissions.is_empty() {
        return Err(cursor.error("at least one allow rule is required"));
    }
    Ok(Config {
        origin,
        seed: seed.ok_or_else(|| cursor.error("file is required"))?,
        database,
        permissions,
        max_records,
        max_bytes,
        max_update_records,
    })
}

#[cfg(feature = "plugin-dynupdate")]
pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), Error> {
    let domains = block
        .keys()
        .iter()
        .map(|key| key.domain.as_str())
        .collect::<Vec<_>>();
    let config = parse(cursor, &domains, crate::root_path(&block.config))?;
    let zone = super::store::validate(&config).map_err(|error| cursor.error(error.to_string()))?;
    let dynamic = super::DynUpdate::new(config, zone);
    #[cfg(feature = "plugin-transfer")]
    dynamic.register_hooks(&mut block.config.lifecycle);
    block.config.dynupdate = Some(dynamic);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse;
    use pharos_corefile::{Cursor, lex};
    use pharos_proto::{Name, Type};

    fn config(text: &str, domains: &[&str]) -> Result<super::Config, pharos_corefile::Error> {
        let tokens = lex("Corefile", text);
        parse(&mut Cursor::new("Corefile", &tokens), domains, None)
    }

    #[test]
    fn parses_coredns_permissions_and_limits() {
        let parsed = config("dynupdate {\nfile seed.zone\ndatabase updates.db\nallow key.example.org. * A TXT\nallow key.example.org. @ ANY\nmax_records 50\nmax_bytes 6000\nmax_update_records 10\n}", &["example.org"]).unwrap();
        let key: Name = "key.example.org.".parse().unwrap();
        let owner: Name = "host.example.org.".parse().unwrap();
        assert!(parsed.allows(&key, &owner, Type::TXT));
        assert!(!parsed.allows(&key, &owner, Type::AAAA));
        assert!(parsed.allows(&key, &parsed.origin, Type::ANY));
        assert_eq!(parsed.seed, std::path::Path::new("seed.zone"));
        assert_eq!(
            parsed.database.as_deref(),
            Some(std::path::Path::new("updates.db"))
        );
        assert_eq!(
            (
                parsed.max_records,
                parsed.max_bytes,
                parsed.max_update_records
            ),
            (50, 6000, 10)
        );
    }

    #[test]
    fn accepts_relative_allow_names_like_coredns() {
        let parsed = config(
            "dynupdate {\nfile seed.zone\nallow key.example.org host.example.org A\n}",
            &["example.org"],
        )
        .unwrap();
        let key: Name = "key.example.org.".parse().unwrap();
        let owner: Name = "host.example.org.".parse().unwrap();
        assert!(parsed.allows(&key, &owner, Type::A));
    }

    #[test]
    fn rejects_coredns_unsafe_setup_cases() {
        for body in [
            "allow key.example.org. * A",
            "file seed.zone",
            "file seed.zone\nallow key.example.org. * TYPE65280",
            "file seed.zone\nallow key.example.org. * ATMA",
            "file seed.zone\nallow key.example.org. * UNSPEC",
            "file seed.zone\nallow key.example.org. * * TXT",
            "file seed.zone\nallow * * TXT",
            "file seed.zone\nallow key.example.org. outside.test. TXT",
            "file seed.zone\nallow key.example.org. * A\nmax_records 0",
            "file seed.zone\nallow key.example.org. * A\nfile seed2.zone",
        ] {
            assert!(
                config(&format!("dynupdate {{\n{body}\n}}"), &["example.org"]).is_err(),
                "{body}"
            );
        }
        assert!(
            config(
                "dynupdate {\nfile seed.zone\nallow key.example.org. * A\n}",
                &["example.org", "other.example"]
            )
            .is_err()
        );
        assert!(config("dynupdate example.org. {\nfile seed.zone\nallow key.example.org. host.example.org. ANY\n}", &["example.org", "other.example"]).is_ok());
    }

    #[test]
    fn coredns_invalid_limit_and_duplicate_options() {
        for property in ["max_records", "max_bytes", "max_update_records"] {
            for value in ["0", "-1", "invalid", "999999999999999999999999", "1 2", ""] {
                let text = format!(
                    "dynupdate example.org. {{\nfile seed\nallow key.example.org. * A\n{property} {value}\n}}"
                );
                assert!(
                    config(&text, &["example.org"]).is_err(),
                    "{property} {value}"
                );
            }
            let text = format!(
                "dynupdate example.org. {{\nfile seed\nallow key.example.org. * A\n{property} 1\n{property} 2\n}}"
            );
            assert!(config(&text, &["example.org"]).is_err());
        }
    }
}

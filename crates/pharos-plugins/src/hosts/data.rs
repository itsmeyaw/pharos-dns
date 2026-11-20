use std::{
    collections::HashMap,
    io::{BufReader, Read},
    net::IpAddr,
};

use pharos_proto::Name;

#[derive(Debug, Default)]
pub(super) struct Map {
    pub(super) v4: HashMap<Vec<u8>, Vec<IpAddr>>,
    pub(super) v6: HashMap<Vec<u8>, Vec<IpAddr>>,
    pub(super) reverse: HashMap<IpAddr, Vec<Name>>,
}

impl Map {
    pub(super) fn len(&self) -> usize {
        self.v4
            .values()
            .chain(self.v6.values())
            .map(Vec::len)
            .sum::<usize>()
            + self.reverse.values().map(Vec::len).sum::<usize>()
    }
    pub(super) fn parse(
        input: impl Read,
        domains: &[Name],
        auto_reverse: bool,
        source: &str,
    ) -> Self {
        const INVALID_NAME_LOG_LIMIT: usize = 10;
        let mut map = Self::default();
        let mut field = Vec::new();
        let mut oversized = false;
        let mut index = 0;
        let mut line = 1;
        let mut comment = false;
        let mut address = None;
        let mut invalid_names = 0;
        for result in BufReader::new(input)
            .bytes()
            .chain(std::iter::once(Ok(b'\n')))
        {
            let byte = match result {
                Ok(byte) => byte,
                Err(error) => {
                    pharos_server::logging::log(
                        "ERROR",
                        "hosts",
                        &format!("Failed to parse {source}: {error}"),
                    );
                    break;
                }
            };
            if !comment && byte == b'#' {
                comment = true;
            }
            if matches!(byte, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') || comment {
                if !field.is_empty() || oversized {
                    index += 1;
                    if oversized {
                        pharos_server::logging::log(
                            "ERROR",
                            "hosts",
                            &format!(
                                "{source}, line {line}: {} longer than 1024 bytes, dropping {}",
                                if index == 1 { "address" } else { "name" },
                                if index == 1 { "the line" } else { "the name" }
                            ),
                        );
                    } else if index == 1 {
                        // RFC 4291 §2.2: IPv6 uses conventional textual address forms.
                        address = std::str::from_utf8(&field)
                            .ok()
                            .and_then(|s| s.split('%').next())
                            .and_then(|s| s.parse::<IpAddr>().ok())
                            .map(|ip| match ip {
                                IpAddr::V6(ip) => {
                                    ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4)
                                }
                                ip => ip,
                            });
                    } else if let Some(ip) = address {
                        // RFC 4343 §2.1: Report host names whose ASCII presentation is invalid.
                        if let Err(reason) = map.add(&field, ip, domains, auto_reverse) {
                            if invalid_names < INVALID_NAME_LOG_LIMIT {
                                let skipped = String::from_utf8_lossy(&field);
                                pharos_server::logging::log(
                                    "ERROR",
                                    "hosts",
                                    &format!(
                                        "{source}, line {line}: {reason}, skipping name {skipped:?}"
                                    ),
                                );
                            }
                            invalid_names += 1;
                        }
                    }
                    field.clear();
                    oversized = false;
                }
                if byte == b'\n' {
                    index = 0;
                    address = None;
                    comment = false;
                    line += 1;
                }
            } else if !oversized {
                if field.len() == 1024 {
                    field.clear();
                    oversized = true;
                } else {
                    field.push(byte);
                }
            }
        }
        if invalid_names > INVALID_NAME_LOG_LIMIT {
            pharos_server::logging::log(
                "ERROR",
                "hosts",
                &format!(
                    "{source}: skipped {invalid_names} invalid names; suppressed {} further entries",
                    invalid_names - INVALID_NAME_LOG_LIMIT
                ),
            );
        }
        map
    }

    fn add(
        &mut self,
        field: &[u8],
        ip: IpAddr,
        domains: &[Name],
        auto_reverse: bool,
    ) -> Result<(), &'static str> {
        let text = std::str::from_utf8(field).map_err(|_| "invalid UTF-8 host name")?;
        // RFC 4343 §3: DNS name lookup compares ASCII letters case-insensitively.
        let text = text.to_ascii_lowercase();
        let text = if text.ends_with('.') {
            text
        } else {
            format!("{text}.")
        };
        // RFC 4343 §2.1: DNS presentation requires escapes for non-ASCII label octets.
        let name = text
            .parse::<Name>()
            .map_err(|_| "invalid DNS presentation name")?;
        // RFC 1034 §3.1: a subdomain is contained within its parent domain.
        if !domains.iter().any(|domain| name.is_subdomain_of(domain)) {
            return Ok(());
        }
        let wildcard = text.starts_with("*.");
        let key = name.as_wire().to_ascii_lowercase();
        match ip {
            IpAddr::V4(_) => self.v4.entry(key).or_default().push(ip),
            IpAddr::V6(_) => self.v6.entry(key).or_default().push(ip),
        }
        if auto_reverse && !wildcard {
            self.reverse.entry(ip).or_default().push(name);
        }
        Ok(())
    }

    pub(super) fn lookup_key(&self, key: &[u8], v4: bool) -> &[IpAddr] {
        let map = if v4 { &self.v4 } else { &self.v6 };
        if let Some(ips) = map.get(key) {
            return ips;
        }
        let Some(&len) = key.first() else { return &[] };
        if len == 0 {
            return &[];
        }
        let mut wildcard = [0u8; 255];
        let suffix = &key[1 + usize::from(len)..];
        // RFC 4592 §2.1.1: an asterisk label has wire encoding 0x01 0x2a.
        wildcard[0] = 1;
        wildcard[1] = b'*';
        wildcard[2..2 + suffix.len()].copy_from_slice(suffix);
        map.get(&wildcard[..2 + suffix.len()])
            .map_or(&[], Vec::as_slice)
    }

    #[cfg(test)]
    fn lookup(&self, text: &str, v4: bool) -> &[IpAddr] {
        let name: Name = text.parse().unwrap();
        self.lookup_key(&name.as_wire().to_ascii_lowercase(), v4)
    }
}

#[cfg(test)]
mod tests;

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
        let mut map = Self::default();
        let mut field = Vec::new();
        let mut oversized = false;
        let mut index = 0;
        let mut line = 1;
        let mut comment = false;
        let mut address = None;
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
                        map.add(&field, ip, domains, auto_reverse);
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
        map
    }

    fn add(&mut self, field: &[u8], ip: IpAddr, domains: &[Name], auto_reverse: bool) {
        let Ok(text) = std::str::from_utf8(field) else {
            return;
        };
        let text = text.to_ascii_lowercase();
        let text = if text.ends_with('.') {
            text
        } else {
            format!("{text}.")
        };
        let Ok(name) = text.parse::<Name>() else {
            return;
        };
        if !domains.iter().any(|domain| name.is_subdomain_of(domain)) {
            return;
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
mod tests {
    use super::*;

    #[test]
    fn parses_scoped_addresses_aliases_and_wildcards() {
        let map = Map::parse(
            &b"127.0.0.2 Odin odinalias # comment\n127.0.0.3 odin\n::2 odin\nfe80::1%lo0 localhost\n127.1.1.2 *.example.org\ninvalid invalid\n"[..],
            &[".".parse().unwrap()], true, "Inline hosts entries");
        assert_eq!(
            map.lookup("odin.", true),
            [
                "127.0.0.2".parse::<IpAddr>().unwrap(),
                "127.0.0.3".parse().unwrap()
            ]
        );
        assert_eq!(
            map.lookup("ODIN.", false),
            ["::2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            map.lookup("localhost.", false),
            ["fe80::1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            map.lookup("a.example.org.", true),
            ["127.1.1.2".parse::<IpAddr>().unwrap()]
        );
        assert!(map.lookup("a.b.example.org.", true).is_empty());
        assert_eq!(
            map.reverse
                .get(&"127.0.0.2".parse::<IpAddr>().unwrap())
                .unwrap()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["odin.", "odinalias."]
        );
        assert!(
            !map.reverse
                .contains_key(&"127.1.1.2".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn long_fields_do_not_discard_following_names_or_lines() {
        let input = format!(
            "127.0.0.1 {} one.example.org\n127.0.0.2 two.example.org\n",
            "x".repeat(70_000)
        );
        let map = Map::parse(
            input.as_bytes(),
            &["example.org.".parse().unwrap()],
            false,
            "Inline hosts entries",
        );
        assert_eq!(
            map.lookup("one.example.org.", true),
            ["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            map.lookup("two.example.org.", true),
            ["127.0.0.2".parse::<IpAddr>().unwrap()]
        );
        assert!(map.reverse.is_empty());
    }

    #[test]
    fn vertical_tab_and_form_feed_separate_fields() {
        let map = Map::parse(
            &b"127.0.0.1\x0bfoo\x0cbar\n"[..],
            &[".".parse().unwrap()],
            true,
            "Inline hosts entries",
        );
        assert_eq!(
            map.lookup("foo.", true),
            ["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            map.lookup("bar.", true),
            ["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn exact_and_wildcard_lookup_is_separate_per_family() {
        let input = &b"192.0.2.1 *.example.org\n192.0.2.2 x.example.org\n2001:db8::1 *.example.org\n192.0.2.3 *.deep.example.org\n"[..];
        let map = Map::parse(input, &["example.org.".parse().unwrap()], true, "test");
        assert_eq!(
            map.lookup("x.example.org.", true),
            ["192.0.2.2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            map.lookup("x.example.org.", false),
            ["2001:db8::1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            map.lookup("y.example.org.", true),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            map.lookup("y.deep.example.org.", true),
            ["192.0.2.3".parse::<IpAddr>().unwrap()]
        );
        assert!(map.lookup("deep.example.org.", false).len() == 1);
        assert!(map.lookup("a.b.deep.example.org.", true).is_empty());
    }

    #[test]
    fn oversized_address_discards_only_its_line() {
        let input = format!(
            "{} ignored.example.org\n192.0.2.1 valid.example.org\n",
            "1".repeat(1025)
        );
        let map = Map::parse(input.as_bytes(), &[".".parse().unwrap()], true, "test");
        assert!(map.lookup("ignored.example.org.", true).is_empty());
        assert_eq!(
            map.lookup("valid.example.org.", true),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
    }
}

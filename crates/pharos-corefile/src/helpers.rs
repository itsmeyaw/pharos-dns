use crate::normalize_key;

/// Normalize a Corefile host into zero or more fully qualified Domains.
pub fn normalize_domain(host: &str) -> Vec<String> {
    // shortcut: Domains are normalized strings until pharos-proto Name is available.
    normalize_key(host)
        .unwrap_or_default()
        .into_iter()
        .map(|key| key.domain)
        .collect()
}

/// Use explicit arguments, or copy and normalize the Server Block Domains.
pub fn origins_from_args_or_server_block(args: &[&str], server_block: &[&str]) -> Vec<String> {
    if args.is_empty() {
        server_block
            .iter()
            .map(|host| {
                normalize_domain(host)
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| (*host).to_owned())
            })
            .collect()
    } else {
        args.iter()
            .flat_map(|host| normalize_domain(host))
            .collect()
    }
}

/// Domains for which a Plugin permits Fallthrough.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Fallthrough {
    pub domains: Vec<String>,
}

impl Fallthrough {
    /// Set matching Domains; no arguments means the root Domain.
    pub fn set_domains_from_args(&mut self, domains: &[&str]) {
        self.domains = if domains.is_empty() {
            vec![".".into()]
        } else {
            domains
                .iter()
                .flat_map(|domain| normalize_domain(domain))
                .collect()
        };
    }

    /// Whether a name is in any configured Domain.
    pub fn through(&self, name: &str) -> bool {
        self.domains.iter().any(|domain| {
            if domain == "." {
                return true;
            }
            let Some(prefix) = name.len().checked_sub(domain.len()) else {
                return false;
            };
            if !name.is_char_boundary(prefix) || !name[prefix..].eq_ignore_ascii_case(domain) {
                return false;
            }
            if prefix == 0 {
                return true;
            }
            let bytes = name.as_bytes();
            if bytes[prefix - 1] != b'.' {
                return false;
            }
            let escapes = bytes[..prefix - 1]
                .iter()
                .rev()
                .take_while(|&&byte| byte == b'\\')
                .count();
            escapes % 2 == 0
        })
    }
}

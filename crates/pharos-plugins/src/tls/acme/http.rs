//! The HTTPS client an ACME client needs: GET, HEAD and POST over one connection per request.

use std::str::FromStr;

/// An `http` or `https` URL with a host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Url {
    pub https: bool,
    /// The host without brackets.
    pub host: String,
    pub port: u16,
    /// The path and query, always starting with `/`.
    pub target: String,
}

impl FromStr for Url {
    type Err = ();

    // RFC 3986 §3: scheme "://" authority path-abempty ["?" query]; fragments and userinfo are not used by ACME.
    fn from_str(value: &str) -> Result<Self, ()> {
        let (https, rest) = if let Some(rest) = value.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = value.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(());
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, target) = rest.split_at(end);
        if authority.is_empty() || authority.contains('@') || target.contains('#') {
            return Err(());
        }
        let default = if https { 443 } else { 80 };
        let (host, port) = match authority.strip_prefix('[') {
            Some(bracketed) => {
                let (host, tail) = bracketed.split_once(']').ok_or(())?;
                let port = match tail.strip_prefix(':') {
                    Some(port) => port.parse().map_err(|_| ())?,
                    None if tail.is_empty() => default,
                    None => return Err(()),
                };
                (host, port)
            }
            None => match authority.split_once(':') {
                Some((host, port)) => (host, port.parse().map_err(|_| ())?),
                None => (authority, default),
            },
        };
        if host.is_empty() || port == 0 {
            return Err(());
        }
        let target = if target.starts_with('/') {
            target.to_owned()
        } else {
            format!("/{target}")
        };
        Ok(Self {
            https,
            host: host.to_owned(),
            port,
            target,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Url;

    #[test]
    fn parses_scheme_host_port_and_target() {
        let url: Url = "https://ca.example/directory".parse().unwrap();
        assert_eq!(
            url,
            Url {
                https: true,
                host: "ca.example".into(),
                port: 443,
                target: "/directory".into()
            }
        );
        let url: Url = "http://[::1]:14000/dir?x=1".parse().unwrap();
        assert_eq!(
            (url.https, url.host.as_str(), url.port),
            (false, "::1", 14000)
        );
        assert_eq!(url.target, "/dir?x=1");
        assert_eq!("https://ca.example".parse::<Url>().unwrap().target, "/");
    }

    #[test]
    fn rejects_other_schemes_and_malformed_authorities() {
        for url in [
            "ftp://ca.example",
            "https://",
            "https:///x",
            "https://u@ca.example",
            "https://ca.example:0",
            "https://ca.example:x",
            "https://[::1",
            "ca.example",
        ] {
            assert!(url.parse::<Url>().is_err(), "{url}");
        }
    }
}

use std::num::IntErrorKind;

use pharos_corefile::{BlockContext, Cursor, Error};

use super::{Config, Dnstap, Endpoint, Role, TlsFiles};

pub(super) const DEFAULT_VERSION: &str = concat!("Pharos-", env!("CARGO_PKG_VERSION"));

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<crate::Chain>,
) -> Result<(), Error> {
    let dnstap = Dnstap::new(parse(cursor)?);
    dnstap.register_hooks(&mut block.config.lifecycle);
    block.config.dnstap = Some(dnstap);
    Ok(())
}

// CoreDNS v1.15.0 plugin/dnstap/setup.go maxMultipleTcpWriteBuf and maxMultipleQueue.
const MAX_WRITE_BUFFER: u32 = 1024;
const MAX_QUEUE: u32 = 4096;

// CoreDNS v1.15.0 plugin/dnstap/setup.go parseConfig: one Config per `dnstap` Directive in the Server Block.
pub(super) fn parse(cursor: &mut Cursor<'_>) -> Result<Vec<Config>, Error> {
    let mut configs = Vec::new();
    while cursor.next() {
        let mut args = cursor.remaining_args();
        if args.is_empty() {
            return Err(cursor.arg_err());
        }
        // CoreDNS v1.15.0 plugin/dnstap/setup.go parseConfig: `listen` makes the endpoint an incoming sink listener.
        let role = if args[0] == "listen" {
            if args.len() < 2 {
                return Err(cursor.error("dnstap listen requires an endpoint argument"));
            }
            args.remove(0);
            Role::Listen
        } else {
            Role::Dial
        };
        let write_buffer = match args.get(2) {
            Some(text) => bounded(
                cursor,
                "MultipleTcpWriteBuf",
                text,
                MAX_WRITE_BUFFER,
                "(MiB units)",
            )?,
            None => 1,
        };
        let queue = match args.get(3) {
            Some(text) => bounded(cursor, "MultipleQueue", text, MAX_QUEUE, "(x10k messages)")?,
            None => 1,
        };
        let mut config = Config {
            role,
            endpoint: endpoint(cursor, &args[0])?,
            full: args.get(1).is_some_and(|arg| arg == "full"),
            write_buffer,
            queue,
            identity: nix::unistd::gethostname()
                .map(|name| name.into_encoded_bytes())
                .unwrap_or_default(),
            version: DEFAULT_VERSION.as_bytes().to_vec(),
            extra: String::new(),
            skip_verify: false,
            tls: None,
        };
        while cursor.next_block() {
            match cursor.val() {
                "skipverify" => config.skip_verify = true,
                "tls" => {
                    if role != Role::Listen {
                        return Err(cursor.error("tls directive only valid for listeners"));
                    }
                    let mut files = cursor.remaining_args().into_iter();
                    let (Some(cert), Some(key)) = (files.next(), files.next()) else {
                        return Err(cursor.error("tls requires cert and key file paths"));
                    };
                    config.tls = Some(TlsFiles {
                        cert,
                        key,
                        ca: files.next(),
                    });
                }
                "identity" => config.identity = one_arg(cursor)?.into_bytes(),
                "version" => config.version = one_arg(cursor)?.into_bytes(),
                "extra" => config.extra = one_arg(cursor)?,
                other => return Err(cursor.error(format!("unknown property '{other}'"))),
            }
        }
        configs.push(config);
    }
    Ok(configs)
}

fn one_arg(cursor: &mut Cursor<'_>) -> Result<String, Error> {
    if cursor.next_arg() {
        Ok(cursor.val().to_owned())
    } else {
        Err(cursor.arg_err())
    }
}

// CoreDNS v1.15.0 plugin/dnstap/setup.go parseConfig: `strconv.Atoi` then a 1..=max check.
fn bounded(
    cursor: &Cursor<'_>,
    name: &str,
    text: &str,
    max: u32,
    unit: &str,
) -> Result<u32, Error> {
    let value = text.parse::<i64>().map_err(|error| {
        let reason = match error.kind() {
            IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => "value out of range",
            _ => "invalid syntax",
        };
        cursor.error(format!(
            "dnstap: invalid {name} {text:?}: strconv.Atoi: parsing {text:?}: {reason}"
        ))
    })?;
    u32::try_from(value)
        .ok()
        .filter(|value| (1..=max).contains(value))
        .ok_or_else(|| {
            cursor.error(format!(
                "dnstap: {name} must be between 1 and {max} {unit}: {value}"
            ))
        })
}

// CoreDNS v1.15.0 plugin/dnstap/setup.go parseConfig: `tls://` and `tcp://` use the URL host, anything else is a Unix path with `unix://` trimmed.
fn endpoint(cursor: &Cursor<'_>, text: &str) -> Result<Endpoint, Error> {
    if let Some(rest) = text.strip_prefix("tls://") {
        Ok(Endpoint::Tls(url_host(cursor, rest)?))
    } else if let Some(rest) = text.strip_prefix("tcp://") {
        Ok(Endpoint::Tcp(url_host(cursor, rest)?))
    } else {
        Ok(Endpoint::Unix(
            text.strip_prefix("unix://").unwrap_or(text).to_owned(),
        ))
    }
}

// Go net/url Parse then `.Host`: the authority without userinfo; a malformed host is an argument error.
// shortcut: checks control bytes, spaces, brackets and the port only, not percent-escapes; tighten if a Corefile needs it.
fn url_host(cursor: &Cursor<'_>, rest: &str) -> Result<String, Error> {
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let port = if let Some(open) = host.strip_prefix('[') {
        open.split_once(']')
            .map(|(_, port)| port)
            .ok_or_else(|| cursor.arg_err())?
    } else {
        host.rfind(':').map_or("", |colon| &host[colon..])
    };
    let valid_port = port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()));
    if !valid_port
        || rest
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(cursor.arg_err());
    }
    Ok(host.to_owned())
}

#[cfg(test)]
mod tests;

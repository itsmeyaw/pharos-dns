use std::{path::Path, sync::Arc};

use pharos_corefile::{
    BlockContext, Cursor, Error, Fallthrough, origins_from_args_or_server_block,
};
use pharos_proto::Name;
use pharos_server::{
    grpc,
    tls::{ClientConfig, ClientOptions, client_config},
};

use super::{
    Config, Credentials, DEFAULT_ENDPOINT, DEFAULT_MAX_LEASE_TTL, DEFAULT_MIN_LEASE_TTL,
    DEFAULT_PATH, Endpoint, Etcd, ttl::parse_ttl,
};

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<crate::Chain>,
) -> Result<(), Error> {
    let domains = block
        .keys()
        .iter()
        .map(|key| key.domain.as_str())
        .collect::<Vec<_>>();
    // CoreDNS v1.15.0 plugin/etcd/setup.go etcdParse: relative `tls` paths join `root`.
    let config = parse(cursor, crate::root_path(&block.config), &domains)?;
    block.config.etcd = Some(Etcd::new(config));
    Ok(())
}

fn parse_domains(cursor: &Cursor<'_>, names: &[String]) -> Result<Vec<Name>, Error> {
    names
        .iter()
        .map(|name| {
            name.parse()
                .map_err(|_| cursor.error(format!("invalid Domain {name}")))
        })
        .collect()
}

fn strs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

// CoreDNS v1.15.0 plugin/etcd/setup.go etcdParse.
pub(super) fn parse(
    cursor: &mut Cursor<'_>,
    root: Option<&Path>,
    server_domains: &[&str],
) -> Result<Config, Error> {
    cursor.next();
    let args = cursor.remaining_args();
    let zones = origins_from_args_or_server_block(&strs(&args), server_domains);
    let mut fallthrough = Fallthrough::default();
    let mut path_prefix = DEFAULT_PATH.to_owned();
    let mut endpoints = vec![DEFAULT_ENDPOINT.to_owned()];
    let mut tls = None;
    let mut credentials = None;
    let mut min_lease_ttl = DEFAULT_MIN_LEASE_TTL;
    let mut max_lease_ttl = DEFAULT_MAX_LEASE_TTL;
    let mut no_apex_fallback = false;
    while cursor.next_block() {
        let option = cursor.val().to_owned();
        match option.as_str() {
            // CoreDNS v1.15.0 plugin/etcd/setup.go etcdParse: `stubzones` and `debug` are ignored, `upstream` is read and ignored.
            "stubzones" | "debug" => {}
            "upstream" => {
                cursor.remaining_args();
            }
            "fallthrough" => {
                let args = cursor.remaining_args();
                fallthrough.set_domains_from_args(&strs(&args));
            }
            "no_apex_fallback" => {
                if !cursor.remaining_args().is_empty() {
                    return Err(cursor.arg_err());
                }
                no_apex_fallback = true;
            }
            "path" => {
                if !cursor.next_arg() {
                    return Err(cursor.arg_err());
                }
                path_prefix = cursor.val().to_owned();
            }
            "endpoint" => {
                endpoints = cursor.remaining_args();
                if endpoints.is_empty() {
                    return Err(cursor.arg_err());
                }
            }
            "tls" => {
                let args = cursor.remaining_args();
                tls = Some(tls_config(&args, root).map_err(|error| cursor.error(error))?);
            }
            "credentials" => {
                let args = cursor.remaining_args();
                let [username, password] = args.as_slice() else {
                    return Err(if args.is_empty() {
                        cursor.arg_err()
                    } else {
                        cursor.error("credentials requires 2 arguments, username and password")
                    });
                };
                // CoreDNS v1.15.0 plugin/etcd/setup.go newEtcdClient: credentials apply only when both are non-empty.
                credentials = (!username.is_empty() && !password.is_empty()).then(|| Credentials {
                    username: username.clone(),
                    password: password.clone(),
                });
            }
            "min-lease-ttl" => min_lease_ttl = ttl_argument(cursor, &option)?,
            "max-lease-ttl" => max_lease_ttl = ttl_argument(cursor, &option)?,
            _ => return Err(cursor.error(format!("unknown property '{option}'"))),
        }
    }
    let endpoints = endpoints
        .iter()
        .map(|text| endpoint(text, tls.is_some()))
        .collect::<Result<_, _>>()
        .map_err(|error| cursor.error(error))?;
    Ok(Config {
        zones: parse_domains(cursor, &zones)?,
        fallthrough: parse_domains(cursor, &fallthrough.domains)?,
        path_prefix,
        endpoints,
        tls,
        credentials,
        min_lease_ttl,
        max_lease_ttl,
        no_apex_fallback,
    })
}

/// The TTL that follows `option` on its line.
fn ttl_argument(cursor: &mut Cursor<'_>, option: &str) -> Result<u32, Error> {
    if !cursor.next_arg() {
        return Err(cursor.arg_err());
    }
    parse_ttl(cursor.val())
        .map_err(|error| cursor.error(format!("invalid {option} value: {error}")))
}

/// CoreDNS v1.15.0 plugin/pkg/tls/tls.go NewTLSConfigFromArgs: no arguments for the system roots, `CA`, `CERT KEY` or `CERT KEY CA`.
fn tls_config(args: &[String], root: Option<&Path>) -> Result<Arc<ClientConfig>, String> {
    if args.len() > 3 {
        return Err(format!(
            "maximum of three arguments allowed for TLS config, found {}",
            args.len()
        ));
    }
    let config = match crate::tls_client_from_args(args, root).map_err(|error| error.to_string())? {
        Some(config) => config,
        None => client_config(&ClientOptions::default()).map_err(|error| error.to_string())?,
    };
    // RFC 7301 §3.1: etcd's gRPC API runs on HTTP/2, so only `h2` is offered.
    let mut config = (*config).clone();
    config.alpn_protocols = grpc::ALPN
        .iter()
        .map(|protocol| protocol.to_vec())
        .collect();
    Ok(Arc::new(config))
}

/// etcd clientv3 internal/endpoint/endpoint.go translateEndpoint: `http://HOST[:PORT]`,
/// `https://HOST[:PORT]` or a bare `HOST[:PORT]`; the port defaults to 443 as in grpc-go.
fn endpoint(text: &str, tls_configured: bool) -> Result<Endpoint, String> {
    // etcd clientv3 endpoint.go translateEndpoint: url.Parse reads userinfo and clientv3 drops it, so it stays out of the text and every message.
    let text = without_userinfo(text);
    let text = text.as_str();
    // shortcut: unix sockets and other schemes are rejected at setup, where etcd clientv3 fails at dial; accept them when a deployment needs one.
    let unsupported = || format!("unsupported etcd endpoint '{text}'");
    if text.starts_with("unix:") || text.starts_with("unixs:") {
        return Err(unsupported());
    }
    let (tls, authority) = match text.split_once("://") {
        // etcd clientv3 endpoint.go schemeToCredsRequirement: `https` requires TLS and `http` never uses it.
        Some(("https", rest)) => (true, rest),
        Some(("http", rest)) => (false, rest),
        Some(_) => return Err(unsupported()),
        // etcd clientv3 endpoint.go schemeToCredsRequirement: without a scheme the `tls` option decides.
        None => (tls_configured, text),
    };
    let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
    let invalid = || format!("invalid etcd endpoint '{text}'");
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']').ok_or_else(invalid)?;
        match after {
            "" => (host, None),
            _ => (host, Some(after.strip_prefix(':').ok_or_else(invalid)?)),
        }
    } else {
        authority
            .split_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)))
    };
    if host.is_empty() {
        return Err(invalid());
    }
    let port = match port {
        Some(port) => port.parse().map_err(|_| invalid())?,
        None => 443,
    };
    Ok(Endpoint {
        text: text.to_owned(),
        host: host.to_owned(),
        port,
        tls,
    })
}

/// `text` without the userinfo before the last `@` of its authority.
fn without_userinfo(text: &str) -> String {
    // Go net/url Parse: the authority ends at the first `/`, `?` or `#`.
    let start = text.find("://").map_or(0, |scheme| scheme + 3);
    let end = text[start..]
        .find(['/', '?', '#'])
        .map_or(text.len(), |at| start + at);
    match text[start..end].rfind('@') {
        Some(at) => format!("{}{}", &text[..start], &text[start + at + 1..]),
        None => text.to_owned(),
    }
}

#[cfg(test)]
mod tests;

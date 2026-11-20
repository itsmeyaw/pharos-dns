//! `tls` Directive: the server certificate of encrypted Listeners.

pub(crate) mod acme;
pub(crate) mod setup;

use std::{path::Path, sync::Arc};

use pharos_corefile::{Cursor, Error};
use pharos_server::tls::{ClientAuth, ServerOptions, ServerTls};

/// A loaded TLS identity and the settings it was loaded with.
#[derive(Debug)]
pub struct Tls {
    /// The files of a `tls CERT KEY [CA]` identity.
    pub options: Option<ServerOptions>,
    /// The identity encrypted Listeners present; absent when the Server Block only answers challenges.
    pub server: Option<ServerTls>,
    /// The ACME configuration of a `tls { acme ... }` block.
    pub acme: Option<Arc<acme::Entry>>,
}

// CoreDNS v1.15.0 plugin/tls/tls.go parseTLS: every `tls` line loads; the last one wins.
pub(crate) fn parse(cursor: &mut Cursor<'_>, root: Option<&Path>) -> Result<Tls, Error> {
    let mut tls = None;
    while cursor.next() {
        let args = cursor.remaining_args();
        tls = Some(if args.is_empty() {
            // CoreDNS v1.15.0 plugin/tls/tls.go parseTLS: no arguments selects ACME.
            let entry = acme::parse(cursor, root)?;
            Tls {
                options: None,
                server: Some(entry.server()),
                acme: Some(Arc::new(entry)),
            }
        } else {
            parse_manual(cursor, root, &args)?
        });
    }
    tls.ok_or_else(|| cursor.arg_err())
}

// CoreDNS v1.15.0 plugin/tls/tls.go parseManualTLS: `tls CERT KEY [CA]` plus `client_auth` and `keylog`.
fn parse_manual(
    cursor: &mut Cursor<'_>,
    root: Option<&Path>,
    args: &[String],
) -> Result<Tls, Error> {
    if !(2..=3).contains(&args.len()) {
        return Err(cursor.arg_err());
    }
    let mut client_auth = ClientAuth::NoCert;
    let mut keylog = None;
    while cursor.next_block() {
        match cursor.val() {
            "client_auth" => {
                let args = cursor.remaining_args();
                let [kind] = args.as_slice() else {
                    return Err(cursor.arg_err());
                };
                client_auth = match kind.as_str() {
                    "nocert" => ClientAuth::NoCert,
                    "request" => ClientAuth::Request,
                    "require" => ClientAuth::Require,
                    "verify_if_given" => ClientAuth::VerifyIfGiven,
                    "require_and_verify" => ClientAuth::RequireAndVerify,
                    other => {
                        return Err(cursor.error(format!("unknown authentication type '{other}'")));
                    }
                };
            }
            "keylog" => {
                let args = cursor.remaining_args();
                let [path] = args.as_slice() else {
                    return Err(cursor.arg_err());
                };
                keylog = Some(crate::resolve_path(path.into(), root));
            }
            other => return Err(cursor.error(format!("unknown option '{other}'"))),
        }
    }
    let path = |index: usize| crate::resolve_path(args[index].clone().into(), root);
    let options = ServerOptions {
        cert: path(0),
        key: path(1),
        ca: (args.len() == 3).then(|| path(2)),
        client_auth,
        keylog,
    };
    let server = ServerTls::load(&options).map_err(|error| cursor.error(error.to_string()))?;
    Ok(Tls {
        options: Some(options),
        server: Some(server),
        acme: None,
    })
}

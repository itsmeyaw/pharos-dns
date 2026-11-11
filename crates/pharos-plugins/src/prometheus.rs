//! Prometheus Directive configuration.

use pharos_corefile::{Cursor, Error};
use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct Prometheus {
    pub address: String,
    pub tls_config: Option<String>,
}

pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Prometheus, Error> {
    cursor.next();
    let args = cursor.remaining_args();
    if args.len() > 1 {
        return Err(cursor.arg_err());
    }
    let address = args.first().map_or("localhost:9153", String::as_str);
    if !crate::valid_http_address(address) {
        return Err(cursor.error("invalid metrics address"));
    }
    let mut tls_config = None;
    while cursor.next_block() {
        match cursor.val() {
            "runtime_metrics" => {
                if !cursor.remaining_args().is_empty() {
                    return Err(cursor.arg_err());
                }
            }
            "tls" => {
                if tls_config.is_some() {
                    return Err(cursor.error("tls block already specified"));
                }
                let args = cursor.remaining_args();
                if args.len() != 1 {
                    return Err(cursor.arg_err());
                }
                tls_config = Some(args[0].clone());
            }
            option => return Err(cursor.error(format!("unknown option: {option}"))),
        }
    }
    Ok(Prometheus {
        address: address.to_owned(),
        tls_config,
    })
}

impl Plugin for Prometheus {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        next.run(cx).await
    }
}

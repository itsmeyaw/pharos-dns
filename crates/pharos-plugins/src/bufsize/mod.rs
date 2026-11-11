//! Limit the EDNS UDP payload advertised to downstream Plugins.

use pharos_corefile::{Cursor, Error as CorefileError};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol};

#[derive(Debug)]
pub struct Bufsize {
    size: u16,
}

impl Bufsize {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, CorefileError> {
        cursor.next();
        let args = cursor.remaining_args();
        let size = match args.as_slice() {
            [] => 1232,
            [arg] => arg
                .parse::<u16>()
                .ok()
                .filter(|n| (512..=4096).contains(n))
                .ok_or_else(|| cursor.arg_err())?,
            _ => return Err(cursor.arg_err()),
        };
        Ok(Self { size })
    }
}

impl Plugin for Bufsize {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        if cx
            .query
            .opt()
            .is_some_and(|opt| opt.udp_payload_size() > self.size)
        {
            // RFC 6891 §6.2.5: limit the advertised UDP payload without increasing it.
            cx.query = cx.query.with_udp_payload_limit(self.size);
            if cx.protocol == Protocol::Udp {
                cx.max_response_size = cx.max_response_size.min(usize::from(self.size));
            }
        }
        next.run(cx).await
    }
}

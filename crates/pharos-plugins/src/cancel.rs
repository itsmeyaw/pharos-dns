//! Cancel Queries that exceed their deadline.

use std::time::Duration;

use pharos_corefile::{Cursor, Error};
use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct Cancel {
    pub timeout: Duration,
}

pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Cancel, Error> {
    let mut timeout = Duration::from_millis(5001);
    while cursor.next() {
        let args = cursor.remaining_args();
        timeout = match args.as_slice() {
            [] => Duration::from_millis(5001),
            [value] => crate::health::parse_duration(value)
                .filter(|duration| !duration.is_zero())
                .ok_or_else(|| cursor.error("invalid duration"))?,
            _ => return Err(cursor.arg_err()),
        };
    }
    Ok(Cancel { timeout })
}

impl Plugin for Cancel {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        tokio::time::timeout(self.timeout, next.run(cx))
            .await
            .unwrap_or(Outcome::Drop)
    }
}

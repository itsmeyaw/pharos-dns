//! dnstap Directive: logs Queries and Responses as dnstap messages.

pub(crate) mod setup;

use pharos_server::{Context, Next, Outcome, Plugin};

/// The `dnstap` Directives of one Server Block.
#[derive(Debug)]
pub struct Dnstap;

impl Plugin for Dnstap {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        next.run(cx).await
    }
}

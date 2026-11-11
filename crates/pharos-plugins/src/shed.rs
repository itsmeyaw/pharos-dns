//! UDP shedding is coordinated by the Listener's per-socket writer.

use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct Shed;

impl Plugin for Shed {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        next.run(cx).await
    }
}

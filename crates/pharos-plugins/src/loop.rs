//! Detect forwarding loops during startup.

use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct Loop {
    pub domain: String,
}

impl Loop {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.into(),
        }
    }
}

impl Plugin for Loop {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        next.run(cx).await
    }
}

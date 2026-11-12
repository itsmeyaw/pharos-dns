//! Server Block selection using compiled expressions.

pub(crate) mod setup;

use crate::expression::Expression;
use pharos_server::{Context, Next, Outcome, Plugin};

pub struct View {
    pub name: String,
    pub expressions: Vec<Expression>,
}

impl std::fmt::Debug for View {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("View")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Plugin for View {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        next.run(cx).await
    }
}
